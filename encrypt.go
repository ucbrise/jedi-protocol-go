/*
 * Copyright (c) 2019, Sam Kumar <samkumar@cs.berkeley.edu>
 * Copyright (c) 2019, University of California, Berkeley
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package jedi

import (
	"context"
	"crypto/aes"
	"errors"
	"time"

	"github.com/ucbrise/jedi-pairing/lang/go/cryptutils"
	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

// EncryptedKeySize the size (in bytes) of the WKD-IBE ciphertext of the
// symmetric key at the beginning of each JEDI ciphertext.
var EncryptedKeySize = wkdibe.CiphertextMarshalledLength(true)

// Encrypt encrypts a message using JEDI, reading from and mutating the
// ClientState instance on which the function is invoked. The "timestamp"
// argument should be set to the current time in most cases, which can be
// obtained by calling time.Now(). The function will work with any URI/time
// combination, but for a single URI you should try to move chronologically
// in time for the best performance.
func (state *ClientState) Encrypt(ctx context.Context, hierarchy []byte, uri string, timestamp time.Time, message []byte) ([]byte, error) {
	var err error

	/* Parse the URI. */
	var uriPath URIPath
	if uriPath, err = ParseURI(uri); err != nil {
		return nil, err
	}

	/* Parse the current time. */
	var timePath TimePath
	if timePath, err = ParseTime(timestamp); err != nil {
		return nil, err
	}

	/* Encode the pattern based on the URI path and time path. */
	pattern := state.encoder.Encode(uriPath, timePath, PatternTypeDecryption)

	return state.EncryptWithPattern(ctx, hierarchy, uriPath, pattern, message)
}

// EncryptWithPattern is like Encrypt, but requires the Pattern to already be
// formed. This is useful if you've already parsed the URI, or are working with
// the URI components directly.
func (state *ClientState) EncryptWithPattern(ctx context.Context, hierarchy []byte, uriPath URIPath, pattern Pattern, message []byte) ([]byte, error) {
	var err error

	/* Get WKD-IBE public parameters for the specified namespace. */
	var paramsInt interface{}
	if paramsInt, err = state.cache.Get(ctx, hierarchyCacheKey(hierarchy)); err != nil {
		return nil, err
	}
	params := (*wkdibe.Params)(paramsInt.(*hierarchyCacheEntry))

	/* Get the cached state (if any) for this URI. */
	var entryInt interface{}
	if entryInt, err = state.cache.Get(ctx, encryptionCacheKey(hierarchy, uriPath)); err != nil {
		return nil, err
	}
	entry := entryInt.(*encryptionCacheEntry)

	var key [AESKeySize]byte
	encrypted := make([]byte, EncryptedKeySize+aes.BlockSize+len(message))

	/*
	 * Acquire the entry's lock as a reader, optimistically assuming that our
	 * URI and time are identical to the cached ones.
	 */
	entry.lock.RLock()

	/* Check if our pattern matches the one in the cache. */
	identical := pattern.Equals(entry.pattern)

	/*
	 * If they match, then save the key so we can reuse it for this
	 * encryption.
	 */
	if identical {
		copy(key[:], entry.key[:])
		copy(encrypted[:EncryptedKeySize], entry.encryptedKey.Marshal(true))
	}

	entry.lock.RUnlock()

	if !identical {
		/*
		 * If they aren't identical to the cached ones, then we can't use the
		 * cached key directly---we must either compute the encryption from
		 * scratch and cache the values, or, if there's already a cached value,
		 * perform precomputation with adjustment. Acquire the entry's lock as
		 * a writer in preparation for this.
		 */
		entry.lock.Lock()

		updateEntryAndEncrypt := false
		var attrs wkdibe.AttributeList

		if entry.pattern == nil {
			/*
			 * It's a new entry, so we need to encrypt from scratch. Obtain the
			 * intermediate value (the precomputation) and store it in the
			 * entry for later use.
			 */
			attrs = pattern.ToAttrs()
			entry.precomputed = wkdibe.PrepareAttributeList(params, attrs)
			updateEntryAndEncrypt = true
		} else {
			/*
			 * It's an existing value with a cached precomputation. We can't
			 * use that precomputation directly in our encryption, but we can
			 * use it to compute our new precomputation faster.
			 */
			attrs, identical = pattern.ToAttrsWithReference(entry.pattern, entry.attrs)

			/*
			 * Since we dropped the lock (as a reader) and re-acquired it as a
			 * writer, another thread may have intervened and calculated the
			 * value we need, so check again just in case.
			 */
			if !identical {
				/*
				 * This is the common case after acquiring the lock as a
				 * writer. Adjust the precomputed value in the entry, and set a
				 * flag so we remember to actually do the encryption and update
				 * the entry's other fields.
				 */
				wkdibe.AdjustPreparedAttributeList(entry.precomputed, params, entry.attrs, attrs)
				updateEntryAndEncrypt = true
			}
		}

		if updateEntryAndEncrypt {
			/* Fill in the entry. */
			entry.pattern = pattern
			entry.attrs = attrs

			/* Sample a new symmetric key and encrypt it with WKD-IBE. */
			_, encryptable := cryptutils.GenerateKey(entry.key[:])
			entry.encryptedKey = wkdibe.EncryptPrepared(encryptable, params, entry.precomputed)
		}

		/*
		 * We've now ensured that the cache entry matches our pattern, so save
		 * the key and its encryption so we can use it here.
		 */
		copy(key[:], entry.key[:])
		copy(encrypted[:EncryptedKeySize], entry.encryptedKey.Marshal(true))

		entry.lock.Unlock()
	}

	/* Encrypt the message with the symmetric key. */
	if err = aesCTREncryptInMem(encrypted[EncryptedKeySize:], message, key[:]); err != nil {
		return nil, err
	}

	return encrypted, nil
}

// Decrypt decrypts a message encrypted with JEDI, reading from and mutating
// the ClientState instance on which the function is invoked. It's very
// important that message's integrity (e.g., signature) is verified before
// calling this function. If not, an attacker could get us to decrypt a message
// with the "wrong" URI/time; if this happens, an incorrect symmetric key will
// be cached in the ClientState, denying service for future proper messages
// reusing that pattern.
func (state *ClientState) Decrypt(ctx context.Context, hierarchy []byte, uri string, timestamp time.Time, encrypted []byte) ([]byte, error) {
	if len(encrypted) < EncryptedKeySize+aes.BlockSize {
		return nil, errors.New("Encrypted blob is too short to be valid")
	}
	encryptedKey := encrypted[:EncryptedKeySize]
	encryptedMessage := encrypted[EncryptedKeySize:]
	return state.DecryptSeparated(ctx, hierarchy, uri, timestamp, encryptedKey, encryptedMessage)
}

// DecryptSeparated is the same as Decrypt, but accepts the encrypted message
// in two parts: the WKD-IBE ciphertext of the encrypted symmetric key, and the
// symmetric-key ciphertext of the encrypted message.
func (state *ClientState) DecryptSeparated(ctx context.Context, hierarchy []byte, uri string, timestamp time.Time, encryptedKey []byte, encryptedMessage []byte) ([]byte, error) {
	var err error

	/* Parse the URI. */
	var uriPath URIPath
	if uriPath, err = ParseURI(uri); err != nil {
		return nil, err
	}

	/* Parse the current time. */
	var timePath TimePath
	if timePath, err = ParseTime(timestamp); err != nil {
		return nil, err
	}

	/* Encode the pattern based on the URI path and time path. */
	pattern := state.encoder.Encode(uriPath, timePath, PatternTypeDecryption)

	return state.DecryptWithPattern(ctx, hierarchy, pattern, encryptedKey, encryptedMessage)
}

// DecryptWithPattern is the same as Decrypt, but requires the Pattern to be
// already formed. This is useful if the pattern itself was sent with the
// message and is available directly in lieu of the URI and timestamp.
func (state *ClientState) DecryptWithPattern(ctx context.Context, hierarchy []byte, pattern Pattern, encryptedKey []byte, encryptedMessage []byte) ([]byte, error) {
	var err error

	/* Sanity-check the length of the encryptedMessage and encryptedKey. */
	if len(encryptedKey) != EncryptedKeySize {
		return nil, errors.New("encryptedKey has invalid size")
	}
	if len(encryptedMessage) < aes.BlockSize {
		return nil, errors.New("encryptedMessage has invalid size")
	}

	/* Check if we've cached the decryption of this ciphertext. */
	var entryInt interface{}
	if entryInt, err = state.cache.Get(ctx, decryptionCacheKey(encryptedKey)); err != nil {
		return nil, err
	}
	entry := entryInt.(*decryptionCacheEntry)

	var key [AESKeySize]byte

	/*
	 * Acquire the entry's lock as a reader, optimistically assuming it's
	 * populated and we can skip the decryption.
	 */
	entry.lock.RLock()
	if entry.populated {
		/*
		 * We've seen this ciphertext before and decrypted it, so just copy
		 * the result.
		 */
		copy(key[:], entry.decrypted[:])
		entry.lock.RUnlock()
	} else {
		/*
		 * We need to decrypt the ciphertext and mutate this cache entry to
		 * store the decrypted key.
		 */
		entry.lock.RUnlock()
		entry.lock.Lock()

		/*
		 * Since we dropped the lock (as a reader) and re-acquired it as a
		 * writer, another thread may have intervened and performed the
		 * decryption for us, so check again just in case.
		 */
		if entry.populated {
			/* The decryption is available now, so just copy it. */
			copy(key[:], entry.decrypted[:])
		} else {
			/*
			 * This is the common case after acquiring the lock as a writer.
			 * Actually perform the decryption, store the result in the entry,
			 * and then release the lock.
			 */
			var ciphertext wkdibe.Ciphertext
			if !ciphertext.Unmarshal(encryptedKey, true, false) {
				entry.lock.Unlock()
				return nil, errors.New("malformed ciphertext")
			}

			var params *wkdibe.Params
			var secretKey *wkdibe.SecretKey
			if params, secretKey, err = state.store.KeyForPattern(ctx, hierarchy, pattern); err != nil {
				entry.lock.Unlock()
				return nil, err
			}
			if secretKey == nil {
				entry.lock.Unlock()
				return nil, errors.New("could not find suitable key for decryption: requisite delegation(s) not received")
			}

			secretKey = wkdibe.NonDelegableQualifyKey(params, secretKey, pattern.ToAttrs())

			encryptable := wkdibe.Decrypt(&ciphertext, secretKey)
			encryptable.HashToSymmetricKey(entry.decrypted[:])
			copy(key[:], entry.decrypted[:])
			entry.populated = true
		}

		entry.lock.Unlock()
	}

	decrypted := make([]byte, len(encryptedMessage)-aes.BlockSize)
	if err = aesCTRDecryptInMem(decrypted, encryptedMessage, key[:]); err != nil {
		return nil, err
	}
	return decrypted, nil
}
