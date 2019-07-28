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
	"time"

	"github.com/ucbrise/jedi-pairing/lang/go/cryptutils"
	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

// EncryptedKeySize the size (in bytes) of the WKD-IBE ciphertext of the
// symmetric key at the beginning of each JEDI ciphertext.
var EncryptedKeySize = wkdibe.CiphertextMarshalledLength(true)

// Encrypt encrypts a message using JEDI, reading from and mutating the
// ClientState instance on which the function is invoked.
func (state *ClientState) Encrypt(ctx context.Context, hierarchy []byte, uri string, message []byte) ([]byte, error) {
	return state.EncryptWithTime(ctx, hierarchy, uri, time.Now(), message)
}

// EncryptWithTime is like Encrypt, but allows the timestamp used for
// encryption to be specified.
func (state *ClientState) EncryptWithTime(ctx context.Context, hierarchy []byte, uri string, timestamp time.Time, message []byte) ([]byte, error) {
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

	return state.EncryptParsed(ctx, hierarchy, uriPath, pattern, message)
}

// EncryptParsed is like Encrypt, but requires the Pattern to already be formed
// already. This is useful if you've already parsed the URI, or are working
// with the URI components directly.
func (state *ClientState) EncryptParsed(ctx context.Context, hierarchy []byte, uriPath URIPath, pattern Pattern, message []byte) ([]byte, error) {
	var err error

	/* Get WKD-IBE public parameters for the specified namespace. */
	var paramsInt interface{}
	if paramsInt, err = state.cache.Get(ctx, hierarchyCacheKey(hierarchy)); err != nil {
		return nil, err
	}
	params := paramsInt.(*wkdibe.Params)

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
				 * This is the common case --- we actually have to do some
				 * crypto to compute the ciphertext. Adjust the precomputed
				 * value in the entry, and set a flag so we remember to
				 * actually do the encryption and update the entry's other
				 * fields.
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
