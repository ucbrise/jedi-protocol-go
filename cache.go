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
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"github.com/samkumar/reqcache"
	"github.com/ucbrise/jedi-pairing/lang/go/bls12381"
	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

// ClientState is the state that JEDI principals keep in memory to accelerate
// encryption, decryption, signing, and verification of messages.
type ClientState struct {
	info    PublicInfoReader
	store   KeyStoreReader
	encoder PatternEncoder
	cache   *reqcache.LRUCache
}

// hierarchyCacheEntry stores the public parameters of a JEDI hierarchy.
type hierarchyCacheEntry wkdibe.Params

// encryptionCacheEntry stores cached data to accelerate encryption for a URI.
type encryptionCacheEntry struct {
	lock         sync.RWMutex
	pattern      Pattern
	attrs        wkdibe.AttributeList
	key          [AESKeySize]byte
	encryptedKey *wkdibe.Ciphertext
	precomputed  *wkdibe.PreparedAttributeList
}

// decryptionCacheEntry stores the cached decryption of a ciphertext.
type decryptionCacheEntry struct {
	lock      sync.RWMutex
	decrypted [AESKeySize]byte
	populated bool
}

/* Key type identifiers for cache. */
const (
	cacheKeyTypeHierarchy = iota
	cacheKeyTypeEncryption
	cacheKeyTypeDecryption
)

// hierarchyCacheKey constructs a key for the cache based on a hierarchy
// identifier, ns, to look up the public parameters for that hierarchy.
func hierarchyCacheKey(ns []byte) string {
	var b strings.Builder
	b.WriteByte(cacheKeyTypeHierarchy)
	b.Write(ns)
	return b.String()
}

// encryptionCacheKey constructs a key for the cache based on a hierarchy
// identifier and a URI path, to look up cached data to speed up encryption.
func encryptionCacheKey(ns []byte, uri URIPath) string {
	var b strings.Builder
	b.WriteByte(cacheKeyTypeEncryption)

	var buffer [4]byte
	binary.LittleEndian.PutUint32(buffer[:], uint32(len(ns)))

	b.Write(buffer[:])
	b.Write(ns)

	for _, component := range uri {
		b.Write(component)
		b.WriteByte('/')
	}

	return b.String()
}

// decryptionCacheKey constructs a key for the cache based on a ciphertext of
// an encrypted symmetric key, to look up the cached plaintext in lieu of
// decryption.
func decryptionCacheKey(ciphertext []byte) string {
	var b strings.Builder
	b.WriteByte(cacheKeyTypeDecryption)
	b.Write(ciphertext)
	return b.String()
}

func parsekey(key string) (keytype byte, content []byte) {
	keybytes := []byte(key)
	keytype = keybytes[0]
	switch keytype {
	case cacheKeyTypeHierarchy:
		content = keybytes[1:]
	case cacheKeyTypeEncryption:
		nslen := binary.LittleEndian.Uint32(keybytes[1:5])
		content = keybytes[5 : 5+nslen]
	case cacheKeyTypeDecryption:
		content = keybytes[1:]
	}
	return
}

// NewClientState creates a new ClientState abstraction with the specified
// abstraction to the key store, algorithm to encode patterns, and memory
// capacity (in bytes) to cache objects to accelerate JEDI's crypto operations.
func NewClientState(public PublicInfoReader, keys KeyStoreReader, encoder PatternEncoder, capacity uint64) *ClientState {
	state := new(ClientState)
	state.info = public
	state.store = keys
	state.encoder = encoder

	state.cache = reqcache.NewLRUCache(capacity,
		func(ctx context.Context, key interface{}) (interface{}, uint64, error) {
			keystring := key.(string)
			keytype, contentbytes := parsekey(keystring)
			size := uint64(len(keystring))
			switch keytype {
			case cacheKeyTypeHierarchy:
				params, err := state.info.ParamsForHierarchy(ctx, contentbytes)
				if err != nil {
					return nil, 0, err
				}
				size += uint64(unsafe.Sizeof(*params)) + uint64(uintptr(params.NumAttributes())*unsafe.Sizeof(*bls12381.G1Zero))
				return (*hierarchyCacheEntry)(params), size, nil
			case cacheKeyTypeEncryption:
				entry := new(encryptionCacheEntry)
				/*
				 * Since these cache entries are mutable anyway, and have an
				 * internal lock to support that, we just have the caller
				 * acquire the lock and perform the initialization.
				 */
				size += uint64(unsafe.Sizeof(*entry) + unsafe.Sizeof(*entry.encryptedKey) + unsafe.Sizeof(*entry.precomputed))
				return entry, size, nil
			case cacheKeyTypeDecryption:
				entry := new(decryptionCacheEntry)
				/*
				 * We can't populate this type of entry here, because we need
				 * the URI and time to be able to decrypt the ciphertext.
				 */
				size += uint64(unsafe.Sizeof(*entry))
				return entry, size, nil
			default:
				panic(fmt.Sprintf("Unknown cache key type: %v", keytype))
			}
		}, nil)

	return state
}
