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

import "github.com/ucbrise/jedi-pairing/lang/go/wkdibe"

// KeyType describes a type of WKD-IBE secret key in the key store.
type KeyType int

// These constants enumerate the types of WKD-IBE secret keys in the key store.
const (
	KeyTypeDecryption = iota
	KeyTypeSigning
)

// KeyStoreReader represents a read-only interface to a key store that can be
// used with JEDI. It represents the interface that a key store must support
// so that JEDI can properly read from it when encrypting messages, decrypting
// messages, and creating delegations.
//
// Currently there's no implementation of this interface in this library. All
// of the applications to which we've applied JEDI so far have their own
// mechanisms to exchange keys; to apply this library to such systems, one
// would lift the interface to the application's locally stored keys to this
// interface. This allows the functions in this library to read the relevant
// keys from the local storage infrastructure that's already part of the
// application.
//
// If we apply JEDI to an application that doesn't have this functionality, I
// would implement a "default" key store, satisfying this interface, that could
// be used to provide the functionality.
type KeyStoreReader interface {
	// ParamsForHierarchy retrieves the WKD-IBE public parameters used for a
	// hierarchy.
	ParamsForHierarchy(hierarchy []byte) (*wkdibe.Params, error)

	// KeyForPattern retrieves a key whose pattern matches the provided URI
	// and time, where "matches" is defined as in Section 3.1 of the JEDI paper
	// (see the README.md file for a full citation of the paper).
	KeyForPattern(hierarchy []byte, uripath URIPath, timepath TimePath, keyType KeyType) (*wkdibe.SecretKey, Pattern, error)
}
