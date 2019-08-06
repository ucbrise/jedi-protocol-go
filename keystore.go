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
	"fmt"

	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
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
	// KeyForPattern retrieves a key whose pattern matches the provided
	// pattern, where "matches" is defined as in Section 3.1 of the JEDI paper
	// (see the README.md file for a full citation of the paper). The pattern
	// should be encoded from a URI and time using the application's
	// PatternEncoder.
	KeyForPattern(ctx context.Context, hierarchy []byte, pattern Pattern) (*wkdibe.Params, *wkdibe.SecretKey, error)
}

// PublicInfoReader represents a read-only interface to the public parameters
// for each hierarchy. It is similar to KeyStoreReader, in that it is meant to
// be implemented by the calling application.
type PublicInfoReader interface {
	// ParamsForHierarchy retrieves the WKD-IBE public parameters used for a
	// hierarchy.
	ParamsForHierarchy(ctx context.Context, hierarchy []byte) (*wkdibe.Params, error)
}

// PatternType describes a type of permission encoded by a pattern.
type PatternType int

// These constants enumerate the types of WKD-IBE secret keys in the key store.
const (
	PatternTypeDecryption = iota
	PatternTypeSigning
)

// PatternEncoder represents an algorithm to encode a URI and time into a
// pattern. The EncodePattern() function is a good starting point, but a real
// application needs to distinguish between encryption and signing keys, and
// may choose to use extra slots to distinguish JEDI keys from other uses of
// WKD-IBE.
type PatternEncoder interface {
	// Encode encodes URI and time into a pattern.
	Encode(uriPath URIPath, timePath TimePath, patternType PatternType) Pattern
}

// DefaultPatternEncoder is a simple pattern encoding that will likely be
// suitable for many applications.
type DefaultPatternEncoder struct {
	patternLength int
}

// NewDefaultPatternEncoder creates a new DefaultPatternEncoder, capable of
// supporting the specified URI length, and returns it.
func NewDefaultPatternEncoder(maxURILength int) *DefaultPatternEncoder {
	return &DefaultPatternEncoder{
		patternLength: maxURILength + MaxTimeLength,
	}
}

// Prefixes attached to each component of a pattern encoded with the default
// encoding.
const (
	decryptionDefaultPatternComponentPrefix = iota
	signingDefaultPatternComponentPrefix
)

// Encode encodes a URI and time into a pattern, using the default encoding. It
// attaches a prefix to each component of the pattern to distinguish decryption
// keys from signing keys, but does not introduce any extra components in the
// pattern.
func (dpe *DefaultPatternEncoder) Encode(uriPath URIPath, timePath TimePath, patternType PatternType) Pattern {
	pattern := make(Pattern, dpe.patternLength)
	EncodePattern(uriPath, timePath, pattern)

	var prefix byte
	switch patternType {
	case PatternTypeDecryption:
		prefix = decryptionDefaultPatternComponentPrefix
	case PatternTypeSigning:
		prefix = signingDefaultPatternComponentPrefix
	default:
		panic(fmt.Sprintf("Unknown key type %d\n", patternType))
	}

	for i, comp := range pattern {
		if len(comp) != 0 {
			pattern[i] = append([]byte{prefix}, comp...)
		}
	}

	return pattern
}
