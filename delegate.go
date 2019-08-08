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
	"errors"
	"time"

	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

// Permission indicates the type of access that is being granted. It is a bit
// vector.
type Permission uint32

// These constants are the base Permissions that can be combined via bitwise
// OR.
const (
	DecryptPermission Permission = 0x1
	SignPermission    Permission = 0x2
)

// Delegation is a bundle of keys that delegate permission.
type Delegation struct {
	Hierarchy []byte
	Params    *wkdibe.Params
	Patterns  []Pattern
	Keys      []*wkdibe.SecretKey
}

// Delegate creates a new JEDI delegation conveying some permissions on a URI
// or URI prefix for a time range.
func Delegate(ctx context.Context, ks KeyStoreReader, pe PatternEncoder, hierarchy []byte, uri string, start time.Time, end time.Time, perm Permission) (*Delegation, error) {
	var err error

	/* Parse the URI. */
	var uriPath URIPath
	if uriPath, err = ParseURI(uri); err != nil {
		return nil, err
	}

	/* Compute the time range. */
	var timePaths []TimePath
	if timePaths, err = TimeRange(start, end); err != nil {
		return nil, err
	}

	return DelegateParsed(ctx, ks, pe, hierarchy, uriPath, timePaths, perm)
}

// DelegateParsed creates a new JEDI delegation conveying permissions on a URI
// or URI prefix for the set of indicated times.
func DelegateParsed(ctx context.Context, ks KeyStoreReader, pe PatternEncoder, hierarchy []byte, uriPath URIPath, timePaths []TimePath, perm Permission) (*Delegation, error) {
	decrypt := (perm & DecryptPermission) == DecryptPermission
	sign := (perm & SignPermission) == SignPermission

	numPatterns := len(timePaths)
	if decrypt && sign {
		numPatterns <<= 1
	}
	patterns := make([]Pattern, 0, numPatterns)

	for i, timePath := range timePaths {
		if decrypt {
			pattern := pe.Encode(uriPath, timePath, PatternTypeDecryption)
			patterns = append(patterns, pattern)
		}
		if sign {
			pattern := pe.Encode(uriPath, timePath, PatternTypeSigning)
			patterns = append(patterns, pattern)
		}

		/* Reorder the last two patterns for efficient delta compression. */
		if decrypt && sign && (i&0x1) == 0x1 {
			j := i << 1
			k := j + 1
			patterns[j], patterns[k] = patterns[k], patterns[j]
		}
	}

	return DelegatePatterns(ctx, ks, hierarchy, patterns)
}

// DelegatePatterns creates a new JEDI delegation granting the permissions
// conveyed in the set of provided patterns.
func DelegatePatterns(ctx context.Context, ks KeyStoreReader, hierarchy []byte, patterns []Pattern) (*Delegation, error) {
	var hierarchyParams *wkdibe.Params
	keys := make([]*wkdibe.SecretKey, len(patterns))
	for i, pattern := range patterns {
		params, key, err := ks.KeyForPattern(ctx, hierarchy, pattern)
		if err != nil {
			return nil, err
		}
		if key == nil {
			return nil, errors.New("could not generate key: requisite delegation(s) not received")
		}
		keys[i] = wkdibe.NonDelegableQualifyKey(params, key, pattern.ToAttrs())
		if hierarchyParams == nil {
			hierarchyParams = params
		}
	}
	return &Delegation{
		Hierarchy: hierarchy,
		Params:    hierarchyParams,
		Patterns:  patterns,
		Keys:      keys,
	}, nil
}
