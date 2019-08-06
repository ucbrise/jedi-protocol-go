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
	"testing"
	"time"
)

func helperTestDelegation(t *testing.T, uri string, start time.Time, end time.Time) {
	ctx := context.Background()
	_, store := NewTestKeyStore()
	encoder := NewDefaultPatternEncoder(TestPatternSize - MaxTimeLength)

	delegation, err := Delegate(ctx, store, encoder, TestHierarchy, uri, start, end, DecryptPermission|SignPermission)
	if err != nil {
		t.Fatal(err)
	}

	/* Parse the URI. */
	var uriPath URIPath
	if uriPath, err = ParseURI(uri); err != nil {
		t.Fatal(err)
	}

	for tm := start; tm.Before(end); tm = tm.Add(time.Hour) {
		timePath, err := ParseTime(tm)
		if err != nil {
			t.Fatal(err)
		}
		for _, patternType := range []PatternType{PatternTypeDecryption, PatternTypeSigning} {
			target := encoder.Encode(uriPath, timePath, patternType)
			conveyed := false
			for _, pattern := range delegation.Patterns {
				if pattern.Matches(target) {
					conveyed = true
					break
				}
			}
			if !conveyed {
				t.Logf("Delegation failed to include key for time %v (type = %d)", tm, patternType)
				t.Fail()
			}
		}
	}
}

func TestDelegationURIPrefix(t *testing.T) {
	helperTestDelegation(t, "a/b/c/*", time.Unix(1565119330, 0), time.Unix(1565219330, 0))
}

func TestDelegationFullURI(t *testing.T) {
	helperTestDelegation(t, "a/b/c/d", time.Unix(1565119330, 0), time.Unix(1565219330, 0))
}
