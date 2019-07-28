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
	"bytes"
	"math/big"

	"github.com/ucbrise/jedi-pairing/lang/go/cryptutils"
	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

// PatternComponentType encodes the type of a pattern component.
type PatternComponentType int

// These constants describe the types of pattern components.
const (
	URIComponentType PatternComponentType = iota
	TimeComponentType
)

// PatternComponent is the interface satsified by URIComponent and
// TimeComponent. It describes a component in a pattern.
type PatternComponent interface {
	Type() PatternComponentType
	String() string

	// These functions are useful if you don't want to use a type assertion
	// but know what the underlying type is.
	Name() string
	Quantity() uint16
}

// Pattern describes a pattern encoding a URIPath and TimePath, represented as
// a list of byte slices.
type Pattern [][]byte

// GetComponent returns a component of the Pattern, abstracted as a
// PatternComponent.
func (p Pattern) GetComponent(index int) PatternComponent {
	if index < len(p)-MaxTimeLength {
		return URIComponent(p[index])
	}
	return TimeComponent(p[index])
}

// Equals returns a boolean indicating whther this Pattern equals the one
// provided as an argument.
func (p Pattern) Equals(q Pattern) bool {
	if len(p) != len(q) {
		return false
	}
	for i, comp := range p {
		if !bytes.Equal(comp, q[i]) {
			return false
		}
	}
	return true
}

// Matches returns a boolean indicating whether this Pattern matches the one
// provided as an argument. The term "matches" is defined in Section 3.1 of the
// JEDI paper (see the README.md file for a full citation of the paper).
func (p Pattern) Matches(q Pattern) bool {
	if len(p) != len(q) {
		panic("Patterns must be the same length to check matching")
	}
	for i, comp := range p {
		if len(comp) != 0 && !bytes.Equal(comp, q[i]) {
			return false
		}
	}
	return true
}

// ToAttrs converts a pattern to a WKD-IBE attribute list by hashing each
// component.
func (p Pattern) ToAttrs() wkdibe.AttributeList {
	attrs := make(wkdibe.AttributeList)
	for i, comp := range p {
		if len(comp) != 0 {
			attrs[wkdibe.AttributeIndex(i)] = cryptutils.HashToZp(new(big.Int), comp)
		}
	}
	return attrs
}

// ToAttrsWithReference is the same as ToAttrs, but it uses a similar pattern
// and its corresponding WKD-IBE attribute list to avoid hashing where
// possible. Some of the big integers in the returned attribute list may be
// aliased with those in the provided attribute list. the returned bool
// indicates if p and q are equal.
func (p Pattern) ToAttrsWithReference(q Pattern, qAttrs wkdibe.AttributeList) (wkdibe.AttributeList, bool) {
	attrs := make(wkdibe.AttributeList)
	equal := true
	for i, comp := range p {
		if len(comp) != 0 {
			idx := wkdibe.AttributeIndex(i)
			if bytes.Equal(comp, q[i]) {
				attrs[idx] = qAttrs[idx]
			} else {
				attrs[idx] = cryptutils.HashToZp(new(big.Int), comp)
				equal = false
			}
		} else if len(q[i]) != 0 {
			equal = false
		}
	}
	return attrs, equal
}

// EncodePattern encodes a URIPath and TimePath into a pattern, where each
// component is represented as a byte slice. The slice into which to encode
// the pattern is provided as an argument. This is designed to be a helper
// function; the "PatternEncoder" interface is designed to support flexible,
// application-dependent encoding.
func EncodePattern(uripath URIPath, timepath TimePath, into Pattern) {
	if len(into) < len(uripath)+MaxTimeLength {
		panic("Not enough space to encode pattern")
	}
	EncodeURIPathInto(uripath, into[:len(into)-MaxTimeLength])
	EncodeTimePathInto(timepath, into[len(into)-MaxTimeLength:])
}

// DecodePattern decodes a pattern encoded as a byte slice for each component
// back into its component URI and time.
func DecodePattern(pattern Pattern) (URIPath, TimePath) {
	if len(pattern) < MaxTimeLength {
		panic("Pattern is too short to be valid")
	}

	uripath := DecodeURIPathFrom(pattern[:len(pattern)-MaxTimeLength])
	timepath := DecodeTimePathFrom(pattern[len(pattern)-MaxTimeLength:])

	return uripath, timepath
}
