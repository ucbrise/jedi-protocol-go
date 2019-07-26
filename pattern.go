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

import "bytes"

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
	Representation() []byte
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

// Matches returns a boolean indicating whether this Pattern matches the one
// provided as an argument. The term "matches" is defined in Section 3.1 of the
// JEDI paper (see the README.md file for a full citation of the paper).
func (p Pattern) Matches(q Pattern) bool {
	if len(p) != len(q) {
		panic("Patterns must be the same length to check matching")
	}
	for i, comp := range p {
		if comp != nil && !bytes.Equal(comp, q[i]) {
			return false
		}
	}
	return true
}

// EncodePattern encodes a URIPath and TimePath into a pattern, where each
// component is represented as a byte slice. The slice into which to encode
// the pattern is provided as an argument.
func EncodePattern(uripath URIPath, timepath TimePath, into Pattern) {
	if len(into) < len(uripath)+MaxTimeLength {
		panic("Not enough space to encode pattern")
	}
	for i, component := range uripath {
		into[i] = component.Representation()
	}
	for j := len(uripath); j != len(into)-MaxTimeLength; j++ {
		into[j] = nil
	}
	for k, component := range timepath {
		into[len(into)-MaxTimeLength+k] = component.Representation()
	}
}

// DecodePattern decodes a pattern encoded as a byte slice for each component
// back into its component URI and time.
func DecodePattern(pattern [][]byte) (URIPath, TimePath) {
	if len(pattern) < MaxTimeLength {
		panic("Pattern is too short to be valid")
	}

	var lastNonNilIndex int

	uripath := make(URIPath, 0, len(pattern)-MaxTimeLength)
	lastNonNilIndex = -1
	for i, slot := range pattern[:len(pattern)-MaxTimeLength] {
		if slot != nil {
			lastNonNilIndex = i
		}
		uripath = append(uripath, URIComponent(slot))
	}
	uripath = uripath[:lastNonNilIndex+1]

	timepath := make(TimePath, 0, MaxTimeLength)
	lastNonNilIndex = -1
	for i, slot := range pattern[len(pattern)-MaxTimeLength:] {
		if slot != nil {
			lastNonNilIndex = i
		}
		timepath = append(timepath, TimeComponent(slot))
	}
	timepath = timepath[:lastNonNilIndex+1]

	return uripath, timepath
}
