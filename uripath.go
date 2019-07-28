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
	"errors"
	"fmt"
	"strings"
)

// URIComponentPosition describes the index of a URIComponent in a URIPath.
type URIComponentPosition uint8

// URIComponent describes a component of a URIPath.
type URIComponent []byte

// NewURIComponent creates a new URIComponent with the given name and position.
func NewURIComponent(name string, position URIComponentPosition) URIComponent {
	uclength := 1 + len(name)
	uc := make([]byte, uclength, uclength)
	uc[0] = byte(position)
	copy(uc[1:], name)
	return uc
}

// Type returns the value URIComponentType.
func (uc URIComponent) Type() PatternComponentType {
	return URIComponentType
}

// String returns a printable string representing this URIComponent.
func (uc URIComponent) String() string {
	if uc == nil {
		return "+"
	}
	return uc.Name()
}

// Name returns the name associated with this URIComponent.
func (uc URIComponent) Name() string {
	return string(uc[1:])
}

// Quantity panics.
func (uc URIComponent) Quantity() uint16 {
	panic("Quantity() is not a valid method for a URI component")
}

// Position returns the index of this URIComponent within a URIPath.
func (uc URIComponent) Position() URIComponentPosition {
	return URIComponentPosition(uc[0])
}

// URIPath represents a URI or URI prefix.
type URIPath []URIComponent

// EndOfURISymbol is the sentinel used at the end of non-prefix URIs to prevent
// further delegation.
const EndOfURISymbol = '$'

// ValidateURIComponent takes a string and returns a boolean indicating if it
// represents a valid URI component.
func ValidateURIComponent(uri string) bool {
	if len(uri) == 0 || (len(uri) == 1 && uri[0] == EndOfURISymbol) {
		return false
	}
	return true
}

// ParseURIFromPath takes a slice of URI components and produces a URIPath
// representing that URI or URI prefix.
func ParseURIFromPath(uriPath []string) (URIPath, error) {
	prefix := false
	components := make(URIPath, 0, len(uriPath)+1)
	for i, name := range uriPath {
		if !ValidateURIComponent(name) {
			return nil, fmt.Errorf("'%s' is not a valid URI component", name)
		}
		if name == "*" {
			if i == len(uriPath)-1 {
				prefix = true
			} else {
				return nil, errors.New("Wildcard '*' not allowed in middle of URI")
			}
		} else if name == "+" {
			components = append(components, nil)
		} else {
			component := NewURIComponent(name, URIComponentPosition(i))
			components = append(components, component)
		}
	}

	if !prefix {
		terminator := NewURIComponent(string(EndOfURISymbol), URIComponentPosition(len(uriPath)))
		components = append(components, terminator)
	}

	return components, nil
}

// ParseURI takes a string representing a URI or URIPrefix and outputs a
// URIPath representing it.
func ParseURI(uri string) (URIPath, error) {
	rawComponents := strings.Split(uri, "/")
	filteredComponents := make([]string, 0, len(rawComponents))
	for _, rawComponent := range rawComponents {
		if rawComponent != "" {
			filteredComponents = append(filteredComponents, rawComponent)
		}
	}
	return ParseURIFromPath(filteredComponents)
}

// String returns a human-readable string representing this URIPath.
func (up URIPath) String() string {
	components := make([]string, len(up), len(up)+1)
	for i := 0; i != len(components); i++ {
		components[i] = up[i].String()
	}
	last := components[len(components)-1]
	if last == "$" {
		components = components[:len(components)-1]
	} else {
		components = append(components, "*")
	}
	return strings.Join(components, "/")
}

// EncodeURIPathInto encodes a URIPath into a pattern, where each component is
// represented as a byte slice. The slice into which to encode the pattern is
// provided as an argument.
func EncodeURIPathInto(up URIPath, into Pattern) {
	for i, component := range up {
		into[i] = component
	}
	for j := len(up); j != len(into); j++ {
		into[j] = nil
	}
}

// DecodeURIPathFrom decodes a URIPath from a pattern, where each component is
// represented as a byte slice.
func DecodeURIPathFrom(from Pattern) URIPath {
	var j int
	for j = len(from) - 1; j != -1; j-- {
		if from[j] != nil {
			break
		}
	}

	uripath := make(URIPath, 0, j+1)
	for i := 0; i <= j; i++ {
		uripath = append(uripath, URIComponent(from[i]))
	}
	return uripath
}

// URIToBytes marshals a URIPath into a string of bytes.
func URIToBytes(up URIPath) []byte {
	length := 0
	for _, component := range up {
		length += len(component)
	}

	buf := make([]byte, 1+length+len(up))
	buf[0] = byte(len(up))
	start := 1
	for _, component := range up {
		copy(buf[start:], component)
		buf[start+len(component)] = 255
		start += len(component) + 1
	}
	return buf
}

// URIFromBytes unmarshals a URIPath from a string of bytes marshalled with
// IDToBytes.
func URIFromBytes(marshalled []byte) URIPath {
	num := marshalled[0]
	up := make(URIPath, num)

	compidx := 0
	start := 1
	for i := 1; i != len(marshalled); i++ {
		if marshalled[i] == 255 {
			if start == i {
				up[compidx] = nil
			} else {
				up[compidx] = marshalled[start:i]
			}
			start = i + 1
			compidx++
		}
	}
	return up
}
