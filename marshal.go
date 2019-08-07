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
	"encoding/binary"
	"reflect"

	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

// MarshalledType is a byte that describes the type of a marshalled object.
type MarshalledType byte

// These constants define the byte corresponding to each type of marshalled
// object.
const (
	MarshalledTypeInvalid = iota
	MarshalledTypePattern
	MarshalledTypeDelegation
)

// Byte returns a byte representation of a MarshalledType.
func (marshalledType MarshalledType) Byte() byte {
	return byte(marshalledType)
}

func newMessageBuffer(cap int, marshalledType MarshalledType) []byte {
	buf := make([]byte, 0, cap)
	return append(buf, marshalledType.Byte())
}

func checkMessageType(message []byte, expected MarshalledType) []byte {
	if message[0] != expected.Byte() {
		return nil
	}
	return message[1:]
}

/* Utilities for marshalling array/slice lengths. */

// MarshalledLengthLength is the length, when marshalled, of an integer
// representing the length of a marshalled object.
const MarshalledLengthLength = 4

func putLength(buf []byte, length int) []byte {
	binary.LittleEndian.PutUint32(buf, uint32(length))
	return buf
}

func getLength(buf []byte) int {
	return int(binary.LittleEndian.Uint32(buf))
}

func marshalAppendLength(length int, buf []byte) []byte {
	lenbuf := putLength(make([]byte, MarshalledLengthLength), length)
	return append(buf, lenbuf...)
}

func unmarshalPrefixLength(buf []byte) (int, []byte) {
	length := getLength(buf[:MarshalledLengthLength])
	buf = buf[MarshalledLengthLength:]
	return length, buf
}

/* Utilities for marshalling more complex structures. */

// Marshallable represents an object that can be marshalled.
type Marshallable interface {
	Marshal() []byte
	Unmarshal([]byte) bool
}

func marshalAppendWithLength(m Marshallable, buf []byte) []byte {
	if m == nil || reflect.ValueOf(m).IsNil() {
		return marshalAppendLength(0, buf)
	}
	marshalled := m.Marshal()
	buf = marshalAppendLength(len(marshalled), buf)
	buf = append(buf, marshalled...)
	return buf
}

func unmarshalPrefixWithLengthRaw(buf []byte) ([]byte, []byte) {
	length, buf := unmarshalPrefixLength(buf)
	if length == 0 {
		return nil, buf
	}
	return buf[:length], buf[length:]
}

func unmarshalPrefixWithLength(m Marshallable, buf []byte) ([]byte, bool) {
	rawbytes, rest := unmarshalPrefixWithLengthRaw(buf)
	if rawbytes != nil {
		success := m.Unmarshal(rawbytes)
		if !success {
			return nil, true
		}
		return rest, true
	}
	return rest, false
}

type marshallableBytes struct {
	b []byte
}

func newMarshallableBytes(b []byte) *marshallableBytes {
	return &marshallableBytes{b}
}

func (ms *marshallableBytes) Marshal() []byte {
	return ms.b
}

func (ms *marshallableBytes) Unmarshal(buf []byte) bool {
	ms.b = buf
	return true
}

// Marshal encodes a Pattern into a byte slice.
func (p Pattern) Marshal() []byte {
	buf := newMessageBuffer(1024, MarshalledTypePattern)

	// Encode the length of the pattern
	buf = marshalAppendLength(len(p), buf)

	var last int
	for last = len(p) - 1; last != -1; last-- {
		if len(p[last]) != 0 {
			break
		}
	}
	last++

	// Append the index one past the last nonempty component
	buf = marshalAppendLength(last, buf)

	// Now, marshal each nonempty component, preceded by its index
	for i := 0; i != last; i++ {
		component := p[i]
		if len(component) != 0 {
			buf = marshalAppendLength(i, buf)
			buf = marshalAppendWithLength(newMarshallableBytes(component), buf)
		}
	}

	return buf
}

// Unmarshal decodes a Pattern from a byte slice encoded with Marshal().
func (p *Pattern) Unmarshal(marshalled []byte) bool {
	var buf []byte
	if buf = checkMessageType(marshalled, MarshalledTypePattern); buf == nil {
		return false
	}

	var patternLength int
	if patternLength, buf = unmarshalPrefixLength(buf); buf == nil {
		return false
	}

	pattern := make(Pattern, patternLength)

	var last int
	if last, buf = unmarshalPrefixLength(buf); buf == nil {
		return false
	}
	last--

	i := -1
	for i != last {
		if i, buf = unmarshalPrefixLength(buf); buf == nil {
			return false
		}

		var comp marshallableBytes
		if buf, _ = unmarshalPrefixWithLength(&comp, buf); buf == nil {
			return false
		}
		pattern[i] = []byte(comp.b)
	}

	*p = pattern
	return true
}

// Marshal encodes a JEDI delegation into a byte array.
func (d *Delegation) Marshal() []byte {
	if len(d.Patterns) != len(d.Keys) {
		panic("Invalid delegation")
	}

	buf := newMessageBuffer(4096, MarshalledTypeDelegation)
	buf = marshalAppendWithLength(newMarshallableBytes(d.Hierarchy), buf)
	buf = marshalAppendWithLength(newMarshallableBytes(d.Params.Marshal(true)), buf)
	buf = marshalAppendLength(len(d.Patterns), buf)

	for i, pattern := range d.Patterns {
		buf = marshalAppendWithLength(&pattern, buf)
		key := d.Keys[i].Marshal(true)
		buf = marshalAppendWithLength(newMarshallableBytes(key), buf)
	}

	return buf
}

// Unmarshal decodes a JEDI delegation from a byte array.
func (d *Delegation) Unmarshal(marshalled []byte) bool {
	var buf []byte
	if buf = checkMessageType(marshalled, MarshalledTypeDelegation); buf == nil {
		return false
	}

	var hierarchy marshallableBytes
	if buf, _ = unmarshalPrefixWithLength(&hierarchy, buf); buf == nil {
		return false
	}
	d.Hierarchy = hierarchy.b

	var marshalledParams marshallableBytes
	if buf, _ = unmarshalPrefixWithLength(&marshalledParams, buf); buf == nil {
		return false
	}
	d.Params = new(wkdibe.Params)
	if !d.Params.Unmarshal(marshalledParams.b, true, false) {
		return false
	}

	var length int
	if length, buf = unmarshalPrefixLength(buf); buf == nil {
		return false
	}

	d.Patterns = make([]Pattern, length)
	d.Keys = make([]*wkdibe.SecretKey, length)
	for i := 0; i != length; i++ {
		if buf, _ = unmarshalPrefixWithLength(&d.Patterns[i], buf); buf == nil {
			return false
		}

		var marshalledKey marshallableBytes
		if buf, _ = unmarshalPrefixWithLength(&marshalledKey, buf); buf == nil {
			return false
		}
		d.Keys[i] = new(wkdibe.SecretKey)
		if !d.Keys[i].Unmarshal(marshalledKey.b, true, false) {
			return false
		}
	}
	return true
}
