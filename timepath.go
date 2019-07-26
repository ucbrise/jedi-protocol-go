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
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TimeComponentPosition describes the location (which defines the semantics)
// of a TimeComponent in a TimePath.
type TimeComponentPosition uint8

// MaxTimeLength is the maximum length of a TimePath.
const MaxTimeLength = 6

// These constants enumerate the valid positions of a TimeComponent (i.e., the
// valid values of a TimeComponentPosition).
//
// We divide time into components as follows:
// Year
// Month (always twelve per year)
// Five-Day Periods (always six per month, last one may be shorter or longer)
// Day (always five per five-day period)
// Six-Hour Periods (always four per day)
//
// For example, 16 Feb 2017 at 5 PM is represented as follows:
// 2017/02/3/16/2/17
// 2017 represents year 2017
// 02 represents February
// 3 represents five-day period starting on the 16th
// 16 represents day 16
// 2 represents six-hour period starting at noon
// 17 represents hour 17
const (
	TimeComponentPositionYear TimeComponentPosition = iota
	TimeComponentPositionMonth
	TimeComponentPositionFiveDays
	TimeComponentPositionDay
	TimeComponentPositionSixHours
	TimeComponentPositionHour
)

// String returns a human-readable string describing the semantics of the
// provided TimeComponentPosition.
func (ecp TimeComponentPosition) String() string {
	switch ecp {
	case TimeComponentPositionYear:
		return "year"
	case TimeComponentPositionMonth:
		return "month"
	case TimeComponentPositionFiveDays:
		return "fivedays"
	case TimeComponentPositionDay:
		return "day"
	case TimeComponentPositionSixHours:
		return "sixhours"
	case TimeComponentPositionHour:
		return "hour"
	default:
		panic("Invalid expiry component position")
	}
}

// These constants describe the minimum and maximum values of each component
// in a TimePath.
const (
	MinYear = 2015
	MaxYear = 2050

	MinMonth = 1
	MaxMonth = 12

	MinFiveDays = 1
	MaxFiveDays = 6

	MinDay                 = 1
	MaxDay                 = 31
	MaxDayShortMonth       = 30
	MaxDayFebruary         = 28
	MaxDayFebruaryLeapYear = 29

	MinSixHours = 1
	MaxSixHours = 4

	MinHour = 0
	MaxHour = 23
)

// TimeComponentBounds takes a prefix of a TimePath and the position of an
// unused component, and returns the minimum and maximum values of that
// component in the TimePath, restricted by the values of components in the
// provided prefix.
func TimeComponentBounds(prefix TimePath, position TimeComponentPosition) (uint16, uint16) {
	switch position {
	case TimeComponentPositionYear:
		return MinYear, MaxYear
	case TimeComponentPositionMonth:
		return MinMonth, MaxMonth
	case TimeComponentPositionFiveDays:
		return MinFiveDays, MaxFiveDays
	case TimeComponentPositionDay:
		fivedays := prefix[TimeComponentPositionFiveDays].Quantity()
		if fivedays == 6 {
			switch time.Month(prefix[TimeComponentPositionMonth].Quantity()) {
			case time.January:
				fallthrough
			case time.March:
				fallthrough
			case time.May:
				fallthrough
			case time.July:
				fallthrough
			case time.August:
				fallthrough
			case time.October:
				fallthrough
			case time.December:
				return 26, MaxDay
			case time.April:
				fallthrough
			case time.June:
				fallthrough
			case time.September:
				fallthrough
			case time.November:
				return 26, MaxDayShortMonth
			case time.February:
				year := prefix[TimeComponentPositionYear].Quantity()
				if year%4 == 0 && (year%100 != 0 || (year%400 == 0)) {
					return 26, MaxDayFebruaryLeapYear
				}
				return 26, MaxDayFebruary
			}
		}
		return 5*(fivedays-1) + 1, 5 * fivedays
	case TimeComponentPositionSixHours:
		return MinSixHours, MaxSixHours
	case TimeComponentPositionHour:
		sixhours := prefix[TimeComponentPositionSixHours].Quantity()
		return 6 * (sixhours - 1), 6*sixhours - 1
	default:
		panic("Invalid position")
	}
}

// TimeComponent describes a component of a URIPath.
type TimeComponent []byte

// NewTimeComponent creates a new TimeComponent with the given quantity and
// position.
func NewTimeComponent(quantity uint16, position TimeComponentPosition) TimeComponent {
	tc := []byte{uint8(position), 0, 0}
	binary.LittleEndian.PutUint16(tc[1:3], quantity)
	return tc
}

// Type returns the value TimeComponentType.
func (tc TimeComponent) Type() PatternComponentType {
	return TimeComponentType
}

// String returns a printable string representing this TimeComponent.
func (tc TimeComponent) String() string {
	return strconv.FormatInt(int64(tc.Quantity()), 10)
}

// Name panics.
func (tc TimeComponent) Name() string {
	panic("Name() is not a valid method for a Time component")
}

// Quantity returns the quantity associated with this TimeComponent.
func (tc TimeComponent) Quantity() uint16 {
	return binary.LittleEndian.Uint16(tc[1:3])
}

// Position returns the position (which corresponds to the semantics) of this
// component within a TimePath.
func (tc TimeComponent) Position() TimeComponentPosition {
	return TimeComponentPosition(tc[0])
}

// TimePath is a hierarchical representation of a point in time, at the
// granularity supported by JEDI's expiry.
type TimePath []TimeComponent

// ValidateTimeComponent takes a TimePath prefix, and position and quantity of
// a proposed component later in the path, and returns a boolean indicating
// whether the proposed component is valid.
func ValidateTimeComponent(prefix TimePath, quantity uint16, position TimeComponentPosition) bool {
	min, max := TimeComponentBounds(prefix, position)
	return min <= quantity && quantity <= max
}

// ParseTimeFromPath takes a slice of time components and produces a TimePath
// representing that time or time prefix.
func ParseTimeFromPath(timePath []uint16) (TimePath, error) {
	if len(timePath) > MaxTimeLength {
		return nil, errors.New("Expiry path too long")
	}

	components := make(TimePath, 0, len(timePath))
	for i, quantity := range timePath {
		pos := TimeComponentPosition(i)
		if !ValidateTimeComponent(components, quantity, pos) {
			return nil, fmt.Errorf("'%d' is not a valid %s", quantity, pos.String())
		}
		component := NewTimeComponent(quantity, pos)
		components = append(components, component)
	}
	return components, nil
}

// ParseTime takes a time.Time and returns a TimePath representing that time.
func ParseTime(time time.Time) (TimePath, error) {
	utctime := time.UTC()

	path := make([]uint16, 6, 6)
	path[0] = uint16(utctime.Year())
	path[1] = uint16(utctime.Month())
	path[3] = uint16(utctime.Day())
	path[2] = (path[3]-1)/5 + 1
	if path[2] == 7 {
		path[2] = 6
	}
	path[5] = uint16(utctime.Hour())
	path[4] = (path[5] / 6) + 1
	return ParseTimeFromPath(path)
}

// String returns a human-readable string representing this TimePath.
func (tp TimePath) String() string {
	components := make([]string, len(tp), len(tp))
	for i := 0; i != len(components); i++ {
		components[i] = tp[i].String()
	}
	return strings.Join(components, "/")
}

// EncodeTimePathInto encodes a TimePath into a pattern, where each component
// is represented as a byte slice. The slice into which to encode the pattern
// is provided as an argument.
func EncodeTimePathInto(tp TimePath, into Pattern) {
	for i, component := range tp {
		into[i] = component
	}
}

// DecodeTimePathFrom decodes a TimePath from a pattern, where each component
// is represented as a byte slice.
func DecodeTimePathFrom(from Pattern) TimePath {
	var j int
	for j = len(from) - 1; j != -1; j-- {
		if from[j] != nil {
			break
		}
	}

	timepath := make(TimePath, 0, j+1)
	for i := 0; i <= j; i++ {
		timepath = append(timepath, TimeComponent(from[i]))
	}
	return timepath
}

// TimeToBytes marshals a TimePath into a string of bytes.
func TimeToBytes(tp TimePath) []byte {
	length := 0
	for _, component := range tp {
		length += len(component)
	}

	bytelen := 2*length + 1
	if length == 0 {
		bytelen = 0
	}

	buf := make([]byte, 1+bytelen)
	buf[0] = byte(len(tp))
	start := 1
	for _, component := range tp {
		copy(buf[start:start+3], component)
		start += 3
	}
	return buf
}

// TimeFromBytes unmarshals a TimePath from a string of bytes marshalled with
// IDToBytes.
func TimeFromBytes(marshalled []byte) TimePath {
	num := marshalled[0]
	tp := make(TimePath, num)

	start := 1
	for idx := range tp {
		tp[idx] = marshalled[start : start+3]
		start += 3
	}

	return tp
}
