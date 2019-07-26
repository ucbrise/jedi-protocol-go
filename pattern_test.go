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
	"testing"
	"time"
)

func checkURI(t *testing.T, uri string) {
	uripath, err := ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}

	marshalled := URIToBytes(uripath)
	unmarshalled := URIFromBytes(marshalled)

	if len(uripath) != len(unmarshalled) {
		t.Fatal("Unmarshalled URI is different length from original URI")
	}

	for i, comp := range uripath {
		ucomp := unmarshalled[i]

		if !bytes.Equal(comp, ucomp) {
			t.Fatalf("Component %d differs from unmarshalled URI and original URI", i)
		}
	}

	if unmarshalled.String() != uri {
		t.Fatal("String representation appears incorrect")
	}
}

func TestURI(t *testing.T) {
	checkURI(t, "a/b/c")
}

func TestURIPrefix(t *testing.T) {
	checkURI(t, "a/b/c/*")
}

func TestURIPlus(t *testing.T) {
	checkURI(t, "a/+/c")
}

func TestURIPlusPrefix(t *testing.T) {
	checkURI(t, "a/+/c/*")
}

func checkTime(t *testing.T, timestamp time.Time, expected string) {
	timepath, err := ParseTime(timestamp)
	if err != nil {
		t.Fatal(err)
	}

	marshalled := TimeToBytes(timepath)
	unmarshalled := TimeFromBytes(marshalled)

	if len(timepath) != len(unmarshalled) {
		t.Fatal("Unmarshalled Time is different length from original Time")
	}

	for i, comp := range timepath {
		ucomp := unmarshalled[i]

		if !bytes.Equal(comp, ucomp) {
			t.Fatalf("Component %d differs from unmarshalled Time and original Time", i)
		}
	}

	actual := unmarshalled.String()
	if actual != expected {
		t.Fatalf("String representation appears incorrect (got %s, expected %s)", actual, expected)
	}
}

func TestTimeJuly25(t *testing.T) {
	checkTime(t, time.Unix(1564089385, 0), "2019/7/5/25/4/21")
}

func TestTimeLastFiveDays(t *testing.T) {
	checkTime(t, time.Unix(1548969385, 0), "2019/1/6/31/4/21")
	checkTime(t, time.Unix(1556658985, 0), "2019/4/6/30/4/21")
	checkTime(t, time.Unix(1564175785, 0), "2019/7/6/26/4/21")
}

func TestEmptyTimePath(t *testing.T) {
	empty := make(TimePath, 0)
	marshalled := TimeToBytes(empty)
	unmarshalled := TimeFromBytes(marshalled)
	if len(unmarshalled) != 0 {
		t.FailNow()
	}
}

func TestTimePositions(t *testing.T) {
	if TimeComponentPositionYear.String() != "year" ||
		TimeComponentPositionMonth.String() != "month" ||
		TimeComponentPositionFiveDays.String() != "fivedays" ||
		TimeComponentPositionDay.String() != "day" ||
		TimeComponentPositionSixHours.String() != "sixhours" ||
		TimeComponentPositionHour.String() != "hour" {
		t.FailNow()
	}
}

func checkPattern(t *testing.T, uri string, timestamp time.Time, expectedTime string) {
	uripath, err := ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	timepath, err := ParseTime(timestamp)
	if err != nil {
		t.Fatal(err)
	}

	pattern := make(Pattern, 20)
	EncodePattern(uripath, timepath, pattern)

	newuri, newtime := DecodePattern(pattern)

	actualURI := newuri.String()
	if actualURI != uri {
		t.Fatalf("Decoded URI is different from original URI (got %s, exepcted %s)", actualURI, uri)
	}

	actualTime := newtime.String()
	if actualTime != expectedTime {
		t.Fatalf("Decoded time is different from original time (got %s, expected %s)", actualTime, uri)
	}
}

func TestPattern(t *testing.T) {
	checkPattern(t, "a/b/c", time.Unix(1564089385, 0), "2019/7/5/25/4/21")
	checkPattern(t, "a/b/c/*", time.Unix(1564089385, 0), "2019/7/5/25/4/21")
	checkPattern(t, "a/+/c", time.Unix(1564089385, 0), "2019/7/5/25/4/21")
	checkPattern(t, "a/+/c/*", time.Unix(1564089385, 0), "2019/7/5/25/4/21")
}

func TestPatternComponent(t *testing.T) {
	uripath, err := ParseURI("a/b/c/*")
	if err != nil {
		t.Fatal(err)
	}
	timepath, err := ParseTime(time.Unix(1564089385, 0))
	if err != nil {
		t.Fatal(err)
	}

	pattern := make(Pattern, 20)
	EncodePattern(uripath, timepath, pattern)

	if pattern.GetComponent(1).String() != "b" {
		t.Fatal("Second component has incorrect string")
	}
	if pattern.GetComponent(18).String() != "4" {
		t.Fatal("Second-to-last component has incorrect string")
	}
}

func TestPatternMatch(t *testing.T) {
	uripath1, err := ParseURI("a/b/c/*")
	if err != nil {
		t.Fatal(err)
	}
	uripath2, err := ParseURI("a/b/c")
	if err != nil {
		t.Fatal(err)
	}
	timepath, err := ParseTime(time.Unix(1564089385, 0))
	if err != nil {
		t.Fatal(err)
	}

	pattern1 := make(Pattern, 20)
	EncodePattern(uripath1, timepath, pattern1)
	pattern2 := make(Pattern, 20)
	EncodePattern(uripath2, timepath, pattern2)

	if !pattern1.Matches(pattern2) {
		t.FailNow()
	}
	if pattern2.Matches(pattern1) {
		t.FailNow()
	}
}

func TestPatternMatchPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Matches() did not panic for different-length patterns")
		}
	}()
	pattern1 := make(Pattern, 19)
	pattern2 := make(Pattern, 20)
	pattern1.Matches(pattern2)
}
