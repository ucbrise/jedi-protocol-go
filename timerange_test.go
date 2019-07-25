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
	"reflect"
	"testing"
	"time"
)

func TimeRangeSafe(t *testing.T, start time.Time, end time.Time) []TimePath {
	res, err := TimeRange(start, end)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TimePathsToStrings(ids []TimePath) []string {
	idStrings := make([]string, len(ids))
	for i, id := range ids {
		idStrings[i] = id.String()
	}
	return idStrings
}

func TestTimeRange(t *testing.T) {
	start, err := time.Parse(time.RFC822Z, "28 Dec 17 21:00 +0000")
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC822Z, "01 Mar 19 06:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	times := TimeRangeSafe(t, start, end)
	timeStrings := TimePathsToStrings(times)
	expectedTimeStrings := []string{"2017/12/6/28/4/21", "2017/12/6/28/4/22",
		"2017/12/6/28/4/23", "2017/12/6/29", "2017/12/6/30", "2017/12/6/31", "2018",
		"2019/1", "2019/2", "2019/3/1/1/1", "2019/3/1/1/2/6"}

	if !reflect.DeepEqual(timeStrings, expectedTimeStrings) {
		t.Fatal("Time IDs in output are incorrect")
	}
}

func TestTimeRangeOneDay(t *testing.T) {
	start, err := time.Parse(time.RFC822Z, "10 Oct 17 00:00 +0000")
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC822Z, "10 Oct 17 23:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	times := TimeRangeSafe(t, start, end)
	timeStrings := TimePathsToStrings(times)
	expectedTimeStrings := []string{"2017/10/2/10"}

	if !reflect.DeepEqual(timeStrings, expectedTimeStrings) {
		t.Fatal("Time IDs in output are incorrect")
	}
}

func TestTimeRangeTwoDays(t *testing.T) {
	start, err := time.Parse(time.RFC822Z, "10 Oct 17 00:00 +0000")
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC822Z, "11 Oct 17 23:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	times := TimeRangeSafe(t, start, end)
	timeStrings := TimePathsToStrings(times)
	expectedTimeStrings := []string{"2017/10/2/10", "2017/10/3/11"}

	if !reflect.DeepEqual(timeStrings, expectedTimeStrings) {
		t.Fatal("Time IDs in output are incorrect")
	}
}

func TestTimeRangeSingle(t *testing.T) {
	start, err := time.Parse(time.RFC822Z, "10 Oct 17 18:00 +0000")
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC822Z, "10 Oct 17 18:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	times := TimeRangeSafe(t, start, end)
	timeStrings := TimePathsToStrings(times)
	expectedTimeStrings := []string{"2017/10/2/10/4/18"}

	if !reflect.DeepEqual(timeStrings, expectedTimeStrings) {
		t.Fatal("Time IDs in output are incorrect")
	}
}

func TestTimeRangeTwoHours(t *testing.T) {
	start, err := time.Parse(time.RFC822Z, "10 Oct 17 18:00 +0000")
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC822Z, "10 Oct 17 19:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	times := TimeRangeSafe(t, start, end)
	timeStrings := TimePathsToStrings(times)
	expectedTimeStrings := []string{"2017/10/2/10/4/18", "2017/10/2/10/4/19"}

	if !reflect.DeepEqual(timeStrings, expectedTimeStrings) {
		t.Fatal("Time IDs in output are incorrect")
	}
}

func TestTimeRangeFebruary(t *testing.T) {
	start, err := time.Parse(time.RFC822Z, "28 Feb 16 23:00 +0000")
	if err != nil {
		t.Fatal(err)
	}
	end, err := time.Parse(time.RFC822Z, "02 Mar 16 00:00 +0000")
	if err != nil {
		t.Fatal(err)
	}

	times := TimeRangeSafe(t, start, end)
	timeStrings := TimePathsToStrings(times)
	expectedTimeStrings := []string{"2016/2/6/28/4/23", "2016/2/6/29", "2016/3/1/1", "2016/3/1/2/1/0"}

	if !reflect.DeepEqual(timeStrings, expectedTimeStrings) {
		t.Fatal("Time IDs in output are incorrect")
	}
}
