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
	"context"
	"crypto/aes"
	"testing"
	"time"

	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

const TestPatternSize = 20

var TestHierarchy = []byte("testHierarchy")

const quote1 = "Imagination is more important than knowledge. --Albert Einstein"
const quote2 = "Today is your day! / Your mountain is waiting. / So... get on your way! --Theodor Seuss Geisel"

type TestKeyStore struct {
	params *wkdibe.Params
	master *wkdibe.MasterKey
}

func NewTestKeyStore() *TestKeyStore {
	tks := new(TestKeyStore)
	tks.params, tks.master = wkdibe.Setup(TestPatternSize, true)
	return tks
}

func (tks *TestKeyStore) ParamsForHierarchy(ctx context.Context, hierarchy []byte) (*wkdibe.Params, error) {
	return tks.params, nil
}

func (tks *TestKeyStore) KeyForPattern(ctx context.Context, hierarchy []byte, pattern Pattern) (*wkdibe.Params, *wkdibe.SecretKey, error) {
	empty := make(Pattern, TestPatternSize)
	return tks.params, wkdibe.KeyGen(tks.params, tks.master, empty.ToAttrs()), nil
}

func NewTestState() *ClientState {
	store := NewTestKeyStore()
	encoder := NewDefaultPatternEncoder(TestPatternSize - MaxTimeLength)
	return NewClientState(store, encoder, 1<<20)
}

func testMessageTransfer(t *testing.T, state *ClientState, hierarchy []byte, uri string, timestamp time.Time, message string) {
	var err error
	ctx := context.Background()

	var encrypted []byte
	if encrypted, err = state.Encrypt(ctx, hierarchy, uri, timestamp, []byte(message)); err != nil {
		t.Fatal(err)
	}

	var decrypted []byte
	if decrypted, err = state.Decrypt(ctx, hierarchy, uri, timestamp, encrypted); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, []byte(message)) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	state := NewTestState()
	now := time.Now()

	testMessageTransfer(t, state, TestHierarchy, "a/b/c", now, quote1)
}

func TestCachedEncryptDecrypt(t *testing.T) {
	state := NewTestState()
	now := time.Now()

	testMessageTransfer(t, state, TestHierarchy, "a/b/c", now, quote1)
	testMessageTransfer(t, state, TestHierarchy, "a/b/c", now, quote2)
}

func TestEncryptAdjustment(t *testing.T) {
	state := NewTestState()
	now := time.Now()
	future := now.Add(time.Hour)

	testMessageTransfer(t, state, TestHierarchy, "a/b/c", now, quote1)
	testMessageTransfer(t, state, TestHierarchy, "a/b/c", future, quote1)
}

func TestDecryptWrongURI(t *testing.T) {
	var err error
	state := NewTestState()
	now := time.Now()
	ctx := context.Background()

	var encrypted []byte
	if encrypted, err = state.Encrypt(ctx, TestHierarchy, "a/b/c", now, []byte(quote1)); err != nil {
		t.Fatal(err)
	}

	var decrypted []byte
	if decrypted, err = state.Decrypt(ctx, TestHierarchy, "a/b/d", now, encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(decrypted, []byte(quote1)) {
		t.Fatal("Successfully decrypted a message using the wrong URI")
	}
}

func TestDecryptWrongLength(t *testing.T) {
	var err error
	state := NewTestState()
	now := time.Now()
	ctx := context.Background()

	if _, err = state.Decrypt(ctx, TestHierarchy, "a/b/c", now, make([]byte, EncryptedKeySize+aes.BlockSize-1)); err == nil {
		t.Fatal("No error for trying to decrypt too short a message")
	}

	if _, err = state.DecryptWithPattern(ctx, TestHierarchy, make(Pattern, TestPatternSize), make([]byte, EncryptedKeySize), make([]byte, aes.BlockSize-1)); err == nil {
		t.Fatal("No error for trying to decrypt too short a message (encrypted key size OK, encrypted message short)")
	}

	if _, err = state.DecryptWithPattern(ctx, TestHierarchy, make(Pattern, TestPatternSize), make([]byte, EncryptedKeySize-1), make([]byte, aes.BlockSize)); err == nil {
		t.Fatal("No error for trying to decrypt too short a message (encrypted key size short, encrypted message OK)")
	}

	if _, err = state.DecryptWithPattern(ctx, TestHierarchy, make(Pattern, TestPatternSize), make([]byte, EncryptedKeySize), make([]byte, aes.BlockSize)); err != nil {
		t.Fatal("Got error for correctly-size message")
	}
}

func TestInvalidURI(t *testing.T) {
	var err error
	state := NewTestState()
	now := time.Now()
	ctx := context.Background()

	if _, err = state.Encrypt(ctx, TestHierarchy, "a/*/c", now, []byte(quote1)); err == nil {
		t.Fatal("No error for trying to encrypt with an invalid URI")
	}

	if _, err = state.Decrypt(ctx, TestHierarchy, "a/*/c", now, make([]byte, EncryptedKeySize+aes.BlockSize)); err == nil {
		t.Fatal("No error for trying to decrypt with an invalid URI")
	}
}
