// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package secrets

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "secret.key")
	k1, err := LoadOrCreateKey(path, nil)
	if err != nil || len(k1) != KeySize {
		t.Fatalf("create: %v", err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o", fi.Mode().Perm())
	}
	k2, err := LoadOrCreateKey(path, nil)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Errorf("reload changed key: %v", err)
	}
	_ = os.Chmod(path, 0o644) //nolint:gosec // deliberately insecure to test the warning
	var warned string
	if _, err := LoadOrCreateKey(path, func(m string) { warned = m }); err != nil || !strings.Contains(warned, "chmod 600") {
		t.Errorf("no permission warning: %q %v", warned, err)
	}
	bad := filepath.Join(t.TempDir(), "short.key")
	_ = os.WriteFile(bad, []byte("short"), 0o600)
	if _, err := LoadOrCreateKey(bad, nil); err == nil {
		t.Error("short key accepted")
	}
}

func TestBox(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	b, err := NewBox(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := b.Seal([]byte("app-password"), []byte("email"))
	if err != nil || bytes.Contains(sealed, []byte("app-password")) {
		t.Fatalf("seal: %v", err)
	}
	again, _ := b.Seal([]byte("app-password"), []byte("email"))
	if bytes.Equal(sealed, again) {
		t.Error("nonce reuse: identical ciphertexts")
	}
	if pt, err := b.Open(sealed, []byte("email")); err != nil || string(pt) != "app-password" {
		t.Errorf("open: %q %v", pt, err)
	}
	if _, err := b.Open(sealed, []byte("other")); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong aad err = %v", err)
	}
	other, _ := NewBox(bytes.Repeat([]byte{8}, KeySize))
	if _, err := other.Open(sealed, []byte("email")); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong key err = %v", err)
	}
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	for _, bad := range [][]byte{nil, {1}, tampered, append([]byte{2}, sealed[1:]...)} {
		if _, err := b.Open(bad, []byte("email")); !errors.Is(err, ErrDecrypt) {
			t.Errorf("bad ciphertext accepted: %v", err)
		}
	}
	if _, err := NewBox([]byte("short")); err == nil {
		t.Error("short key accepted")
	}
}

func TestSecretIsRedactedEverywhere(t *testing.T) {
	s := Secret("hunter2-app-password")
	type cfg struct {
		User     string
		Password Secret
	}
	c := cfg{"me@gmail.com", s}
	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("cfg", "password", s, "cfg", c)
	js, _ := json.Marshal(c) //nolint:gosec // G117: proving Secret marshals redacted
	outputs := []string{
		fmt.Sprint(s), fmt.Sprintf("%v %s %q %#v %x %+v", s, s, s, s, s, c), fmt.Sprintf("%#v", c),
		string(js), logBuf.String(), s.String(), s.GoString(),
	}
	for _, o := range outputs {
		if strings.Contains(o, "hunter2") {
			t.Errorf("secret leaked: %s", o)
		}
	}
	if s.Reveal() != "hunter2-app-password" || !s.IsSet() || Secret("").IsSet() {
		t.Error("Reveal/IsSet wrong")
	}
}
