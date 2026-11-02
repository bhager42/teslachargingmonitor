// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package auth

import (
	"strings"
	"testing"
)

var fast = Params{MemoryKiB: 8 * 1024, Time: 1, Threads: 1}

func TestHashVerify(t *testing.T) {
	h, err := Hash("correct horse battery staple", fast)
	if err != nil || !strings.HasPrefix(h, "$argon2id$v=19$m=8192,t=1,p=1$") || !ValidHash(h) {
		t.Fatalf("hash = %q, %v", h, err)
	}
	h2, _ := Hash("correct horse battery staple", fast)
	if h == h2 {
		t.Error("salt not random")
	}
	ok, rehash, err := Verify(h, "correct horse battery staple", fast)
	if !ok || rehash || err != nil {
		t.Errorf("verify = %v %v %v", ok, rehash, err)
	}
	if ok, _, _ := Verify(h, "correct horse battery stapl", fast); ok {
		t.Error("wrong password accepted")
	}
	if _, rehash, _ := Verify(h, "x", DefaultParams); !rehash {
		t.Error("weaker hash should need rehash")
	}
	// NFKC: full-width and composed forms are the same password.
	hf, _ := Hash("ｃａｆé-ｃａｆé-ｃａｆé", fast)
	if ok, _, _ := Verify(hf, "café-café-café", fast); !ok {
		t.Error("NFKC normalization not applied")
	}
	for _, bad := range []string{"", "plain", "$argon2i$v=19$m=8192,t=1,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
		"$argon2id$v=18$m=8192,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=1,t=1,p=1$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5a2V5",
		"$argon2id$v=19$m=8192,t=1,p=1$!!$a2V5a2V5a2V5a2V5a2V5a2V5"} {
		if ValidHash(bad) {
			t.Errorf("ValidHash(%q) = true", bad)
		}
		if _, _, err := Verify(bad, "x", fast); err == nil {
			t.Errorf("Verify accepted malformed hash %q", bad)
		}
	}
	VerifyDummy("anything", fast)
}

func TestPolicy(t *testing.T) {
	good := []string{"purple-otter-kayak-1987", "correct horse battery staple", "Ünïcödé ok längere Phrase", "tesla garage purple elephant"}
	for _, pw := range good {
		if err := CheckPolicy(pw); err != nil {
			t.Errorf("CheckPolicy(%q) = %v", pw, err)
		}
	}
	bad := map[string]string{
		"short":                       "at least 12",
		"password1234":                "commonly used",
		"qwertyuiop123":               "commonly used",
		"aaaaaaaaaaaaaaaa":            "commonly used",
		"zzzzzzzzzzzzzzzzzzz":         "repeated character",
		"Tesla1234567":                "tesla",
		"mywallconnector!":            "wallconnector",
		strings.Repeat("ab", 70):      "at most 128",
		"\xff\xfe invalid utf8 bytes": "invalid characters",
	}
	for pw, want := range bad {
		if err := CheckPolicy(pw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckPolicy(%q) = %v, want error containing %q", pw, err, want)
		}
	}
}
