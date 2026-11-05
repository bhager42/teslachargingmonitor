// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package auth

import (
	"testing"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// FuzzCheckPolicy checks that every accepted password meets the documented
// policy, and that the normalised form a user may type later (passwords are
// hashed after NFKC) is accepted too.
func FuzzCheckPolicy(f *testing.F) {
	for _, s := range []string{"purple otter kayak sunrise", "aaaaaaaaaaaaaaaa", "password1234", "teslateslatesla!",
		"ｆｕｌｌｗｉｄｔｈ ｐａｓｓ", "ﬁﬁﬁﬁﬁﬁﬁﬁﬁﬁﬁﬁ", "\xff\xfe invalid utf8 x", "short"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, pw string) {
		if CheckPolicy(pw) != nil {
			return
		}
		n := norm.NFKC.String(pw)
		if !utf8.ValidString(pw) {
			t.Fatalf("accepted invalid UTF-8 %q", pw)
		}
		if c := utf8.RuneCountInString(n); c < MinPasswordLength || c > MaxPasswordLength {
			t.Fatalf("accepted %q with %d characters after NFKC", pw, c)
		}
		if isCommon(n) {
			t.Fatalf("accepted common password %q", pw)
		}
		if err := CheckPolicy(n); err != nil {
			t.Fatalf("%q accepted but its NFKC form %q is not: %v", pw, n, err)
		}
	})
}
