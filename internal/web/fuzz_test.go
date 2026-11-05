// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import "testing"

// FuzzParseClock checks the off-peak time fields of the electricity price
// form: accepted values are minutes within a day and survive a round trip
// through the value shown back in the form.
func FuzzParseClock(f *testing.F) {
	for _, s := range []string{"23:00", "0:0", "06:30", "24:00", "-1:30", "12:60", "7:05junk", " 7:05", "+7:05", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, ok := parseClock(s)
		if !ok {
			return
		}
		if v < 0 || v >= 24*60 {
			t.Fatalf("%q -> %d minutes", s, v)
		}
		if back, ok := parseClock(hhmm(v)); !ok || back != v {
			t.Fatalf("%q -> %d -> %q -> %d, %v", s, v, hhmm(v), back, ok)
		}
	})
}
