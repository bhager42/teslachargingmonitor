// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package wallconnector

import (
	"errors"
	"testing"
)

func TestParseFirmware(t *testing.T) {
	good := map[string]FirmwareVersion{
		"26.26.10+g42855ec9b9cd1": {Major: 26, Minor: 26, Patch: 10, Build: "g42855ec9b9cd1"},
		"24.4.1":                  {Major: 24, Minor: 4, Patch: 1},
		"25.10.0-rc1+abc":         {Major: 25, Minor: 10, Patch: 0, Pre: "rc1", Build: "abc"},
	}
	for in, want := range good {
		got, err := ParseFirmware(in)
		want.Raw = in
		if err != nil || got != want {
			t.Errorf("ParseFirmware(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "26.26", "26.26.10.1", "a.b.c", "26.-1.0", "26.26.10+", "26.26.10+bad build", "1.2.3456789", "+1.2.3"} {
		if _, err := ParseFirmware(in); !errors.Is(err, ErrBadFirmware) {
			t.Errorf("ParseFirmware(%q) err = %v, want ErrBadFirmware", in, err)
		}
	}
}

func TestFirmwareCompare(t *testing.T) {
	p := func(s string) FirmwareVersion {
		f, err := ParseFirmware(s)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	tests := []struct {
		a, b string
		want int
	}{
		{"26.26.10+gaaa", "26.26.10+gbbb", 0},
		{"26.26.10", "26.30.0", -1},
		{"27.0.0", "26.99.99", 1},
		{"26.26.10-rc1", "26.26.10", -1},
		{"26.26.10", "26.26.10-rc1", 1},
		{"26.26.10-rc1", "26.26.10-rc2", -1},
	}
	for _, tc := range tests {
		if got := p(tc.a).Compare(p(tc.b)); got != tc.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
	if s := p("26.26.10+gx").String(); s != "26.26.10+gx" {
		t.Errorf("String() = %q", s)
	}
}
