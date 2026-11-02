// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package buildinfo

import (
	"strings"
	"testing"
)

func TestSourceLink(t *testing.T) {
	tests := []struct {
		name   string
		info   Info
		expect string
	}{
		{"no commit", Info{SourceURL: "https://github.com/o/r"}, "https://github.com/o/r"},
		{"commit", Info{SourceURL: "https://github.com/o/r/", Commit: "abc123"}, "https://github.com/o/r/tree/abc123"},
		{"non-github fork", Info{SourceURL: "https://git.example.org/o/r", Commit: "abc123"}, "https://git.example.org/o/r"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.info.SourceLink(); got != tc.expect {
				t.Fatalf("SourceLink() = %q, want %q", got, tc.expect)
			}
		})
	}
}

func TestStringMentionsLicenseAndSource(t *testing.T) {
	s := Get().String()
	for _, want := range []string{"Tesla Charger Monitoring", "AGPL-3.0-or-later", "Source: https://"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() missing %q:\n%s", want, s)
		}
	}
}
