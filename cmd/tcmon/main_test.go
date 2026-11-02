// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		args     []string
		code     int
		inStdout string
		inStderr string
	}{
		{[]string{"version"}, 0, "AGPL-3.0-or-later", ""},
		{[]string{"help"}, 0, "Usage: tcmon", ""},
		{nil, 2, "", "Usage: tcmon"},
		{[]string{"bogus"}, 2, "", `unknown command "bogus"`},
	}
	for _, tc := range tests {
		var out, errOut bytes.Buffer
		if code := run(tc.args, &out, &errOut); code != tc.code {
			t.Errorf("run(%v) = %d, want %d", tc.args, code, tc.code)
		}
		if !strings.Contains(out.String(), tc.inStdout) {
			t.Errorf("run(%v) stdout %q missing %q", tc.args, out.String(), tc.inStdout)
		}
		if !strings.Contains(errOut.String(), tc.inStderr) {
			t.Errorf("run(%v) stderr %q missing %q", tc.args, errOut.String(), tc.inStderr)
		}
	}
}
