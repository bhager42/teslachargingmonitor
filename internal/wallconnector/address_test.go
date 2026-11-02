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

func TestParseAddress(t *testing.T) {
	good := map[string]string{
		"192.168.1.17":           "http://192.168.1.17",
		" 192.168.1.17 ":         "http://192.168.1.17",
		"192.168.1.17:8080":      "http://192.168.1.17:8080",
		"http://192.168.1.17/":   "http://192.168.1.17",
		"https://10.0.0.5":       "https://10.0.0.5",
		"WallConnector.LAN":      "http://wallconnector.lan",
		"wc.home.arpa.":          "http://wc.home.arpa",
		"fd00::17":               "http://[fd00::17]",
		"http://[fd00::17]:8080": "http://[fd00::17]:8080",
		"::ffff:192.168.1.17":    "http://192.168.1.17",
		"localhost:8099":         "http://localhost:8099",
		"127.0.0.1:8099":         "http://127.0.0.1:8099",
	}
	for in, want := range good {
		a, err := ParseAddress(in, AddressOptions{})
		if err != nil {
			t.Errorf("ParseAddress(%q) error: %v", in, err)
			continue
		}
		if got := a.BaseURL(); got != want {
			t.Errorf("ParseAddress(%q).BaseURL() = %q, want %q", in, got, want)
		}
	}

	bad := []string{
		"", "   ", "8.8.8.8", "169.254.169.254", "ftp://192.168.1.17", "file:///etc/passwd",
		"http://user:pw@192.168.1.17", "192.168.1.17/api/1/vitals", "192.168.1.17?x=1",
		"192.168.1.17#frag", "192.168.1.17:0", "192.168.1.17:70000", "fe80::1%eth0",
		"http://[fe80::1%25eth0]", "bad_host.lan", "0.0.0.0.", "8.8.8.8.", "0..", "wc.lan..",
		"2130706433", "0x7f.1", "127.1", "10.0.0.256", "-bad.lan", "a..b", "javascript:alert(1)",
	}
	for _, in := range bad {
		if _, err := ParseAddress(in, AddressOptions{}); !errors.Is(err, ErrBadAddress) {
			t.Errorf("ParseAddress(%q) err = %v, want ErrBadAddress", in, err)
		}
	}

	if a, err := ParseAddress("8.8.8.8", AddressOptions{AllowNonLAN: true}); err != nil || a.Host != "8.8.8.8" {
		t.Errorf("AllowNonLAN: %+v %v", a, err)
	}
}
