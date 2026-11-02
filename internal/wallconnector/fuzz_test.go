// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package wallconnector

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

func FuzzDecode(f *testing.F) {
	files, _ := filepath.Glob("../../testdata/fixtures/*/*/*.json")
	for _, p := range files {
		if b, err := os.ReadFile(p); err == nil { //nolint:gosec // test fixture path
			f.Add(b)
		}
	}
	f.Add([]byte(`{"grid_v":1e309}`))
	f.Add([]byte(`{"current_alerts":[1,"x",null]}`))
	f.Add([]byte(`{"wifi_ssid":12}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, dec := range []func([]byte) (Report, error){
			func(b []byte) (Report, error) { _, r, err := DecodeVitals(b); return r, err },
			func(b []byte) (Report, error) { _, r, err := DecodeLifetime(b); return r, err },
			func(b []byte) (Report, error) { w, r, err := DecodeWifiStatus(b); _, _ = w.SSID(); return r, err },
			func(b []byte) (Report, error) { v, r, err := DecodeVersion(b); _, _ = v.Firmware(); return r, err },
		} {
			rep, err := dec(data)
			if err != nil {
				continue
			}
			if len(rep.Unknown) > maxReportedUnknown+1 {
				t.Fatalf("too many unknown keys reported: %d", len(rep.Unknown))
			}
			for _, fe := range rep.Invalid {
				if utf8.RuneCountInString(fe.Reason) > maxReasonLen+1 {
					t.Fatalf("reason too long: %d", len(fe.Reason))
				}
			}
		}
	})
}

func FuzzParseAddress(f *testing.F) {
	for _, s := range []string{"192.168.1.17", "http://[fd00::1]:80", "wc.lan", "https://x:1/", "::ffff:10.0.0.1", "%", "[::1]"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := ParseAddress(s, AddressOptions{})
		if err != nil {
			return
		}
		// A valid address must round-trip to itself.
		b, err := ParseAddress(a.BaseURL(), AddressOptions{})
		if err != nil || a != b {
			t.Fatalf("round trip %q -> %q -> %+v, %v", s, a.BaseURL(), b, err)
		}
	})
}

func FuzzParseFirmware(f *testing.F) {
	for _, s := range []string{"26.26.10+g42855ec9b9cd1", "1.2.3-rc1", "", "1.2"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseFirmware(s)
		if err != nil {
			return
		}
		if v.Compare(v) != 0 {
			t.Fatal("Compare not reflexive")
		}
		if !bytes.Equal([]byte(v.String()), []byte(s)) {
			t.Fatal("String() must return the raw input")
		}
	})
}
