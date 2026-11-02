// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package fixturecheck

import (
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixturesDir = "../../testdata/fixtures"

// Placeholders that scripts/capture.sh writes in place of identifiers.
const (
	redactedSerial = "REDACTED00000"
	redactedMAC    = "02:00:00:00:00:00"
	redactedSSID   = "REDACTED"
)

func fixtureFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(fixturesDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".json") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking fixtures: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no fixtures found")
	}
	return files
}

func TestFixturesAreRedactedJSON(t *testing.T) {
	for _, path := range fixtureFiles(t) {
		t.Run(filepath.ToSlash(path), func(t *testing.T) {
			raw, err := os.ReadFile(path) //nolint:gosec // path comes from WalkDir over the repo fixtures directory
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if v, ok := doc["serial_number"]; ok && v != redactedSerial {
				t.Errorf("serial_number %q is not redacted (want %q)", v, redactedSerial)
			}
			if v, ok := doc["wifi_mac"]; ok && v != redactedMAC {
				t.Errorf("wifi_mac %q is not redacted (want %q)", v, redactedMAC)
			}
			if v, ok := doc["wifi_ssid"].(string); ok {
				dec, err := base64.StdEncoding.DecodeString(v)
				if err != nil || string(dec) != redactedSSID {
					t.Errorf("wifi_ssid %q is not the redacted placeholder", v)
				}
			}
			if v, ok := doc["wifi_infra_ip"].(string); ok {
				addr, err := netip.ParseAddr(v)
				testNet := netip.MustParsePrefix("192.0.2.0/24") // RFC 5737 TEST-NET-1
				if err != nil || !testNet.Contains(addr) {
					t.Errorf("wifi_infra_ip %q must be in 192.0.2.0/24 (documentation range)", v)
				}
			}
		})
	}
}
