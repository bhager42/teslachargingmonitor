// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package fixtureexport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway/redact"
)

// Made-up identifiers standing in for the owner's real ones.
const (
	fakeSerial = "PGT24123456789"
	fakeMAC    = "98:ed:5c:12:34:56"
	fakeIP     = "192.168.1.17"
	fakeSSID   = "SG9tZU5ldA==" // base64("HomeNet")
)

func TestWallConnector(t *testing.T) {
	raw := map[string][]byte{
		"version":     []byte(`{"firmware_version":"26.34.0+gabc","part_number":"1734412-02-F","serial_number":"` + fakeSerial + `"}`),
		"vitals":      []byte(`{"contactor_closed":true,"vehicle_current_a":47.4,"grid_v":241.2}`),
		"lifetime":    []byte(`{"energy_wh":1234567}`),
		"wifi_status": []byte(`{"wifi_ssid":"` + fakeSSID + `","wifi_mac":"` + fakeMAC + `","wifi_infra_ip":"` + fakeIP + `","wifi_connected":true}`),
	}
	f, err := WallConnector(raw, "charging")
	if err != nil {
		t.Fatal(err)
	}
	if f.Firmware != "26.34.0" {
		t.Errorf("firmware = %q", f.Firmware)
	}
	want := []string{"lifetime.charging.json", "version.charging.json", "vitals.charging.json", "wifi_status.charging.json"}
	if !slices.Equal(f.Names(), want) {
		t.Errorf("files = %v, want %v", f.Names(), want)
	}
	all := ""
	for _, n := range f.Names() {
		all += string(f.Files[n])
		var doc map[string]any
		if err := json.Unmarshal(f.Files[n], &doc); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if p := CheckWallConnector(doc); len(p) > 0 {
			t.Errorf("%s: %v", n, p)
		}
	}
	for _, leak := range []string{fakeSerial, fakeMAC, fakeIP, fakeSSID} {
		if strings.Contains(all, leak) {
			t.Errorf("output contains %s", leak)
		}
	}
	for _, keep := range []string{`"wifi_infra_ip":"192.0.2.17"`, `"vehicle_current_a":47.4`, `"energy_wh":1234567`, `"part_number":"1734412-02-F"`} {
		if !strings.Contains(all, keep) {
			t.Errorf("output lacks %s", keep)
		}
	}

	// Unlabeled, the names match scripts/capture.sh.
	f, err = WallConnector(raw, "")
	if err != nil || f.Files["vitals.json"] == nil {
		t.Errorf("unlabeled: %v, %v", f.Names(), err)
	}

	for name, bad := range map[string]map[string][]byte{
		"no vitals":   {"version": raw["version"]},
		"no version":  {"vitals": raw["vitals"]},
		"not JSON":    {"version": raw["version"], "vitals": []byte(`{`)},
		"not object":  {"version": raw["version"], "vitals": []byte(`[1]`)},
		"no firmware": {"version": []byte(`{}`), "vitals": raw["vitals"]},
	} {
		if _, err := WallConnector(bad, ""); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestCheckWallConnector(t *testing.T) {
	doc := map[string]any{"serial_number": fakeSerial, "wifi_mac": fakeMAC, "wifi_ssid": fakeSSID, "wifi_infra_ip": fakeIP}
	p := CheckWallConnector(doc)
	if len(p) != 4 {
		t.Errorf("problems = %v", p)
	}
	for _, s := range p {
		for _, leak := range []string{fakeSerial, fakeMAC, fakeIP, fakeSSID} {
			if strings.Contains(s, leak) {
				t.Errorf("problem text contains the value: %s", s)
			}
		}
	}
	RedactWallConnector(doc)
	if p := CheckWallConnector(doc); len(p) > 0 {
		t.Errorf("after redaction: %v", p)
	}
	// IPv6 and empty addresses.
	doc = map[string]any{"wifi_infra_ip": "fe80::1"}
	RedactWallConnector(doc)
	if doc["wifi_infra_ip"] != "192.0.2.1" {
		t.Errorf("IPv6 -> %v", doc["wifi_infra_ip"])
	}
	doc = map[string]any{"wifi_infra_ip": ""}
	RedactWallConnector(doc)
	if doc["wifi_infra_ip"] != "" || len(CheckWallConnector(doc)) > 0 {
		t.Errorf("empty address -> %v", doc["wifi_infra_ip"])
	}
}

func TestGateway(t *testing.T) {
	dir := "../../testdata/fixtures/gateway/26.34.2"
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name+".day.json")) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// The committed fixtures are already redacted, so put identifiers back
	// in, as the Gateway sends them.
	status := map[string]any{}
	if err := json.Unmarshal(read("status"), &status); err != nil {
		t.Fatal(err)
	}
	status["din"] = "1232100-00-E--" + fakeSerial
	statusB, _ := json.Marshal(status)
	raw := map[string][]byte{
		"/api/status":                    statusB,
		"/api/meters/aggregates":         read("meters_aggregates"),
		"/api/system_status/soe":         read("system_status_soe"),
		"/api/system_status/grid_status": read("system_status_grid_status"),
		"/api/system_status":             read("system_status"),
		"/api/operation":                 read("operation"),
		"/api/sitemaster":                []byte(`{"running":true,"note":"gateway ` + fakeSerial + ` at ` + fakeIP + ` mac ` + fakeMAC + `"}`),
	}
	polled := time.Date(2026, 11, 20, 3, 0, 0, 0, time.UTC)
	f, err := Gateway(raw, "night", polled)
	if err != nil {
		t.Fatal(err)
	}
	if f.Firmware != "26.34.2" {
		t.Errorf("firmware = %q", f.Firmware)
	}
	want := []string{"index.night.json", "meters_aggregates.night.json", "operation.night.json", "sitemaster.night.json",
		"status.night.json", "system_status.night.json", "system_status_grid_status.night.json", "system_status_soe.night.json"}
	if !slices.Equal(f.Names(), want) {
		t.Errorf("files = %v, want %v", f.Names(), want)
	}
	for _, n := range f.Names() {
		b := f.Files[n]
		for _, leak := range []string{fakeSerial, fakeMAC, fakeIP} {
			if strings.Contains(string(b), leak) {
				t.Errorf("%s contains %s", n, leak)
			}
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
		if p := redact.Check(v); len(p) > 0 {
			t.Errorf("%s: %v", n, p)
		}
	}
	var idx map[string]any
	_ = json.Unmarshal(f.Files["index.night.json"], &idx)
	if idx["polled_at"] != "2026-11-20T03:00:00Z" || idx["source"] != "tcmon fixture export" {
		t.Errorf("index = %v", idx)
	}
	if e, _ := idx["/api/status"].(map[string]any); e["file"] != "status.night.json" {
		t.Errorf("index entry = %v", idx["/api/status"])
	}

	if _, err := Gateway(map[string][]byte{"/api/operation": read("operation")}, "", polled); err == nil {
		t.Error("no status: no error")
	}
	if _, err := Gateway(map[string][]byte{"/api/status": []byte(`nope`)}, "", polled); err == nil {
		t.Error("not JSON: no error")
	}
}
