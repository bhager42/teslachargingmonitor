// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package redact

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func decode(t *testing.T, s string) any {
	t.Helper()
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func encode(t *testing.T, v any) string {
	t.Helper()
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(b.String())
}

func TestSensitive(t *testing.T) {
	for key, want := range map[string]bool{
		"din": true, "PackageSerialNumber": true, "serial_number": true, "gateway_id": true,
		"email": true, "firstname": true, "site_name": true, "token": true, "ip_address": true,
		"IPAddress": true, "wifi_mac": true, "latitude": true, "address": true, "grid_code": true,
		"instant_power": false, "energy_exported": false, "percentage": false, "grid_status": false,
		"version": false, "up_time_seconds": false, "last_communication_time": false, "timeout": false,
		"part_number": false, "machine": false,
	} {
		if got := Sensitive(key); got != want {
			t.Errorf("Sensitive(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestRedactor(t *testing.T) {
	status := decode(t, `{"din":"1232100-00-E--TG123456789ABC","version":"26.34.2 abc123","up_time_seconds":"1h"}`)
	other := decode(t, `{
		"site_name":"Hager Home","note":"seen TG123456789ABC at 192.168.1.246 (aa:bb:cc:dd:ee:ff) by me@home.net",
		"doc_ip":"203.0.113.9","kept":"via 198.51.100.7","latitude":38.6,"address":{"line1":"1 Main St","zip":"12345"},
		"powerwalls":[{"PackageSerialNumber":"TG987654321XYZ","energy":13500}],
		"instant_power":-1234.5,"grid_status":"SystemGridConnected"}`)
	r := New()
	r.Learn(status)
	r.Learn(other)

	if got, want := encode(t, r.Apply(status)),
		`{"din":"REDACTED","up_time_seconds":"1h","version":"26.34.2 abc123"}`; got != want {
		t.Errorf("status:\n got %s\nwant %s", got, want)
	}
	got := r.Apply(other)
	want := decode(t, `{
		"site_name":"REDACTED","note":"seen REDACTED at 192.0.2.246 (02:00:00:00:00:00) by redacted@example.com",
		"doc_ip":"192.0.2.1","kept":"via 198.51.100.7","latitude":0,"address":{"line1":"REDACTED","zip":"REDACTED"},
		"powerwalls":[{"PackageSerialNumber":"REDACTED","energy":13500}],
		"instant_power":-1234.5,"grid_status":"SystemGridConnected"}`)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("other:\n got %s\nwant %s", encode(t, got), encode(t, want))
	}
	if p := Check(got); len(p) != 0 {
		t.Errorf("Check(redacted) = %v, want none", p)
	}
}

func TestCheck(t *testing.T) {
	doc := decode(t, `{"din":"1232100-00-E--TG1","ok":"192.0.2.1","x":["10.0.0.5"],
		"m":{"note":"aa:bb:cc:dd:ee:ff a@b.org"},"latitude":38.6,"email":"redacted@example.com","ip":""}`)
	got := Check(doc)
	want := []string{
		"$.din: sensitive key is not redacted",
		"$.latitude: sensitive key is not redacted",
		"$.m.note: MAC address",
		"$.m.note: email address",
		"$.x[0]: IPv4 address outside the documentation ranges",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Check =\n%v\nwant\n%v", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, p := range got {
		if strings.Contains(p, "TG1") || strings.Contains(p, "10.0.0.5") {
			t.Errorf("problem %q leaks the value", p)
		}
	}
}
