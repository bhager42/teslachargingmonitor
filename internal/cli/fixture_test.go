// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

func TestFixtureExport(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "tcmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := st.CreateDevice(ctx, store.NewDevice("Garage", "192.168.1.17"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 20, 18, 0, 0, 0, time.UTC)
	for i, charging := range []bool{true, false} {
		snap := &wallconnector.Snapshot{
			FetchedAt: at.Add(time.Duration(i) * time.Hour),
			Vitals:    wallconnector.Vitals{ContactorClosed: charging, VehicleConnected: charging},
			Reports:   map[wallconnector.Endpoint]wallconnector.Report{},
			Raw: map[wallconnector.Endpoint][]byte{
				wallconnector.EndpointVersion:    []byte(`{"firmware_version":"26.34.0","serial_number":"PGT24123456789"}`),
				wallconnector.EndpointVitals:     []byte(`{"contactor_closed":true,"vehicle_current_a":47.4}`),
				wallconnector.EndpointWifiStatus: []byte(`{"wifi_mac":"98:ed:5c:12:34:56","wifi_infra_ip":"192.168.1.17"}`),
			},
		}
		if err := st.SaveSnapshot(ctx, d.ID, snap, nil, 1, time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.Close()

	r := runCLI(t, ctx, dir, "fixture", "export", "-device", "1", "-when", "charging")
	if r.code != 0 {
		t.Fatalf("export: %+v", r)
	}
	out := filepath.Join(dir, "fixtures", "uwc", "26.34.0")
	if !strings.Contains(r.stdout, "2026-11-20T18:00:00Z") || !strings.Contains(r.stdout, "testdata/fixtures/uwc/26.34.0/") {
		t.Errorf("stdout = %s", r.stdout)
	}
	for _, n := range []string{"version.charging.json", "vitals.charging.json", "wifi_status.charging.json"} {
		b, err := os.ReadFile(filepath.Join(out, n)) //nolint:gosec // test temp dir
		if err != nil {
			t.Fatal(err)
		}
		for _, leak := range []string{"PGT24123456789", "98:ed:5c", "192.168.1.17"} {
			if strings.Contains(string(b), leak) {
				t.Errorf("%s contains %s", n, leak)
			}
		}
	}

	for _, tc := range []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"fixture"}, 2, "Usage"},
		{[]string{"fixture", "export"}, 2, "exactly one of"},
		{[]string{"fixture", "export", "-device", "1", "-gateway", "1"}, 2, "exactly one of"},
		{[]string{"fixture", "export", "-device", "1", "-when", "night"}, 2, "latest, charging, plugged"},
		{[]string{"fixture", "export", "-gateway", "1", "-when", "plugged"}, 2, "latest, charging, night, off-grid"},
		{[]string{"fixture", "export", "-device", "1", "-before", "yesterday"}, 2, "RFC 3339"},
		{[]string{"fixture", "export", "-device", "1", "-label", "Bad/Label"}, 2, "-label"},
		{[]string{"fixture", "export", "-device", "1", "-when", "plugged"}, 1, "no stored plugged poll"},
		{[]string{"fixture", "export", "-device", "1", "-when", "charging", "-before", "2026-11-20T17:00:00Z"}, 1, "no stored charging poll"},
		{[]string{"fixture", "export", "-gateway", "7"}, 1, "no stored latest poll"},
	} {
		r := runCLI(t, ctx, dir, tc.args...)
		if r.code != tc.code || !strings.Contains(r.stderr, tc.msg) {
			t.Errorf("%v: %+v", tc.args, r)
		}
	}
}
