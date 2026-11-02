// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package wcsim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

// The idle baseline must reproduce the real UWC capture.
func TestBaselineMatchesFixtures(t *testing.T) {
	b := Baseline()
	for name, v := range map[string]any{
		"vitals.json": b.Vitals, "lifetime.json": b.Lifetime,
		"wifi_status.json": b.WifiStatus, "version.json": b.Version,
	} {
		raw, err := os.ReadFile(filepath.Join("../../testdata/fixtures/uwc/26.26.10", name)) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		gen, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var want, got map[string]any
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(gen, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%s differs from baseline\nfixture: %v\nbaseline: %v", name, want, got)
		}
	}
}

// Every scenario must produce payloads that decode without schema problems
// at several points in simulated time.
func TestScenariosDecodeCleanly(t *testing.T) {
	for _, sc := range Scenarios() {
		for _, e := range []time.Duration{0, 5 * time.Minute, EventAfter + time.Minute, 3 * time.Hour} {
			st, _ := sc.State(e)
			for ep, v := range map[string]any{"vitals": st.Vitals, "lifetime": st.Lifetime, "wifi": st.WifiStatus, "version": st.Version} {
				b, _ := json.Marshal(v)
				var rep wallconnector.Report
				var err error
				switch ep {
				case "vitals":
					_, rep, err = wallconnector.DecodeVitals(b)
				case "lifetime":
					_, rep, err = wallconnector.DecodeLifetime(b)
				case "wifi":
					_, rep, err = wallconnector.DecodeWifiStatus(b)
				case "version":
					var ver wallconnector.Version
					ver, rep, err = wallconnector.DecodeVersion(b)
					if _, ferr := ver.Firmware(); ferr != nil {
						t.Errorf("%s@%v firmware: %v", sc.Name, e, ferr)
					}
				}
				if err != nil || !rep.Clean() {
					t.Errorf("%s@%v %s: err=%v report=%+v", sc.Name, e, ep, err, rep)
				}
			}
		}
	}
}

func TestScenarioDynamics(t *testing.T) {
	get := func(name string, e time.Duration) State {
		sc, ok := Lookup(name)
		if !ok {
			t.Fatalf("no scenario %q", name)
		}
		s, _ := sc.State(e)
		return s
	}
	if s := get("overheat", 30*time.Minute); s.Vitals.HandleTempC < 70 {
		t.Errorf("overheat handle temp at 30 min = %v, want >= 70", s.Vitals.HandleTempC)
	}
	before, after := get("thermal-foldback", EventAfter-time.Second), get("thermal-foldback", EventAfter)
	if after.Lifetime.ThermalFoldbacks != before.Lifetime.ThermalFoldbacks+1 || after.Vitals.VehicleCurrentA >= before.Vitals.VehicleCurrentA {
		t.Errorf("foldback not applied: before=%+v after=%+v", before.Lifetime, after.Lifetime)
	}
	if s := get("reboot", EventAfter+30*time.Second); s.Vitals.UptimeS != 30 {
		t.Errorf("reboot uptime = %d, want 30", s.Vitals.UptimeS)
	}
	if a, b := get("firmware-change", 0), get("firmware-change", EventAfter); a.Version.FirmwareVersion == b.Version.FirmwareVersion || a.Version.GridProfile() == b.Version.GridProfile() {
		t.Error("firmware-change did not change firmware and grid profile")
	}
	c1, c2 := get("charging", time.Minute), get("charging", time.Hour)
	if c2.Vitals.SessionEnergyWh <= c1.Vitals.SessionEnergyWh || c2.Lifetime.EnergyWh <= c1.Lifetime.EnergyWh {
		t.Error("charging energy does not increase")
	}
	if c1.Vitals.VehicleCurrentA > 48 {
		t.Errorf("charging current %v exceeds the 48 A limit", c1.Vitals.VehicleCurrentA)
	}
	if s := get("overcurrent", time.Minute); s.Vitals.VehicleCurrentA <= 48*1.05 {
		t.Errorf("overcurrent current %v not above threshold", s.Vitals.VehicleCurrentA)
	}
}

func TestServer(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	srv, err := NewServer(Options{Scenario: "charging", Speed: 60, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(Options{Scenario: "nope"}); err == nil {
		t.Error("unknown scenario accepted")
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	now = now.Add(10 * time.Second) // 10 s real × 60 = 10 simulated minutes
	if e := srv.Elapsed(); e != 10*time.Minute {
		t.Errorf("Elapsed() = %v, want 10m", e)
	}

	resp, err := http.Get(ts.URL + "/api/1/vitals") //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	var v wallconnector.Vitals
	_ = json.NewDecoder(resp.Body).Decode(&v)
	_ = resp.Body.Close()
	if !v.ContactorClosed || v.SessionS != 600 {
		t.Errorf("vitals = %+v", v)
	}

	resp, err = http.PostForm(ts.URL+"/_sim/scenario", url.Values{"name": {"idle"}}) //nolint:noctx // test
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("switch scenario: %v %v", err, resp)
	}
	_ = resp.Body.Close()
	if sc, _, _ := srv.Current(); sc.Name != "idle" {
		t.Errorf("scenario = %s", sc.Name)
	}

	resp, _ = http.PostForm(ts.URL+"/_sim/scenario", url.Values{"name": {"bogus"}}) //nolint:noctx // test
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bogus scenario status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	resp, _ = http.Get(ts.URL + "/_sim") //nolint:noctx // test
	var status map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&status)
	_ = resp.Body.Close()
	if status["scenario"] != "idle" {
		t.Errorf("status = %v", status)
	}

	resp, _ = http.Get(ts.URL + "/api/1/nope") //nolint:noctx // test
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown endpoint status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/1/vitals", nil) //nolint:noctx // test
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE status = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	_ = srv.SetScenario("malformed")
	resp, _ = http.Get(ts.URL + "/api/1/vitals") //nolint:noctx // test
	var sb strings.Builder
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	sb.Write(buf[:n])
	_ = resp.Body.Close()
	if json.Valid([]byte(sb.String())) {
		t.Errorf("malformed scenario returned valid JSON: %s", sb.String())
	}
}
