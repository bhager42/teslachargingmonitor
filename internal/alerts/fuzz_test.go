// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package alerts

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

func validSeverity(s Severity) bool { return s >= None && s <= Critical }

// FuzzRules feeds arbitrary /vitals payloads (untrusted device data)
// through every rule, as Eval and through step(), and checks the results
// stay well-formed.
func FuzzRules(f *testing.F) {
	files, _ := filepath.Glob("../../testdata/fixtures/*/*/vitals*.json")
	for _, p := range files {
		b, err := os.ReadFile(p) //nolint:gosec // test fixture path
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, 48.0)
	}
	f.Add([]byte(`{"contactor_closed":true,"vehicle_connected":true,"vehicle_current_a":119,"grid_v":0}`), 0.0)
	f.Add([]byte(`{"relay_k1_v":-1,"relay_coil_v":60,"evse_not_ready_reasons":null}`), 100.0)
	f.Add([]byte(`{"handle_temp_c":1e9,"grid_hz":-3}`), -1.0)
	f.Fuzz(func(t *testing.T, data []byte, maxCurrent float64) {
		v, rep, err := wallconnector.DecodeVitals(data)
		if err != nil {
			return
		}
		at := t0
		in := idle(at)
		in.Snapshot.Vitals = v
		in.Snapshot.Reports[wallconnector.EndpointVitals] = rep
		in.Device.MaxCurrentA = maxCurrent
		for _, def := range Definitions() {
			res := def.Eval(in, def.DefaultConfig().Params, newState())
			if !validSeverity(res.Severity) {
				t.Fatalf("%s: severity %d", def.Key, res.Severity)
			}
			if !res.Skip && def.Kind == Condition && res.Severity != None && res.Message == "" {
				t.Fatalf("%s: severity %v without a message", def.Key, res.Severity)
			}
			if res.Value != nil && (math.IsNaN(*res.Value) || math.IsInf(*res.Value, 0)) {
				t.Fatalf("%s: non-finite value %v", def.Key, *res.Value)
			}
			cfg := def.DefaultConfig()
			cfg.Enabled = true
			st := newState()
			for i := range 3 {
				in.At = at.Add(time.Duration(i) * time.Hour)
				in.Snapshot.FetchedAt = in.At
				for _, n := range step(def, cfg, in, st, false) {
					if !validSeverity(n.sev) || n.kind == "" {
						t.Fatalf("%s: bad notice %+v", def.Key, n)
					}
				}
			}
		}
	})
}

// FuzzParseQuietHours checks that every accepted window is within a day,
// non-empty, and never holds back critical notifications.
func FuzzParseQuietHours(f *testing.F) {
	for _, s := range []string{"22:00-07:00", "00:00-23:59", "7:5-8:6", "22:00-22:00", "24:00-01:00", "-1:00-02:00", "22:00-07:00x", ""} {
		f.Add(s, int64(0))
	}
	f.Fuzz(func(t *testing.T, s string, unix int64) {
		q, err := ParseQuietHours(s)
		if err != nil {
			return
		}
		day := 24 * time.Hour
		if !q.Enabled || q.Start < 0 || q.Start >= day || q.End < 0 || q.End >= day || q.Start == q.End {
			t.Fatalf("%q parsed to %+v", s, q)
		}
		at := time.Unix(unix%(1<<40), 0).UTC()
		_ = q.Active(at)
		if !q.Allows(Critical, at) {
			t.Fatalf("%q holds back a critical notification at %v", s, at)
		}
	})
}
