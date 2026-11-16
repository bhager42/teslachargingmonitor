// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package gateway

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const fixtures = "../../testdata/fixtures/gateway"

// decoders maps a fixture's endpoint name (the file name before the label)
// to its decoder. Fixtures without a decoder (meters_site, powerwalls,
// system_update_status) are captured for reference only.
var decoders = map[string]func([]byte) (Report, error){
	"status":                    func(b []byte) (Report, error) { _, r, err := DecodeStatus(b); return r, err },
	"meters_aggregates":         func(b []byte) (Report, error) { _, r, err := DecodeAggregates(b); return r, err },
	"system_status_soe":         func(b []byte) (Report, error) { _, r, err := DecodeSOE(b); return r, err },
	"system_status_grid_status": func(b []byte) (Report, error) { _, r, err := DecodeGridStatus(b); return r, err },
	"system_status":             func(b []byte) (Report, error) { _, r, err := DecodeSystemStatus(b); return r, err },
	"operation":                 func(b []byte) (Report, error) { _, r, err := DecodeOperation(b); return r, err },
	"sitemaster":                func(b []byte) (Report, error) { _, r, err := DecodeSitemaster(b); return r, err },
	"site_info":                 func(b []byte) (Report, error) { _, r, err := DecodeSiteInfo(b); return r, err },
	"solars":                    func(b []byte) (Report, error) { _, r, err := DecodeSolars(b); return r, err },
}

func TestEveryFixtureDecodesCleanly(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(fixtures, "*", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no Gateway fixtures (%v)", err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		name, _, _ := strings.Cut(filepath.Base(f), ".")
		dec, ok := decoders[name]
		if !ok {
			continue
		}
		seen[name] = true
		t.Run(filepath.Base(filepath.Dir(f))+"/"+filepath.Base(f), func(t *testing.T) {
			b, err := os.ReadFile(f) //nolint:gosec // fixture path from Glob
			if err != nil {
				t.Fatal(err)
			}
			rep, err := dec(b)
			if err != nil {
				t.Fatal(err)
			}
			if !rep.Clean() {
				t.Errorf("report not clean: unknown %v, missing %v, invalid %v", rep.Unknown, rep.Missing, rep.Invalid)
			}
		})
	}
	for name := range decoders {
		if !seen[name] {
			t.Errorf("no fixture for decoder %q", name)
		}
	}
}

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, "26.34.2", name)) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFixtureValues(t *testing.T) {
	st, _, _ := DecodeStatus(read(t, "status.day.json"))
	if up, err := st.Uptime(); st.Firmware() != "26.34.2" || err != nil || up.Truncate(time.Second) != 420*time.Hour+27*time.Minute+56*time.Second {
		t.Errorf("status: firmware %q uptime %v %v", st.Firmware(), up, err)
	}
	agg, _, _ := DecodeAggregates(read(t, "meters_aggregates.day.json"))
	if agg.Load.NumMetersAggregated != nil || agg.Site.NumMetersAggregated == nil || *agg.Battery.NumMetersAggregated != 2 {
		t.Errorf("num_meters_aggregated: %+v", agg)
	}
	if got := agg.Solar.InstantPower + agg.Battery.InstantPower + agg.Site.InstantPower; math.Abs(got-agg.Load.InstantPower) > 20 {
		t.Errorf("power balance %g vs load %g", got, agg.Load.InstantPower)
	}
	soe, _, _ := DecodeSOE(read(t, "system_status_soe.day.json"))
	sys, _, _ := DecodeSystemStatus(read(t, "system_status.day.json"))
	if raw := 100 * sys.NominalEnergyRemaining / sys.NominalFullPackEnergy; math.Abs(raw-soe.Percentage) > 0.01 {
		t.Errorf("soe %g is not remaining/full %g", soe.Percentage, raw)
	}
	if got := soe.AppPercent(); math.Abs(got-31.6) > 0.1 {
		t.Errorf("app percent = %g, want ≈31.6", got)
	}
	if len(sys.BatteryBlocks) != 2 || sys.BatteryBlocks[0].NominalFullPackEnergy != 13341 || sys.BatteryBlocks[1].PackagePartNumber != "2012170-05-E" {
		t.Errorf("battery blocks = %+v", sys.BatteryBlocks)
	}
	var charged float64
	for _, b := range sys.BatteryBlocks {
		charged += b.EnergyCharged
	}
	if math.Abs(charged-agg.Battery.EnergyImported) > 1000 {
		t.Errorf("block energy_charged sum %g vs battery meter %g", charged, agg.Battery.EnergyImported)
	}
	op, _, _ := DecodeOperation(read(t, "operation.day.json"))
	if op.AppReservePercent() != 30 || op.RealMode != "self_consumption" {
		t.Errorf("operation = %+v (app reserve %g)", op, op.AppReservePercent())
	}
	gs, _, _ := DecodeGridStatus(read(t, "system_status_grid_status.day.json"))
	if !gs.OnGrid() {
		t.Errorf("grid status = %+v", gs)
	}
	sm, _, _ := DecodeSitemaster(read(t, "sitemaster.day.json"))
	if !sm.Running || sm.ConnectedToTesla {
		t.Errorf("sitemaster = %+v", sm)
	}
}

func TestAppPercent(t *testing.T) {
	for raw, want := range map[float64]float64{0: 0, 5: 0, 33.5: 30, 100: 100, 120: 100, -3: 0} {
		if got := AppPercent(raw); math.Abs(got-want) > 1e-9 {
			t.Errorf("AppPercent(%g) = %g, want %g", raw, got, want)
		}
	}
}

func TestDecodeProblemsUseDottedPaths(t *testing.T) {
	_, rep, err := DecodeSystemStatus([]byte(`{
		"nominal_full_pack_energy": 27217, "nominal_energy_remaining": "lots", "new_thing": 1,
		"battery_blocks": [
			{"PackagePartNumber":"p","PackageSerialNumber":"s","nominal_full_pack_energy":-5,"nominal_energy_remaining":1,"surprise":true},
			"not an object"
		]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := Report{
		Endpoint: EndpointSystemStatus,
		Unknown:  []string{"battery_blocks[0].surprise", "new_thing"},
		Invalid: []FieldError{
			{Field: "nominal_energy_remaining", Reason: "expected float64, got JSON string"},
			{Field: "battery_blocks[0].nominal_full_pack_energy", Reason: "value -5 outside plausible range [0, 100000]"},
			{Field: "battery_blocks[1]", Reason: "expected a JSON object"},
		},
	}
	if !reflect.DeepEqual(rep, want) {
		t.Errorf("report =\n%+v\nwant\n%+v", rep, want)
	}
	if !rep.Untrusted("battery_blocks[0].nominal_full_pack_energy") || rep.Untrusted("nominal_full_pack_energy") {
		t.Error("Untrusted")
	}

	_, rep, _ = DecodeAggregates([]byte(`{"site":{"instant_power":1},"solar":null,"load":[]}`))
	wantMissing := []string{"site.energy_imported", "site.energy_exported", "battery", "solar"}
	if !reflect.DeepEqual(rep.Missing, wantMissing) || !rep.IsInvalid("load") {
		t.Errorf("aggregates report = %+v", rep)
	}
}

func TestDecodeRejectsWrongShapes(t *testing.T) {
	if _, _, err := DecodeStatus([]byte(`[1]`)); !errors.Is(err, ErrNotObject) {
		t.Errorf("array as object: %v", err)
	}
	if _, _, err := DecodeStatus([]byte(`null`)); !errors.Is(err, ErrNotObject) {
		t.Errorf("null: %v", err)
	}
	if _, _, err := DecodeSolars([]byte(`{}`)); !errors.Is(err, ErrNotArray) {
		t.Errorf("object as array: %v", err)
	}
	big := "[" + strings.Repeat(`{"power_rating_watts":1},`, maxArrayItems+5) + `{"power_rating_watts":1}]`
	sol, rep, err := DecodeSolars([]byte(big))
	if err != nil || len(sol) != maxArrayItems || !rep.IsInvalid("") {
		t.Errorf("oversized array: %d items, %+v, %v", len(sol), rep, err)
	}
}

func TestUptime(t *testing.T) {
	for in, ok := range map[string]bool{"420h27m56.44310566s": true, "1s": true, "": false, "-5s": false, "soon": false} {
		if _, err := (Status{UpTimeSeconds: in}).Uptime(); (err == nil) != ok {
			t.Errorf("Uptime(%q) err = %v", in, err)
		}
	}
}
