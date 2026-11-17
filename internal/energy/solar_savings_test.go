// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package energy

import (
	"testing"
	"time"
)

// A day with solar charging the Powerwalls and exporting, then a night on
// the Powerwalls, at a flat $0.20/kWh.
func TestSolarSavings(t *testing.T) {
	loc := time.UTC
	t0 := time.Date(2026, 6, 20, 0, 0, 0, 0, loc)
	p := NewPlan([]Rate{{Price: 0.20}}, loc)
	iv := []SiteInterval{
		// Night before any charge: the Powerwalls' contents are unknown,
		// so their discharge counts as grid.
		{From: t0, To: t0.Add(6 * time.Hour), HomeWh: 4000, DischargeWh: 3000, ImportWh: 1000},
		// Midday: 20 kWh solar, 6 kWh to the home, 9 kWh into the Powerwalls, 5 kWh exported.
		{From: t0.Add(6 * time.Hour), To: t0.Add(18 * time.Hour), SolarWh: 20000, HomeWh: 6000, ChargeWh: 9000, ExportWh: 5000},
		// Evening: 8 kWh from the Powerwalls (all solar), 1 kWh grid.
		{From: t0.Add(18 * time.Hour), To: t0.Add(24 * time.Hour), HomeWh: 9000, DischargeWh: 8000, ImportWh: 1000},
	}
	for _, tc := range []struct {
		m     SavingsMethod
		saved [3]float64
	}{
		{SavingsUsedAtHome, [3]float64{0, 6000, 8000}},
		{SavingsNetMetering, [3]float64{0, 20000, 0}},
	} {
		got := p.SolarSavings(iv, tc.m, 27000)
		for i, x := range got {
			if !approx(x.SavedWh, tc.saved[i]) || !approx(x.Savings, tc.saved[i]/1000*0.20) {
				t.Errorf("%s interval %d: saved %g Wh, %g", tc.m, i, x.SavedWh, x.Savings)
			}
		}
		b := SiteTotal(got, t0, t0.AddDate(0, 0, 1))
		want := (tc.saved[0] + tc.saved[1] + tc.saved[2]) / 1000
		if !approx(b.SavedKWh, want) || !approx(b.Savings, want*0.20) || !approx(b.SolarKWh, 20) {
			t.Errorf("%s total = %+v", tc.m, b)
		}
	}
	if iv[1].SavedWh != 0 {
		t.Error("SolarSavings changed its input")
	}
}

// Powerwalls charged partly from the grid: a later discharge counts as
// solar in proportion to what went in.
func TestSolarSavingsMixedCharge(t *testing.T) {
	t0 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	p := NewPlan([]Rate{{Price: 0.10}}, time.UTC)
	h := func(n int) time.Time { return t0.Add(time.Duration(n) * time.Hour) }
	iv := []SiteInterval{
		// 3 kWh solar, all into the Powerwalls; 1 kWh more from the grid.
		{From: h(0), To: h(1), SolarWh: 3000, ChargeWh: 4000, ImportWh: 1000},
		// 2 kWh discharged to the home: 3/4 solar.
		{From: h(1), To: h(2), DischargeWh: 2000, HomeWh: 2000},
		// The share is unchanged by the discharge: 2 kWh more, 3/4 solar.
		{From: h(2), To: h(3), DischargeWh: 2000, HomeWh: 2000},
	}
	got := p.SolarSavings(iv, SavingsUsedAtHome, 27000)
	if got[0].SavedWh != 0 || !approx(got[1].SavedWh, 1500) || !approx(got[2].SavedWh, 1500) {
		t.Errorf("saved = %g %g %g", got[0].SavedWh, got[1].SavedWh, got[2].SavedWh)
	}
}

// The pools are scaled to the battery's capacity, so energy lost in
// round trips does not build up and old grid charging fades out.
func TestSolarSavingsCapacity(t *testing.T) {
	t0 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	p := NewPlan(nil, time.UTC)
	h := func(n int) time.Time { return t0.Add(time.Duration(n) * time.Hour) }
	iv := []SiteInterval{
		{From: h(0), To: h(1), ChargeWh: 10000, ImportWh: 10000}, // 10 kWh from the grid
		{From: h(1), To: h(2), ChargeWh: 10000, SolarWh: 10000},  // 10 kWh from solar: pools scaled to 10 kWh, half solar
		{From: h(2), To: h(3), DischargeWh: 2000, HomeWh: 2000},  // half solar
		{From: h(3), To: h(4), ChargeWh: 2000, SolarWh: 2000},    // back to 10 kWh: 4 + 2 = 6 solar of 10
		{From: h(4), To: h(5), DischargeWh: 1000, HomeWh: 1000},  // 60 % solar
	}
	got := p.SolarSavings(iv, SavingsUsedAtHome, 10000)
	if !approx(got[2].SavedWh, 1000) || !approx(got[4].SavedWh, 600) {
		t.Errorf("saved = %g, %g", got[2].SavedWh, got[4].SavedWh)
	}
	if p.SolarSavings(iv[:1], SavingsUsedAtHome, 0)[0].SavedWh != 0 {
		t.Error("default capacity")
	}
}

// Savings are priced like charging: time-of-use applies when the energy
// was produced or used.
func TestSolarSavingsTimeOfUse(t *testing.T) {
	off := 0.05
	p := NewPlan([]Rate{{Price: 0.30, OffPeakPrice: &off, OffPeakStart: 0, OffPeakEnd: 6 * 60}}, time.UTC)
	t0 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	iv := []SiteInterval{
		{From: t0.Add(2 * time.Hour), To: t0.Add(3 * time.Hour), SolarWh: 1000, HomeWh: 1000},
		{From: t0.Add(12 * time.Hour), To: t0.Add(13 * time.Hour), SolarWh: 1000, HomeWh: 1000},
	}
	got := p.SolarSavings(iv, SavingsNetMetering, 0)
	if !approx(got[0].Savings, 0.05) || !approx(got[1].Savings, 0.30) {
		t.Errorf("savings = %g, %g", got[0].Savings, got[1].Savings)
	}
	if !SavingsUsedAtHome.Valid() || SavingsMethod("all").Valid() {
		t.Error("Valid")
	}
}
