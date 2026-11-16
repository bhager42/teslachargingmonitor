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

func TestSiteIntervalsAndBuckets(t *testing.T) {
	loc := time.UTC
	day := time.Date(2026, 6, 20, 0, 0, 0, 0, loc)
	s := SiteSample{TS: day.Add(6 * time.Hour), SolarWh: 4e7, LoadWh: 2.5e8, GridImportWh: 2e8, GridExportWh: 2e6,
		BatteryChargeWh: 9e6, BatteryDischargeWh: 7e6}
	samples := []SiteSample{s}
	step := func(d time.Duration, solar, home, imp, exp, chg, dis float64) {
		s.TS = s.TS.Add(d)
		s.SolarWh += solar
		s.LoadWh += home
		s.GridImportWh += imp
		s.GridExportWh += exp
		s.BatteryChargeWh += chg
		s.BatteryDischargeWh += dis
		samples = append(samples, s)
	}
	step(6*time.Hour, 20000, 8000, 1000, 9000, 4000, 0) // morning to noon
	step(12*time.Hour, 10000, 9000, 0, 2000, 0, 1000)   // a long gap is kept: counters are exact
	reset := s
	reset.TS = s.TS.Add(time.Hour)
	reset.GridImportWh = 0 // meter reset: skipped
	samples = append(samples, reset)

	iv := SiteIntervals(samples)
	if len(iv) != 2 {
		t.Fatalf("intervals = %+v", iv)
	}
	p := NewPlan(nil, loc)
	b := p.SiteBuckets(iv, Day, 2, day.Add(23*time.Hour))
	if b[0].SolarKWh != 0 || !approx(b[1].SolarKWh, 30) || !approx(b[1].HomeKWh, 17) || !approx(b[1].ExportKWh, 11) ||
		!approx(b[1].ImportKWh, 1) || !approx(b[1].ChargeKWh, 4) || !approx(b[1].DischargeKWh, 1) {
		t.Errorf("buckets = %+v", b)
	}
	sc, ok := b[1].SelfConsumption()
	if !ok || !approx(sc, 19.0/30) {
		t.Errorf("self-consumption = %g %v", sc, ok)
	}
	ss, ok := b[1].SelfSufficiency()
	if !ok || !approx(ss, 16.0/17) {
		t.Errorf("self-sufficiency = %g %v", ss, ok)
	}
	if _, ok := b[0].SelfConsumption(); ok {
		t.Error("self-consumption without production")
	}
	if _, ok := b[0].SelfSufficiency(); ok {
		t.Error("self-sufficiency without use")
	}
	tot := SiteTotal(iv, day, day.AddDate(0, 0, 1))
	if !approx(tot.SolarKWh, 30) {
		t.Errorf("total = %+v", tot)
	}
}
