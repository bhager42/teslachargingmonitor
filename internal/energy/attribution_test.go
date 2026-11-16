// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package energy

import (
	"math"
	"testing"
	"time"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestHomeSupply(t *testing.T) {
	for name, tc := range map[string]struct {
		solar, imp, exp, charge, discharge float64
		want                               Supply
	}{
		// The owner's capture: solar 3730 W, battery charging 1290 W, 49 W exported.
		"battery charging from solar": {3730, 0, 49, 1290, 0, Supply{Solar: 2391}},
		"sunny with export":           {6200, 0, 1500, 3200, 0, Supply{Solar: 1500}},
		"cloudy":                      {600, 900, 0, 0, 0, Supply{Solar: 600, Grid: 900}},
		"night on battery":            {0, 0, 0, 0, 1100, Supply{Battery: 1100}},
		"night on grid":               {0, 1200, 0, 0, 0, Supply{Grid: 1200}},
		"battery charging from grid":  {0, 5000, 0, 3000, 0, Supply{Grid: 2000}},
		"solar and grid charge":       {1000, 4000, 0, 3000, 0, Supply{Grid: 2000}},
		"battery exporting":           {0, 0, 2000, 0, 5000, Supply{Battery: 3000}},
		"solar export then battery":   {500, 0, 800, 0, 2000, Supply{Battery: 1700}},
		"car on everything":           {6000, 3100, 0, 0, 0, Supply{Solar: 6000, Grid: 3100}},
		"noise below zero":            {-1, -2, -3, -4, -5, Supply{}},
	} {
		got := HomeSupply(tc.solar, tc.imp, tc.exp, tc.charge, tc.discharge)
		if !approx(got.Solar, tc.want.Solar) || !approx(got.Battery, tc.want.Battery) || !approx(got.Grid, tc.want.Grid) {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
}

// site builds Gateway samples every step from start, applying flow (W) per
// sample; flows[i] is the flow during the interval ending at sample i+1.
func site(start time.Time, step time.Duration, flows ...[5]float64) []SiteSample {
	s := SiteSample{TS: start, SolarWh: 4e7, GridImportWh: 2e8, GridExportWh: 2e6, BatteryChargeWh: 9e6, BatteryDischargeWh: 7e6}
	out := []SiteSample{s}
	h := step.Hours()
	for _, f := range flows {
		s.TS = s.TS.Add(step)
		s.SolarWh += f[0] * h
		s.GridImportWh += f[1] * h
		s.GridExportWh += f[2] * h
		s.BatteryChargeWh += f[3] * h
		s.BatteryDischargeWh += f[4] * h
		out = append(out, s)
	}
	return out
}

func TestSupplyIntervalsSkipResetsAndGaps(t *testing.T) {
	t0 := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	s := site(t0, 15*time.Minute, [5]float64{4000, 0, 0, 0, 0}, [5]float64{4000, 0, 0, 0, 0}, [5]float64{4000, 0, 0, 0, 0})
	s[2].GridImportWh = 0 // a meter reset between samples 1 and 2
	s[3].GridImportWh = 0
	got := SupplyIntervals(s)
	if len(got) != 2 || !got[0].To.Equal(s[1].TS) || !got[1].From.Equal(s[2].TS) {
		t.Fatalf("reset: %+v", got)
	}
	if !approx(got[1].Solar, 1000) {
		t.Errorf("solar after reset = %g Wh, want 1000", got[1].Solar)
	}
	gap := []SiteSample{s[0], s[1]}
	gap[1].TS = s[0].TS.Add(MaxSupplyGap + time.Minute)
	gap[1].GridImportWh = s[0].GridImportWh
	if got := SupplyIntervals(gap); len(got) != 0 {
		t.Errorf("an interval longer than MaxSupplyGap was used: %+v", got)
	}
	if got := SupplyIntervals([]SiteSample{s[1], s[0]}); len(got) != 0 {
		t.Errorf("out of order samples: %+v", got)
	}
}

func TestAttribute(t *testing.T) {
	t0 := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	// 12:00–12:15 all solar (4 kW), 12:15–12:30 half grid (2 kW each).
	sup := SupplyIntervals(site(t0, 15*time.Minute, [5]float64{4000, 0, 0, 0, 0}, [5]float64{2000, 2000, 0, 0, 0}))
	p := NewPlan([]Rate{{Price: 0.20}}, time.UTC)
	iv := []Interval{
		{From: t0, To: t0.Add(15 * time.Minute), Wh: 1000},                                 // all solar
		{From: t0.Add(15 * time.Minute), To: t0.Add(30 * time.Minute), Wh: 1000},           // half/half
		{From: t0.Add(5 * time.Minute), To: t0.Add(25 * time.Minute), Wh: 2000},            // spans both
		{From: t0.Add(25 * time.Minute), To: t0.Add(45 * time.Minute), Wh: 1000},           // 25 % covered
		{From: t0.Add(-time.Hour), To: t0.Add(-30 * time.Minute), Wh: 1000},                // before the Gateway
		{From: t0.Add(20 * time.Minute), To: t0.Add(20 * time.Minute), Wh: 1000},           // zero length
		{From: t0.Add(15 * time.Minute), To: t0.Add(30 * time.Minute), Wh: 0, Cost: 0},     // no energy
		{From: t0.Add(10 * time.Minute), To: t0.Add(20 * time.Minute), Wh: 1200, Cost: 10}, // savings
	}
	for i := range iv {
		if iv[i].Cost == 0 && iv[i].Wh > 0 {
			iv[i].Cost = p.Cost(iv[i].From, iv[i].To, iv[i].Wh)
		}
	}
	got := Attribute(iv, sup)
	type want struct {
		attributed          bool
		solar, battery, grd float64
	}
	// Interval 2: 10 min of the solar interval (4000·10/15·¼h … ) and 10 min
	// of the half/half one, energy-weighted: solar 666.7+333.3 = 1000 Wh,
	// grid 333.3 Wh of 1333.3 → 75 % solar.
	for i, w := range []want{
		{true, 1000, 0, 0}, {true, 500, 0, 500}, {true, 1500, 0, 500},
		{false, 0, 0, 0}, {false, 0, 0, 0}, {false, 0, 0, 0}, {true, 0, 0, 0},
		{true, 900, 0, 300}, // 5 min of each: solar 333+167, grid 167 → 75 % solar
	} {
		g := got[i]
		if g.Attributed != w.attributed || !approx(g.SolarWh, w.solar) || !approx(g.BatteryWh, w.battery) || !approx(g.GridWh, w.grd) {
			t.Errorf("interval %d: %+v, want %+v", i, g, w)
		}
		if g.Attributed && !approx(g.SolarWh+g.BatteryWh+g.GridWh, g.Wh) {
			t.Errorf("interval %d: split %g+%g+%g ≠ %g", i, g.SolarWh, g.BatteryWh, g.GridWh, g.Wh)
		}
	}
	if s := got[7].Savings; !approx(s, 7.5) {
		t.Errorf("savings = %g, want the solar share of the cost", s)
	}
	if got[0].Savings != got[0].Cost {
		t.Errorf("an all-solar interval saved %g of %g", got[0].Savings, got[0].Cost)
	}
	if iv[0].Attributed {
		t.Error("Attribute modified its input")
	}
	if a := Attribute(iv, nil); a[0].Attributed {
		t.Error("attributed without a Gateway")
	}
}

// Plan step 9.3 acceptance: a sunny-day session's split adds up to its
// kWh; night charging is all grid or all battery.
func TestSessionsWithSupply(t *testing.T) {
	loc := time.UTC
	day := time.Date(2026, 6, 20, 0, 0, 0, 0, loc)
	p := NewPlan([]Rate{{Price: 0.20}}, loc)
	// The car charges at 7.6 kW, polled every 5 min.
	session := func(from time.Time, polls int) []PlugSample {
		var ps []PlugSample
		wh := 1e6
		add := func(ts time.Time, plugged bool) {
			v := wh
			ps = append(ps, PlugSample{TS: ts, Plugged: plugged, CurrentA: 32, Wh: &v})
		}
		add(from.Add(-5*time.Minute), false)
		for i := range polls {
			if i > 0 {
				wh += 7600.0 / 12
			}
			add(from.Add(time.Duration(i)*5*time.Minute), true)
		}
		wh += 7600.0 / 12
		add(from.Add(time.Duration(polls)*5*time.Minute), false)
		return ps
	}
	gw := func(from time.Time, n int, flow [5]float64) []SupplyInterval {
		flows := make([][5]float64, n)
		for i := range flows {
			flows[i] = flow
		}
		return SupplyIntervals(site(from, 5*time.Minute, flows...))
	}

	for name, tc := range map[string]struct {
		start     time.Time
		flow      [5]float64 // solar, import, export, charge, discharge (W)
		wantSolar float64    // share of the session
		wantBatt  float64
		wantGrid  float64
	}{
		// gwsim "charging": solar 6 kW, home 9.1 kW incl. the car, 3.1 kW imported.
		"sunny":            {day.Add(11 * time.Hour), [5]float64{6000, 3100, 0, 0, 0}, 6000.0 / 9100, 0, 3100.0 / 9100},
		"sunny surplus":    {day.Add(12 * time.Hour), [5]float64{12000, 0, 1500, 1000, 0}, 1, 0, 0},
		"night on grid":    {day.Add(22 * time.Hour), [5]float64{0, 8800, 0, 0, 0}, 0, 0, 1},
		"night on battery": {day.Add(23 * time.Hour), [5]float64{0, 0, 0, 0, 8800}, 0, 1, 0},
	} {
		ps := session(tc.start, 24) // 2 hours
		sup := gw(tc.start.Add(-30*time.Minute), 40, tc.flow)
		ss := SessionsWithSupply(ps, p, sup)
		if len(ss) != 1 {
			t.Fatalf("%s: %d sessions", name, len(ss))
		}
		s := ss[0]
		if !approx(s.AttributedKWh, s.KWh) || !approx(s.SolarKWh+s.BatteryKWh+s.GridKWh, s.KWh) {
			t.Errorf("%s: split %.3f+%.3f+%.3f of %.3f kWh (attributed %.3f)", name, s.SolarKWh, s.BatteryKWh, s.GridKWh, s.KWh, s.AttributedKWh)
		}
		if !approx(s.SolarKWh/s.KWh, tc.wantSolar) || !approx(s.BatteryKWh/s.KWh, tc.wantBatt) || !approx(s.GridKWh/s.KWh, tc.wantGrid) {
			t.Errorf("%s: shares %.3f/%.3f/%.3f, want %.3f/%.3f/%.3f", name, s.SolarKWh/s.KWh, s.BatteryKWh/s.KWh,
				s.GridKWh/s.KWh, tc.wantSolar, tc.wantBatt, tc.wantGrid)
		}
		if !approx(s.Savings, s.Cost*tc.wantSolar) {
			t.Errorf("%s: savings %.4f, want %.4f", name, s.Savings, s.Cost*tc.wantSolar)
		}
	}

	// Without a Gateway, sessions are unchanged and unattributed.
	plain := Sessions(session(day.Add(11*time.Hour), 24), p)
	if len(plain) != 1 || plain[0].AttributedKWh != 0 || !approx(plain[0].KWh, 7.6*2) {
		t.Errorf("without a Gateway: %+v", plain)
	}
}

func TestBucketsCarryTheSplit(t *testing.T) {
	loc := time.UTC
	t0 := time.Date(2026, 6, 20, 12, 0, 0, 0, loc)
	p := NewPlan([]Rate{{Price: 0.20, MonthlyFee: 10}}, loc)
	iv := []Interval{
		{From: t0, To: t0.Add(time.Hour), Wh: 3000, Cost: 0.6, Attributed: true, SolarWh: 2000, GridWh: 1000, Savings: 0.4},
		{From: t0.Add(time.Hour), To: t0.Add(2 * time.Hour), Wh: 1000, Cost: 0.2}, // no Gateway data
	}
	b := p.Total(iv, t0, t0.Add(3*time.Hour))
	if !approx(b.KWh, 4) || !approx(b.AttributedKWh, 3) || !approx(b.SolarKWh, 2) || !approx(b.GridKWh, 1) ||
		!approx(b.Savings, 0.4) || !approx(b.Cost, 10.8) || !approx(b.SolarShare(), 2.0/3) {
		t.Errorf("total = %+v share %g", b, b.SolarShare())
	}
	bs := p.Buckets(iv, Day, 1, t0)
	if !approx(bs[0].SolarKWh, 2) || !approx(bs[0].Savings, 0.4) {
		t.Errorf("bucket = %+v", bs[0])
	}
	if (Bucket{}).SolarShare() != 0 {
		t.Error("empty bucket share")
	}
}
