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

var chicago, _ = time.LoadLocation("America/Chicago")

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func f(v float64) *float64 { return &v }

func at(y int, m time.Month, d, h, min int) time.Time {
	return time.Date(y, m, d, h, min, 0, 0, chicago)
}

func TestDefaultAndRateHistory(t *testing.T) {
	p := NewPlan(nil, chicago)
	if got := p.Cost(at(2026, 11, 3, 1, 0), at(2026, 11, 3, 2, 0), 10000); !near(got, 1.55) {
		t.Errorf("default 10 kWh = %v, want 1.55", got)
	}
	p = NewPlan([]Rate{
		{EffectiveFrom: at(2026, 12, 1, 0, 0), Price: 0.20},
		{EffectiveFrom: at(2026, 1, 1, 0, 0), Price: 0.155},
	}, chicago)
	if r := p.RateAt(at(2025, 6, 1, 0, 0)); r.Price != 0.155 {
		t.Errorf("before the first rate = %v (earliest rate should apply)", r.Price)
	}
	if r := p.RateAt(at(2026, 11, 30, 23, 59)); r.Price != 0.155 {
		t.Errorf("Nov = %v", r.Price)
	}
	if r := p.RateAt(at(2026, 12, 1, 0, 0)); r.Price != 0.20 {
		t.Errorf("Dec 1 = %v", r.Price)
	}
}

func TestTimeOfUseSplit(t *testing.T) {
	// Off-peak 23:00-06:00 at $0.08, peak $0.20.
	p := NewPlan([]Rate{{Price: 0.20, OffPeakPrice: f(0.08), OffPeakStart: 23 * 60, OffPeakEnd: 6 * 60}}, chicago)
	cases := []struct {
		name     string
		from, to time.Time
		want     float64 // for 10 kWh
	}{
		{"all peak", at(2026, 11, 3, 12, 0), at(2026, 11, 3, 13, 0), 2.0},
		{"all off-peak across midnight", at(2026, 11, 3, 23, 30), at(2026, 11, 4, 0, 30), 0.8},
		{"early morning off-peak", at(2026, 11, 4, 2, 0), at(2026, 11, 4, 3, 0), 0.8},
		{"half and half at 23:00", at(2026, 11, 3, 22, 30), at(2026, 11, 3, 23, 30), 1.4},
		{"half and half at 06:00", at(2026, 11, 4, 5, 30), at(2026, 11, 4, 6, 30), 1.4},
	}
	for _, c := range cases {
		if got := p.Cost(c.from, c.to, 10000); !near(got, c.want) {
			t.Errorf("%s = %v, want %v", c.name, got, c.want)
		}
	}
	if got := p.Cost(at(2026, 11, 4, 1, 0), at(2026, 11, 4, 1, 0), 1000); !near(got, 0.08) {
		t.Errorf("instant off-peak = %v", got)
	}
	day := NewPlan([]Rate{{Price: 0.20, OffPeakPrice: f(0.10), OffPeakStart: 9 * 60, OffPeakEnd: 17 * 60}}, chicago)
	if got := day.Cost(at(2026, 11, 3, 8, 0), at(2026, 11, 3, 10, 0), 2000); !near(got, 0.30) {
		t.Errorf("daytime window = %v", got)
	}
}

// The off-peak window follows the wall clock on days with a DST change
// (2026-03-08 has 23 hours, 2026-11-01 has 25). Found by FuzzCosts.
func TestTimeOfUseAcrossDST(t *testing.T) {
	p := NewPlan([]Rate{{Price: 0.20, OffPeakPrice: f(0.08), OffPeakStart: 23 * 60, OffPeakEnd: 6 * 60}}, chicago)
	cases := []struct {
		name     string
		from, to time.Time
		want     float64 // for 10 kWh
	}{
		{"spring forward: half and half at 23:00", at(2026, 3, 8, 22, 30), at(2026, 3, 8, 23, 30), 1.4},
		{"spring forward: half and half at 06:00", at(2026, 3, 8, 5, 30), at(2026, 3, 8, 6, 30), 1.4},
		{"fall back: all peak before 23:00", at(2026, 11, 1, 21, 30), at(2026, 11, 1, 22, 30), 2.0},
		{"fall back: half and half at 23:00", at(2026, 11, 1, 22, 30), at(2026, 11, 1, 23, 30), 1.4},
	}
	for _, c := range cases {
		if got := p.Cost(c.from, c.to, 10000); !near(got, c.want) {
			t.Errorf("%s = %v, want %v", c.name, got, c.want)
		}
	}
	// A window spanning almost a whole day must not be counted twice on
	// the short day: the cost stays between the off-peak and peak prices.
	wide := NewPlan([]Rate{{Price: 0.20, OffPeakPrice: f(0.08), OffPeakStart: 48, OffPeakEnd: 42}}, chicago)
	if got := wide.Cost(at(2026, 3, 7, 12, 0), at(2026, 3, 10, 12, 0), 10000); got < 0.8-1e-9 || got > 2.0 {
		t.Errorf("wide window across spring forward = %v, want 0.8-2.0", got)
	}
}

func TestIntervalsHandleResets(t *testing.T) {
	p := NewPlan(nil, chicago)
	s := []Sample{
		{at(2026, 11, 3, 0, 0), 433_293}, {at(2026, 11, 3, 1, 0), 443_293}, // +10 kWh
		{at(2026, 11, 3, 2, 0), 443_293}, // idle
		{at(2026, 11, 3, 3, 0), 1_000},   // counter reset: new baseline, no negative
		{at(2026, 11, 3, 4, 0), 3_000},   // +2 kWh
	}
	iv := Intervals(s, p)
	if len(iv) != 2 || !near(iv[0].Wh, 10000) || !near(iv[1].Wh, 2000) || !near(iv[0].Cost, 1.55) {
		t.Errorf("intervals = %+v", iv)
	}
}

func TestBucketsDaysWeeksMonthsAndDST(t *testing.T) {
	p := NewPlan([]Rate{{Price: 0.155, MonthlyFee: 10}}, chicago)
	now := at(2026, 11, 3, 12, 0) // Tuesday; DST ended Sun 1 Nov 2026 in Chicago
	var s []Sample
	wh := 0.0
	// 1 kWh per hour from 30 Oct 00:00 to now.
	for ts := at(2026, 10, 30, 0, 0); !ts.After(now); ts = ts.Add(time.Hour) {
		s = append(s, Sample{ts, wh})
		wh += 1000
	}
	iv := Intervals(s, p)
	days := p.Buckets(iv, Day, 5, now)
	if !days[0].Start.Equal(at(2026, 10, 30, 0, 0)) || !days[4].Start.Equal(at(2026, 11, 3, 0, 0)) {
		t.Fatalf("day starts = %v … %v", days[0].Start, days[4].Start)
	}
	// 1 Nov 2026 had 25 hours in Chicago.
	if !near(days[2].KWh, 25) || !near(days[3].KWh, 24) || !near(days[4].KWh, 12) {
		t.Errorf("kWh per day = %v %v %v", days[2].KWh, days[3].KWh, days[4].KWh)
	}
	// Each hour counts on the day its midpoint falls (23:00–00:00 stays on 30 Oct).
	if !near(days[0].KWh, 24) {
		t.Errorf("first day = %v", days[0].KWh)
	}
	weeks := p.Buckets(iv, Week, 2, now)
	if !weeks[1].Start.Equal(at(2026, 11, 2, 0, 0)) || weeks[1].Start.Weekday() != time.Monday {
		t.Errorf("week start = %v", weeks[1].Start)
	}
	months := p.Buckets(iv, Month, 3, now)
	if !months[0].Start.Equal(at(2026, 9, 1, 0, 0)) || months[0].KWh != 0 || months[0].Cost != 0 {
		t.Errorf("empty month = %+v (no fee without usage)", months[0])
	}
	if !near(months[1].Cost, months[1].KWh*0.155+10) || !near(months[2].Cost, months[2].KWh*0.155+10) {
		t.Errorf("monthly fee not added: %+v", months[1:])
	}
	tot := p.Total(iv, at(2026, 10, 1, 0, 0), now)
	if !near(tot.KWh, months[1].KWh+months[2].KWh) || !near(tot.Cost, months[1].Cost+months[2].Cost) {
		t.Errorf("total = %+v", tot)
	}
	if !p.Next(Month, at(2026, 12, 1, 0, 0)).Equal(at(2027, 1, 1, 0, 0)) {
		t.Error("month rollover")
	}
}

func TestSessions(t *testing.T) {
	p := NewPlan(nil, chicago)
	w := func(v float64) *float64 { return &v }
	ps := []PlugSample{
		{TS: at(2026, 11, 3, 17, 0), Wh: w(433_000)},                                        // unplugged (baseline)
		{TS: at(2026, 11, 3, 18, 0), Plugged: true, CurrentA: 47.9, Wh: w(433_000 + 9_000)}, // charging started between polls
		{TS: at(2026, 11, 3, 18, 5), Plugged: true, CurrentA: 48.1, Wh: w(433_000 + 10_000)},
		{TS: at(2026, 11, 3, 18, 10), Plugged: true, CurrentA: 0.1, Wh: w(433_000 + 10_000)},
		{TS: at(2026, 11, 3, 19, 0), Wh: w(433_000 + 10_000)},       // unplugged
		{TS: at(2026, 11, 3, 20, 0), Plugged: true, Wh: w(443_000)}, // plugged, no energy: skipped
		{TS: at(2026, 11, 3, 21, 0), Wh: w(443_000)},
		{TS: at(2026, 11, 3, 22, 0), Plugged: true, CurrentA: 32, Wh: w(445_000)}, // ongoing
	}
	got := Sessions(ps, p)
	if len(got) != 2 {
		t.Fatalf("sessions = %+v", got)
	}
	a := got[0]
	if !a.Start.Equal(at(2026, 11, 3, 18, 0)) || !a.End.Equal(at(2026, 11, 3, 19, 0)) || a.Ongoing ||
		!near(a.KWh, 10) || !near(a.Cost, 1.55) || a.PeakA != 48.1 {
		t.Errorf("first = %+v", a)
	}
	b := got[1]
	if !b.Ongoing || !near(b.KWh, 2) || b.PeakA != 32 {
		t.Errorf("ongoing = %+v", b)
	}
}
