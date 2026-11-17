// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package energy

import (
	"sort"
	"time"
)

// SiteInterval is the Gateway's energy flows between two samples, in Wh.
type SiteInterval struct {
	From, To    time.Time
	SolarWh     float64 // produced
	HomeWh      float64 // used by the home, including the car
	ImportWh    float64 // from the grid
	ExportWh    float64 // to the grid
	ChargeWh    float64 // into the Powerwalls
	DischargeWh float64 // out of the Powerwalls
	// Set by Plan.SolarSavings: the solar energy counted as savings and
	// what it would have cost from the grid.
	SavedWh float64
	Savings float64
}

// Mid is the interval's midpoint, used to assign it to a period.
func (x SiteInterval) Mid() time.Time { return x.From.Add(x.To.Sub(x.From) / 2) }

// SiteIntervals converts Gateway samples (oldest first) into energy per
// interval. Unlike SupplyIntervals, long gaps are kept: lifetime counters
// make totals exact at any polling cadence. An interval in which any
// counter went down (a reset) is skipped.
func SiteIntervals(samples []SiteSample) []SiteInterval {
	var out []SiteInterval
	for i := 1; i < len(samples); i++ {
		a, b := samples[i-1], samples[i]
		if !b.TS.After(a.TS) {
			continue
		}
		x := SiteInterval{From: a.TS, To: b.TS, SolarWh: b.SolarWh - a.SolarWh, HomeWh: b.LoadWh - a.LoadWh,
			ImportWh: b.GridImportWh - a.GridImportWh, ExportWh: b.GridExportWh - a.GridExportWh,
			ChargeWh: b.BatteryChargeWh - a.BatteryChargeWh, DischargeWh: b.BatteryDischargeWh - a.BatteryDischargeWh}
		if x.SolarWh < 0 || x.HomeWh < 0 || x.ImportWh < 0 || x.ExportWh < 0 || x.ChargeWh < 0 || x.DischargeWh < 0 {
			continue
		}
		out = append(out, x)
	}
	return out
}

// SiteBucket is a period's energy flows in kWh.
type SiteBucket struct {
	Start                                   time.Time
	SolarKWh, HomeKWh, ImportKWh, ExportKWh float64
	ChargeKWh, DischargeKWh                 float64
	SavedKWh, Savings                       float64 // see Plan.SolarSavings
}

func (b *SiteBucket) add(x SiteInterval) {
	b.SolarKWh += x.SolarWh / 1000
	b.HomeKWh += x.HomeWh / 1000
	b.ImportKWh += x.ImportWh / 1000
	b.ExportKWh += x.ExportWh / 1000
	b.ChargeKWh += x.ChargeWh / 1000
	b.DischargeKWh += x.DischargeWh / 1000
	b.SavedKWh += x.SavedWh / 1000
	b.Savings += x.Savings
}

// SelfConsumption is the share of solar used on site (by the home or the
// Powerwalls) rather than exported; ok is false without production.
func (b SiteBucket) SelfConsumption() (share float64, ok bool) {
	if b.SolarKWh <= 0 {
		return 0, false
	}
	return max(0, min(1, (b.SolarKWh-b.ExportKWh)/b.SolarKWh)), true
}

// SelfSufficiency is the share of the home's use not imported from the
// grid; ok is false without use.
func (b SiteBucket) SelfSufficiency() (share float64, ok bool) {
	if b.HomeKWh <= 0 {
		return 0, false
	}
	return max(0, min(1, 1-b.ImportKWh/b.HomeKWh)), true
}

// SiteBuckets totals intervals into n consecutive periods ending with the
// one containing now (empty periods included), by interval midpoint, like
// Buckets.
func (p Plan) SiteBuckets(iv []SiteInterval, per Period, n int, now time.Time) []SiteBucket {
	starts := make([]time.Time, n)
	s := p.Start(per, now)
	for i := n - 1; i >= 0; i-- {
		starts[i] = s
		s = p.Start(per, s.Add(-time.Hour))
	}
	out := make([]SiteBucket, n)
	for i := range out {
		out[i].Start = starts[i]
	}
	for _, x := range iv {
		mid := x.Mid()
		i := sort.Search(n, func(k int) bool { return starts[k].After(mid) }) - 1
		if i < 0 || !mid.Before(p.Next(per, starts[i])) {
			continue
		}
		out[i].add(x)
	}
	return out
}

// SiteTotal sums intervals whose midpoint is in [from, to).
func SiteTotal(iv []SiteInterval, from, to time.Time) SiteBucket {
	b := SiteBucket{Start: from}
	for _, x := range iv {
		if mid := x.Mid(); !mid.Before(from) && mid.Before(to) {
			b.add(x)
		}
	}
	return b
}
