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

// Solar attribution (Phase 9, docs/DEVELOPMENT_PLAN.md "Solar-aware
// charging"): where the energy for each charging interval came from,
// estimated from a Tesla Backup Gateway's lifetime counters. Within one
// interval the car is assumed to get the same mix as the rest of the
// home, so results are approximate and labeled so.

// MaxSupplyGap is the longest Gateway interval used for attribution. A
// longer one (the Gateway was unreachable) only gives a day-long average,
// which says little about when the car charged, so it is left out.
const MaxSupplyGap = 2 * time.Hour

// minCoverage is the share of a charging interval that Gateway intervals
// must cover for it to be attributed.
const minCoverage = 0.5

// SiteSample is one reading of the Gateway's lifetime counters, in Wh.
type SiteSample struct {
	TS                 time.Time
	SolarWh            float64 // solar produced (solar meter, exported)
	LoadWh             float64 // used by the home (load meter, imported)
	GridImportWh       float64 // site meter, imported
	GridExportWh       float64 // site meter, exported
	BatteryChargeWh    float64 // battery meter, imported
	BatteryDischargeWh float64 // battery meter, exported
}

// Supply is how much energy (Wh) from each source went to the home,
// including the car.
type Supply struct{ Solar, Battery, Grid float64 }

// Total is the energy that supplied the home.
func (s Supply) Total() float64 { return s.Solar + s.Battery + s.Grid }

func (s Supply) scale(f float64) Supply { return Supply{s.Solar * f, s.Battery * f, s.Grid * f} }

func (s Supply) add(o Supply) Supply {
	return Supply{s.Solar + o.Solar, s.Battery + o.Battery, s.Grid + o.Grid}
}

// SupplyInterval is the home's supply between two Gateway samples.
type SupplyInterval struct {
	From, To time.Time
	Supply
}

// HomeSupply splits one interval's counter deltas into what supplied the
// home. Energy leaving the home's circuits (grid export, battery charging)
// is assigned to a source first: exports come from solar, then from the
// Powerwall; battery charging comes from solar, then from the grid. What
// is left of each source supplied the home. Every result is ≥ 0.
func HomeSupply(solar, gridImport, gridExport, charge, discharge float64) Supply {
	return splitFlows(solar, gridImport, gridExport, charge, discharge).home
}

// flows is one interval's counter deltas assigned to sources, by the rules
// HomeSupply describes.
type flows struct {
	home            Supply  // what supplied the home
	chargeFromSolar float64 // into the Powerwalls from solar
	chargeOther     float64 // into the Powerwalls from the grid (or unexplained)
}

func splitFlows(solar, gridImport, gridExport, charge, discharge float64) flows {
	solar, gridImport, gridExport = max(solar, 0), max(gridImport, 0), max(gridExport, 0)
	charge, discharge = max(charge, 0), max(discharge, 0)
	exportFromSolar := min(gridExport, solar)
	exportFromBattery := min(gridExport-exportFromSolar, discharge)
	chargeFromSolar := min(charge, solar-exportFromSolar)
	chargeFromGrid := min(charge-chargeFromSolar, gridImport)
	return flows{
		home: Supply{
			Solar:   solar - exportFromSolar - chargeFromSolar,
			Battery: discharge - exportFromBattery,
			Grid:    gridImport - chargeFromGrid,
		},
		chargeFromSolar: chargeFromSolar,
		chargeOther:     charge - chargeFromSolar,
	}
}

// SupplyIntervals converts Gateway samples (oldest first) into the home's
// supply per interval. An interval in which any counter went down (a
// Gateway or meter reset) starts a new baseline, and intervals longer
// than MaxSupplyGap are dropped.
func SupplyIntervals(samples []SiteSample) []SupplyInterval {
	var out []SupplyInterval
	for i := 1; i < len(samples); i++ {
		a, b := samples[i-1], samples[i]
		if !b.TS.After(a.TS) || b.TS.Sub(a.TS) > MaxSupplyGap {
			continue
		}
		d := [5]float64{b.SolarWh - a.SolarWh, b.GridImportWh - a.GridImportWh, b.GridExportWh - a.GridExportWh,
			b.BatteryChargeWh - a.BatteryChargeWh, b.BatteryDischargeWh - a.BatteryDischargeWh}
		reset := false
		for _, x := range d {
			reset = reset || x < 0
		}
		if reset {
			continue
		}
		out = append(out, SupplyInterval{From: a.TS, To: b.TS, Supply: HomeSupply(d[0], d[1], d[2], d[3], d[4])})
	}
	return out
}

// mixOver returns the supply in [from, to), taking from each Gateway
// interval the share that overlaps (energy assumed even within it), and
// the fraction of [from, to) the Gateway intervals cover. sup must be
// sorted by From and not overlap.
func mixOver(sup []SupplyInterval, from, to time.Time) (Supply, float64) {
	span := to.Sub(from)
	if span <= 0 {
		return Supply{}, 0
	}
	// First interval that ends after from.
	i := sort.Search(len(sup), func(k int) bool { return sup[k].To.After(from) })
	var mix Supply
	var covered time.Duration
	for ; i < len(sup) && sup[i].From.Before(to); i++ {
		x := sup[i]
		lo, hi := maxTime(from, x.From), minTime(to, x.To)
		if !hi.After(lo) {
			continue
		}
		covered += hi.Sub(lo)
		mix = mix.add(x.scale(float64(hi.Sub(lo)) / float64(x.To.Sub(x.From))))
	}
	return mix, float64(covered) / float64(span)
}

// Attribute splits each charging interval into solar, Powerwall and grid
// energy in proportion to the home's supply over the same time, and adds
// the solar savings: the solar share of the interval's cost. Intervals the
// Gateway did not cover (no Gateway, or it was unreachable) are left
// unattributed. sup must be sorted by From (as SupplyIntervals returns it).
func Attribute(iv []Interval, sup []SupplyInterval) []Interval {
	out := make([]Interval, len(iv))
	copy(out, iv)
	if len(sup) == 0 {
		return out
	}
	for k := range out {
		x := &out[k]
		mix, cov := mixOver(sup, x.From, x.To)
		t := mix.Total()
		if cov < minCoverage || t <= 0 {
			continue
		}
		x.Attributed = true
		x.SolarWh = x.Wh * mix.Solar / t
		x.BatteryWh = x.Wh * mix.Battery / t
		x.GridWh = x.Wh * mix.Grid / t
		x.Savings = x.Cost * mix.Solar / t
	}
	return out
}
