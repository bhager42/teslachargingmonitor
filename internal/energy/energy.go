// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package energy turns the Wall Connector's lifetime energy counter into
// costs: per-poll energy deltas priced with the owner's rate history
// (optionally time-of-use), bucketed by day, week, month and year in local time,
// and grouped into charging sessions. It is pure (no I/O).
package energy

import (
	"slices"
	"sort"
	"time"
)

// DefaultPrice is used until the owner enters a rate (owner decision D18).
const DefaultPrice = 0.155

// Rate is an electricity price in effect from EffectiveFrom onwards.
type Rate struct {
	ID            int64
	EffectiveFrom time.Time
	Price         float64 // per kWh
	// Optional time-of-use: OffPeakPrice applies between OffPeakStart and
	// OffPeakEnd (minutes after local midnight; the window may span midnight).
	OffPeakPrice *float64
	OffPeakStart int
	OffPeakEnd   int
	MonthlyFee   float64 // fixed charge added to each month with usage
}

// HasOffPeak reports whether the rate has a time-of-use window.
func (r Rate) HasOffPeak() bool { return r.OffPeakPrice != nil && r.OffPeakStart != r.OffPeakEnd }

// Plan is the rate history and the time zone used for days and months.
type Plan struct {
	Rates []Rate
	Loc   *time.Location
}

// NewPlan sorts rates; with none it uses DefaultPrice for all time.
func NewPlan(rates []Rate, loc *time.Location) Plan {
	if loc == nil {
		loc = time.Local
	}
	rs := slices.Clone(rates)
	slices.SortFunc(rs, func(a, b Rate) int { return a.EffectiveFrom.Compare(b.EffectiveFrom) })
	if len(rs) == 0 {
		rs = []Rate{{Price: DefaultPrice}}
	}
	return Plan{Rates: rs, Loc: loc}
}

// RateAt returns the rate in effect at t (the earliest rate also covers
// any time before it, so old data is never free).
func (p Plan) RateAt(t time.Time) Rate {
	r := p.Rates[0]
	for _, x := range p.Rates[1:] {
		if !x.EffectiveFrom.After(t) {
			r = x
		}
	}
	return r
}

// offPeakOverlap returns how much of [a, b) falls inside r's off-peak window.
func (p Plan) offPeakOverlap(r Rate, a, b time.Time) time.Duration {
	var total time.Duration
	y, m, d := a.In(p.Loc).Date()
	for day := time.Date(y, m, d-1, 0, 0, 0, 0, p.Loc); day.Before(b); day = time.Date(day.Year(), day.Month(), day.Day()+1, 0, 0, 0, 0, p.Loc) {
		// Wall-clock times, not durations from midnight: days with a DST
		// change are 23 or 25 hours long.
		dy, dm, dd := day.Date()
		start := time.Date(dy, dm, dd, 0, r.OffPeakStart, 0, 0, p.Loc)
		endDay := dd
		if r.OffPeakEnd <= r.OffPeakStart {
			endDay++ // window spans midnight
		}
		end := time.Date(dy, dm, endDay, 0, r.OffPeakEnd, 0, 0, p.Loc)
		lo, hi := maxTime(a, start), minTime(b, end)
		if hi.After(lo) {
			total += hi.Sub(lo)
		}
	}
	return total
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Cost prices wh consumed evenly over [from, to] using the rate in effect at
// the end of the interval; time-of-use energy is split in proportion to time.
func (p Plan) Cost(from, to time.Time, wh float64) float64 {
	r := p.RateAt(to)
	kwh := wh / 1000
	if !r.HasOffPeak() {
		return kwh * r.Price
	}
	span := to.Sub(from)
	if span <= 0 {
		if p.offPeakOverlap(r, to, to.Add(time.Second)) > 0 {
			return kwh * *r.OffPeakPrice
		}
		return kwh * r.Price
	}
	f := float64(p.offPeakOverlap(r, from, to)) / float64(span)
	return kwh * (r.Price*(1-f) + *r.OffPeakPrice*f)
}

// Sample is one reading of the lifetime energy counter.
type Sample struct {
	TS time.Time
	Wh float64
}

// Interval is the energy delivered between two consecutive samples.
type Interval struct {
	From, To time.Time
	Wh, Cost float64
}

// Intervals converts counter samples (oldest first) into priced intervals.
// A counter that goes down (device reset or replaced) starts a new
// baseline instead of producing negative energy.
func Intervals(samples []Sample, p Plan) []Interval {
	var out []Interval
	for i := 1; i < len(samples); i++ {
		a, b := samples[i-1], samples[i]
		d := b.Wh - a.Wh
		if d <= 0 || !b.TS.After(a.TS) {
			continue
		}
		out = append(out, Interval{From: a.TS, To: b.TS, Wh: d, Cost: p.Cost(a.TS, b.TS, d)})
	}
	return out
}

// Mid is the interval's midpoint, used to assign it to a day or month.
func (x Interval) Mid() time.Time { return x.From.Add(x.To.Sub(x.From) / 2) }

// Bucket is a period's total.
type Bucket struct {
	Start time.Time
	KWh   float64
	Cost  float64
}

// Period identifies how buckets are aligned.
type Period int

// Periods.
const (
	Day Period = iota
	Week
	Month
	Year
)

// Start returns the local start of the period containing t (weeks start
// on Monday). Uses calendar arithmetic, so DST days are 23 or 25 hours.
func (p Plan) Start(per Period, t time.Time) time.Time {
	t = t.In(p.Loc)
	y, m, d := t.Date()
	switch per {
	case Week:
		wd := (int(t.Weekday()) + 6) % 7 // Monday = 0
		return time.Date(y, m, d-wd, 0, 0, 0, 0, p.Loc)
	case Month:
		return time.Date(y, m, 1, 0, 0, 0, 0, p.Loc)
	case Year:
		return time.Date(y, 1, 1, 0, 0, 0, 0, p.Loc)
	default:
		return time.Date(y, m, d, 0, 0, 0, 0, p.Loc)
	}
}

// Next returns the start of the following period.
func (p Plan) Next(per Period, start time.Time) time.Time {
	y, m, d := start.In(p.Loc).Date()
	switch per {
	case Week:
		return time.Date(y, m, d+7, 0, 0, 0, 0, p.Loc)
	case Month:
		return time.Date(y, m+1, 1, 0, 0, 0, 0, p.Loc)
	case Year:
		return time.Date(y+1, 1, 1, 0, 0, 0, 0, p.Loc)
	default:
		return time.Date(y, m, d+1, 0, 0, 0, 0, p.Loc)
	}
}

// Buckets totals intervals into n consecutive periods ending with the one
// containing now (empty periods included). An interval counts in the
// period containing its midpoint, so values are accurate to the polling
// interval. Monthly fees are added to month and year buckets for each
// month that has usage (day and week buckets are energy only).
func (p Plan) Buckets(iv []Interval, per Period, n int, now time.Time) []Bucket {
	starts := make([]time.Time, n)
	s := p.Start(per, now)
	for i := n - 1; i >= 0; i-- {
		starts[i] = s
		y, m, d := s.Date()
		switch per {
		case Week:
			s = time.Date(y, m, d-7, 0, 0, 0, 0, p.Loc)
		case Month:
			s = time.Date(y, m-1, 1, 0, 0, 0, 0, p.Loc)
		case Year:
			s = time.Date(y-1, 1, 1, 0, 0, 0, 0, p.Loc)
		default:
			s = time.Date(y, m, d-1, 0, 0, 0, 0, p.Loc)
		}
	}
	out := make([]Bucket, n)
	feeMonths := make([]map[time.Time]bool, n) // months with usage, per bucket
	for i := range out {
		out[i].Start = starts[i]
		feeMonths[i] = map[time.Time]bool{}
	}
	for _, x := range iv {
		mid := x.Mid()
		// Last period starting at or before the interval's midpoint.
		i := sort.Search(n, func(k int) bool { return starts[k].After(mid) }) - 1
		if i < 0 || !mid.Before(p.Next(per, starts[i])) {
			continue
		}
		out[i].KWh += x.Wh / 1000
		out[i].Cost += x.Cost
		feeMonths[i][p.Start(Month, mid)] = true
	}
	if per == Month || per == Year {
		for i := range out {
			for m := range feeMonths[i] {
				out[i].Cost += p.RateAt(m).MonthlyFee
			}
		}
	}
	return out
}

// Total sums intervals whose midpoint is in [from, to), adding monthly fees
// for each month in the range that has usage.
func (p Plan) Total(iv []Interval, from, to time.Time) Bucket {
	var b Bucket
	months := map[time.Time]bool{}
	for _, x := range iv {
		if mid := x.Mid(); !mid.Before(from) && mid.Before(to) {
			b.KWh += x.Wh / 1000
			b.Cost += x.Cost
			months[p.Start(Month, mid)] = true
		}
	}
	for m := range months {
		b.Cost += p.RateAt(m).MonthlyFee
	}
	b.Start = from
	return b
}

// PlugSample is one poll's plug state, current and lifetime counter.
type PlugSample struct {
	TS       time.Time
	Plugged  bool
	CurrentA float64
	Wh       *float64 // lifetime counter; nil if not valid
}

// Session is a charging session derived from polls.
type Session struct {
	Start, End time.Time
	Ongoing    bool
	KWh, Cost  float64
	PeakA      float64
}

// Sessions groups consecutive plugged-in polls into sessions. Energy is the
// counter difference from the last poll before the car was plugged in to
// the first poll after it was unplugged (or the latest poll while still
// plugged), so nothing delivered between polls is lost. Times are accurate
// to the polling interval. Plug-ins with no energy are skipped.
func Sessions(ps []PlugSample, p Plan) []Session {
	var out []Session
	var cur *Session
	var base *PlugSample
	var samples []Sample
	finish := func(end PlugSample, ongoing bool) {
		if end.Wh != nil {
			samples = append(samples, Sample{end.TS, *end.Wh})
		}
		cur.End, cur.Ongoing = end.TS, ongoing
		for _, iv := range Intervals(samples, p) {
			cur.KWh += iv.Wh / 1000
			cur.Cost += iv.Cost
		}
		if cur.KWh > 0 {
			out = append(out, *cur)
		}
		cur, samples = nil, nil
	}
	for i := range ps {
		s := ps[i]
		switch {
		case s.Plugged && cur == nil:
			cur = &Session{Start: s.TS, PeakA: s.CurrentA}
			samples = nil
			if base != nil && base.Wh != nil {
				samples = append(samples, Sample{base.TS, *base.Wh})
			}
			if s.Wh != nil {
				samples = append(samples, Sample{s.TS, *s.Wh})
			}
		case s.Plugged:
			cur.PeakA = max(cur.PeakA, s.CurrentA)
			if s.Wh != nil {
				samples = append(samples, Sample{s.TS, *s.Wh})
			}
		case cur != nil:
			finish(s, false)
		}
		if !s.Plugged {
			base = &ps[i]
		}
	}
	if cur != nil {
		last := ps[len(ps)-1]
		cur.End, cur.Ongoing = last.TS, true
		for _, iv := range Intervals(samples, p) {
			cur.KWh += iv.Wh / 1000
			cur.Cost += iv.Cost
		}
		if cur.KWh > 0 {
			out = append(out, *cur)
		}
	}
	return out
}
