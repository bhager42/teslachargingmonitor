// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package energy

import (
	"encoding/binary"
	"math"
	"testing"
	"time"
)

func finiteNonNeg(v float64) bool { return v >= 0 && !math.IsNaN(v) && !math.IsInf(v, 0) }

// FuzzCosts turns arbitrary bytes into a poll history (counter readings
// that may jump, stall, go backwards or be missing) and checks that every
// interval, session and total is finite and non-negative for any price the
// settings form accepts, including time-of-use windows across DST changes.
func FuzzCosts(f *testing.F) {
	f.Add([]byte{0, 60, 0, 100, 3, 40, 0, 60, 0, 200, 3, 48, 0, 60, 0, 0, 0, 0}, 0.155, 0.08, 1320, 420, 10.0)
	f.Add([]byte{255, 255, 128, 0, 1, 0, 0, 1, 127, 255, 3, 255}, 0.0, 0.0, 0, 0, 0.0)
	f.Add([]byte{}, 99.0, 99.0, 1439, 0, 100000.0)
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		loc = time.UTC
	}
	f.Fuzz(func(t *testing.T, data []byte, price, offPrice float64, offStart, offEnd int, fee float64) {
		// Same bounds as the electricity price form (store.ErrBadRate).
		if !(price >= 0 && price < 100 && offPrice >= 0 && offPrice < 100 && fee >= 0 && fee <= 100000 &&
			offStart >= 0 && offStart <= 1439 && offEnd >= 0 && offEnd <= 1439) {
			return
		}
		plan := NewPlan([]Rate{{Price: price, OffPeakPrice: &offPrice, OffPeakStart: offStart, OffPeakEnd: offEnd,
			MonthlyFee: fee, EffectiveFrom: time.Date(2026, 3, 1, 0, 0, 0, 0, loc)}}, loc)

		// 6 bytes per poll: minutes since the last poll (uint16), counter
		// change in Wh (int16), flags (plugged, counter valid), current (A).
		ts := time.Date(2026, 3, 7, 12, 0, 0, 0, loc) // the weekend before a DST change
		wh := 433293.0
		var polls []PlugSample
		var samples []Sample
		for len(data) >= 6 {
			ts = ts.Add(time.Duration(binary.BigEndian.Uint16(data[0:2])) * time.Minute)
			wh += float64(int16(binary.BigEndian.Uint16(data[2:4]))) //nolint:gosec // deliberate wrap-around: a signed counter change
			ps := PlugSample{TS: ts, Plugged: data[4]&1 != 0, CurrentA: float64(data[5])}
			if data[4]&2 != 0 {
				v := wh
				ps.Wh = &v
				samples = append(samples, Sample{TS: ts, Wh: wh})
			}
			polls = append(polls, ps)
			data = data[6:]
		}

		maxPrice := max(price, offPrice)
		ivs := Intervals(samples, plan)
		for _, iv := range ivs {
			if iv.Wh <= 0 || !iv.To.After(iv.From) || !finiteNonNeg(iv.Cost) || iv.Cost > iv.Wh/1000*maxPrice*(1+1e-9)+1e-9 {
				t.Fatalf("bad interval %+v (price %v / %v)", iv, price, offPrice)
			}
		}
		for _, s := range Sessions(polls, plan) {
			if !(s.KWh > 0) || !finiteNonNeg(s.Cost) || s.End.Before(s.Start) || s.PeakA < 0 {
				t.Fatalf("bad session %+v", s)
			}
		}
		if len(samples) > 0 {
			from, to := samples[0].TS, samples[len(samples)-1].TS.Add(time.Hour)
			if b := plan.Total(ivs, from, to); !finiteNonNeg(b.KWh) || !finiteNonNeg(b.Cost) {
				t.Fatalf("bad total %+v", b)
			}
			for _, per := range []Period{Day, Week, Month} {
				for _, b := range plan.Buckets(ivs, per, 3, to) {
					if !finiteNonNeg(b.KWh) || !finiteNonNeg(b.Cost) {
						t.Fatalf("bad bucket %+v", b)
					}
				}
			}
		}
	})
}
