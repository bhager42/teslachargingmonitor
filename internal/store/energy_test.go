// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package store

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/energy"
)

func TestRatesAndEnergySamples(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	op := 0.08
	if _, err := s.AddRate(ctx, energy.Rate{EffectiveFrom: t0, Price: 0.2, OffPeakPrice: &op, OffPeakStart: 1380, OffPeakEnd: 360, MonthlyFee: 5}, t0); err != nil {
		t.Fatal(err)
	}
	id, _ := s.AddRate(ctx, energy.Rate{EffectiveFrom: t0.Add(-24 * time.Hour), Price: 0.155}, t0)
	if _, err := s.AddRate(ctx, energy.Rate{EffectiveFrom: t0, Price: 0.21}, t0); err != nil { // replaces same start
		t.Fatal(err)
	}
	for _, bad := range []energy.Rate{{Price: -1}, {Price: 100}, {Price: 0.1, MonthlyFee: -1}, {Price: 0.1, OffPeakStart: 1440}} {
		if _, err := s.AddRate(ctx, bad, t0); !errors.Is(err, ErrBadRate) {
			t.Errorf("bad rate %+v accepted", bad)
		}
	}
	rates, err := s.Rates(ctx)
	if err != nil || len(rates) != 2 || rates[0].Price != 0.155 || rates[1].Price != 0.21 || rates[1].OffPeakPrice != nil {
		t.Fatalf("rates = %+v, %v", rates, err)
	}
	if err := s.DeleteRate(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRate(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("double delete = %v", err)
	}

	d := addDevice(t, s)
	for i := range 4 {
		sc := "idle"
		if i == 2 {
			sc = "charging"
		}
		if err := s.SaveSnapshot(ctx, d.ID, snapshotFrom(t, sc, time.Hour, t0.Add(time.Duration(i)*time.Hour)), nil, 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	samples, err := s.EnergySamples(ctx, d.ID, t0.Add(90*time.Minute), t0.Add(10*time.Hour))
	if err != nil || len(samples) != 3 || !samples[0].TS.Equal(t0.Add(time.Hour)) {
		t.Errorf("energy samples (with the one before 'from') = %+v, %v", samples, err)
	}
	ps, err := s.PlugSamples(ctx, d.ID, t0.Add(90*time.Minute), t0.Add(10*time.Hour))
	if err != nil || len(ps) != 3 || ps[0].Plugged || !ps[1].Plugged || ps[1].CurrentA != 47.9 || ps[1].Wh == nil {
		t.Errorf("plug samples = %+v, %v", ps, err)
	}
}

// Pruning thins lifetime readings past the retention cutoff but never
// changes a cost: every day's and the whole history's kWh and cost are the
// same before and after, for several devices, time-of-use prices, a
// monthly fee, readings without an energy value and a counter reset.
func TestPruneKeepsCosts(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	garage := addDevice(t, s)
	d2 := NewDevice("Driveway", "192.168.1.18")
	d2.BreakerA = 40
	driveway, err := s.CreateDevice(ctx, d2, t0)
	if err != nil {
		t.Fatal(err)
	}
	op := 0.08
	if _, err := s.AddRate(ctx, energy.Rate{EffectiveFrom: time.Unix(0, 0), Price: 0.2, OffPeakPrice: &op,
		OffPeakStart: 23 * 60, OffPeakEnd: 6 * 60, MonthlyFee: 5}, t0); err != nil {
		t.Fatal(err)
	}
	insert := func(dev int64, at time.Time, wh *int64) {
		t.Helper()
		if _, err := s.db.ExecContext(ctx, "INSERT INTO readings_lifetime (device_id, ts, energy_wh) VALUES (?, ?, ?)",
			dev, ms(at), wh); err != nil {
			t.Fatal(err)
		}
	}
	whOf := func(v int64) *int64 { return &v }
	start := t0.Add(-60 * 24 * time.Hour)
	for i, dev := range []int64{garage.ID, driveway.ID} {
		wh := int64(1_000_000 * (i + 1))
		for day := range 60 {
			midnight := start.Add(time.Duration(day) * 24 * time.Hour)
			for h := range 24 {
				at := midnight.Add(time.Duration(h) * time.Hour)
				switch {
				case dev == garage.ID && day%3 == 0 && h == 22: // charge 22:00–01:00 at 5-minute polls
					for m := 0; m < 180; m += 5 {
						wh += 900
						insert(dev, at.Add(time.Duration(m)*time.Minute), whOf(wh))
					}
				case dev == garage.ID && day%3 == 0 && (h == 23 || h == 0):
					// covered by the charging polls above
				case dev == driveway.ID && day%4 == 1 && h >= 9 && h < 13: // hourly polls while charging
					wh += 7_000
					insert(dev, at, whOf(wh))
				case h == 5 && day%7 == 2:
					insert(dev, at, nil) // the device sent an invalid counter
				default:
					insert(dev, at, whOf(wh))
				}
			}
			if dev == driveway.ID && day == 30 {
				wh = 500 // counter reset (device replaced): a new baseline, not negative energy
			}
		}
	}

	plan := func() energy.Plan {
		rates, err := s.Rates(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return energy.NewPlan(rates, time.UTC)
	}()
	costs := func() (days []energy.Bucket, total energy.Bucket) {
		t.Helper()
		var all []energy.Interval
		for _, dev := range []int64{garage.ID, driveway.ID} {
			ss, err := s.EnergySamples(ctx, dev, time.Unix(0, 0), t0)
			if err != nil {
				t.Fatal(err)
			}
			all = append(all, energy.Intervals(ss, plan)...)
		}
		return plan.Buckets(all, energy.Day, 62, t0), plan.Total(all, time.Unix(0, 0), t0)
	}
	count := func(q string, args ...any) (n int64) {
		t.Helper()
		if err := s.db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	beforeDays, beforeTotal := costs()
	cutoff := t0.Add(-10 * 24 * time.Hour)
	oldBefore := count("SELECT COUNT(*) FROM readings_lifetime WHERE ts < ?", ms(cutoff))
	newBefore := count("SELECT COUNT(*) FROM readings_lifetime WHERE ts >= ?", ms(cutoff))
	if beforeTotal.KWh < 100 {
		t.Fatalf("test data delivers only %.1f kWh", beforeTotal.KWh)
	}

	r := DefaultRetention()
	r.ReadingsDays = 10
	res, err := s.Prune(ctx, t0, r)
	if err != nil {
		t.Fatal(err)
	}
	afterDays, afterTotal := costs()
	for i := range beforeDays {
		b, a := beforeDays[i], afterDays[i]
		if math.Abs(a.KWh-b.KWh) > 1e-9 || math.Abs(a.Cost-b.Cost) > 1e-9 {
			t.Errorf("%s: %.3f kWh %.4f before pruning, %.3f kWh %.4f after", b.Start.Format(time.DateOnly), b.KWh, b.Cost, a.KWh, a.Cost)
		}
	}
	if math.Abs(afterTotal.KWh-beforeTotal.KWh) > 1e-9 || math.Abs(afterTotal.Cost-beforeTotal.Cost) > 1e-9 {
		t.Errorf("total %+v before pruning, %+v after", beforeTotal, afterTotal)
	}
	oldAfter := count("SELECT COUNT(*) FROM readings_lifetime WHERE ts < ?", ms(cutoff))
	if res["readings_lifetime"] != oldBefore-oldAfter || oldAfter*4 > oldBefore {
		t.Errorf("pruned %d of %d old readings, %d left; want most of the idle ones gone", res["readings_lifetime"], oldBefore, oldAfter)
	}
	if n := count("SELECT COUNT(*) FROM readings_lifetime WHERE ts >= ?", ms(cutoff)); n != newBefore {
		t.Errorf("readings inside retention: %d before, %d after", newBefore, n)
	}
	if n := count("SELECT COUNT(*) FROM readings_lifetime WHERE ts < ? AND energy_wh IS NULL", ms(cutoff)); n != 0 {
		t.Errorf("%d old readings without energy survived", n)
	}
	// Pruning again finds nothing more to remove.
	if res, _ := s.Prune(ctx, t0, r); res["readings_lifetime"] != 0 {
		t.Errorf("second prune removed %d more", res["readings_lifetime"])
	}
	t.Logf("old lifetime readings: %d → %d; %.1f kWh, %.2f", oldBefore, oldAfter, afterTotal.KWh, afterTotal.Cost)
}
