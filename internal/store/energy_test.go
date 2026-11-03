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
