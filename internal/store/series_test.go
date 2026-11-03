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
)

func TestSeriesLatestAndExport(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	d := addDevice(t, s)
	if _, err := s.LatestPoint(ctx, d.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("LatestPoint on empty = %v", err)
	}
	start := t0.Add(-40 * 24 * time.Hour)
	for at := start; at.Before(t0); at = at.Add(time.Hour) {
		if err := s.SaveSnapshot(ctx, d.ID, snapshotFrom(t, "charging", time.Minute, at), nil, 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Rollup(ctx, t0); err != nil {
		t.Fatal(err)
	}
	pt, err := s.LatestPoint(ctx, d.ID)
	if err != nil || !pt.Snapshot.FetchedAt.Equal(t0.Add(-time.Hour)) || pt.Snapshot.Vitals.VehicleCurrentA != 47.9 {
		t.Fatalf("latest = %+v, %v", pt, err)
	}
	raw, at, err := s.LatestRaw(ctx, d.ID)
	if err != nil || len(raw) != 1 || !at.Equal(t0.Add(-time.Hour)) {
		t.Errorf("latest raw = %v %v %v", raw, at, err)
	}

	day, err := s.Series(ctx, d.ID, "vehicle_current_a", t0.Add(-24*time.Hour), t0, 400)
	if err != nil || len(day) != 24 || day[0].Avg != 47.9 {
		t.Errorf("24h series = %d points %+v, %v", len(day), day[:min(len(day), 1)], err)
	}
	year, err := s.Series(ctx, d.ID, "handle_temp_c", t0.Add(-365*24*time.Hour), t0, 100)
	if err != nil || len(year) == 0 || len(year) > 101 {
		t.Errorf("1y series (rollups) = %d points, %v", len(year), err)
	}
	kwh, _ := s.Series(ctx, d.ID, "lifetime_energy_kwh", t0.Add(-24*time.Hour), t0, 50)
	if len(kwh) == 0 || kwh[0].Avg < 433 || kwh[0].Avg > 434 {
		t.Errorf("kWh scaling: %+v", kwh)
	}
	if _, err := s.Series(ctx, d.ID, "nope", t0, t0, 10); !errors.Is(err, ErrUnknownMetric) {
		t.Errorf("unknown metric = %v", err)
	}
	if _, ok := LookupMetric("grid_v"); !ok {
		t.Error("grid_v not chartable")
	}
	var rows int
	err = s.ExportVitals(ctx, d.ID, t0.Add(-48*time.Hour), t0, func(r ExportRow) error {
		rows++
		if !r.CurrentA.Valid || r.CurrentA.Float64 != 47.9 {
			t.Errorf("export row = %+v", r)
		}
		return nil
	})
	if err != nil || rows != 48 {
		t.Errorf("export rows = %d, %v", rows, err)
	}
}
