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
	"database/sql"
	"time"
)

// WeekHealth summarizes a device's polls and readings over a period, for
// the weekly digest. Nil maxima mean no valid reading in the period.
type WeekHealth struct {
	PollsOK, PollFailures int
	Readings              int
	MaxHandleC, MaxPCBAC  *float64
	MaxMCUC               *float64
	MinGridV, MaxGridV    *float64
	Events                map[string]int // device events by kind (reboot, firmware change, ...)
}

func nullPtr(n sql.NullFloat64) *float64 {
	if !n.Valid {
		return nil
	}
	return &n.Float64
}

// Health returns WeekHealth for a device in [from, to).
func (s *Store) Health(ctx context.Context, deviceID int64, from, to time.Time) (WeekHealth, error) {
	var h WeekHealth
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(ok), 0), COALESCE(SUM(1 - ok), 0)
		FROM poll_log WHERE device_id = ? AND ts >= ? AND ts < ?`, deviceID, ms(from), ms(to)).
		Scan(&h.PollsOK, &h.PollFailures); err != nil {
		return h, err
	}
	var hc, pc, mc, gmin, gmax sql.NullFloat64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), MAX(handle_temp_c), MAX(pcba_temp_c), MAX(mcu_temp_c),
		MIN(grid_v), MAX(grid_v) FROM readings_vitals WHERE device_id = ? AND ts >= ? AND ts < ?`,
		deviceID, ms(from), ms(to)).Scan(&h.Readings, &hc, &pc, &mc, &gmin, &gmax); err != nil {
		return h, err
	}
	h.MaxHandleC, h.MaxPCBAC, h.MaxMCUC, h.MinGridV, h.MaxGridV = nullPtr(hc), nullPtr(pc), nullPtr(mc), nullPtr(gmin), nullPtr(gmax)
	rows, err := s.db.QueryContext(ctx, `SELECT kind, COUNT(*) FROM device_events WHERE device_id = ? AND ts >= ? AND ts < ?
		GROUP BY kind`, deviceID, ms(from), ms(to))
	if err != nil {
		return h, err
	}
	defer func() { _ = rows.Close() }()
	h.Events = map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return h, err
		}
		h.Events[k] = n
	}
	return h, rows.Err()
}
