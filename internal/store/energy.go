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
	"errors"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/energy"
)

// Rates returns the electricity price history, oldest first.
func (s *Store) Rates(ctx context.Context) ([]energy.Rate, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, effective_from, price_per_kwh, offpeak_price_per_kwh,
		offpeak_start_min, offpeak_end_min, monthly_fee FROM energy_rates ORDER BY effective_from, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []energy.Rate
	for rows.Next() {
		var r energy.Rate
		var from int64
		var off sql.NullFloat64
		if err := rows.Scan(&r.ID, &from, &r.Price, &off, &r.OffPeakStart, &r.OffPeakEnd, &r.MonthlyFee); err != nil {
			return nil, err
		}
		r.EffectiveFrom = fromMS(from)
		if off.Valid {
			r.OffPeakPrice = &off.Float64
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ErrBadRate is returned for rates outside the allowed ranges.
var ErrBadRate = errors.New("prices must be between 0 and 100 per kWh, the monthly fee between 0 and 100000, and off-peak times valid")

// AddRate stores a price that applies from r.EffectiveFrom onwards. A rate
// with the same start replaces the old one.
func (s *Store) AddRate(ctx context.Context, r energy.Rate, now time.Time) (int64, error) {
	if r.Price < 0 || r.Price >= 100 || r.MonthlyFee < 0 || r.MonthlyFee >= 100000 ||
		r.OffPeakStart < 0 || r.OffPeakStart > 1439 || r.OffPeakEnd < 0 || r.OffPeakEnd > 1439 ||
		(r.OffPeakPrice != nil && (*r.OffPeakPrice < 0 || *r.OffPeakPrice >= 100)) {
		return 0, ErrBadRate
	}
	var off any
	if r.OffPeakPrice != nil {
		off = *r.OffPeakPrice
	}
	var id int64
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM energy_rates WHERE effective_from = ?", ms(r.EffectiveFrom)); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO energy_rates (effective_from, price_per_kwh, offpeak_price_per_kwh,
			offpeak_start_min, offpeak_end_min, monthly_fee, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			ms(r.EffectiveFrom), r.Price, off, r.OffPeakStart, r.OffPeakEnd, r.MonthlyFee, ms(now))
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// DeleteRate removes one entry of the price history.
func (s *Store) DeleteRate(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM energy_rates WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// EnergySamples returns lifetime energy counter readings in [from, to),
// plus the last reading before from (so the first interval is complete).
func (s *Store) EnergySamples(ctx context.Context, deviceID int64, from, to time.Time) ([]energy.Sample, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, energy_wh FROM (
			SELECT ts, energy_wh FROM readings_lifetime WHERE device_id = ? AND ts < ? AND energy_wh IS NOT NULL
			ORDER BY ts DESC LIMIT 1)
		UNION ALL
		SELECT ts, energy_wh FROM readings_lifetime WHERE device_id = ? AND ts >= ? AND ts < ? AND energy_wh IS NOT NULL
		ORDER BY ts`, deviceID, ms(from), deviceID, ms(from), ms(to))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []energy.Sample
	for rows.Next() {
		var ts, wh int64
		if err := rows.Scan(&ts, &wh); err != nil {
			return nil, err
		}
		out = append(out, energy.Sample{TS: fromMS(ts), Wh: float64(wh)})
	}
	return out, rows.Err()
}

// PlugSamples returns per-poll plug state, current and lifetime energy in
// [from, to), plus the last poll before from.
func (s *Store) PlugSamples(ctx context.Context, deviceID int64, from, to time.Time) ([]energy.PlugSample, error) {
	const cols = `v.ts, v.vehicle_connected OR v.contactor_closed, COALESCE(v.vehicle_current_a, 0), l.energy_wh
		FROM readings_vitals v LEFT JOIN readings_lifetime l ON l.device_id = v.device_id AND l.ts = v.ts`
	rows, err := s.db.QueryContext(ctx, `SELECT * FROM (SELECT `+cols+` WHERE v.device_id = ? AND v.ts < ?
			ORDER BY v.ts DESC LIMIT 1)
		UNION ALL
		SELECT `+cols+` WHERE v.device_id = ? AND v.ts >= ? AND v.ts < ? ORDER BY 1`,
		deviceID, ms(from), deviceID, ms(from), ms(to))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []energy.PlugSample
	for rows.Next() {
		var ps energy.PlugSample
		var ts int64
		var wh sql.NullInt64
		if err := rows.Scan(&ts, &ps.Plugged, &ps.CurrentA, &wh); err != nil {
			return nil, err
		}
		ps.TS = fromMS(ts)
		if wh.Valid {
			v := float64(wh.Int64)
			ps.Wh = &v
		}
		out = append(out, ps)
	}
	return out, rows.Err()
}
