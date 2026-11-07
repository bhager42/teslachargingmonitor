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
	"fmt"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/i18n"
)

// LatestPoint returns the most recent stored poll for a device, or
// ErrNotFound when it has never been polled successfully.
func (s *Store) LatestPoint(ctx context.Context, deviceID int64) (*HistoryPoint, error) {
	var ts sql.NullInt64
	if err := s.db.QueryRowContext(ctx, "SELECT MAX(ts) FROM readings_vitals WHERE device_id = ?", deviceID).Scan(&ts); err != nil {
		return nil, err
	}
	if !ts.Valid {
		return nil, ErrNotFound
	}
	at := fromMS(ts.Int64)
	pts, err := s.History(ctx, deviceID, at, at.Add(time.Millisecond))
	if err != nil {
		return nil, err
	}
	if len(pts) == 0 {
		return nil, ErrNotFound
	}
	return &pts[0], nil
}

// LatestRaw returns the most recent raw payload per endpoint.
func (s *Store) LatestRaw(ctx context.Context, deviceID int64) (map[string][]byte, time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT endpoint, body, ts FROM raw_payloads WHERE device_id = ? AND ts =
		(SELECT MAX(ts) FROM raw_payloads WHERE device_id = ?)`, deviceID, deviceID)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]byte{}
	var ts int64
	for rows.Next() {
		var ep string
		var body []byte
		if err := rows.Scan(&ep, &body, &ts); err != nil {
			return nil, time.Time{}, err
		}
		out[ep] = body
	}
	return out, fromMS(ts), rows.Err()
}

// tr is the catalog for user-facing text: chart labels and validation errors.
var tr = i18n.English()

// SeriesMetric describes a chartable metric.
type SeriesMetric struct {
	Key    string
	Label  string
	Unit   string // "C" for temperatures (converted for display), otherwise literal
	table  string
	column string
	scale  float64
}

// SeriesMetrics are the metrics the UI can chart.
var SeriesMetrics = []SeriesMetric{
	{"vehicle_current_a", tr.T("metric.vehicle_current_a"), "A", "readings_vitals", "vehicle_current_a", 1},
	{"handle_temp_c", tr.T("metric.handle_temp_c"), "C", "readings_vitals", "handle_temp_c", 1},
	{"pcba_temp_c", tr.T("metric.pcba_temp_c"), "C", "readings_vitals", "pcba_temp_c", 1},
	{"mcu_temp_c", tr.T("metric.mcu_temp_c"), "C", "readings_vitals", "mcu_temp_c", 1},
	{"grid_v", tr.T("metric.grid_v"), "V", "readings_vitals", "grid_v", 1},
	{"grid_hz", tr.T("metric.grid_hz"), "Hz", "readings_vitals", "grid_hz", 1},
	{"relay_k1_v", tr.T("metric.relay_k1_v"), "V", "readings_vitals", "relay_k1_v", 1},
	{"relay_k2_v", tr.T("metric.relay_k2_v"), "V", "readings_vitals", "relay_k2_v", 1},
	{"session_energy_kwh", tr.T("metric.session_energy_kwh"), "kWh", "readings_vitals", "session_energy_wh", 0.001},
	{"wifi_rssi", tr.T("metric.wifi_rssi"), "dBm", "readings_wifi", "rssi", 1},
	{"lifetime_energy_kwh", tr.T("metric.lifetime_energy_kwh"), "kWh", "readings_lifetime", "energy_wh", 0.001},
}

// LookupMetric finds a metric by key.
func LookupMetric(key string) (SeriesMetric, bool) {
	for _, m := range SeriesMetrics {
		if m.Key == key {
			return m, true
		}
	}
	return SeriesMetric{}, false
}

// SeriesPoint is one (possibly aggregated) chart point.
type SeriesPoint struct {
	TS  time.Time `json:"t"`
	Min float64   `json:"min"`
	Avg float64   `json:"avg"`
	Max float64   `json:"max"`
}

// rawSeriesWindow is how far back raw readings are used; older ranges use
// the hourly rollups when the metric has them.
const rawSeriesWindow = 35 * 24 * time.Hour

// ErrUnknownMetric is returned for metrics not in SeriesMetrics.
var ErrUnknownMetric = errors.New("store: unknown metric")

// Series returns at most ~maxPoints aggregated points for a metric in
// [from, to). NULL (decoder-flagged) values are ignored.
func (s *Store) Series(ctx context.Context, deviceID int64, metric string, from, to time.Time, maxPoints int) ([]SeriesPoint, error) {
	m, ok := LookupMetric(metric)
	if !ok {
		return nil, ErrUnknownMetric
	}
	if maxPoints < 10 {
		maxPoints = 10
	}
	bucket := max(to.Sub(from).Milliseconds()/int64(maxPoints), 1)
	useRollups := to.Sub(from) > rawSeriesWindow && m.table == "readings_vitals"
	var q string
	var args []any
	if useRollups {
		bucket = max(bucket, hourMS)
		q = `SELECT (bucket_ts / ?) * ?, MIN(min), SUM(avg * count) / SUM(count), MAX(max) FROM rollups_1h
			WHERE device_id = ? AND metric = ? AND bucket_ts >= ? AND bucket_ts < ? GROUP BY bucket_ts / ? ORDER BY 1`
		args = []any{bucket, bucket, deviceID, m.column, ms(from), ms(to), bucket}
	} else {
		// table and column come from the SeriesMetrics constant list.
		q = fmt.Sprintf(`SELECT (ts / ?) * ?, MIN(%[2]s), AVG(%[2]s), MAX(%[2]s) FROM %[1]s
			WHERE device_id = ? AND ts >= ? AND ts < ? AND %[2]s IS NOT NULL GROUP BY ts / ? ORDER BY 1`, m.table, m.column)
		args = []any{bucket, bucket, deviceID, ms(from), ms(to), bucket}
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SeriesPoint
	for rows.Next() {
		var ts int64
		var p SeriesPoint
		if err := rows.Scan(&ts, &p.Min, &p.Avg, &p.Max); err != nil {
			return nil, err
		}
		p.TS = fromMS(ts)
		p.Min, p.Avg, p.Max = p.Min*m.scale, p.Avg*m.scale, p.Max*m.scale
		out = append(out, p)
	}
	return out, rows.Err()
}

// ExportRow is one CSV export line.
type ExportRow struct {
	TS                                                       time.Time
	VehicleConnected, ContactorClosed                        bool
	CurrentA, GridV, GridHz, HandleC, PCBAC, MCUC, SessionWh sql.NullFloat64
	EVSEState                                                sql.NullInt64
}

// ExportVitals streams readings in [from, to) to fn, oldest first.
func (s *Store) ExportVitals(ctx context.Context, deviceID int64, from, to time.Time, fn func(ExportRow) error) error {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, vehicle_connected, contactor_closed, vehicle_current_a, grid_v, grid_hz,
		handle_temp_c, pcba_temp_c, mcu_temp_c, session_energy_wh, evse_state FROM readings_vitals
		WHERE device_id = ? AND ts >= ? AND ts < ? ORDER BY ts`, deviceID, ms(from), ms(to))
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r ExportRow
		var ts int64
		if err := rows.Scan(&ts, &r.VehicleConnected, &r.ContactorClosed, &r.CurrentA, &r.GridV, &r.GridHz, &r.HandleC,
			&r.PCBAC, &r.MCUC, &r.SessionWh, &r.EVSEState); err != nil {
			return err
		}
		r.TS = fromMS(ts)
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}
