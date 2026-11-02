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
	"os"
	"time"
)

// RollupMetrics are the vitals columns aggregated into rollups_1h. NULL
// values (fields the decoder flagged invalid) are ignored by the aggregates.
var RollupMetrics = []string{
	"grid_v", "grid_hz", "vehicle_current_a", "handle_temp_c", "pcba_temp_c", "mcu_temp_c",
	"relay_k1_v", "relay_k2_v",
}

const (
	rollupWatermarkKey = "rollup_watermark_ms"
	hourMS             = int64(time.Hour / time.Millisecond)
	pruneBatch         = 5000
)

// Rollup aggregates every complete hour of vitals before now into
// rollups_1h and returns the number of rows written. It is idempotent.
func (s *Store) Rollup(ctx context.Context, now time.Time) (int64, error) {
	var from int64
	if err := s.GetSetting(ctx, rollupWatermarkKey, &from); err != nil && !errors.Is(err, ErrNotFound) {
		return 0, err
	}
	until := ms(now) / hourMS * hourMS // start of the current (incomplete) hour
	if until <= from {
		return 0, nil
	}
	var total int64
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		for _, m := range RollupMetrics {
			// m comes from the constant list above, never from input.
			//nolint:gosec // G202: column name from RollupMetrics constant
			q := `INSERT OR REPLACE INTO rollups_1h (device_id, bucket_ts, metric, min, max, avg, count)
				SELECT device_id, (ts / ?) * ?, ?, MIN(` + m + `), MAX(` + m + `), AVG(` + m + `), COUNT(` + m + `)
				FROM readings_vitals WHERE ts >= ? AND ts < ? AND ` + m + ` IS NOT NULL
				GROUP BY device_id, ts / ?`
			res, err := tx.ExecContext(ctx, q, hourMS, hourMS, m, from, until, hourMS)
			if err != nil {
				return fmt.Errorf("store: rolling up %s: %w", m, err)
			}
			n, _ := res.RowsAffected()
			total += n
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value_json, updated_at) VALUES (?, ?, ?)
			ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
			rollupWatermarkKey, fmt.Sprint(until), ms(now))
		return err
	})
	return total, err
}

// PruneResult reports how many rows Prune deleted per table.
type PruneResult map[string]int64

// Prune deletes data older than the retention policy, in small batches so
// pollers are never blocked for long. Raw vitals are never deleted before
// they have been rolled up.
func (s *Store) Prune(ctx context.Context, now time.Time, r Retention) (PruneResult, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var watermark int64
	if err := s.GetSetting(ctx, rollupWatermarkKey, &watermark); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	cutoff := func(days int) int64 { return ms(now.Add(-time.Duration(days) * 24 * time.Hour)) }

	res := PruneResult{}
	targets := []struct {
		table string
		col   string
		days  int
	}{
		{"readings_vitals", "ts", r.ReadingsDays},
		{"readings_lifetime", "ts", r.ReadingsDays},
		{"readings_wifi", "ts", r.ReadingsDays},
		{"raw_payloads", "ts", r.RawPayloadsDays},
		{"rollups_1h", "bucket_ts", r.RollupsDays},
		{"device_events", "ts", r.EventsDays},
		{"alert_events", "ts", r.EventsDays},
		{"poll_log", "ts", r.PollLogDays},
		{"notify_deliveries", "created_at", r.PollLogDays},
	}
	for _, t := range targets {
		if t.days == KeepForever {
			continue
		}
		c := cutoff(t.days)
		if t.table == "readings_vitals" && c > watermark {
			c = watermark // keep un-rolled data until it has been aggregated
		}
		n, err := s.deleteOlder(ctx, t.table, t.col, c)
		res[t.table] = n
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

func (s *Store) deleteOlder(ctx context.Context, table, col string, cutoff int64) (int64, error) {
	// table and col come from the constant list in Prune, never from input.
	q := `DELETE FROM ` + table + ` WHERE rowid IN (SELECT rowid FROM ` + table + ` WHERE ` + col + ` < ? LIMIT ?)` //nolint:gosec // G202: constants
	if table == "notify_deliveries" {                                                                               // never drop messages still waiting to be sent
		q = `DELETE FROM notify_deliveries WHERE id IN
			(SELECT id FROM notify_deliveries WHERE created_at < ? AND status != 'pending' LIMIT ?)`
	}
	if table == "rollups_1h" { // WITHOUT ROWID: delete by primary key
		q = `DELETE FROM rollups_1h WHERE (device_id, bucket_ts, metric) IN
			(SELECT device_id, bucket_ts, metric FROM rollups_1h WHERE bucket_ts < ? LIMIT ?)`
	}
	var total int64
	for {
		r, err := s.db.ExecContext(ctx, q, cutoff, pruneBatch)
		if err != nil {
			return total, fmt.Errorf("store: pruning %s: %w", table, err)
		}
		n, _ := r.RowsAffected()
		total += n
		if n < pruneBatch {
			return total, nil
		}
		if err := ctx.Err(); err != nil {
			return total, err
		}
	}
}

// MaintenanceResult summarizes one maintenance run.
type MaintenanceResult struct {
	RolledUp int64
	Pruned   PruneResult
}

// Maintain runs rollups, retention pruning and SQLite housekeeping.
func (s *Store) Maintain(ctx context.Context, now time.Time) (MaintenanceResult, error) {
	var out MaintenanceResult
	var err error
	if out.RolledUp, err = s.Rollup(ctx, now); err != nil {
		return out, err
	}
	r, err := s.Retention(ctx)
	if err != nil {
		return out, err
	}
	if out.Pruned, err = s.Prune(ctx, now, r); err != nil {
		return out, err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM alert_snoozes WHERE until_ts < ?", ms(now)); err != nil {
		return out, fmt.Errorf("store: removing expired snoozes: %w", err)
	}
	for _, q := range []string{"PRAGMA incremental_vacuum", "PRAGMA optimize", "PRAGMA wal_checkpoint(TRUNCATE)"} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			return out, fmt.Errorf("store: %s: %w", q, err)
		}
	}
	return out, nil
}

// Backup writes a consistent copy of the database to dest (which must not
// exist) with mode 0600.
func (s *Store) Backup(ctx context.Context, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("store: backup destination %s already exists", dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", dest); err != nil {
		return fmt.Errorf("store: backup: %w", err)
	}
	return os.Chmod(dest, 0o600)
}

// Stats describes the database for the diagnostics page.
type Stats struct {
	SizeBytes     int64
	Rows          map[string]int64
	OldestReading time.Time // zero if no readings
}

// StatsTables are the tables counted by Stats.
var StatsTables = []string{
	"devices", "readings_vitals", "readings_lifetime", "readings_wifi", "raw_payloads",
	"rollups_1h", "device_events", "poll_log", "alert_events", "notify_channels", "notify_deliveries",
}

// Stats returns database size and row counts.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	st := Stats{Rows: map[string]int64{}}
	var pages, size int64
	if err := s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
		return st, err
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size); err != nil {
		return st, err
	}
	st.SizeBytes = pages * size
	for _, t := range StatsTables {
		var n int64
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+t).Scan(&n); err != nil {
			return st, err
		}
		st.Rows[t] = n
	}
	var oldest sql.NullInt64
	if err := s.db.QueryRowContext(ctx, "SELECT MIN(ts) FROM readings_vitals").Scan(&oldest); err != nil {
		return st, err
	}
	if oldest.Valid {
		st.OldestReading = fromMS(oldest.Int64)
	}
	return st, nil
}
