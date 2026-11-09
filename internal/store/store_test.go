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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
	"github.com/bhager42/teslachargingmonitor/internal/wcsim"
)

var t0 = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "data", "tcmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func addDevice(t *testing.T, s *Store) Device {
	t.Helper()
	d := NewDevice("Garage", "192.168.1.17")
	d.BreakerA = 60
	d, err := s.CreateDevice(context.Background(), d, t0)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// snapshotFrom builds a Snapshot from a simulator scenario state.
func snapshotFrom(t *testing.T, scenario string, e time.Duration, at time.Time) *wallconnector.Snapshot {
	t.Helper()
	sc, ok := wcsim.Lookup(scenario)
	if !ok {
		t.Fatalf("no scenario %s", scenario)
	}
	st, _ := sc.State(e)
	return &wallconnector.Snapshot{
		FetchedAt:  at,
		Version:    st.Version,
		Vitals:     st.Vitals,
		Lifetime:   st.Lifetime,
		WifiStatus: st.WifiStatus,
		Reports:    map[wallconnector.Endpoint]wallconnector.Report{},
		Raw:        map[wallconnector.Endpoint][]byte{wallconnector.EndpointVitals: []byte(`{}`)},
	}
}

func TestOpenCreatesSecureFileAndMigrates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "tcmon.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("db file mode = %o, want 600", perm)
	}
	if v, err := s.SchemaVersion(context.Background()); err != nil || v != 6 {
		t.Errorf("schema version = %d, %v", v, err)
	}
	var av, fk int
	_ = s.db.QueryRowContext(context.Background(), "PRAGMA auto_vacuum").Scan(&av)
	_ = s.db.QueryRowContext(context.Background(), "PRAGMA foreign_keys").Scan(&fk)
	var jm string
	_ = s.db.QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&jm)
	if av != 2 || fk != 1 || jm != "wal" {
		t.Errorf("pragmas auto_vacuum=%d foreign_keys=%d journal_mode=%s", av, fk, jm)
	}
	_ = s.Close()

	// Re-opening is idempotent.
	s, err = Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	// A database from a newer version is refused.
	_, _ = s.db.ExecContext(context.Background(), "INSERT INTO schema_migrations (version, name, applied_at) VALUES (99, 'future', 0)")
	_ = s.Close()
	if _, err := Open(context.Background(), path); !errors.Is(err, ErrTooNew) {
		t.Errorf("err = %v, want ErrTooNew", err)
	}

	if _, err := Open(context.Background(), filepath.Join(dir, "bad?.db")); err == nil {
		t.Error("path with '?' accepted")
	}
}

func TestDeviceCRUD(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	d := addDevice(t, s)
	if d.ID == 0 || d.Address != "http://192.168.1.17" || d.MaxCurrentA != 48 {
		t.Errorf("created = %+v", d)
	}
	got, err := s.Device(ctx, d.ID)
	if err != nil || got != d {
		t.Errorf("Device() = %+v, %v\nwant %+v", got, err, d)
	}

	d.Address = "192.168.1.42"
	d.PollInterval = 30 * time.Minute
	upd, err := s.UpdateDevice(ctx, d, t0.Add(time.Hour))
	if err != nil || upd.Address != "http://192.168.1.42" || upd.PollInterval != 30*time.Minute || !upd.UpdatedAt.After(upd.CreatedAt) {
		t.Errorf("updated = %+v, %v", upd, err)
	}

	bad := []func(*Device){
		func(d *Device) { d.Name = "" },
		func(d *Device) { d.Address = "8.8.8.8" },
		func(d *Device) { d.PollInterval = 30 * time.Second },
		func(d *Device) { d.PluggedInterval = 25 * time.Hour },
		func(d *Device) { d.NominalVoltageV = 250 },
		func(d *Device) { d.NominalHz = 55 },
		func(d *Device) { d.MaxCurrentA = 60 }, // > 80 % of 60 A breaker
	}
	for i, mut := range bad {
		x := d
		mut(&x)
		if _, err := s.UpdateDevice(ctx, x, t0); err == nil {
			t.Errorf("bad device %d accepted: %+v", i, x)
		}
	}

	list, _ := s.Devices(ctx)
	if len(list) != 1 {
		t.Errorf("Devices() = %d", len(list))
	}
	if err := s.DeleteDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Device(ctx, d.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete err = %v", err)
	}
	if err := s.DeleteDevice(ctx, d.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("double delete err = %v", err)
	}
	if _, err := s.UpdateDevice(ctx, d, t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("update missing err = %v", err)
	}
}

func TestSaveSnapshotAndLatestState(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	d := addDevice(t, s)

	st, err := s.LatestState(ctx, d.ID)
	if err != nil || st.Info != nil || !st.LastSuccess.IsZero() {
		t.Fatalf("fresh state = %+v, %v", st, err)
	}

	snap := snapshotFrom(t, "charging", 10*time.Minute, t0)
	// Pretend the decoder flagged handle_temp_c: it must be stored as NULL.
	snap.Reports[wallconnector.EndpointVitals] = wallconnector.Report{
		Invalid: []wallconnector.FieldError{{Field: "handle_temp_c", Reason: "test"}},
	}
	ev := []DeviceEvent{{TS: t0, Kind: EventReboot, Details: map[string]string{"uptime_s": "5"}}}
	if err := s.SaveSnapshot(ctx, d.ID, snap, ev, 1, 120*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	st, err = s.LatestState(ctx, d.ID)
	if err != nil || st.Info == nil || !st.LastSuccess.Equal(t0) || !st.HasUptime || !st.LastPlugged {
		t.Fatalf("state = %+v, %v", st, err)
	}
	if st.Info.FirmwareVersion != "26.26.10+g42855ec9b9cd1" || st.Info.GridProfile.VfTrips != "BB5EABC5" {
		t.Errorf("info = %+v", st.Info)
	}

	var handle any
	var invalid string
	_ = s.db.QueryRowContext(context.Background(), "SELECT handle_temp_c, invalid_json FROM readings_vitals").Scan(&handle, &invalid)
	if handle != nil || invalid != `["handle_temp_c"]` {
		t.Errorf("invalid field stored as %v / %s", handle, invalid)
	}

	evs, err := s.Events(ctx, d.ID, t0.Add(-time.Hour), 10)
	if err != nil || len(evs) != 1 || evs[0].Kind != EventReboot || evs[0].Details["uptime_s"] != "5" {
		t.Errorf("events = %+v, %v", evs, err)
	}

	if err := s.RecordPollFailure(ctx, d.ID, t0.Add(time.Minute), 2, time.Second, errors.New("timeout")); err != nil {
		t.Fatal(err)
	}
	log, err := s.PollLog(ctx, d.ID, 10)
	if err != nil || len(log) != 2 || log[0].OK || log[0].Error != "timeout" || !log[1].OK || log[1].Duration != 120*time.Millisecond {
		t.Errorf("poll log = %+v, %v", log, err)
	}

	// Deleting the device cascades to all its data.
	if err := s.DeleteDevice(ctx, d.ID); err != nil {
		t.Fatal(err)
	}
	stats, _ := s.Stats(ctx)
	for _, tbl := range StatsTables {
		if stats.Rows[tbl] != 0 {
			t.Errorf("%s has %d rows after device delete", tbl, stats.Rows[tbl])
		}
	}
}

func TestRetentionSettings(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	r, err := s.Retention(ctx)
	if err != nil || r != DefaultRetention() || r.ReadingsDays != 730 {
		t.Errorf("default = %+v, %v", r, err)
	}
	r.ReadingsDays = 365
	if err := s.SetRetention(ctx, r, t0); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Retention(ctx); got.ReadingsDays != 365 {
		t.Errorf("stored = %+v", got)
	}
	for _, bad := range []int{-1, MaxRetentionDays + 1} {
		x := r
		x.PollLogDays = bad
		if err := s.SetRetention(ctx, x, t0); err == nil {
			t.Errorf("retention %d accepted", bad)
		}
	}
}

func TestRollupAndPrune(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	d := addDevice(t, s)

	// 40 days of hourly polls, with 5-minute polls during one charging hour.
	start := t0.Add(-40 * 24 * time.Hour).Truncate(time.Hour)
	n := 0
	for at := start; at.Before(t0); at = at.Add(time.Hour) {
		if err := s.SaveSnapshot(ctx, d.ID, snapshotFrom(t, "idle", 0, at), nil, 1, 0); err != nil {
			t.Fatal(err)
		}
		n++
	}
	chargeHour := t0.Add(-3 * time.Hour)
	for i := 1; i < 12; i++ {
		at := chargeHour.Add(time.Duration(i) * 5 * time.Minute)
		if err := s.SaveSnapshot(ctx, d.ID, snapshotFrom(t, "charging", time.Duration(i)*5*time.Minute, at), nil, 1, 0); err != nil {
			t.Fatal(err)
		}
	}

	rolled, err := s.Rollup(ctx, t0.Add(30*time.Minute))
	if err != nil || rolled == 0 {
		t.Fatalf("rollup = %d, %v", rolled, err)
	}
	var count int64
	var avgCurrent, maxCurrent float64
	err = s.db.QueryRowContext(context.Background(), "SELECT count, avg, max FROM rollups_1h WHERE metric = 'vehicle_current_a' AND bucket_ts = ?",
		ms(chargeHour)).Scan(&count, &avgCurrent, &maxCurrent)
	if err != nil || count != 12 || maxCurrent != 47.9 || avgCurrent <= 0 || avgCurrent >= 47.9 {
		t.Errorf("charging hour rollup count=%d avg=%v max=%v err=%v", count, avgCurrent, maxCurrent, err)
	}
	if again, _ := s.Rollup(ctx, t0.Add(30*time.Minute)); again != 0 {
		t.Errorf("second rollup wrote %d rows, want 0 (idempotent)", again)
	}

	// Shorten retention to 30 days: older readings, raw payloads and poll
	// logs go; rollups are kept forever by default.
	r := DefaultRetention()
	r.ReadingsDays, r.RawPayloadsDays, r.PollLogDays = 30, 7, 30
	res, err := s.Prune(ctx, t0, r)
	if err != nil {
		t.Fatal(err)
	}
	wantGone := int64(10 * 24) // hours older than 30 days
	if res["readings_vitals"] != wantGone || res["poll_log"] != wantGone {
		t.Errorf("prune result = %v, want %d per readings table", res, wantGone)
	}
	// Lifetime readings are thinned (TestPruneKeepsCosts): the idle stretch
	// keeps its first reading.
	if res["readings_lifetime"] != wantGone-1 {
		t.Errorf("lifetime readings pruned = %d, want %d", res["readings_lifetime"], wantGone-1)
	}
	if res["raw_payloads"] != int64(33*24) {
		t.Errorf("raw payloads pruned = %d", res["raw_payloads"])
	}
	if _, ok := res["rollups_1h"]; ok {
		t.Error("rollups must be kept forever by default")
	}
	var oldest int64
	_ = s.db.QueryRowContext(context.Background(), "SELECT MIN(ts) FROM readings_vitals").Scan(&oldest)
	if fromMS(oldest).Before(t0.Add(-30 * 24 * time.Hour)) {
		t.Errorf("reading older than 30 days survived: %v", fromMS(oldest))
	}
	var oldestRollup int64
	_ = s.db.QueryRowContext(context.Background(), "SELECT MIN(bucket_ts) FROM rollups_1h").Scan(&oldestRollup)
	if !fromMS(oldestRollup).Equal(start) {
		t.Errorf("oldest rollup = %v, want %v", fromMS(oldestRollup), start)
	}

	// Un-rolled readings are never pruned, even with a 1-day policy.
	if err := s.SaveSnapshot(ctx, d.ID, snapshotFrom(t, "idle", 0, t0.Add(10*time.Minute)), nil, 1, 0); err != nil {
		t.Fatal(err)
	}
	r.ReadingsDays = 1
	if _, err := s.Prune(ctx, t0.Add(72*time.Hour), r); err != nil {
		t.Fatal(err)
	}
	var survivors int
	_ = s.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM readings_vitals WHERE ts >= ?", ms(t0)).Scan(&survivors)
	if survivors != 1 {
		t.Errorf("un-rolled reading pruned (survivors=%d)", survivors)
	}

	if _, err := s.Prune(ctx, t0, Retention{ReadingsDays: -1}); err == nil {
		t.Error("invalid retention accepted by Prune")
	}

	mres, err := s.Maintain(ctx, t0.Add(2*time.Hour))
	if err != nil || mres.RolledUp == 0 {
		t.Errorf("maintain = %+v, %v", mres, err)
	}
	_ = n
}

func TestBackupAndStats(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	d := addDevice(t, s)
	if err := s.SaveSnapshot(ctx, d.ID, snapshotFrom(t, "idle", 0, t0), nil, 1, 0); err != nil {
		t.Fatal(err)
	}
	st, err := s.Stats(ctx)
	if err != nil || st.SizeBytes == 0 || st.Rows["readings_vitals"] != 1 || !st.OldestReading.Equal(t0) {
		t.Errorf("stats = %+v, %v", st, err)
	}

	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := s.Backup(ctx, dest); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dest); fi.Mode().Perm() != 0o600 {
		t.Errorf("backup mode = %o", fi.Mode().Perm())
	}
	if err := s.Backup(ctx, dest); err == nil {
		t.Error("overwriting an existing backup should fail")
	}
	b, err := Open(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if list, _ := b.Devices(ctx); len(list) != 1 {
		t.Errorf("backup has %d devices", len(list))
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	var v map[string]int
	if err := s.GetSetting(ctx, "x", &v); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v", err)
	}
	if err := s.SetSetting(ctx, "x", map[string]int{"a": 1}, t0); err != nil {
		t.Fatal(err)
	}
	if err := s.GetSetting(ctx, "x", &v); err != nil || v["a"] != 1 {
		t.Errorf("v = %v, %v", v, err)
	}
}
