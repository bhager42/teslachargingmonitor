// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
)

var testPin = strings.Repeat("ab", 32)

func testBox(t *testing.T) *secrets.Box {
	t.Helper()
	b, err := secrets.NewBox(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func addGateway(t *testing.T, s *Store, box *secrets.Box) Gateway {
	t.Helper()
	enc, err := SealGatewayPassword(box, "ABCDE")
	if err != nil {
		t.Fatal(err)
	}
	g, err := s.CreateGateway(context.Background(), NewGateway("Powerwall", "192.168.1.20", testPin, enc), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// fixtureSnapshot decodes the owner's captured Gateway payloads.
func fixtureSnapshot(t *testing.T, at time.Time) *gateway.Snapshot {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("../../testdata/fixtures/gateway/26.34.2", name+".day.json")) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	s := &gateway.Snapshot{FetchedAt: at, Reports: map[gateway.Endpoint]gateway.Report{}, Raw: map[gateway.Endpoint][]byte{}}
	var rep gateway.Report
	s.Status, rep, _ = gateway.DecodeStatus(read("status"))
	s.Reports[gateway.EndpointStatus] = rep
	s.Aggregates, rep, _ = gateway.DecodeAggregates(read("meters_aggregates"))
	s.Reports[gateway.EndpointAggregates] = rep
	s.SOE, rep, _ = gateway.DecodeSOE(read("system_status_soe"))
	s.Reports[gateway.EndpointSOE] = rep
	s.GridStatus, rep, _ = gateway.DecodeGridStatus(read("system_status_grid_status"))
	s.Reports[gateway.EndpointGridStatus] = rep
	s.SystemStatus, rep, _ = gateway.DecodeSystemStatus(read("system_status"))
	s.Reports[gateway.EndpointSystemStatus] = rep
	s.Operation, rep, _ = gateway.DecodeOperation(read("operation"))
	s.Reports[gateway.EndpointOperation] = rep
	s.Sitemaster, rep, _ = gateway.DecodeSitemaster(read("sitemaster"))
	s.Reports[gateway.EndpointSitemaster] = rep
	s.Raw[gateway.EndpointStatus] = read("status")
	return s
}

func TestGatewayPasswordIsSealed(t *testing.T) {
	s, box := openTest(t), testBox(t)
	g := addGateway(t, s, box)
	if bytes.Contains(g.PasswordEnc, []byte("ABCDE")) {
		t.Fatal("password stored in clear")
	}
	got, err := s.Gateway(context.Background(), g.ID)
	if err != nil {
		t.Fatal(err)
	}
	pw, err := got.Password(box)
	if err != nil || pw.Reveal() != "ABCDE" {
		t.Fatalf("Password = %q, %v", pw.Reveal(), err)
	}
	other, _ := secrets.NewBox(bytes.Repeat([]byte{8}, 32))
	if _, err := got.Password(other); err == nil {
		t.Error("another key opened the password")
	}
	if _, err := SealGatewayPassword(box, ""); err == nil {
		t.Error("empty password sealed")
	}
}

func TestGatewayNormalize(t *testing.T) {
	ok := NewGateway("PW", " 192.168.1.20 ", strings.Repeat("AB:", 31)+"AB", []byte{1})
	if err := ok.Normalize(); err != nil || ok.Address != "192.168.1.20" || ok.Pin != testPin {
		t.Fatalf("Normalize = %v, %+v", err, ok)
	}
	for name, mut := range map[string]func(*Gateway){
		"name":     func(g *Gateway) { g.Name = "" },
		"address":  func(g *Gateway) { g.Address = "8.8.8.8" },
		"path":     func(g *Gateway) { g.Address = "192.168.1.20/api" },
		"pin":      func(g *Gateway) { g.Pin = "abcd" },
		"pin hex":  func(g *Gateway) { g.Pin = strings.Repeat("zz", 32) },
		"password": func(g *Gateway) { g.PasswordEnc = nil },
		"interval": func(g *Gateway) { g.PollInterval = time.Second },
		"charging": func(g *Gateway) { g.ChargingInterval = 25 * time.Hour },
	} {
		g := NewGateway("PW", "192.168.1.20", testPin, []byte{1})
		mut(&g)
		if err := g.Normalize(); err == nil {
			t.Errorf("%s: accepted %+v", name, g)
		}
	}
}

func TestGatewayBackoffAndPinKeepUpdatedAt(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	g := addGateway(t, s, testBox(t))
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)
	if err := s.SetGatewayBackoff(ctx, g.ID, gateway.Backoff{Failures: 2, Until: until, Cause: "rejected"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGatewayPendingPin(ctx, g.ID, strings.Repeat("cd", 32)); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Gateway(ctx, g.ID)
	if !got.UpdatedAt.Equal(g.UpdatedAt) {
		t.Error("back-off or pending pin changed updated_at (would restart the worker)")
	}
	if got.Backoff.Failures != 2 || !got.Backoff.Until.Equal(until) || got.Backoff.Cause != "rejected" {
		t.Errorf("backoff = %+v", got.Backoff)
	}
	if err := s.SetGatewayPendingPin(ctx, g.ID, "nope"); err == nil {
		t.Error("invalid pending pin accepted")
	}

	later := time.Now().Add(time.Minute)
	if err := s.AcceptGatewayPin(ctx, g.ID, later); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Gateway(ctx, g.ID)
	if got.Pin != strings.Repeat("cd", 32) || got.PendingPin != "" || got.UpdatedAt.Equal(g.UpdatedAt) {
		t.Errorf("after accept: %+v", got)
	}
	if err := s.AcceptGatewayPin(ctx, g.ID, later); !errors.Is(err, ErrNotFound) {
		t.Errorf("accept without a pending pin: %v", err)
	}
}

func TestUpdateGatewayClearsBackoffOnNewCredentials(t *testing.T) {
	ctx := context.Background()
	s, box := openTest(t), testBox(t)
	g := addGateway(t, s, box)
	if err := s.SetGatewayBackoff(ctx, g.ID, gateway.Backoff{Failures: 3, Until: time.Now().Add(time.Hour), Cause: "rejected"}); err != nil {
		t.Fatal(err)
	}
	g, _ = s.Gateway(ctx, g.ID)
	g.Name = "Renamed"
	g, err := s.UpdateGateway(ctx, g, time.Now())
	if err != nil || g.Backoff.Failures != 3 {
		t.Fatalf("rename kept back-off? %+v %v", g.Backoff, err)
	}
	g.PasswordEnc, _ = SealGatewayPassword(box, "FGHIJ")
	g, err = s.UpdateGateway(ctx, g, time.Now())
	if err != nil || g.Backoff != (gateway.Backoff{}) {
		t.Errorf("new password kept back-off: %+v %v", g.Backoff, err)
	}
}

func TestSaveGatewaySnapshot(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	g := addGateway(t, s, testBox(t))
	t0 := time.Date(2026, 11, 16, 13, 33, 0, 0, time.UTC)
	snap := fixtureSnapshot(t, t0)
	info := &gateway.Info{SiteInfo: gateway.SiteInfo{NominalSystemEnergyKWh: 27, Timezone: "America/New_York"},
		Solars: []gateway.Solar{{PowerRatingWatts: 7600}}}
	if err := s.SaveGatewaySnapshot(ctx, g.ID, snap, info, nil, 1, 40*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	gi, err := s.GatewayInfo(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gi.FirmwareVersion != "26.34.2" || gi.BatteryCount != 2 || gi.FullPackWh != 27217 || gi.FirstFullPackWh != 27217 ||
		gi.SolarRatingW != 7600 || gi.Timezone != "America/New_York" || !gi.HasUptime || gi.BackupReservePct != 33.5 {
		t.Errorf("info = %+v", gi)
	}

	// A later poll with less capacity keeps the first-seen baseline, keeps
	// the site info it was not given, and flags an invalid field as NULL.
	snap2 := fixtureSnapshot(t, t0.Add(15*time.Minute))
	snap2.SystemStatus.NominalFullPackEnergy = 26000
	rep := snap2.Reports[gateway.EndpointAggregates]
	rep.Invalid = append(rep.Invalid, gateway.FieldError{Field: "solar.instant_power", Reason: "test"})
	snap2.Reports[gateway.EndpointAggregates] = rep
	ev := []GatewayEvent{{TS: snap2.FetchedAt, Kind: GatewayEventReboot, Details: map[string]string{"uptime_s": "5"}}}
	if err := s.SaveGatewaySnapshot(ctx, g.ID, snap2, nil, ev, 2, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	gi, _ = s.GatewayInfo(ctx, g.ID)
	if gi.FullPackWh != 26000 || gi.FirstFullPackWh != 27217 || gi.Timezone != "America/New_York" || gi.SolarRatingW != 7600 {
		t.Errorf("info after second poll = %+v", gi)
	}

	rs, err := s.SiteReadings(ctx, g.ID, t0, t0.Add(time.Hour))
	if err != nil || len(rs) != 2 {
		t.Fatalf("readings = %d, %v", len(rs), err)
	}
	if rs[0].SolarW == nil || *rs[0].SolarW != 3730 || *rs[0].SiteW != -49 || rs[0].GridStatus != gateway.GridConnected {
		t.Errorf("first reading = %+v", rs[0])
	}
	if rs[1].SolarW != nil || rs[1].LoadW == nil {
		t.Error("an invalid field was stored, or a valid one dropped")
	}
	evs, _ := s.GatewayEvents(ctx, g.ID, t0, 10)
	if len(evs) != 1 || evs[0].Kind != GatewayEventReboot || evs[0].Details["uptime_s"] != "5" {
		t.Errorf("events = %+v", evs)
	}
	st, err := s.LatestGatewayState(ctx, g.ID)
	if err != nil || !st.LastSuccess.Equal(snap2.FetchedAt) || st.GridStatus != gateway.GridConnected || st.Info == nil {
		t.Errorf("state = %+v, %v", st, err)
	}
	log, _ := s.GatewayPollLog(ctx, g.ID, 10)
	if len(log) != 2 || !log[0].OK || log[0].Attempt != 2 {
		t.Errorf("poll log = %+v", log)
	}
}

func TestSiteRollupAndPrune(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	g := addGateway(t, s, testBox(t))
	old := time.Now().Add(-800 * 24 * time.Hour).Truncate(time.Hour)
	for i := range 4 {
		if err := s.SaveGatewaySnapshot(ctx, g.ID, fixtureSnapshot(t, old.Add(time.Duration(i)*15*time.Minute)), nil, nil, 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RecordGatewayPollFailure(ctx, g.ID, old, 1, 0, errors.New("x")); err != nil {
		t.Fatal(err)
	}
	// Retention cannot remove readings that have not been rolled up; raw
	// payloads and the poll log do not wait for rollups.
	if res, err := s.Prune(ctx, time.Now(), DefaultRetention()); err != nil || res["readings_site"] != 0 ||
		res["gateway_raw_payloads"] != 4 || res["gateway_poll_log"] != 5 {
		t.Fatalf("prune before rollup = %v, %v", res, err)
	}
	res, err := s.Maintain(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if res.RolledUp != int64(len(SiteRollupMetrics)) {
		t.Errorf("rolled up %d rows, want %d", res.RolledUp, len(SiteRollupMetrics))
	}
	if res.Pruned["readings_site"] != 4 {
		t.Errorf("pruned = %v", res.Pruned)
	}
	var avg float64
	if err := s.db.QueryRowContext(ctx, `SELECT avg FROM rollups_site_1h WHERE gateway_id = ? AND metric = 'solar_w'`,
		g.ID).Scan(&avg); err != nil || avg != 3730 {
		t.Errorf("solar_w rollup avg = %g, %v", avg, err)
	}
	stats, err := s.Stats(ctx)
	if err != nil || stats.Rows["gateways"] != 1 || stats.Rows["rollups_site_1h"] != int64(len(SiteRollupMetrics)) {
		t.Errorf("stats = %+v, %v", stats.Rows, err)
	}
}

func TestAnyVehiclePlugged(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if p, err := s.AnyVehiclePlugged(ctx); err != nil || p {
		t.Fatalf("no devices: %v %v", p, err)
	}
	d := addDevice(t, s)
	t0 := time.Now().Add(-time.Hour)
	if err := s.SaveSnapshot(ctx, d.ID, snapshotFrom(t, "charging", time.Minute, t0), nil, 1, 0); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.AnyVehiclePlugged(ctx); !p {
		t.Error("charging device not seen as plugged")
	}
	if err := s.SaveSnapshot(ctx, d.ID, snapshotFrom(t, "idle", time.Minute, t0.Add(time.Minute)), nil, 1, 0); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.AnyVehiclePlugged(ctx); p {
		t.Error("idle (latest) device seen as plugged")
	}
}

func TestDeleteGatewayCascades(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	g := addGateway(t, s, testBox(t))
	if err := s.SaveGatewaySnapshot(ctx, g.ID, fixtureSnapshot(t, time.Now()), nil, nil, 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGateway(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"gateway_info", "readings_site", "gateway_raw_payloads", "gateway_poll_log"} {
		var n int
		_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+tbl).Scan(&n) //nolint:gosec // constant table names
		if n != 0 {
			t.Errorf("%s has %d rows after delete", tbl, n)
		}
	}
	if err := s.DeleteGateway(ctx, g.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestSiteSamples(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if xs, err := s.SiteSamples(ctx, time.Unix(0, 0), time.Now()); err != nil || xs != nil {
		t.Fatalf("no gateway: %v %v", xs, err)
	}
	if has, _ := s.HasGateway(ctx); has {
		t.Error("HasGateway without one")
	}
	g := addGateway(t, s, testBox(t))
	t0 := time.Date(2026, 11, 16, 13, 0, 0, 0, time.UTC)
	for i := range 4 {
		snap := fixtureSnapshot(t, t0.Add(time.Duration(i)*15*time.Minute))
		snap.Aggregates.Solar.EnergyExported += float64(i) * 900
		if i == 2 { // a flagged counter: skipped
			rep := snap.Reports[gateway.EndpointAggregates]
			rep.Invalid = append(rep.Invalid, gateway.FieldError{Field: "site.energy_imported"})
			snap.Reports[gateway.EndpointAggregates] = rep
		}
		if err := s.SaveGatewaySnapshot(ctx, g.ID, snap, nil, nil, 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	xs, err := s.SiteSamples(ctx, t0.Add(20*time.Minute), t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// The reading before from (15 min), then 45 min; 30 min is flagged.
	if len(xs) != 2 || !xs[0].TS.Equal(t0.Add(15*time.Minute)) || !xs[1].TS.Equal(t0.Add(45*time.Minute)) {
		t.Fatalf("samples = %+v", xs)
	}
	if xs[1].SolarWh-xs[0].SolarWh != 1800 || xs[0].GridExportWh != 1890463.3841501034 {
		t.Errorf("counters = %+v", xs)
	}
	if has, _ := s.HasGateway(ctx); !has {
		t.Error("HasGateway")
	}
}
