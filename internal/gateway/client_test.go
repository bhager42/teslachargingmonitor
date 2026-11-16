// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package gateway

import (
	"context"
	"errors"
	"io"
	"log"
	"math"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gwsim"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
)

const simPassword = "SIMPW"

// clock is a settable time source shared by the simulator and the client.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type rig struct {
	sim   *gwsim.Server
	clk   *clock
	host  string
	start time.Time
}

func newRig(t *testing.T, scenario string) *rig {
	t.Helper()
	clk := &clock{t: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
	sim, err := gwsim.NewServer(gwsim.Options{Scenario: scenario, Password: simPassword, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(sim)
	srv.TLS = sim.TLSConfig()
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // expected handshake failures (cert-changed)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &rig{sim: sim, clk: clk, host: strings.TrimPrefix(srv.URL, "https://"), start: clk.Now()}
}

func (r *rig) client(t *testing.T, password string) *Client {
	t.Helper()
	c, err := NewClient(r.host, Options{Pin: r.sim.Fingerprint(), Password: secrets.Secret(password), Now: r.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestSnapshotReusesTheSession(t *testing.T) {
	r := newRig(t, "day")
	c := r.client(t, simPassword)
	ctx := context.Background()
	var first *Snapshot
	for i := range 3 {
		s, err := c.Snapshot(ctx)
		if err != nil {
			t.Fatalf("snapshot %d: %v", i, err)
		}
		if first == nil {
			first = s
		}
		for ep, rep := range s.Reports {
			if !rep.Clean() {
				t.Errorf("%s: report not clean: %+v", ep, rep)
			}
		}
		r.clk.Add(5 * time.Minute)
	}
	if n := r.sim.Logins(); n != 1 {
		t.Errorf("logins = %d, want 1 (session reused)", n)
	}
	if first.Status.Firmware() != "26.34.2" || !first.GridStatus.OnGrid() || !first.Sitemaster.Running {
		t.Errorf("snapshot = %+v", first)
	}
	a := first.Aggregates
	if got := a.Solar.InstantPower + a.Battery.InstantPower + a.Site.InstantPower; math.Abs(got-a.Load.InstantPower) > 1 {
		t.Errorf("power does not balance: solar+battery+site = %g, load = %g", got, a.Load.InstantPower)
	}
	if len(first.SystemStatus.BatteryBlocks) != 2 || first.Operation.AppReservePercent() != 30 {
		t.Errorf("system status / operation = %+v / %+v", first.SystemStatus, first.Operation)
	}
}

func TestSessionExpiryLogsInAgainOnce(t *testing.T) {
	r := newRig(t, "day")
	c := r.client(t, simPassword)
	if _, err := c.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.sim.ExpireSessions()
	if _, err := c.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := r.sim.Logins(); n != 2 {
		t.Errorf("logins = %d, want 2", n)
	}
}

// The acceptance test for step 9.1: a rejected login is never retried
// before its back-off step has passed, and the steps double up to 6 h.
func TestRejectedLoginBacksOff(t *testing.T) {
	r := newRig(t, "day")
	c := r.client(t, "Zq9-not-it")
	ctx := context.Background()
	wantLogins := 0
	wait := BackoffMin
	for step := 1; step <= 10; step++ {
		_, err := c.Snapshot(ctx)
		wantLogins++
		var be *BackoffError
		if !errors.As(err, &be) || !errors.Is(err, ErrLoginRejected) {
			t.Fatalf("step %d: err = %v, want a rejected-login BackoffError", step, err)
		}
		if strings.Contains(err.Error(), "Zq9-not-it") {
			t.Fatal("error message contains the password")
		}
		if got := be.Until.Sub(r.clk.Now()); got != wait {
			t.Fatalf("step %d: back-off %v, want %v", step, got, wait)
		}
		// Polling during the back-off never reaches the login endpoint.
		for range 3 {
			r.clk.Add(wait / 4)
			if _, err := c.Snapshot(ctx); !errors.As(err, &be) {
				t.Fatalf("step %d: err = %v during back-off", step, err)
			}
		}
		if n := r.sim.Logins(); n != wantLogins {
			t.Fatalf("step %d: logins = %d, want %d", step, n, wantLogins)
		}
		r.clk.Add(wait - 3*(wait/4))
		wait = min(wait*2, BackoffMax)
	}
	if b := c.Backoff(); b.Failures != 10 || b.Cause != "rejected" {
		t.Errorf("backoff = %+v", b)
	}
}

func TestRateLimitedLoginBacksOff(t *testing.T) {
	r := newRig(t, "rate-limited")
	c := r.client(t, simPassword)
	_, err := c.Snapshot(context.Background())
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v", err)
	}
	if b := c.Backoff(); b.Cause != "rate_limited" || b.Failures != 1 {
		t.Errorf("backoff = %+v", b)
	}
	if _, err := c.Snapshot(context.Background()); !errors.Is(err, ErrRateLimited) {
		t.Errorf("second err = %v", err)
	}
	if n := r.sim.Logins(); n != 1 {
		t.Errorf("logins = %d, want 1", n)
	}
}

func TestSuccessfulLoginClearsBackoff(t *testing.T) {
	r := newRig(t, "login-rejected")
	c := r.client(t, simPassword)
	if _, err := c.Snapshot(context.Background()); !errors.Is(err, ErrLoginRejected) {
		t.Fatalf("err = %v", err)
	}
	if err := r.sim.SetScenario("day"); err != nil {
		t.Fatal(err)
	}
	r.clk.Add(BackoffMin)
	if _, err := c.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b := c.Backoff(); b != (Backoff{}) {
		t.Errorf("backoff = %+v, want cleared", b)
	}
}

func TestRestoredBackoffIsHonoured(t *testing.T) {
	r := newRig(t, "day")
	c := r.client(t, simPassword)
	c.RestoreBackoff(Backoff{Failures: 3, Until: r.clk.Now().Add(time.Hour), Cause: "rejected"})
	if _, err := c.Snapshot(context.Background()); !errors.Is(err, ErrLoginRejected) {
		t.Fatalf("err = %v", err)
	}
	if r.sim.Logins() != 0 {
		t.Error("logged in during a restored back-off")
	}
	c.ResetBackoff()
	if _, err := c.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateChangeStopsBeforeLogin(t *testing.T) {
	r := newRig(t, "day")
	c := r.client(t, simPassword)
	if err := r.sim.SetScenario("cert-changed"); err != nil {
		t.Fatal(err)
	}
	_, err := c.Snapshot(context.Background())
	var ce *CertError
	if !errors.As(err, &ce) || !errors.Is(err, ErrCertChanged) {
		t.Fatalf("err = %v, want CertError", err)
	}
	if ce.Fingerprint != r.sim.Fingerprint() {
		t.Error("CertError does not carry the new fingerprint")
	}
	if r.sim.Logins() != 0 {
		t.Error("the password was sent to an unpinned certificate")
	}
}

func TestFingerprintMatchesTheServer(t *testing.T) {
	r := newRig(t, "day")
	fp, err := Fingerprint(context.Background(), r.host, false)
	if err != nil {
		t.Fatal(err)
	}
	if fp != r.sim.Fingerprint() || r.sim.Logins() != 0 {
		t.Errorf("fingerprint %s, want %s (logins %d)", fp, r.sim.Fingerprint(), r.sim.Logins())
	}
}

func TestNewClientRequiresPinAndPassword(t *testing.T) {
	if _, err := NewClient("192.168.1.2", Options{Pin: "abcd", Password: "x"}); !errors.Is(err, ErrNoPin) {
		t.Errorf("short pin: %v", err)
	}
	if _, err := NewClient("192.168.1.2", Options{Pin: strings.Repeat("ab", 32)}); !errors.Is(err, ErrNoPassword) {
		t.Errorf("no password: %v", err)
	}
	if _, err := NewClient("192.168.1.2", Options{Pin: strings.Repeat("AB:", 31) + "AB", Password: "x"}); err != nil {
		t.Errorf("colon-separated upper-case pin: %v", err)
	}
}

func TestNonLANAddressIsRefused(t *testing.T) {
	c, err := NewClient("192.0.2.1", Options{Pin: strings.Repeat("ab", 32), Password: "x", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Snapshot(context.Background()); !errors.Is(err, ErrBlockedAddress) {
		t.Errorf("err = %v", err)
	}
}

func TestMalformedPayloadIsAnError(t *testing.T) {
	r := newRig(t, "malformed")
	s, err := r.client(t, simPassword).Snapshot(context.Background())
	if !errors.Is(err, ErrNotObject) {
		t.Fatalf("err = %v", err)
	}
	if s.Status.Firmware() != "26.34.2" {
		t.Error("the partial snapshot lost /api/status")
	}
}

func TestOutageAndBatteryLow(t *testing.T) {
	r := newRig(t, "outage")
	c := r.client(t, simPassword)
	s, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.GridStatus.OnGrid() || s.Aggregates.Site.InstantPower != 0 {
		t.Errorf("outage: grid %+v, site %g", s.GridStatus, s.Aggregates.Site.InstantPower)
	}
	if err := r.sim.SetScenario("battery-low"); err != nil {
		t.Fatal(err)
	}
	s, err = c.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := s.SOE.Percentage; math.Abs(got-12) > 0.01 {
		t.Errorf("battery-low raw soe = %g, want 12", got)
	}
}

func TestCountersFollowSimulatedTime(t *testing.T) {
	r := newRig(t, "sunny")
	c := r.client(t, simPassword)
	before, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r.clk.Add(time.Hour)
	after, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d := func(a, b float64) float64 { return math.Round(b - a) }
	if got := d(before.Aggregates.Solar.EnergyExported, after.Aggregates.Solar.EnergyExported); got != 6200 {
		t.Errorf("solar Wh in 1 h = %g, want 6200", got)
	}
	if got := d(before.Aggregates.Battery.EnergyImported, after.Aggregates.Battery.EnergyImported); got != 3200 {
		t.Errorf("battery charged Wh in 1 h = %g, want 3200", got)
	}
	if got := d(before.Aggregates.Site.EnergyExported, after.Aggregates.Site.EnergyExported); got != 1500 {
		t.Errorf("exported Wh in 1 h = %g, want 1500", got)
	}
	if after.SOE.Percentage <= before.SOE.Percentage {
		t.Error("battery level did not rise while charging")
	}
}

func TestInfo(t *testing.T) {
	r := newRig(t, "day")
	in, err := r.client(t, simPassword).Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if in.SiteInfo.NominalSystemEnergyKWh != 27 || len(in.Solars) != 1 || in.Solars[0].PowerRatingWatts != 7600 {
		t.Errorf("info = %+v", in)
	}
	for _, rep := range in.Reports {
		if !rep.Clean() {
			t.Errorf("%s: %+v", rep.Endpoint, rep)
		}
	}
}
