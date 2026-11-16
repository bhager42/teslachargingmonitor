// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package poller

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/gwsim"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

const gwPassword = "SIMPW"

type gwHarness struct {
	*harness
	gsim *gwsim.Server
	host string
	box  *secrets.Box
}

func newGatewayHarness(t *testing.T, scenario string) *gwHarness {
	t.Helper()
	h := newHarness(t, "idle")
	gsim, err := gwsim.NewServer(gwsim.Options{Scenario: scenario, Password: gwPassword})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(gsim)
	srv.TLS = gsim.TLSConfig()
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	box, err := secrets.NewBox(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return &gwHarness{harness: h, gsim: gsim, host: strings.TrimPrefix(srv.URL, "https://"), box: box}
}

func (h *gwHarness) addGateway(t *testing.T, pin string) store.Gateway {
	t.Helper()
	enc, err := store.SealGatewayPassword(h.box, gwPassword)
	if err != nil {
		t.Fatal(err)
	}
	g, err := h.st.CreateGateway(context.Background(), store.NewGateway("Powerwall", h.host, pin, enc), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func (h *gwHarness) config() Config {
	cfg := fastConfig()
	cfg.Box = h.box
	return cfg
}

func nextGW(t *testing.T, ch <-chan GatewayUpdate) GatewayUpdate {
	t.Helper()
	select {
	case u := <-ch:
		return u
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for gateway update")
		return GatewayUpdate{}
	}
}

func TestGatewayPollStoresAndPublishes(t *testing.T) {
	h := newGatewayHarness(t, "day")
	g := h.addGateway(t, h.gsim.Fingerprint())
	m := New(h.st, h.config())
	ch, unsub := m.SubscribeGateways(4)
	defer unsub()
	stop := run(t, m)
	defer stop()

	u := nextGW(t, ch)
	if u.Err != nil || u.Snapshot == nil || u.Gateway.ID != g.ID || u.Attempts != 1 {
		t.Fatalf("update = %+v", u)
	}
	if u.Gateway.PasswordEnc != nil {
		t.Error("published update carries the sealed password")
	}
	if u.Next.Sub(u.At) != time.Hour {
		t.Errorf("next poll in %v", u.Next.Sub(u.At))
	}
	rs, err := h.st.SiteReadings(context.Background(), g.ID, u.At.Add(-time.Second), u.At.Add(time.Second))
	if err != nil || len(rs) != 1 || rs[0].SolarW == nil || *rs[0].SolarW != 3730 {
		t.Fatalf("readings = %+v, %v", rs, err)
	}
	info, err := h.st.GatewayInfo(context.Background(), g.ID)
	if err != nil || info.SolarRatingW != 7600 || info.Timezone != "America/New_York" {
		t.Errorf("site info not stored: %+v, %v", info, err)
	}
	if err := m.PollGatewayNow(g.ID); err != nil {
		t.Fatal(err)
	}
	if u := nextGW(t, ch); u.Err != nil {
		t.Fatal(u.Err)
	}
	if n := h.gsim.Logins(); n != 1 {
		t.Errorf("logins = %d, want 1 (session reused across polls)", n)
	}
}

// Plan step 9.2 acceptance: a restart keeps the login back-off.
func TestGatewayBackoffSurvivesRestart(t *testing.T) {
	h := newGatewayHarness(t, "login-rejected")
	g := h.addGateway(t, h.gsim.Fingerprint())
	m := New(h.st, h.config())
	ch, unsub := m.SubscribeGateways(4)
	stop := run(t, m)
	u := nextGW(t, ch)
	stop()
	unsub()
	var be *gateway.BackoffError
	if !errors.As(u.Err, &be) || !errors.Is(u.Err, gateway.ErrLoginRejected) {
		t.Fatalf("err = %v", u.Err)
	}
	if h.gsim.Logins() != 1 {
		t.Fatalf("logins = %d, want 1 (a rejected login is not retried)", h.gsim.Logins())
	}
	saved, _ := h.st.Gateway(context.Background(), g.ID)
	if saved.Backoff.Failures != 1 || !saved.Backoff.Until.After(time.Now()) {
		t.Fatalf("back-off not persisted: %+v", saved.Backoff)
	}

	// The password is fixed on the Gateway, but the restarted poller must
	// still wait out the back-off instead of trying again at once.
	if err := h.gsim.SetScenario("day"); err != nil {
		t.Fatal(err)
	}
	m2 := New(h.st, h.config())
	ch2, unsub2 := m2.SubscribeGateways(4)
	defer unsub2()
	stop2 := run(t, m2)
	defer stop2()
	if u := nextGW(t, ch2); !errors.As(u.Err, &be) {
		t.Fatalf("after restart err = %v, want a BackoffError", u.Err)
	}
	if h.gsim.Logins() != 1 {
		t.Errorf("logins = %d after restart, want still 1", h.gsim.Logins())
	}
}

// Plan step 9.2 acceptance: a restart keeps the pin; a changed certificate
// stops polling until the owner accepts it.
func TestGatewayCertificateChangeStopsPolling(t *testing.T) {
	h := newGatewayHarness(t, "day")
	g := h.addGateway(t, h.gsim.Fingerprint())
	if err := h.gsim.SetScenario("cert-changed"); err != nil {
		t.Fatal(err)
	}
	newFP := h.gsim.Fingerprint()
	m := New(h.st, h.config())
	ch, unsub := m.SubscribeGateways(4)
	defer unsub()
	stop := run(t, m)
	defer stop()

	u := nextGW(t, ch)
	var ce *gateway.CertError
	if !errors.As(u.Err, &ce) || ce.Fingerprint != newFP || len(u.Events) != 1 || u.Events[0].Kind != store.GatewayEventCertChanged {
		t.Fatalf("update = %+v", u)
	}
	if h.gsim.Logins() != 0 {
		t.Fatal("the password was sent to an unpinned certificate")
	}
	saved, _ := h.st.Gateway(context.Background(), g.ID)
	if saved.PendingPin != newFP || saved.Pin != g.Pin {
		t.Fatalf("pending pin not recorded: %+v", saved)
	}

	// A restart does not poll while the change is pending.
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.PollGatewayNow(g.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case u := <-ch:
		if u.Snapshot != nil {
			t.Fatal("polled although the certificate change is pending")
		}
	case <-time.After(200 * time.Millisecond):
	}

	if err := h.st.AcceptGatewayPin(context.Background(), g.ID, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	for {
		u := nextGW(t, ch)
		if u.Snapshot != nil {
			break
		}
		if !errors.As(u.Err, &ce) {
			t.Fatalf("after accept: %v", u.Err)
		}
	}
	if h.gsim.Logins() != 1 {
		t.Errorf("logins = %d", h.gsim.Logins())
	}
}

func TestGatewayWithoutKeyIsNotPolled(t *testing.T) {
	h := newGatewayHarness(t, "day")
	h.addGateway(t, h.gsim.Fingerprint())
	m := New(h.st, fastConfig()) // no Box
	ch, unsub := m.SubscribeGateways(4)
	defer unsub()
	stop := run(t, m)
	defer stop()
	if u := nextGW(t, ch); !errors.Is(u.Err, ErrNoBox) {
		t.Fatalf("err = %v", u.Err)
	}
	if h.gsim.Logins() != 0 {
		t.Error("logged in without a key")
	}
}

func TestGatewayChargingCadence(t *testing.T) {
	h := newGatewayHarness(t, "day")
	g := h.addGateway(t, h.gsim.Fingerprint())
	cfg := h.config()
	cfg.IntervalOverride = 0
	cfg.MaxJitter = time.Nanosecond
	m := New(h.st, cfg)
	ctx := context.Background()
	near := func(got, want time.Duration) bool {
		return got >= want-time.Microsecond && got <= want+time.Microsecond
	}
	if got := m.gatewayInterval(ctx, g); !near(got, store.DefaultGatewayInterval) {
		t.Errorf("no car: %v", got)
	}
	if err := h.sim.SetScenario("charging"); err != nil {
		t.Fatal(err)
	}
	h.addDevice(t)
	dm := New(h.st, fastConfig())
	dch, unsub := dm.Subscribe(4)
	defer unsub()
	stop := run(t, dm)
	if u := next(t, dch); u.Err != nil {
		t.Fatal(u.Err)
	}
	stop()
	if got := m.gatewayInterval(ctx, g); !near(got, store.DefaultGatewayChargingInterval) {
		t.Errorf("car charging: %v", got)
	}
}

func TestDetectGatewayEvents(t *testing.T) {
	t0 := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	prev := store.GatewayState{
		Info:       &store.GatewayInfo{FirmwareVersion: "26.30.1", UptimeS: 7200, HasUptime: true},
		GridStatus: gateway.GridConnected,
	}
	snap := func(version, uptime, grid string, invalid ...string) *gateway.Snapshot {
		s := &gateway.Snapshot{FetchedAt: t0, Reports: map[gateway.Endpoint]gateway.Report{}}
		s.Status = gateway.Status{Version: version, UpTimeSeconds: uptime}
		s.GridStatus = gateway.GridStatus{GridStatus: grid}
		rep := gateway.Report{Endpoint: gateway.EndpointStatus}
		for _, f := range invalid {
			rep.Invalid = append(rep.Invalid, gateway.FieldError{Field: f})
		}
		s.Reports[gateway.EndpointStatus] = rep
		return s
	}
	kinds := func(evs []store.GatewayEvent) string {
		var k []string
		for _, e := range evs {
			k = append(k, e.Kind)
		}
		return strings.Join(k, ",")
	}
	for name, tc := range map[string]struct {
		s    *gateway.Snapshot
		want string
	}{
		"steady":    {snap("26.30.1 abc", "3h", gateway.GridConnected), ""},
		"firmware":  {snap("26.34.2 56d7", "3h", gateway.GridConnected), store.GatewayEventFirmwareChanged},
		"reboot":    {snap("26.30.1 abc", "10m", gateway.GridConnected), store.GatewayEventReboot},
		"both":      {snap("26.34.2 56d7", "10m", gateway.GridConnected), store.GatewayEventFirmwareChanged + "," + store.GatewayEventReboot},
		"grid":      {snap("26.30.1 abc", "3h", "SystemIslandedActive"), store.GatewayEventGridChanged},
		"untrusted": {snap("26.34.2 56d7", "10m", gateway.GridConnected, "version", "up_time_seconds"), ""},
		"bad time":  {snap("26.30.1 abc", "soon", gateway.GridConnected), ""},
	} {
		if got := kinds(detectGatewayEvents(prev, tc.s)); got != tc.want {
			t.Errorf("%s: events %q, want %q", name, got, tc.want)
		}
	}
	if evs := detectGatewayEvents(store.GatewayState{}, snap("26.34.2 x", "1s", "SystemIslandedActive")); len(evs) != 0 {
		t.Errorf("first poll produced events: %+v", evs)
	}
	next := nextGatewayState(prev, snap("26.34.2 56d7", "10m", "SystemIslandedActive"))
	if next.Info.FirmwareVersion != "26.34.2" || !next.Info.FirmwareSince.Equal(t0) || next.Info.UptimeS != 600 ||
		next.GridStatus != "SystemIslandedActive" {
		t.Errorf("next state = %+v / %+v", next, next.Info)
	}
}
