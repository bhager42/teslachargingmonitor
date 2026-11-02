// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package poller

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wcsim"
)

type harness struct {
	st  *store.Store
	sim *wcsim.Server
	url string
}

func newHarness(t *testing.T, scenario string) *harness {
	t.Helper()
	return newHarnessSpeed(t, scenario, 1)
}

func newHarnessSpeed(t *testing.T, scenario string, speed float64) *harness {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tcmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	sim, err := wcsim.NewServer(wcsim.Options{Scenario: scenario, Speed: speed})
	if err != nil {
		t.Fatal(err)
	}
	sim.SlowDelay = time.Second
	ts := httptest.NewServer(sim)
	t.Cleanup(ts.Close)
	return &harness{st: st, sim: sim, url: ts.URL}
}

func (h *harness) addDevice(t *testing.T) store.Device {
	t.Helper()
	d, err := h.st.CreateDevice(context.Background(), store.NewDevice("Garage", h.url), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func fastConfig() Config {
	return Config{
		RetryDelays:      []time.Duration{10 * time.Millisecond, 10 * time.Millisecond},
		IntervalOverride: time.Hour, // only the initial poll unless triggered
		PollNowGap:       time.Nanosecond,
		SyncEvery:        time.Hour,
	}
}

func next(t *testing.T, ch <-chan Update) Update {
	t.Helper()
	select {
	case u := <-ch:
		return u
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for poll update")
		return Update{}
	}
}

func run(t *testing.T, m *Manager) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = m.Run(ctx); close(done) }()
	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("manager did not stop")
		}
	}
}

func TestPollSuccessStoresAndPublishes(t *testing.T) {
	h := newHarnessSpeed(t, "charging", 3600) // 1 real second = 1 simulated hour
	d := h.addDevice(t)
	m := New(h.st, fastConfig())
	ch, unsub := m.Subscribe(4)
	defer unsub()
	stop := run(t, m)
	defer stop()

	u := next(t, ch)
	if u.Err != nil || u.Snapshot == nil || u.Attempts != 1 || u.Device.ID != d.ID {
		t.Fatalf("update = %+v", u)
	}
	if !u.Snapshot.Vitals.ContactorClosed || u.Next.Sub(u.At) != time.Hour {
		t.Errorf("snapshot/next wrong: %+v next=%v", u.Snapshot.Vitals, u.Next.Sub(u.At))
	}
	st, err := h.st.LatestState(context.Background(), d.ID)
	if err != nil || st.Info == nil || !st.LastPlugged {
		t.Errorf("stored state = %+v, %v", st, err)
	}
	stats, _ := h.st.Stats(context.Background())
	if stats.Rows["readings_vitals"] != 1 || stats.Rows["raw_payloads"] != 4 || stats.Rows["poll_log"] != 1 {
		t.Errorf("rows = %v", stats.Rows)
	}

	// Poll now triggers another poll; a firmware update (simulated 30 min
	// later) is detected against the stored baseline.
	_ = h.sim.SetScenario("firmware-change")
	time.Sleep(500 * time.Millisecond)
	if err := m.PollNow(d.ID); err != nil {
		t.Fatal(err)
	}
	u = next(t, ch)
	got := map[string]bool{}
	for _, ev := range u.Events {
		got[ev.Kind] = true
	}
	if u.Err != nil || !got[store.EventFirmwareChanged] || !got[store.EventGridProfileChanged] {
		t.Errorf("expected firmware and grid profile events, got %+v", u.Events)
	}
	evs, _ := h.st.Events(context.Background(), d.ID, time.Time{}, 10)
	if len(evs) != len(u.Events) {
		t.Errorf("stored %d events, published %d", len(evs), len(u.Events))
	}
}

func TestRetriesThenFailure(t *testing.T) {
	h := newHarness(t, "offline")
	d := h.addDevice(t)
	m := New(h.st, fastConfig())
	ch, unsub := m.Subscribe(4)
	defer unsub()
	stop := run(t, m)
	defer stop()

	u := next(t, ch)
	if u.Err == nil || u.Attempts != 3 || u.Snapshot != nil {
		t.Fatalf("update = %+v", u)
	}
	log, _ := h.st.PollLog(context.Background(), d.ID, 10)
	if len(log) != 3 || log[0].OK || log[0].Error == "" {
		t.Errorf("poll log = %+v", log)
	}
}

func TestRecoveryDuringRetry(t *testing.T) {
	h := newHarness(t, "offline")
	h.addDevice(t)
	cfg := fastConfig()
	cfg.RetryDelays = []time.Duration{300 * time.Millisecond}
	m := New(h.st, cfg)
	ch, unsub := m.Subscribe(4)
	defer unsub()
	stop := run(t, m)
	defer stop()
	time.Sleep(100 * time.Millisecond)
	_ = h.sim.SetScenario("idle")
	u := next(t, ch)
	if u.Err != nil || u.Attempts != 2 {
		t.Errorf("update = %+v", u)
	}
}

func TestSyncFollowsConfiguration(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, "idle")
	m := New(h.st, fastConfig())
	ch, unsub := m.Subscribe(8)
	defer unsub()
	stop := run(t, m)
	defer stop()

	if len(m.Devices()) != 0 {
		t.Fatal("no devices expected")
	}
	d := h.addDevice(t)
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	next(t, ch)
	if ids := m.Devices(); len(ids) != 1 || ids[0] != d.ID {
		t.Errorf("devices = %v", ids)
	}

	// Editing the device restarts its worker, which polls immediately.
	d.Name = "Garage UWC"
	if _, err := h.st.UpdateDevice(ctx, d, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_ = m.Reload(ctx)
	if u := next(t, ch); u.Device.Name != "Garage UWC" {
		t.Errorf("restarted worker uses %q", u.Device.Name)
	}

	d.Enabled = false
	d.Name = "Garage UWC"
	if _, err := h.st.UpdateDevice(ctx, d, time.Now().Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	_ = m.Reload(ctx)
	if len(m.Devices()) != 0 {
		t.Error("disabled device still polled")
	}
	if err := m.PollNow(d.ID); !errors.Is(err, ErrUnknownDevice) {
		t.Errorf("PollNow on disabled device err = %v", err)
	}
}

func TestPollNowRateLimit(t *testing.T) {
	h := newHarness(t, "idle")
	d := h.addDevice(t)
	cfg := fastConfig()
	cfg.PollNowGap = time.Hour
	m := New(h.st, cfg)
	ch, unsub := m.Subscribe(4)
	defer unsub()
	stop := run(t, m)
	defer stop()
	next(t, ch)
	if err := m.PollNow(d.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.PollNow(d.ID); !errors.Is(err, ErrRateLimited) {
		t.Errorf("second PollNow err = %v", err)
	}
}

func TestNoGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()
	func() {
		h := newHarness(t, "idle")
		h.addDevice(t)
		m := New(h.st, fastConfig())
		ch, unsub := m.Subscribe(1)
		stop := run(t, m)
		next(t, ch)
		stop()
		unsub()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Errorf("goroutines before=%d after=%d", before, after)
	}
}

// Regression: Reload from a short-lived (HTTP request) context must not tie
// the worker's lifetime to that context.
func TestReloadFromShortLivedContext(t *testing.T) {
	h := newHarness(t, "idle")
	cfg := fastConfig()
	cfg.IntervalOverride = 50 * time.Millisecond
	m := New(h.st, cfg)
	ch, unsub := m.Subscribe(8)
	defer unsub()
	stop := run(t, m)
	defer stop()
	if len(m.Devices()) != 0 {
		t.Fatal("unexpected device")
	}
	h.addDevice(t)
	reqCtx, cancel := context.WithCancel(context.Background())
	if err := m.Reload(reqCtx); err != nil {
		t.Fatal(err)
	}
	cancel() // the HTTP request that saved the device has finished
	next(t, ch)
	next(t, ch) // still polling after the request context was canceled
	if len(m.Devices()) != 1 {
		t.Error("worker stopped")
	}
}
