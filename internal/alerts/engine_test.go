// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package alerts

import (
	"context"
	"errors"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
	"github.com/bhager42/teslachargingmonitor/internal/wcsim"
)

func openStore(t *testing.T) (*store.Store, store.Device) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tcmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	d := store.NewDevice("Garage", "192.168.1.17")
	d.BreakerA = 60
	d, err = st.CreateDevice(ctx, d, t0.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return st, d
}

func update(d store.Device, in Input) poller.Update {
	return poller.Update{Device: d, Snapshot: in.Snapshot, Err: in.Err, Events: in.Events, At: in.At}
}

func TestEngineProcessPersistsAndReloads(t *testing.T) {
	ctx := context.Background()
	st, d := openStore(t)
	e := New(st, nil)
	if err := e.Load(ctx); err != nil {
		t.Fatal(err)
	}
	ch, unsub := e.Subscribe(4)
	defer unsub()

	hot := withHandle(scenario("device-alert", 0, t0), 60)
	ns, err := e.Process(ctx, update(d, hot))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Severity{}
	for _, n := range ns {
		got[n.RuleKey] = n.Severity
		if n.EventID == 0 || n.DeviceName != "Garage" || n.RuleTitle == "" {
			t.Errorf("notification incomplete: %+v", n)
		}
	}
	if got["handle_temp_high"] != Warning || got["device_alert_active"] != Warning || len(got) != 2 {
		t.Errorf("notifications = %+v", ns)
	}
	select {
	case batch := <-ch:
		if len(batch) != len(ns) {
			t.Errorf("published %d, returned %d", len(batch), len(ns))
		}
	default:
		t.Error("batch not published")
	}

	// A new engine (restart) resumes the firing state: no duplicate notice.
	e2 := New(st, nil)
	if err := e2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	ns, _ = e2.Process(ctx, update(d, withHandle(scenario("device-alert", 0, t0.Add(time.Hour)), 61)))
	if len(ns) != 0 {
		t.Errorf("restart re-notified: %+v", ns)
	}
	ns, _ = e2.Process(ctx, update(d, withHandle(idle(t0.Add(2*time.Hour)), 30)))
	if len(ns) != 2 || ns[0].Kind != KindResolved {
		t.Errorf("expected two resolved notices, got %+v", ns)
	}

	hist, err := st.AlertEvents(ctx, store.AlertEventFilter{DeviceID: d.ID})
	if err != nil || len(hist) != 4 {
		t.Fatalf("history = %d, %v", len(hist), err)
	}
	if err := st.AckAlertEvent(ctx, hist[0].ID, t0); err != nil {
		t.Fatal(err)
	}
	if un, _ := st.AlertEvents(ctx, store.AlertEventFilter{UnackedOnly: true}); len(un) != 3 {
		t.Errorf("unacked = %d", len(un))
	}
	if err := st.AckAlertEvent(ctx, hist[0].ID, t0); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("double ack err = %v", err)
	}
}

func TestEngineOverridesAndSnoozes(t *testing.T) {
	ctx := context.Background()
	st, d := openStore(t)
	e := New(st, nil)

	// Raise the warning threshold for this device only.
	cfg := mustRule(t, "handle_temp_high").DefaultConfig()
	cfg.Params = Params{"warn_c": 65}
	if err := e.SetConfig(ctx, "handle_temp_high", d.ID, cfg, t0); err != nil {
		t.Fatal(err)
	}
	if err := e.SetConfig(ctx, "handle_temp_high", 0, Config{Params: Params{"warn_c": 500}}, t0); err == nil {
		t.Error("invalid override accepted")
	}
	if err := e.SetConfig(ctx, "nope", 0, cfg, t0); err == nil {
		t.Error("unknown rule accepted")
	}
	// Disable a rule for all devices.
	off := mustRule(t, "device_alert_active").DefaultConfig()
	off.Enabled = false
	if err := e.SetConfig(ctx, "device_alert_active", 0, off, t0); err != nil {
		t.Fatal(err)
	}
	cfgs, err := e.Configs(ctx, d.ID)
	if err != nil || cfgs["handle_temp_high"].Params["warn_c"] != 65 || cfgs["handle_temp_high"].Params["crit_c"] != 70 ||
		cfgs["device_alert_active"].Enabled {
		t.Fatalf("configs = %+v, %v", cfgs["handle_temp_high"], err)
	}
	if global, _ := e.Configs(ctx, 0); global["handle_temp_high"].Params["warn_c"] != 55 {
		t.Error("device override leaked into global config")
	}

	ns, _ := e.Process(ctx, update(d, withHandle(scenario("device-alert", 0, t0), 60)))
	if len(ns) != 0 {
		t.Errorf("override/disable ignored: %+v", ns)
	}

	// Snooze everything: firing recorded but not notified.
	if _, err := st.AddSnooze(ctx, store.Snooze{DeviceID: d.ID, Until: t0.Add(2 * time.Hour), Reason: "electrician"}, t0); err != nil {
		t.Fatal(err)
	}
	ns, _ = e.Process(ctx, update(d, withHandle(idle(t0.Add(time.Hour)), 66)))
	if len(ns) != 0 {
		t.Errorf("snoozed device notified: %+v", ns)
	}
	hist, _ := st.AlertEvents(ctx, store.AlertEventFilter{})
	if len(hist) != 1 || hist[0].Notified {
		t.Errorf("history = %+v", hist)
	}
	// After the snooze ends the held-back notice is sent.
	ns, _ = e.Process(ctx, update(d, withHandle(idle(t0.Add(3*time.Hour)), 66)))
	if len(ns) != 1 || ns[0].Kind != KindFiring {
		t.Errorf("after snooze: %+v", ns)
	}
	if _, err := st.AddSnooze(ctx, store.Snooze{DeviceID: d.ID, Until: t0.Add(60 * 24 * time.Hour)}, t0); err == nil {
		t.Error("snooze longer than 30 days accepted")
	}
}

func TestPreview(t *testing.T) {
	ctx := context.Background()
	st, d := openStore(t)
	e := New(st, nil)
	for i := range 24 {
		at := t0.Add(time.Duration(i) * time.Hour)
		in := idle(at)
		if i >= 10 && i < 14 {
			in = withHandle(in, 58)
		}
		if err := st.SaveSnapshot(ctx, d.ID, in.Snapshot, nil, 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	def := mustRule(t, "handle_temp_high").DefaultConfig()
	evs, err := e.Preview(ctx, d, "handle_temp_high", def, t0, t0.Add(24*time.Hour))
	if err != nil || len(evs) != 2 || evs[0].Kind != KindFiring || !evs[0].At.Equal(t0.Add(10*time.Hour)) ||
		evs[1].Kind != KindResolved || !evs[1].At.Equal(t0.Add(14*time.Hour)) {
		t.Errorf("preview = %+v, %v", evs, err)
	}
	def.Params = Params{"warn_c": 60}
	if evs, _ := e.Preview(ctx, d, "handle_temp_high", def, t0, t0.Add(24*time.Hour)); len(evs) != 0 {
		t.Errorf("preview with 60 °C threshold = %+v", evs)
	}
	if _, err := e.Preview(ctx, d, "nope", def, t0, t0); !errors.Is(err, ErrUnknownRule) {
		t.Errorf("err = %v", err)
	}
	// Preview must not change live state or history.
	if hist, _ := st.AlertEvents(ctx, store.AlertEventFilter{}); len(hist) != 0 {
		t.Errorf("preview wrote history: %+v", hist)
	}
}

// Acceptance (plan Phase 3): the simulator's overheat scenario fires and
// resolves exactly once, end to end through the poller and the engine.
func TestOverheatFiresAndResolvesOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "tcmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	sim, err := wcsim.NewServer(wcsim.Options{Scenario: "overheat", Speed: 600}) // 10 simulated min per second
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(sim)
	defer ts.Close()
	d := store.NewDevice("Garage", ts.URL)
	d.BreakerA = 60
	if _, err := st.CreateDevice(ctx, d, time.Now()); err != nil {
		t.Fatal(err)
	}

	m := poller.New(st, poller.Config{IntervalOverride: 50 * time.Millisecond, SyncEvery: time.Hour,
		RetryDelays: []time.Duration{}, Client: wallconnector.Options{Timeout: time.Second}})
	updates, unsubU := m.Subscribe(64)
	defer unsubU()
	e := New(st, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if err := e.Load(ctx); err != nil {
		t.Fatal(err)
	}
	// The simulator runs 600× faster than real time but "for" debounce uses
	// real time; debounce is covered by TestDebounceWithFastSampling.
	cfg := mustRule(t, "handle_temp_high").DefaultConfig()
	cfg.For = 0
	if err := e.SetConfig(ctx, "handle_temp_high", 0, cfg, time.Now()); err != nil {
		t.Fatal(err)
	}
	notes, unsubN := e.Subscribe(64)
	defer unsubN()
	go func() { _ = m.Run(ctx) }()
	go e.Run(ctx, updates)

	var kinds []string
	collect := func(until func() bool, timeout time.Duration) {
		deadline := time.After(timeout)
		for !until() {
			select {
			case batch := <-notes:
				for _, n := range batch {
					if n.RuleKey == "handle_temp_high" {
						kinds = append(kinds, n.Kind+":"+n.Severity.String())
					}
				}
			case <-deadline:
				t.Fatalf("timed out; handle_temp_high notices so far: %v", kinds)
			}
		}
	}
	has := func(k string) func() bool {
		return func() bool {
			for _, x := range kinds {
				if x == k {
					return true
				}
			}
			return false
		}
	}
	collect(has("escalated:critical"), 15*time.Second) // 30→90 °C over ~3 s real
	time.Sleep(500 * time.Millisecond)                 // more hot polls: no duplicates
	_ = sim.SetScenario("idle")                        // cools to 20 °C
	collect(has("resolved:critical"), 15*time.Second)
	time.Sleep(500 * time.Millisecond)

	want := []string{"firing:warning", "escalated:critical", "resolved:critical"}
	if len(kinds) != len(want) {
		t.Fatalf("handle_temp_high notices = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("handle_temp_high notices = %v, want %v", kinds, want)
		}
	}
}
