// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package poller

import (
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
	"github.com/bhager42/teslachargingmonitor/internal/wcsim"
)

var t0 = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func snap(scenario string, e time.Duration, at time.Time) *wallconnector.Snapshot {
	sc, _ := wcsim.Lookup(scenario)
	st, _ := sc.State(e)
	return &wallconnector.Snapshot{FetchedAt: at, Version: st.Version, Vitals: st.Vitals, Lifetime: st.Lifetime,
		WifiStatus: st.WifiStatus, Reports: map[wallconnector.Endpoint]wallconnector.Report{}}
}

func kinds(evs []store.DeviceEvent) []string {
	var k []string
	for _, e := range evs {
		k = append(k, e.Kind)
	}
	return k
}

func TestFirstSightingIsBaselineOnly(t *testing.T) {
	s := snap("firmware-change", wcsim.EventAfter, t0)
	if evs := detectEvents(store.DeviceState{}, s); len(evs) != 0 {
		t.Errorf("first poll produced events: %v", kinds(evs))
	}
}

func TestDetectEvents(t *testing.T) {
	first := snap("idle", 0, t0)
	st := nextState(store.DeviceState{}, first)

	// Normal hourly poll: uptime grew by an hour — no events.
	hourly := snap("idle", time.Hour, t0.Add(time.Hour))
	if evs := detectEvents(st, hourly); len(evs) != 0 {
		t.Errorf("normal poll produced %v", kinds(evs))
	}

	// Reboot between hourly polls: uptime is only 30 s.
	reboot := snap("idle", time.Hour, t0.Add(time.Hour))
	reboot.Vitals.UptimeS = 30
	evs := detectEvents(st, reboot)
	if len(evs) != 1 || evs[0].Kind != store.EventReboot || evs[0].Details["uptime_s"] != "30" {
		t.Errorf("reboot events = %+v", evs)
	}
	// Invalid uptime must not produce a reboot event.
	reboot.Reports[wallconnector.EndpointVitals] = wallconnector.Report{Invalid: []wallconnector.FieldError{{Field: "uptime_s"}}}
	if evs := detectEvents(st, reboot); len(evs) != 0 {
		t.Errorf("invalid uptime produced %v", kinds(evs))
	}

	// Firmware + grid profile change.
	fw := snap("firmware-change", wcsim.EventAfter+time.Minute, t0.Add(wcsim.EventAfter+time.Minute))
	got := kinds(detectEvents(st, fw))
	want := map[string]bool{store.EventFirmwareChanged: true, store.EventGridProfileChanged: true, store.EventReboot: true}
	if len(got) != 3 {
		t.Errorf("firmware-change events = %v", got)
	}
	for _, k := range got {
		if !want[k] {
			t.Errorf("unexpected event %s", k)
		}
	}

	// A different Wall Connector answering at the same address.
	other := snap("idle", time.Hour, t0.Add(time.Hour))
	other.Version.SerialNumber = "OTHER0000001"
	evs = detectEvents(st, other)
	if len(evs) != 1 || evs[0].Kind != store.EventIdentityMismatch || evs[0].Details["serial"] != "••••••••0001" {
		t.Errorf("identity events = %+v", evs)
	}
}

func TestNextStateAndPlugged(t *testing.T) {
	st := nextState(store.DeviceState{}, snap("charging", time.Minute, t0))
	if !st.LastPlugged || !st.HasUptime || st.Info == nil || !st.Info.FirstSeen.Equal(t0) {
		t.Errorf("state = %+v", st)
	}
	st2 := nextState(st, snap("idle", 0, t0.Add(time.Hour)))
	if st2.LastPlugged || !st2.Info.FirstSeen.Equal(t0) || !st2.Info.LastSeen.Equal(t0.Add(time.Hour)) {
		t.Errorf("state2 = %+v", st2)
	}
	s := snap("charging", time.Minute, t0)
	s.Reports[wallconnector.EndpointVitals] = wallconnector.Report{Invalid: []wallconnector.FieldError{
		{Field: "vehicle_connected"}, {Field: "contactor_closed"},
	}}
	if plugged(s) {
		t.Error("invalid plug flags must not count as plugged")
	}
}

func TestInterval(t *testing.T) {
	m := New(nil, Config{})
	d := store.NewDevice("x", "192.168.1.17")
	for range 200 {
		iv := m.interval(d, store.DeviceState{})
		if iv < 59*time.Minute || iv > 61*time.Minute {
			t.Fatalf("idle interval %v outside 60 min ± 60 s", iv)
		}
		iv = m.interval(d, store.DeviceState{LastPlugged: true})
		if iv < 4*time.Minute+54*time.Second || iv > 5*time.Minute+6*time.Second {
			t.Fatalf("plugged interval %v outside 5 min ± 2 %%", iv)
		}
	}
	d.FastWhenPlugged = false
	if iv := m.interval(d, store.DeviceState{LastPlugged: true}); iv < 59*time.Minute {
		t.Errorf("fast polling disabled but interval = %v", iv)
	}
}
