// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package digest

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/energy"
	"github.com/bhager42/teslachargingmonitor/internal/notify"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
	"github.com/bhager42/teslachargingmonitor/internal/wcsim"
)

func newYork(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no time zone data:", err)
	}
	return loc
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tcmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func snap(t *testing.T, scenario string, at time.Time, wh int64, handleC float64) *wallconnector.Snapshot {
	t.Helper()
	sc, _ := wcsim.Lookup(scenario)
	s, _ := sc.State(10 * time.Minute)
	s.Lifetime.EnergyWh = wh
	s.Vitals.HandleTempC = handleC
	return &wallconnector.Snapshot{FetchedAt: at, Version: s.Version, Vitals: s.Vitals, Lifetime: s.Lifetime,
		WifiStatus: s.WifiStatus, Reports: map[wallconnector.Endpoint]wallconnector.Report{},
		Raw: map[wallconnector.Endpoint][]byte{}}
}

// seed stores two weeks of hourly polls for a device: one 10 kWh charge
// in the earlier week (which has the DST change on 1 Nov 2026) and two
// charges (20 + 12 kWh) in the week the digest covers.
func seed(t *testing.T, st *store.Store, loc *time.Location) (store.Device, time.Time, time.Time) {
	t.Helper()
	ctx := context.Background()
	d, err := st.CreateDevice(ctx, store.NewDevice("Garage & Co", "192.168.1.10"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRate(ctx, energy.Rate{Price: 0.20, EffectiveFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, loc)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 11, 2, 0, 0, 0, 0, loc)
	to := time.Date(2026, 11, 9, 0, 0, 0, 0, loc)
	charging := map[time.Time]int64{} // poll time -> Wh delivered since the previous poll
	addCharge := func(start time.Time, hours int, kWh float64) {
		for i := 1; i <= hours; i++ {
			charging[start.Add(time.Duration(i)*time.Hour)] = int64(kWh * 1000 / float64(hours))
		}
	}
	addCharge(time.Date(2026, 10, 28, 18, 0, 0, 0, loc), 2, 10)
	addCharge(time.Date(2026, 11, 3, 18, 0, 0, 0, loc), 4, 20)
	addCharge(time.Date(2026, 11, 5, 1, 0, 0, 0, loc), 3, 12)
	wh := int64(1_000_000)
	for at := from.AddDate(0, 0, -7).Add(-time.Hour); at.Before(to.Add(2 * time.Hour)); at = at.Add(time.Hour) {
		scenario, handle := "idle", 25.0
		if add, ok := charging[at]; ok {
			wh += add
			scenario, handle = "charging", 41.0
		}
		if at.Equal(time.Date(2026, 11, 3, 21, 0, 0, 0, loc)) {
			handle = 47.5 // the week's maximum
		}
		if at.Equal(time.Date(2026, 10, 28, 19, 0, 0, 0, loc)) {
			handle = 60 // previous week: must not count
		}
		var evs []store.DeviceEvent
		if at.Equal(time.Date(2026, 11, 6, 3, 0, 0, 0, loc)) {
			evs = []store.DeviceEvent{{Kind: store.EventReboot, TS: at}}
		}
		if err := st.SaveSnapshot(ctx, d.ID, snap(t, scenario, at, wh, handle), evs, 1, time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RecordPollFailure(ctx, d.ID, time.Date(2026, 11, 7, 4, 30, 0, 0, loc), 1, time.Second,
		errors.New("timeout")); err != nil {
		t.Fatal(err)
	}
	evs := []store.AlertEvent{
		{RuleKey: "handle_temp_high", DeviceID: d.ID, TS: time.Date(2026, 11, 3, 21, 0, 0, 0, loc), Kind: "firing", Severity: "warning", Message: "hot"},
		{RuleKey: "handle_temp_high", DeviceID: d.ID, TS: time.Date(2026, 11, 3, 22, 0, 0, 0, loc), Kind: "resolved", Severity: "warning", Message: "ok"},
		{RuleKey: "handle_temp_high", DeviceID: d.ID, TS: time.Date(2026, 11, 5, 2, 0, 0, 0, loc), Kind: "firing", Severity: "warning", Message: "hot"},
		{RuleKey: "device_unreachable", DeviceID: d.ID, TS: time.Date(2026, 11, 7, 4, 40, 0, 0, loc), Kind: "firing", Severity: "critical", Message: "gone"},
		{RuleKey: "device_unreachable", DeviceID: d.ID, TS: time.Date(2026, 11, 7, 5, 0, 0, 0, loc), Kind: "repeat", Severity: "critical", Message: "gone"},
		{RuleKey: "wifi_weak", DeviceID: d.ID, TS: time.Date(2026, 10, 30, 5, 0, 0, 0, loc), Kind: "firing", Severity: "info", Message: "last week"},
		{RuleKey: "wifi_weak", DeviceID: d.ID, TS: time.Date(2026, 11, 9, 1, 0, 0, 0, loc), Kind: "firing", Severity: "info", Message: "this week"},
	}
	if err := st.SaveAlertResult(ctx, nil, evs, time.Now()); err != nil {
		t.Fatal(err)
	}
	return d, from, to
}

func TestWeek(t *testing.T) {
	loc := newYork(t)
	for _, now := range []time.Time{
		time.Date(2026, 11, 9, 0, 0, 0, 0, loc), time.Date(2026, 11, 9, 8, 0, 0, 0, loc),
		time.Date(2026, 11, 15, 23, 59, 0, 0, loc),
	} {
		from, to := Week(now, loc)
		if !from.Equal(time.Date(2026, 11, 2, 0, 0, 0, 0, loc)) || !to.Equal(time.Date(2026, 11, 9, 0, 0, 0, 0, loc)) {
			t.Errorf("Week(%v) = %v – %v", now, from, to)
		}
	}
	// The week with the DST change is 169 hours long.
	if from, to := Week(time.Date(2026, 11, 3, 0, 0, 0, 0, loc), loc); to.Sub(from) != 169*time.Hour {
		t.Errorf("DST week = %v", to.Sub(from))
	}
}

func TestBuild(t *testing.T) {
	loc := newYork(t)
	st := openStore(t)
	_, from, to := seed(t, st, loc)
	msg, err := Build(context.Background(), st, from, to, loc)
	if err != nil {
		t.Fatal(err)
	}
	want := "Weekly summary Mon 2 Nov – Sun 8 Nov 2026: 32.0 kWh, $6.40, 3 alerts"
	if msg.Subject != want {
		t.Errorf("Subject = %q, want %q", msg.Subject, want)
	}
	for _, s := range []string{
		"Charging: 32.0 kWh, $6.40 · 2 charging sessions",
		"== Garage & Co ==",
		"Previous week: 10.0 kWh, $2.00",
		"168 successful polls, 1 failed attempt",
		"handle 47.5 °C",
		"Device events: 1 restart",
		"[critical] Wall Connector unreachable — Garage & Co: 1 time, last Sat 7 Nov 04:40",
		"Handle temperature high — Garage & Co: 2 times, last Thu 5 Nov 02:00",
	} {
		if !strings.Contains(msg.Text, s) {
			t.Errorf("text lacks %q:\n%s", s, msg.Text)
		}
	}
	if strings.Contains(msg.Text, "60.0 °C") || strings.Contains(msg.Text, "wifi") || strings.Contains(msg.Text, "Wi-Fi") {
		t.Errorf("text includes data from outside the week:\n%s", msg.Text)
	}
	if i, j := strings.Index(msg.Text, "unreachable"), strings.Index(msg.Text, "Handle temperature"); i < 0 || j < i {
		t.Error("critical alerts are not listed first")
	}
	if !strings.Contains(msg.HTML, "Garage &amp; Co") || strings.Contains(msg.HTML, "Garage & Co") {
		t.Error("HTML does not escape the device name")
	}

	// Temperatures follow the display setting.
	if err := st.SetSetting(context.Background(), displayKey, map[string]string{"temp_unit": "F"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if msg, _ := Build(context.Background(), st, from, to, loc); !strings.Contains(msg.Text, "handle 117.5 °F") {
		t.Errorf("°F not applied:\n%s", msg.Text)
	}
}

func TestBuildEmpty(t *testing.T) {
	loc := newYork(t)
	st := openStore(t)
	from, to := Week(time.Date(2026, 11, 9, 8, 0, 0, 0, loc), loc)
	msg, err := Build(context.Background(), st, from, to, loc)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"0.0 kWh, $0.00", "No Wall Connector is configured yet.", "No alerts this week."} {
		if !strings.Contains(msg.Text, s) {
			t.Errorf("empty digest lacks %q:\n%s", s, msg.Text)
		}
	}
}

type fakeQueue struct {
	mu   sync.Mutex
	msgs []notify.Message
	n    int
}

func (q *fakeQueue) EnqueueDigest(_ context.Context, m notify.Message) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.msgs = append(q.msgs, m)
	return q.n, nil
}

func TestScheduler(t *testing.T) {
	loc := newYork(t)
	st := openStore(t)
	q := &fakeQueue{} // no channel opted in at first
	var now time.Time
	sched := func() *Scheduler {
		return NewScheduler(st, q, Config{Location: loc, Now: func() time.Time { return now }})
	}
	s := sched()
	tick := func(at time.Time, want int) {
		t.Helper()
		now = at
		n, err := s.Tick(context.Background())
		if err != nil || n != want {
			t.Fatalf("Tick at %v = %d, %v; want %d", at, n, err, want)
		}
	}
	// First start (a Sunday): the week before last is caught up, but no
	// channel wants it.
	tick(time.Date(2026, 11, 8, 23, 0, 0, 0, loc), 0)
	q.n = 1
	tick(time.Date(2026, 11, 8, 23, 30, 0, 0, loc), -1)
	if d := s.next(); d != time.Hour {
		t.Errorf("next on Sunday night = %v", d)
	}
	tick(time.Date(2026, 11, 9, 7, 30, 0, 0, loc), -1) // Monday, too early
	if d := s.next(); d != 30*time.Minute {
		t.Errorf("next at 07:30 = %v", d)
	}
	tick(time.Date(2026, 11, 9, 8, 0, 0, 0, loc), 1) // due
	if len(q.msgs) != 2 || !strings.Contains(q.msgs[1].Subject, "Mon 2 Nov – Sun 8 Nov 2026") {
		t.Fatalf("queued = %+v", q.msgs)
	}
	tick(time.Date(2026, 11, 9, 9, 0, 0, 0, loc), -1) // already queued
	s = sched()                                       // restart
	tick(time.Date(2026, 11, 11, 12, 0, 0, 0, loc), -1)

	// Down over the next Monday: caught up on Wednesday.
	tick(time.Date(2026, 11, 18, 12, 0, 0, 0, loc), 1)
	if len(q.msgs) != 3 || !strings.Contains(q.msgs[2].Subject, "Mon 9 Nov – Sun 15 Nov 2026") {
		t.Fatalf("catch-up = %+v", q.msgs[2:])
	}

	// No channel opted in: still recorded, so enabling it later in the
	// week does not send an old summary.
	q.n = 0
	tick(time.Date(2026, 11, 23, 8, 5, 0, 0, loc), 0)
	q.n = 1
	tick(time.Date(2026, 11, 24, 8, 5, 0, 0, loc), -1)
}

func TestEventCount(t *testing.T) {
	for _, c := range []struct {
		kind string
		n    int
		want string
	}{
		{store.EventIdentityMismatch, 1, "1 identity mismatch"},
		{store.EventIdentityMismatch, 2, "2 identity mismatches"},
		{store.EventReboot, 3, "3 restarts"},
		{"some_kind", 2, "2 some kinds"},
	} {
		if got := eventCount(c.kind, c.n); got != c.want {
			t.Errorf("eventCount(%q, %d) = %q, want %q", c.kind, c.n, got, c.want)
		}
	}
}
