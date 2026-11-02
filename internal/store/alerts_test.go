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
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

func TestRuleOverrides(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	o := RuleOverride{RuleKey: "handle_temp_high", DeviceID: 0, Enabled: true, Params: map[string]float64{"warn_c": 60},
		For: time.Minute, Cooldown: time.Hour, Repeat: 6 * time.Hour, MinSamples: 2, NotifyResolved: true}
	if err := s.SaveRuleOverride(ctx, o, t0); err != nil {
		t.Fatal(err)
	}
	o.Params = map[string]float64{"warn_c": 62}
	if err := s.SaveRuleOverride(ctx, o, t0); err != nil { // replace
		t.Fatal(err)
	}
	if err := s.SaveRuleOverride(ctx, RuleOverride{RuleKey: "wifi_weak", MinSamples: 1}, t0); err != nil {
		t.Fatal(err)
	}
	list, err := s.RuleOverrides(ctx)
	if err != nil || len(list) != 2 || list[0].Params["warn_c"] != 62 || list[0].Cooldown != time.Hour ||
		list[0].MinSamples != 2 || !list[0].UpdatedAt.Equal(t0) || list[1].Params == nil {
		t.Fatalf("overrides = %+v, %v", list, err)
	}
	if err := s.DeleteRuleOverride(ctx, "handle_temp_high", 0); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.RuleOverrides(ctx); len(list) != 1 {
		t.Errorf("after delete = %+v", list)
	}
	if err := s.SaveRuleOverride(ctx, RuleOverride{RuleKey: "x", MinSamples: 0}, t0); err == nil {
		t.Error("min_samples 0 accepted by schema")
	}
}

func TestAlertStateAndEvents(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	d := addDevice(t, s)
	v := 61.5
	evs := []AlertEvent{
		{RuleKey: "handle_temp_high", DeviceID: d.ID, TS: t0, Kind: "firing", Severity: "warning", Message: "hot", Value: &v, Notified: true},
		{RuleKey: "wifi_weak", DeviceID: d.ID, TS: t0.Add(time.Minute), Kind: "firing", Severity: "info", Message: "weak", Notified: false},
	}
	states := []AlertStateRow{{RuleKey: "handle_temp_high", DeviceID: d.ID, JSON: []byte(`{"status":"firing"}`)}}
	if err := s.SaveAlertResult(ctx, states, evs, t0); err != nil {
		t.Fatal(err)
	}
	if evs[0].ID == 0 || evs[1].ID == 0 {
		t.Error("event IDs not filled in")
	}
	rows, err := s.AlertStates(ctx)
	if err != nil || len(rows) != 1 || string(rows[0].JSON) != `{"status":"firing"}` {
		t.Errorf("states = %+v, %v", rows, err)
	}
	got, err := s.AlertEvents(ctx, AlertEventFilter{DeviceID: d.ID, Limit: 10})
	if err != nil || len(got) != 2 || got[0].RuleKey != "wifi_weak" || got[1].Value == nil || *got[1].Value != 61.5 ||
		got[0].Value != nil || got[0].Notified {
		t.Fatalf("events = %+v, %v", got, err)
	}
	if got, _ := s.AlertEvents(ctx, AlertEventFilter{Since: t0.Add(30 * time.Second)}); len(got) != 1 {
		t.Errorf("since filter: %d", len(got))
	}
	if got, _ := s.AlertEvents(ctx, AlertEventFilter{DeviceID: 999}); len(got) != 0 {
		t.Errorf("device filter: %d", len(got))
	}
	if err := s.AckAlertEvent(ctx, evs[0].ID, t0); err != nil {
		t.Fatal(err)
	}
	got, _ = s.AlertEvents(ctx, AlertEventFilter{})
	if got[1].AckedAt == nil || !got[1].AckedAt.Equal(t0) {
		t.Errorf("ack not stored: %+v", got[1])
	}

	// Alert history follows the events retention; state is removed with the device.
	if res, _ := s.Prune(ctx, t0.Add(800*24*time.Hour), DefaultRetention()); res["alert_events"] != 2 {
		t.Errorf("alert events pruned = %d", res["alert_events"])
	}
	_ = s.DeleteDevice(ctx, d.ID)
	if rows, _ := s.AlertStates(ctx); len(rows) != 0 {
		t.Error("alert state survived device deletion")
	}
}

func TestSnoozes(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	d := addDevice(t, s)
	long := string(make([]rune, 300))
	sn, err := s.AddSnooze(ctx, Snooze{DeviceID: d.ID, Until: t0.Add(2 * time.Hour), Reason: long}, t0)
	if err != nil || sn.ID == 0 {
		t.Fatal(err)
	}
	if _, err := s.AddSnooze(ctx, Snooze{DeviceID: d.ID, RuleKey: "wifi_weak", Until: t0.Add(time.Hour)}, t0); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []time.Time{t0, t0.Add(-time.Hour), t0.Add(MaxSnooze + time.Hour)} {
		if _, err := s.AddSnooze(ctx, Snooze{DeviceID: d.ID, Until: bad}, t0); err == nil {
			t.Errorf("snooze until %v accepted", bad)
		}
	}
	active, err := s.ActiveSnoozes(ctx, d.ID, t0.Add(90*time.Minute))
	if err != nil || len(active) != 1 || active[0].RuleKey != "" || len([]rune(active[0].Reason)) != 200 {
		t.Errorf("active = %+v, %v", active, err)
	}
	if err := s.DeleteSnooze(ctx, sn.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSnooze(ctx, sn.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("double delete = %v", err)
	}
	// Maintenance removes expired snoozes.
	if _, err := s.Maintain(ctx, t0.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_snoozes").Scan(&n)
	if n != 0 {
		t.Errorf("%d expired snoozes left", n)
	}
}

func TestHistory(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	d := addDevice(t, s)
	for i := range 3 {
		at := t0.Add(time.Duration(i) * time.Hour)
		snap := snapshotFrom(t, "charging", time.Duration(i)*time.Minute, at)
		var evs []DeviceEvent
		if i == 2 {
			snap.Reports[wallconnector.EndpointVitals] = wallconnector.Report{
				Invalid: []wallconnector.FieldError{{Field: "handle_temp_c"}},
			}
			evs = []DeviceEvent{{TS: at, Kind: EventReboot, Details: map[string]string{"uptime_s": "1"}}}
		}
		if err := s.SaveSnapshot(ctx, d.ID, snap, evs, 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	h, err := s.History(ctx, d.ID, t0, t0.Add(3*time.Hour))
	if err != nil || len(h) != 3 {
		t.Fatalf("history = %d, %v", len(h), err)
	}
	first := h[0].Snapshot
	if !first.FetchedAt.Equal(t0) || !first.Vitals.ContactorClosed || first.Vitals.VehicleCurrentA != 47.9 ||
		first.Vitals.RelayK1V == nil || first.Lifetime.EnergyWh == 0 || first.WifiStatus.WifiRSSI != -47 ||
		!first.WifiStatus.Internet || !first.Reports[wallconnector.EndpointVitals].Clean() {
		t.Errorf("first point = %+v", first)
	}
	last := h[2]
	if !last.Snapshot.Reports[wallconnector.EndpointVitals].IsInvalid("handle_temp_c") || len(last.Events) != 1 ||
		last.Events[0].Kind != EventReboot {
		t.Errorf("last point = %+v events=%+v", last.Snapshot.Reports, last.Events)
	}
	if h, _ := s.History(ctx, d.ID, t0.Add(time.Hour), t0.Add(2*time.Hour)); len(h) != 1 {
		t.Errorf("range filter: %d", len(h))
	}
}
