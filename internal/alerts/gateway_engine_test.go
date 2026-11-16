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
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

func addTestGateway(t *testing.T, st *store.Store) store.Gateway {
	t.Helper()
	g, err := st.CreateGateway(context.Background(),
		store.NewGateway("Powerwall", "192.168.1.20", strings.Repeat("ab", 32), []byte{1}), t0.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func gwUpdate(g store.Gateway, in Input) poller.GatewayUpdate {
	return poller.GatewayUpdate{Gateway: g, Snapshot: in.GatewaySnap, Err: in.Err, Events: in.GatewayEvents, At: in.At}
}

func TestEngineProcessGateway(t *testing.T) {
	ctx := context.Background()
	st, d := openStore(t)
	g := addTestGateway(t, st)
	e := New(st, nil)
	if err := e.Load(ctx); err != nil {
		t.Fatal(err)
	}

	// An outage: grid_outage fires for the Gateway, nothing for the device.
	batch, err := e.ProcessGateway(ctx, gwUpdate(g, gwOK(t0, islanded(60))))
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 1 || batch[0].RuleKey != "grid_outage" || batch[0].GatewayID != g.ID || batch[0].DeviceID != 0 ||
		batch[0].DeviceName != "Powerwall" {
		t.Fatalf("batch = %+v", batch)
	}
	if a := e.ActiveGateway(g.ID); len(a) != 1 || a[0].RuleKey != "grid_outage" {
		t.Errorf("active gateway alerts = %+v", a)
	}
	if a := e.Active(d.ID); len(a) != 0 {
		t.Errorf("device has gateway alerts: %+v", a)
	}
	// A device poll never evaluates Gateway rules.
	if batch, err := e.Process(ctx, update(d, idle(t0))); err != nil || len(batch) != 0 {
		t.Fatalf("device poll: %+v %v", batch, err)
	}

	evs, err := st.AlertEvents(ctx, store.AlertEventFilter{GatewayID: g.ID})
	if err != nil || len(evs) != 1 || evs[0].GatewayID != g.ID || evs[0].DeviceID != 0 {
		t.Fatalf("stored events = %+v, %v", evs, err)
	}
	if evs, _ := st.AlertEvents(ctx, store.AlertEventFilter{DeviceID: d.ID}); len(evs) != 0 {
		t.Errorf("gateway event listed for the device: %+v", evs)
	}

	// State survives a restart: the grid coming back resolves it.
	e2 := New(st, nil)
	if err := e2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	batch, err = e2.ProcessGateway(ctx, gwUpdate(g, gwOK(t0.Add(15*time.Minute), nil)))
	if err != nil || len(batch) != 1 || batch[0].Kind != KindResolved {
		t.Fatalf("after reload: %+v %v", batch, err)
	}

	// A Gateway snooze holds back its notices but records them.
	if _, err := st.AddSnooze(ctx, store.Snooze{GatewayID: g.ID, Until: t0.Add(2 * time.Hour)}, t0); err != nil {
		t.Fatal(err)
	}
	batch, err = e2.ProcessGateway(ctx, gwUpdate(g, gwOK(t0.Add(30*time.Minute), islanded(60))))
	if err != nil || len(batch) != 0 {
		t.Fatalf("snoozed: %+v %v", batch, err)
	}
	if evs, _ := st.AlertEvents(ctx, store.AlertEventFilter{GatewayID: g.ID}); len(evs) != 3 || evs[0].Notified {
		t.Errorf("snoozed event not recorded as suppressed: %+v", evs)
	}

	// Deleting the Gateway removes its alert state, history and snoozes.
	if err := st.DeleteGateway(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	if evs, _ := st.AlertEvents(ctx, store.AlertEventFilter{}); len(evs) != 0 {
		t.Errorf("events after gateway delete: %+v", evs)
	}
	rows, _ := st.AlertStates(ctx)
	for _, r := range rows {
		if r.GatewayID != 0 {
			t.Errorf("state after gateway delete: %+v", r)
		}
	}
}

func TestPreviewGateway(t *testing.T) {
	ctx := context.Background()
	st, _ := openStore(t)
	g := addTestGateway(t, st)
	for i, mod := range []func(*gateway.Snapshot){nil, islanded(60), islanded(40), nil} {
		in := gwOK(t0.Add(time.Duration(i)*15*time.Minute), mod)
		if err := st.SaveGatewaySnapshot(ctx, g.ID, in.GatewaySnap, nil, nil, 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	e := New(st, nil)
	def := mustRule(t, "grid_outage")
	evs, err := e.PreviewGateway(ctx, g, "grid_outage", def.DefaultConfig(), t0.Add(-time.Minute), t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, ev := range evs {
		got = append(got, ev.Kind+":"+ev.Severity.String())
	}
	if strings.Join(got, ",") != "firing:warning,resolved:warning" {
		t.Errorf("preview = %v", got)
	}
	if _, err := e.PreviewGateway(ctx, g, "handle_temp_high", def.DefaultConfig(), t0, t0); err == nil {
		t.Error("a device rule previewed against a Gateway")
	}
}
