// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// Plan step 9.5: the dashboard's power-flow card (live over SSE) and the
// Solar page.
func TestSolarPageAndPowerFlow(t *testing.T) {
	f := newFull(t)
	ctx := context.Background()

	// Without a Gateway: no menu entry, an invitation on /solar.
	_, home := f.get("/")
	if strings.Contains(home, `href="/solar"`) {
		t.Error("Solar in the menu without a Gateway")
	}
	if strings.Count(home, `href="/settings/gateway"`) != 2 { // header and the empty-state card
		t.Error("dashboard lacks the Add Solar Gateway buttons")
	}
	if status, body := f.get("/solar"); status != 200 || !strings.Contains(body, "No Solar Gateway yet") {
		t.Fatalf("/solar without a Gateway = %d", status)
	}

	g, err := f.st.CreateGateway(ctx, store.NewGateway("Powerwall", "192.168.1.20", strings.Repeat("ab", 32), []byte{1}), f.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	// Two hours of readings every 15 min: 4 kW solar, 1.5 kW home,
	// 1 kW into the Powerwalls, 1.5 kW exported; then the latest one
	// as captured (day, battery raw 35 %).
	now := f.clk.now()
	for i := range 9 {
		h := float64(i) / 4
		s := &gateway.Snapshot{FetchedAt: now.Add(time.Duration(i-8) * 15 * time.Minute), Reports: map[gateway.Endpoint]gateway.Report{}}
		a := &s.Aggregates
		a.Solar.InstantPower, a.Load.InstantPower, a.Battery.InstantPower, a.Site.InstantPower = 4000, 1500, -1000, -1500
		a.Solar.EnergyExported, a.Load.EnergyImported = 4e7+4000*h, 2.5e8+1500*h
		a.Site.EnergyImported, a.Site.EnergyExported = 2e8, 2e6+1500*h
		a.Battery.EnergyImported, a.Battery.EnergyExported = 9e6+1000*h, 7e6
		s.SOE.Percentage = 35
		s.GridStatus.GridStatus = gateway.GridConnected
		if err := f.st.SaveGatewaySnapshot(ctx, g.ID, s, nil, nil, 1, 0); err != nil {
			t.Fatal(err)
		}
	}

	_, home = f.get("/")
	if strings.Contains(home, "Add Solar Gateway") {
		t.Error("Add Solar Gateway shown with a Gateway")
	}
	for _, want := range []string{"state-exporting", "Exporting to grid", `class="seg-self" x="0" y="0" width="100"`,
		"100 % solar and Powerwall · 0 % grid"} {
		if !strings.Contains(home, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	for _, want := range []string{`href="/solar"`, `data-gateway-id="1"`, "4.00 kW", "exporting 1.50 kW", "charging 1.00 kW",
		"32 %", "connected"} {
		if !strings.Contains(home, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	status, body := f.get("/solar")
	if status != 200 || inlineScript.MatchString(body) || strings.Contains(body, "style=") {
		t.Fatalf("/solar = %d", status)
	}
	for _, want := range []string{"Solar and Powerwall", "8.0 kWh solar · 3.0 kWh used at home", "62 % of solar used on site",
		"100 % self-sufficient", `class="bar solar"`, `class="chart-line solar"`, `class="chart-line battery"`,
		"Battery at 32 %", "Solar now 4.00 kW"} {
		if !strings.Contains(body, want) {
			t.Errorf("/solar missing %q", want)
		}
	}
	for _, p := range []string{"/solar?period=week", "/solar?period=month", "/solar?period=year"} {
		if status, _ := f.get(p); status != 200 {
			t.Errorf("%s = %d", p, status)
		}
	}

	// A Gateway poll publishes the card over SSE.
	ch, unsub := f.srv.hub.subscribe()
	defer unsub()
	f.srv.HandleGatewayUpdate(poller.GatewayUpdate{Gateway: g, At: now})
	select {
	case ev := <-ch:
		var pf PowerFlow
		if ev.name != "gateway" || json.Unmarshal(ev.data, &pf) != nil || pf.ID != g.ID || pf.Fields["solar"] != "4.00 kW" {
			t.Errorf("event %s %s", ev.name, ev.data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no gateway event")
	}
}

// The power-flow card's state line and solar/grid split.
func TestFlowState(t *testing.T) {
	w := func(v float64) *float64 { return &v }
	for _, tc := range []struct {
		name       string
		site, load *float64
		offGrid    bool
		state      string
		class      string
		known      bool
		self, grid int
	}{
		{"importing", w(1500), w(6000), false, "Using grid", "grid", true, 75, 25},
		{"all from grid", w(2000), w(2000), false, "Using grid", "grid", true, 0, 100},
		{"more than load", w(2500), w(2000), false, "Using grid", "grid", true, 0, 100},
		{"meter noise", w(30), w(2000), false, "Self-powered", "solar", true, 100, 0},
		{"exporting", w(-1500), w(1500), false, "Exporting to grid", "exporting", true, 100, 0},
		{"outage", w(0), w(900), true, "Grid outage", "fault", true, 100, 0},
		{"no site meter", nil, w(900), false, "", "", false, 0, 0},
		{"no load meter", w(500), nil, false, "Using grid", "grid", false, 0, 0},
		{"no load", w(100), w(0), false, "Using grid", "grid", true, 100, 0},
	} {
		pf := PowerFlow{OffGrid: tc.offGrid}
		pf.flowState(store.SiteReading{SiteW: tc.site, LoadW: tc.load})
		if pf.State != tc.state || pf.StateClass != tc.class || pf.MixKnown != tc.known || pf.SelfPct != tc.self || pf.GridPct != tc.grid {
			t.Errorf("%s: %+v", tc.name, pf)
		}
		if tc.known && pf.Mix == "" {
			t.Errorf("%s: no mix text", tc.name)
		}
	}
}
