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
