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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// Plan step 9.4: Gateway alerts show on the Alerts page, Gateway rules
// appear once a Gateway exists, and the rule preview replays its readings.
func TestGatewayAlertsPage(t *testing.T) {
	f := newFull(t)
	ctx := context.Background()
	if _, body := f.get("/alerts"); strings.Contains(body, "Grid outage") {
		t.Fatal("Gateway rules listed without a Gateway")
	}
	g, err := f.st.CreateGateway(ctx, store.NewGateway("Powerwall", "192.168.1.20", strings.Repeat("ab", 32), []byte{1}), f.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	now := f.clk.now()
	snap := func(at time.Time, grid string) *gateway.Snapshot {
		s := &gateway.Snapshot{FetchedAt: at, Reports: map[gateway.Endpoint]gateway.Report{}}
		s.GridStatus.GridStatus, s.SOE.Percentage = grid, 60
		return s
	}
	for i, grid := range []string{gateway.GridConnected, "SystemIslandedActive", gateway.GridConnected} {
		if err := f.st.SaveGatewaySnapshot(ctx, g.ID, snap(now.Add(time.Duration(i-3)*time.Hour), grid), nil, nil, 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.engine.ProcessGateway(ctx, poller.GatewayUpdate{Gateway: g, Snapshot: snap(now, "SystemIslandedActive"), At: now}); err != nil {
		t.Fatal(err)
	}

	_, body := f.get("/alerts")
	for _, want := range []string{"Grid outage", "Powerwall", "Gateway login failed", "the home is running on the Powerwalls"} {
		if !strings.Contains(body, want) {
			t.Errorf("/alerts missing %q", want)
		}
	}

	form := url.Values{"enabled": {"1"}, "notify_resolved": {"1"}, "for_s": {"0"}, "cooldown_min": {"30"},
		"repeat_h": {"0"}, "min_samples": {"1"}, "action": {"preview"}}
	r := f.post("/alerts/rules/grid_outage", form)
	b := bodyOf(t, r)
	if r.StatusCode != 200 || !strings.Contains(b, "Powerwall · ") || !strings.Contains(b, "firing") || !strings.Contains(b, "resolved") {
		t.Errorf("gateway rule preview = %d", r.StatusCode)
	}
}
