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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// seedSolar stores hourly Gateway readings alongside seed's polls: 3 kW of
// solar from 10:00 to 16:00 (half exported), the home on the grid
// otherwise; during the 3 Nov evening charge the home (with the car) is
// supplied half by solar, half by the grid. One grid outage on 6 Nov.
// It returns the solar produced and exported in [from, to), in kWh.
func seedSolar(t *testing.T, st *store.Store, loc *time.Location, from, to time.Time) (produced, exported float64) {
	t.Helper()
	ctx := context.Background()
	g, err := st.CreateGateway(ctx, store.NewGateway("Powerwall", "192.168.1.20", strings.Repeat("ab", 32), []byte{1}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	solar, load, imp, exp := 4e7, 2.5e8, 2e8, 2e6
	for at := from.AddDate(0, 0, -7).Add(-time.Hour); at.Before(to.Add(2 * time.Hour)); at = at.Add(time.Hour) {
		h := at.Add(-time.Hour).In(loc).Hour() // the hour that just ended
		var s, l, i, e float64
		switch {
		case !at.Before(time.Date(2026, 11, 3, 19, 0, 0, 0, loc)) && !at.After(time.Date(2026, 11, 3, 22, 0, 0, 0, loc)):
			s, l, i = 5000, 10000, 5000 // the car charging at 5 kW, half solar
		case h >= 10 && h < 16:
			s, l, e = 3000, 1500, 1500
		default:
			l, i = 1500, 1500
		}
		solar, load, imp, exp = solar+s, load+l, imp+i, exp+e
		if mid := at.Add(-30 * time.Minute); !mid.Before(from) && mid.Before(to) {
			produced, exported = produced+s, exported+e
		}
		snap := &gateway.Snapshot{FetchedAt: at, Reports: map[gateway.Endpoint]gateway.Report{}}
		a := &snap.Aggregates
		a.Solar.EnergyExported, a.Load.EnergyImported, a.Site.EnergyImported, a.Site.EnergyExported = solar, load, imp, exp
		a.Battery.EnergyImported, a.Battery.EnergyExported = 9e6, 7e6
		snap.GridStatus.GridStatus = gateway.GridConnected
		var evs []store.GatewayEvent
		if at.Equal(time.Date(2026, 11, 6, 12, 0, 0, 0, loc)) {
			evs = []store.GatewayEvent{{TS: at, Kind: store.GatewayEventGridChanged,
				Details: map[string]string{"from": gateway.GridConnected, "to": "SystemIslandedActive"}}}
		}
		if err := st.SaveGatewaySnapshot(ctx, g.ID, snap, nil, evs, 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	return produced / 1000, exported / 1000
}

// Plan step 9.6 acceptance: a week and a month with solar data, and a
// system without a Gateway, which shows no solar section.
func TestBuildWithSolar(t *testing.T) {
	ctx := context.Background()
	loc := newYork(t)

	plain := openStore(t)
	_, from, to := seed(t, plain, loc)
	msg, err := Build(ctx, plain, Weekly, from, to, loc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg.Text, "Solar and Powerwall") || strings.Contains(msg.HTML, "Solar and Powerwall") {
		t.Error("solar section without a Gateway")
	}

	st := openStore(t)
	seed(t, st, loc)
	produced, exported := seedSolar(t, st, loc, from, to)
	msg, err = Build(ctx, st, Weekly, from, to, loc)
	if err != nil {
		t.Fatal(err)
	}
	// 32 kWh charged this week; 4 × 5 kWh on 3 Nov were half solar = 10 kWh,
	// worth $2.00 at $0.20. Solar savings (the default method, solar used
	// at home, with no Powerwall cycling) are the solar not exported.
	for _, want := range []string{
		"== Solar and Powerwall (Powerwall) ==",
		fmt.Sprintf("%.1f kWh of solar produced, saving $%.2f", produced, 0.20*(produced-exported)),
		"Previous week: ",
		"self-sufficient",
		"Grid: ",
		"Charging: about 31 % from solar (10.0 kWh), saving $2.00",
		"Device events: 1 grid outage",
	} {
		if !strings.Contains(msg.Text, want) {
			t.Errorf("text lacks %q:\n%s", want, msg.Text)
		}
	}
	if !strings.Contains(msg.HTML, "Solar and Powerwall (Powerwall)") || !strings.Contains(msg.HTML, "about 31 % from solar") {
		t.Error("HTML lacks the solar section")
	}

	mf, mt := Monthly.Range(time.Date(2026, 12, 1, 8, 0, 0, 0, loc), loc)
	m, err := Build(ctx, st, Monthly, mf, mt, loc)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"== Solar and Powerwall (Powerwall) ==", "Previous month: ",
		"Charging: about 31 % from solar (10.0 kWh), saving $2.00", "1 grid outage"} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("monthly text lacks %q:\n%s", want, m.Text)
		}
	}

	// With net metering every kWh produced counts.
	if err := st.SetSetting(ctx, costKey, map[string]string{"currency": "$", "solar_savings": "net_metering"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if msg, err = Build(ctx, st, Weekly, from, to, loc); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("%.1f kWh of solar produced, saving $%.2f", produced, 0.20*produced); !strings.Contains(msg.Text, want) ||
		!strings.Contains(msg.HTML, want) {
		t.Errorf("net metering: text lacks %q:\n%s", want, msg.Text)
	}
}
