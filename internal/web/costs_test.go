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
	"encoding/csv"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/energy"
	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
	"github.com/bhager42/teslachargingmonitor/internal/wcsim"
)

// chargeSession stores polls of a simulated charging session: unplugged
// at start, plugged for `minutes` at 5-minute polls, then unplugged.
func (f *full) chargeSession(d store.Device, start time.Time, minutes int) (deliveredWh float64) {
	f.t.Helper()
	ctx := context.Background()
	save := func(scenario string, e time.Duration, at time.Time) wallconnector.Lifetime {
		sc, _ := wcsim.Lookup(scenario)
		st, _ := sc.State(e)
		snap := &wallconnector.Snapshot{FetchedAt: at, Version: st.Version, Vitals: st.Vitals, Lifetime: st.Lifetime,
			WifiStatus: st.WifiStatus, Reports: map[wallconnector.Endpoint]wallconnector.Report{}}
		if err := f.st.SaveSnapshot(ctx, d.ID, snap, nil, 1, 0); err != nil {
			f.t.Fatal(err)
		}
		return st.Lifetime
	}
	before := save("idle", 0, start)
	var last wallconnector.Lifetime
	for m := 5; m <= minutes; m += 5 {
		last = save("charging", time.Duration(m)*time.Minute, start.Add(time.Duration(m)*time.Minute))
	}
	_ = save("idle", 0, start.Add(time.Duration(minutes+5)*time.Minute)) // unplugged; counter back to baseline (sim)
	return float64(last.EnergyWh - before.EnergyWh)
}

// Acceptance (plan Phase 6b): a simulated charging session's kWh and cost
// match the lifetime counters.
func TestCostsMatchCounters(t *testing.T) {
	f := newFull(t)
	d := f.addDevice()
	start := f.clk.now().Add(-3 * time.Hour).Truncate(time.Minute)
	wh := f.chargeSession(d, start, 60)
	ps, err := f.st.PlugSamples(context.Background(), d.ID, start.Add(-time.Hour), f.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	ss := energy.Sessions(ps, energy.NewPlan(nil, time.Local))
	if len(ss) != 1 {
		t.Fatalf("sessions = %+v", ss)
	}
	if math.Abs(ss[0].KWh*1000-wh) > 1 || math.Abs(ss[0].Cost-wh/1000*0.155) > 0.005 {
		t.Errorf("session %.3f kWh $%.2f, counters say %.3f kWh $%.2f", ss[0].KWh, ss[0].Cost, wh/1000, wh/1000*0.155)
	}
	_, body := f.get("/costs")
	cost := "$" + strconv.FormatFloat(math.Round(wh/1000*0.155*100)/100, 'f', 2, 64)
	for _, want := range []string{"Charging costs", "$0.155 per kWh", cost, "Charging sessions", "48 A", "<rect class=\"bar\""} {
		if !strings.Contains(body, want) {
			t.Errorf("/costs missing %q", want)
		}
	}
	for _, p := range []string{"/costs?period=week", "/costs?period=month", "/costs?period=year", "/settings/energy"} {
		if status, b := f.get(p); status != 200 || inlineScript.MatchString(b) || strings.Contains(b, "style=") {
			t.Errorf("%s = %d", p, status)
		}
	}
	r := f.do("GET", "/costs/sessions", nil, cookie(f.c))
	if csv := bodyOf(t, r); r.StatusCode != 200 || !strings.HasPrefix(csv, "device,start,end") || strings.Count(csv, "\n") != 2 {
		t.Errorf("sessions csv = %q", csv)
	}
	r = f.do("GET", "/costs/daily", nil, cookie(f.c))
	if csv := bodyOf(t, r); r.StatusCode != 200 || strings.Count(csv, "\n") != 366 {
		t.Errorf("daily csv lines = %d", strings.Count(csv, "\n"))
	}
	if r := f.do("GET", "/costs/nope", nil, cookie(f.c)); r.StatusCode != 404 {
		t.Errorf("unknown csv = %d", r.StatusCode)
	}
}

func TestEnergySettings(t *testing.T) {
	f := newFull(t)
	if _, body := f.get("/settings/energy"); !strings.Contains(body, "default price of $0.155") {
		t.Error("default price notice missing")
	}
	base := url.Values{"price": {"0.155"}, "currency": {"$"}, "from": {"2026-01-01"}, "fee": {"0"}}
	if r := f.post("/settings/energy", base); r.StatusCode != 303 {
		t.Fatalf("save = %d %s", r.StatusCode, bodyOf(t, r))
	}
	tou := url.Values{"price": {"0.20"}, "currency": {"€"}, "from": {"2026-11-01"}, "fee": {"12.5"},
		"offpeak_price": {"0.08"}, "offpeak_start": {"23:00"}, "offpeak_end": {"06:00"}}
	if r := f.post("/settings/energy", tou); r.StatusCode != 303 {
		t.Fatalf("save TOU = %d %s", r.StatusCode, bodyOf(t, r))
	}
	rates, _ := f.st.Rates(context.Background())
	if len(rates) != 2 || rates[1].OffPeakPrice == nil || *rates[1].OffPeakPrice != 0.08 || rates[1].OffPeakStart != 23*60 ||
		rates[1].MonthlyFee != 12.5 {
		t.Fatalf("rates = %+v", rates)
	}
	_, body := f.get("/settings/energy")
	if !strings.Contains(body, "€0.08 23:00–06:00") || !strings.Contains(body, "€12.50") {
		t.Error("history not shown")
	}
	bad := []url.Values{
		{"price": {"abc"}, "currency": {"$"}, "from": {"2026-01-01"}},
		{"price": {"-1"}, "currency": {"$"}, "from": {"2026-01-01"}},
		{"price": {"0.1"}, "currency": {"<b>"}, "from": {"2026-01-01"}},
		{"price": {"0.1"}, "currency": {"$"}, "from": {"not a date"}},
		{"price": {"0.1"}, "currency": {"$"}, "from": {"2026-01-01"}, "offpeak_price": {"0.05"}, "offpeak_start": {"23:00"}, "offpeak_end": {"23:00"}},
	}
	for i, b := range bad {
		if r := f.post("/settings/energy", b); r.StatusCode != 400 {
			t.Errorf("bad form %d = %d", i, r.StatusCode)
		}
	}
	past := url.Values{"price": {"0.155"}, "currency": {"$"}, "apply_past": {"1"}}
	_ = f.post("/settings/energy", past)
	if _, body := f.get("/settings/energy"); !strings.Contains(body, "all past data") {
		t.Error("apply-to-past rate not shown")
	}
	if r := f.post("/settings/energy/"+itoa(rates[0].ID)+"/delete", url.Values{}); r.StatusCode != 303 {
		t.Errorf("delete = %d", r.StatusCode)
	}
	if rates, _ := f.st.Rates(context.Background()); len(rates) != 2 {
		t.Errorf("after delete = %d rates", len(rates))
	}
}

func TestCardShowsCosts(t *testing.T) {
	f := newFull(t)
	d := f.addDevice()
	start := f.clk.now().Add(-2 * time.Hour).Truncate(time.Minute)
	sc, _ := wcsim.Lookup("idle")
	st, _ := sc.State(0)
	_ = f.st.SaveSnapshot(context.Background(), d.ID, &wallconnector.Snapshot{FetchedAt: start, Version: st.Version,
		Vitals: st.Vitals, Lifetime: st.Lifetime, WifiStatus: st.WifiStatus, Reports: map[wallconnector.Endpoint]wallconnector.Report{}}, nil, 1, 0)
	ch, _ := wcsim.Lookup("charging")
	cs, _ := ch.State(time.Hour)
	_ = f.st.SaveSnapshot(context.Background(), d.ID, &wallconnector.Snapshot{FetchedAt: start.Add(time.Hour), Version: cs.Version,
		Vitals: cs.Vitals, Lifetime: cs.Lifetime, WifiStatus: cs.WifiStatus, Reports: map[wallconnector.Endpoint]wallconnector.Report{}}, nil, 1, 0)
	_, body := f.get("/")
	if !strings.Contains(body, `data-field="session_cost">$1.78`) || !strings.Contains(body, "Session cost") {
		t.Errorf("session cost missing from card")
	}
}

func TestPriceFormatting(t *testing.T) {
	for in, want := range map[float64]string{0.155: "$0.155", 0.2: "$0.20", 1: "$1.00", 0.1234: "$0.1234"} {
		if got := price(in, "$"); got != want {
			t.Errorf("price(%v) = %q, want %q", in, got, want)
		}
	}
}

// The Year tab shows every year from the first one with charging data to
// the current one.
func TestCostsByYear(t *testing.T) {
	f := newFull(t)
	d := f.addDevice()
	now := f.clk.now().In(time.Local)
	if status, body := f.get("/costs?period=year"); status != 200 || strings.Count(body, `<rect class="bar"`) != 1 ||
		!strings.Contains(body, "<td>"+strconv.Itoa(now.Year())+"</td>") {
		t.Fatalf("no data: %d, %d bars", status, strings.Count(body, `<rect class="bar"`))
	}
	prev := now.Year() - 1
	whA := f.chargeSession(d, time.Date(prev, 1, 10, 12, 0, 0, 0, time.Local), 60)
	start := now.Add(-3 * time.Hour).Truncate(time.Minute)
	whB := f.chargeSession(d, start, 30)
	prevWh, thisWh := whA, whB
	if start.Year() == prev { // the test runs in the first hours of a year
		prevWh, thisWh = whA+whB, 0
	}
	_, body := f.get("/costs?period=year")
	if n := strings.Count(body, `<rect class="bar"`); n != 2 {
		t.Errorf("bars = %d, want 2 (%d and %d)", n, prev, now.Year())
	}
	cost := func(wh float64) string {
		return "$" + strconv.FormatFloat(math.Round(wh/1000*0.155*100)/100, 'f', 2, 64)
	}
	for _, want := range []string{
		"Cost per year", "Charging cost per year, all time",
		"<td>" + strconv.Itoa(prev) + "</td><td>" + strconv.FormatFloat(prevWh/1000, 'f', 1, 64) + "</td><td>" + cost(prevWh) + "</td>",
		"<td>" + strconv.Itoa(now.Year()) + "</td><td>" + strconv.FormatFloat(thisWh/1000, 'f', 1, 64) + "</td><td>" + cost(thisWh) + "</td>",
		`href="?period=year" aria-current="page"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/costs?period=year missing %q", want)
		}
	}
}

// Plan step 9.3: with a Gateway, the Costs page and the CSV exports split
// charging into solar, Powerwall and grid and show the solar savings.
func TestCostsShowSolarSplit(t *testing.T) {
	f := newFull(t)
	d := f.addDevice()
	ctx := context.Background()
	start := f.clk.now().Add(-3 * time.Hour).Truncate(time.Minute)

	_, body := f.get("/costs")
	if strings.Contains(body, "Solar kWh") {
		t.Fatal("solar columns shown without a Gateway")
	}

	g, err := f.st.CreateGateway(ctx, store.NewGateway("Powerwall", "192.168.1.20", strings.Repeat("ab", 32), []byte{1}), f.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	// Every 15 min from an hour before the session: 4 kW solar and 4 kW
	// from the grid, nothing exported or stored, so half of it is solar.
	for i := range 10 {
		h := float64(i) / 4
		snap := &gateway.Snapshot{FetchedAt: start.Add(-time.Hour + time.Duration(i)*15*time.Minute),
			Reports: map[gateway.Endpoint]gateway.Report{}}
		snap.Aggregates.Solar.EnergyExported = 4e7 + 4000*h
		snap.Aggregates.Site.EnergyImported = 2e8 + 4000*h
		snap.Aggregates.Site.EnergyExported = 2e6
		snap.Aggregates.Battery.EnergyImported = 9e6
		snap.Aggregates.Battery.EnergyExported = 7e6
		if err := f.st.SaveGatewaySnapshot(ctx, g.ID, snap, nil, nil, 1, 0); err != nil {
			t.Fatal(err)
		}
	}
	wh := f.chargeSession(d, start, 60)
	cost := wh / 1000 * 0.155

	_, body = f.get("/costs")
	for _, want := range []string{"Solar kWh", "Powerwall kWh", "Solar savings", "≈ 50 % solar, saved",
		"figures are approximate", fmt.Sprintf("%.1f", wh/2000), money(cost/2, "$")} {
		if !strings.Contains(body, want) {
			t.Errorf("/costs missing %q", want)
		}
	}

	r := f.do("GET", "/costs/sessions", nil, cookie(f.c))
	rows, err := csv.NewReader(r.Body).ReadAll()
	_ = r.Body.Close()
	if err != nil || len(rows) != 2 {
		t.Fatalf("sessions CSV: %v %v", rows, err)
	}
	if got := strings.Join(rows[0][7:], ","); got != "attributed_kwh,solar_kwh,powerwall_kwh,grid_kwh,solar_savings" {
		t.Errorf("CSV header = %q", got)
	}
	num := func(s string) float64 { v, _ := strconv.ParseFloat(s, 64); return v }
	row := rows[1]
	if math.Abs(num(row[8])-wh/2000) > 0.002 || num(row[9]) != 0 || math.Abs(num(row[10])-wh/2000) > 0.002 ||
		math.Abs(num(row[8])+num(row[9])+num(row[10])-num(row[4])) > 0.002 {
		t.Errorf("CSV split = %v (session %.3f kWh)", row, wh/1000)
	}

	r = f.do("GET", "/costs/daily", nil, cookie(f.c))
	daily, _ := csv.NewReader(r.Body).ReadAll()
	_ = r.Body.Close()
	var attributed float64
	for _, row := range daily[1:] {
		attributed += num(row[3])
		if num(row[1]) == 0 && row[4] != "" {
			t.Errorf("a day without charging has a solar split: %v", row)
		}
	}
	if math.Abs(attributed-wh/1000) > 0.002 {
		t.Errorf("daily CSV attributed %.3f kWh, want %.3f", attributed, wh/1000)
	}
}
