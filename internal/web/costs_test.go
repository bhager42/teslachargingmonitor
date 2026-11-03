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
	"math"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/energy"
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
	for _, p := range []string{"/costs?period=week", "/costs?period=month", "/settings/energy"} {
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
