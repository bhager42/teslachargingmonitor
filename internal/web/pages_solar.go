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
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/energy"
	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// Phase 9 step 5: the dashboard's power-flow card and the Solar page.
// Like the device cards, every value is formatted in Go; the browser only
// sets textContent.

// PowerFlow is the dashboard view of the Backup Gateway.
type PowerFlow struct {
	ID        int64             `json:"id"`
	Name      string            `json:"name"`
	Fields    map[string]string `json:"fields"`
	Updated   string            `json:"updated"`
	UpdatedAt time.Time         `json:"updated_at"`
	Stale     bool              `json:"stale"`
	OffGrid   bool              `json:"off_grid"`
	// State is a one-line summary like a Wall Connector's "Plugged in";
	// StateClass (solar | exporting | grid | fault | unknown) colors it.
	State      string `json:"state"`
	StateClass string `json:"state_class"`
	// SelfPct and GridPct split what the home (car included) uses right now
	// between solar plus Powerwall and the grid, for the source bar
	// (MixKnown false: no bar). Mix is the same as text.
	MixKnown bool   `json:"mix_known"`
	SelfPct  int    `json:"self_pct"`
	GridPct  int    `json:"grid_pct"`
	Mix      string `json:"mix"`
}

// gridIdleW is the grid power treated as neither importing nor exporting
// (meter noise and the Powerwall's control margin).
const gridIdleW = 50

// flowState sets the card's state line and source split from a reading.
func (pf *PowerFlow) flowState(r store.SiteReading) {
	switch {
	case pf.OffGrid:
		pf.State, pf.StateClass = tr.T("flow.state_outage"), "fault"
	case r.SiteW == nil:
		return
	case *r.SiteW > gridIdleW:
		pf.State, pf.StateClass = tr.T("flow.state_grid"), "grid"
	case *r.SiteW < -gridIdleW:
		pf.State, pf.StateClass = tr.T("flow.state_exporting"), "exporting"
	default:
		pf.State, pf.StateClass = tr.T("flow.state_self"), "solar"
	}
	switch {
	case r.SiteW == nil || r.LoadW == nil:
		return
	case *r.LoadW <= 0 || *r.SiteW <= gridIdleW:
		pf.SelfPct = 100
	default:
		pf.SelfPct = int(math.Round(100 * math.Max(0, 1 - *r.SiteW / *r.LoadW)))
	}
	pf.GridPct, pf.MixKnown = 100-pf.SelfPct, true
	pf.Mix = tr.T("flow.mix", "self", strconv.Itoa(pf.SelfPct), "grid", strconv.Itoa(pf.GridPct))
}

// FlowFields lists the power-flow card's fields, in order, with labels.
var FlowFields = []struct{ Key, Label string }{
	{"solar", tr.T("flow.solar")}, {"home", tr.T("flow.home")}, {"car", tr.T("flow.car")},
	{"grid", tr.T("flow.grid")}, {"powerwall", tr.T("flow.powerwall")}, {"battery", tr.T("flow.battery")},
	{"grid_status", tr.T("flow.grid_status")},
}

// fmtPower formats watts as "49 W" or "3.73 kW".
func fmtPower(w float64) string {
	if math.Abs(w) < 1000 {
		return fmtNum(math.Round(w), "W", 0)
	}
	return fmtNum(w/1000, "kW", 2)
}

// flowDir formats a signed flow with its direction, e.g. "exporting 49 W";
// below 10 W it is shown as idle.
func flowDir(w float64, positive, negative string) string {
	switch {
	case w >= 10:
		return tr.T(positive, "power", fmtPower(w))
	case w <= -10:
		return tr.T(negative, "power", fmtPower(-w))
	default:
		return tr.T("flow.idle")
	}
}

func orDash(v *float64, f func(float64) string) string {
	if v == nil {
		return "–"
	}
	return f(*v)
}

// flowFor builds the power-flow card from the latest stored reading.
func (s *Server) flowFor(ctx context.Context, g store.Gateway) PowerFlow {
	now := s.now()
	pf := PowerFlow{ID: g.ID, Name: g.Name, Fields: map[string]string{},
		State: tr.T("state.waiting"), StateClass: "unknown"}
	for _, f := range FlowFields {
		pf.Fields[f.Key] = "–"
	}
	pf.Updated = tr.T("time.never")
	r, ok, err := s.st.LatestSiteReading(ctx, g.ID)
	if err != nil || !ok {
		return pf
	}
	pf.UpdatedAt, pf.Updated = r.TS, fmtAgo(r.TS, now)
	pf.Stale = now.Sub(r.TS) > 2*g.PollInterval
	pf.Fields["solar"] = orDash(r.SolarW, func(w float64) string { return fmtPower(max(w, 0)) })
	pf.Fields["home"] = orDash(r.LoadW, fmtPower)
	pf.Fields["grid"] = orDash(r.SiteW, func(w float64) string { return flowDir(w, "flow.importing", "flow.exporting") })
	pf.Fields["powerwall"] = orDash(r.BatteryW, func(w float64) string { return flowDir(w, "flow.discharging", "flow.charging") })
	pf.Fields["battery"] = orDash(r.SOEPct, func(p float64) string { return fmt.Sprintf("%.0f %%", gateway.AppPercent(p)) })
	switch r.GridStatus {
	case "":
	case gateway.GridConnected:
		pf.Fields["grid_status"] = tr.T("flow.grid_connected")
	default:
		pf.Fields["grid_status"], pf.OffGrid = tr.T("flow.grid_down"), true
	}
	pf.flowState(r)
	if w, at, err := s.st.ChargingPowerW(ctx); err == nil && !at.IsZero() {
		pf.Fields["car"] = fmtPower(w)
	}
	return pf
}

// flows returns the dashboard's power-flow cards (one per Gateway).
func (s *Server) flows(ctx context.Context) []PowerFlow {
	gws, _ := s.st.Gateways(ctx)
	var out []PowerFlow
	for _, g := range gws {
		if g.Enabled {
			out = append(out, s.flowFor(ctx, g))
		}
	}
	return out
}

// HandleGatewayUpdate publishes a refreshed power-flow card after every
// Gateway poll.
func (s *Server) HandleGatewayUpdate(u poller.GatewayUpdate) {
	if s.hub == nil {
		return
	}
	ctx, cancel := contextWithTimeout()
	defer cancel()
	g, err := s.st.Gateway(ctx, u.Gateway.ID)
	if err != nil {
		return
	}
	s.hub.publish("gateway", s.flowFor(ctx, g))
}

// ---- Solar page ----

type solarRow struct {
	Period, Solar, Home, Import, Export, Charge, Discharge, SelfUse string
}

type line struct {
	Class, Points, Label string
}

func pct(v float64, ok bool) string {
	if !ok {
		return "–"
	}
	return fmt.Sprintf("%.0f %%", 100*v)
}

func kwh(v float64) string { return fmt.Sprintf("%.1f", v) }

// solarSummary is a total as one readable line.
func solarSummary(b energy.SiteBucket) string {
	sc, okSC := b.SelfConsumption()
	ss, okSS := b.SelfSufficiency()
	return tr.T("solar.total_line", "solar", kwh(b.SolarKWh), "home", kwh(b.HomeKWh), "imported", kwh(b.ImportKWh),
		"exported", kwh(b.ExportKWh), "self_use", pct(sc, okSC), "self_sufficiency", pct(ss, okSS))
}

// polyline scales (t, v) points into a W×H box (top padding 8, bottom
// axis at H-bottom) for times in [from, to] and values in [lo, hi].
func polyline(ts []time.Time, vs []float64, from, to time.Time, lo, hi, w, h, left, bottom float64) string {
	var b strings.Builder
	span := float64(to.Sub(from))
	for i := range ts {
		x := left + float64(ts[i].Sub(from))/span*(w-left-4)
		y := 8 + (1-(vs[i]-lo)/(hi-lo))*(h-bottom-8)
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(strconv.FormatFloat(x, 'f', 1, 64) + "," + strconv.FormatFloat(y, 'f', 1, 64))
	}
	return b.String()
}

func (s *Server) solarPage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx := r.Context()
	g, ok := s.firstGateway(ctx)
	if !ok {
		s.render(w, r, http.StatusOK, "solar", s.base(page{"Title": tr.T("solar.title")}, sess, "solar"))
		return
	}
	p := s.plan(ctx)
	now := s.now()
	end := now.Add(time.Minute)
	sel := periods[0]
	for _, x := range periods {
		if x.Key == r.URL.Query().Get("period") {
			sel = x
		}
	}
	samples, err := s.st.SiteSamples(ctx, time.Unix(0, 0), end)
	if err != nil {
		s.log.Warn("reading gateway counters", "err", err)
	}
	iv := energy.SiteIntervals(samples)
	n := sel.N
	if n == 0 {
		n = 1
		if len(iv) > 0 {
			n = now.In(p.Loc).Year() - iv[0].Mid().In(p.Loc).Year() + 1
		}
	}

	dayStart := p.Start(energy.Day, now)
	totals := []kv{}
	for _, t := range []struct {
		label    string
		from, to time.Time
	}{{tr.T("solar.today"), dayStart, end}, {tr.T("costs.this_month"), p.Start(energy.Month, now), end},
		{tr.T("costs.this_year"), p.Start(energy.Year, now), end}, {tr.T("costs.all_time"), time.Unix(0, 0), end}} {
		totals = append(totals, kv{t.label, solarSummary(energy.SiteTotal(iv, t.from, t.to))})
	}

	// Production per period, as bars like the Costs page.
	buckets := p.SiteBuckets(iv, sel.Per, n, now)
	labelFmt := map[energy.Period]string{energy.Day: "2 Jan", energy.Week: "2 Jan", energy.Month: "Jan 2006", energy.Year: "2006"}[sel.Per]
	const W, H, top, bottom = 1000.0, 260.0, 8.0, 26.0
	maxV := 0.0
	for _, b := range buckets {
		maxV = max(maxV, b.SolarKWh)
	}
	slot := W / float64(len(buckets))
	barW := min(slot*0.7, 120)
	every := max(1, len(buckets)/6)
	var bars []bar
	var rows []solarRow
	for i, b := range buckets {
		h := 0.0
		if maxV > 0 {
			h = (H - top - bottom) * b.SolarKWh / maxV
		}
		label := b.Start.In(p.Loc).Format(labelFmt)
		br := bar{X: float64(i)*slot + (slot-barW)/2, Y: H - bottom - h, W: barW, H: h, Label: label,
			Title: tr.T("solar.bar_title", "period", label, "kwh", kwh(b.SolarKWh)), ShowLabel: i%every == 0 || i == len(buckets)-1,
			LabelX: float64(i)*slot + slot/2, Anchor: "middle"}
		if slot < 100 && i == 0 {
			br.LabelX, br.Anchor = 0, "start"
		} else if slot < 100 && i == len(buckets)-1 {
			br.LabelX, br.Anchor = W, "end"
		}
		bars = append(bars, br)
		sc, okSC := b.SelfConsumption()
		rows = append(rows, solarRow{Period: label, Solar: kwh(b.SolarKWh), Home: kwh(b.HomeKWh), Import: kwh(b.ImportKWh),
			Export: kwh(b.ExportKWh), Charge: kwh(b.ChargeKWh), Discharge: kwh(b.DischargeKWh), SelfUse: pct(sc, okSC)})
	}
	chartFrom := buckets[0].Start
	total := energy.SiteTotal(iv, chartFrom, end)
	summary := tr.T("solar.summary", "period", sel.Name, "range", strings.ToLower(sel.Label), "total", kwh(total.SolarKWh),
		"max", kwh(maxV))

	// The last 24 hours: solar and home power, and the battery level.
	from := now.Add(-24 * time.Hour)
	readings, _ := s.st.SiteReadings(ctx, g.ID, from, end)
	const LW, LH, LL, LB = 600.0, 160.0, 44.0, 18.0
	var pts struct {
		solarT, homeT, battT []time.Time
		solar, home, batt    []float64
	}
	hiW := 1000.0
	for _, x := range readings {
		if x.SolarW != nil {
			pts.solarT, pts.solar = append(pts.solarT, x.TS), append(pts.solar, max(*x.SolarW, 0))
			hiW = max(hiW, *x.SolarW)
		}
		if x.LoadW != nil {
			pts.homeT, pts.home = append(pts.homeT, x.TS), append(pts.home, max(*x.LoadW, 0))
			hiW = max(hiW, *x.LoadW)
		}
		if x.SOEPct != nil {
			pts.battT, pts.batt = append(pts.battT, x.TS), append(pts.batt, gateway.AppPercent(*x.SOEPct))
		}
	}
	hiW = math.Ceil(hiW/1000) * 1000
	powerLines := []line{
		{Class: "chart-line solar", Label: tr.T("flow.solar"), Points: polyline(pts.solarT, pts.solar, from, now, 0, hiW, LW, LH, LL, LB)},
		{Class: "chart-line home", Label: tr.T("flow.home"), Points: polyline(pts.homeT, pts.home, from, now, 0, hiW, LW, LH, LL, LB)},
	}
	battLine := polyline(pts.battT, pts.batt, from, now, 0, 100, LW, LH, LL, LB)
	var powerSummary, battSummary string
	if len(pts.solar) > 0 {
		powerSummary = tr.T("solar.power_summary", "solar", fmtPower(pts.solar[len(pts.solar)-1]),
			"peak", fmtPower(maxOf(pts.solar)), "home", fmtPower(lastOr(pts.home)))
	}
	if len(pts.batt) > 0 {
		battSummary = tr.T("solar.battery_summary", "now", fmt.Sprintf("%.0f", pts.batt[len(pts.batt)-1]),
			"low", fmt.Sprintf("%.0f", minOf(pts.batt)), "high", fmt.Sprintf("%.0f", maxOf(pts.batt)))
	}

	s.render(w, r, http.StatusOK, "solar", s.base(page{"Title": tr.T("solar.title"), "Gateway": g, "Flow": s.flowFor(ctx, g),
		"FlowFields": FlowFields, "Totals": totals, "Bars": bars, "Rows": rows, "Summary": summary, "Periods": periods,
		"Period": sel.Key, "PeriodName": sel.Name, "PeriodLabel": sel.Label, "ChartW": W, "ChartH": H, "Baseline": H - bottom,
		"LabelY": H - 6, "LW": LW, "LH": LH, "LL": LL, "LBase": LH - LB, "PowerLines": powerLines, "PowerMax": fmtPower(hiW),
		"PowerSummary": powerSummary, "BatteryLine": battLine, "BatterySummary": battSummary, "TZ": time.Local.String()},
		sess, "solar"))
}

func maxOf(v []float64) float64 {
	m := math.Inf(-1)
	for _, x := range v {
		m = max(m, x)
	}
	return m
}

func minOf(v []float64) float64 {
	m := math.Inf(1)
	for _, x := range v {
		m = min(m, x)
	}
	return m
}

func lastOr(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	return v[len(v)-1]
}
