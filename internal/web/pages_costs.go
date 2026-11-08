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
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/energy"
)

// CostSettings are display preferences for money.
type CostSettings struct {
	Currency string `json:"currency"`
}

const costKey = "cost"

func (s *Server) costSettings(ctx context.Context) CostSettings {
	c := CostSettings{Currency: "$"}
	_ = s.st.GetSetting(ctx, costKey, &c)
	if c.Currency == "" {
		c.Currency = "$"
	}
	return c
}

func (s *Server) plan(ctx context.Context) energy.Plan {
	rates, err := s.st.Rates(ctx)
	if err != nil {
		s.log.Warn("reading electricity rates", "err", err)
	}
	return energy.NewPlan(rates, time.Local)
}

func money(v float64, cur string) string {
	return cur + strconv.FormatFloat(math.Round(v*100)/100, 'f', 2, 64)
}

// price shows a per-kWh price with as many decimals as it has (0.155 stays
// 0.155), but at least two.
func price(v float64, cur string) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if i := strings.IndexByte(s, '.'); i < 0 {
		s += ".00"
	} else if len(s)-i-1 < 2 {
		s += strings.Repeat("0", 2-(len(s)-i-1))
	}
	return cur + s
}

// intervals returns priced energy intervals for all devices in [from, to).
func (s *Server) intervals(ctx context.Context, p energy.Plan, from, to time.Time) []energy.Interval {
	devices, _ := s.st.Devices(ctx)
	var all []energy.Interval
	for _, d := range devices {
		samples, err := s.st.EnergySamples(ctx, d.ID, from, to)
		if err != nil {
			s.log.Warn("reading energy samples", "err", err)
			continue
		}
		all = append(all, energy.Intervals(samples, p)...)
	}
	return all
}

// costFields adds session and month cost to a device card.
func (s *Server) costFields(ctx context.Context, c *DeviceCard, deviceID int64) {
	p := s.plan(ctx)
	cur := s.costSettings(ctx).Currency
	now := s.now()
	monthStart := p.Start(energy.Month, now)
	samples, err := s.st.EnergySamples(ctx, deviceID, monthStart, now.Add(time.Minute))
	if err == nil {
		t := p.Total(energy.Intervals(samples, p), monthStart, now.Add(time.Minute))
		c.Fields["month_cost"] = money(t.Cost, cur) + " · " + fmtNum(t.KWh, "kWh", 1)
	}
	if ps, err := s.st.PlugSamples(ctx, deviceID, now.Add(-48*time.Hour), now.Add(time.Minute)); err == nil {
		if ss := energy.Sessions(ps, p); len(ss) > 0 && ss[len(ss)-1].Ongoing {
			c.Fields["session_cost"] = money(ss[len(ss)-1].Cost, cur)
		}
	}
}

// ---- Costs page ----

type bar struct {
	X, Y, W, H        float64
	LabelX            float64
	Label, Title, Key string
	Anchor            string
	ShowLabel         bool
}

type costRow struct{ Period, KWh, Cost string }

type sessionRow struct{ Start, End, Duration, KWh, Cost, Peak string }

// periods are the chart's tabs. N is the number of bars; 0 means every
// year from the first one with charging data.
var periods = []struct {
	Key, Name, Label string
	Per              energy.Period
	N                int
}{
	{"day", tr.T("costs.period_day"), tr.T("costs.last_30_days"), energy.Day, 30},
	{"week", tr.T("costs.period_week"), tr.T("costs.last_12_weeks"), energy.Week, 12},
	{"month", tr.T("costs.period_month"), tr.T("costs.last_12_months"), energy.Month, 12},
	{"year", tr.T("costs.period_year"), tr.T("costs.all_time"), energy.Year, 0},
}

// yearsOfData is the number of years from the first one with charging
// data to the current one (1 when there is none).
func yearsOfData(iv []energy.Interval, p energy.Plan, now time.Time) int {
	first := now.In(p.Loc).Year()
	for _, x := range iv {
		first = min(first, x.Mid().In(p.Loc).Year())
	}
	return now.In(p.Loc).Year() - first + 1
}

func (s *Server) costsPage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx := r.Context()
	p := s.plan(ctx)
	cur := s.costSettings(ctx).Currency
	now := s.now()
	end := now.Add(time.Minute)

	sel := periods[0]
	for _, x := range periods {
		if x.Key == r.URL.Query().Get("period") {
			sel = x
		}
	}
	all := s.intervals(ctx, p, time.Unix(0, 0), end)
	n := sel.N
	if n == 0 {
		n = yearsOfData(all, p, now)
	}
	chartFrom := p.Start(sel.Per, now)
	for range n - 1 {
		chartFrom = p.Start(sel.Per, chartFrom.Add(-time.Hour))
	}

	monthStart := p.Start(energy.Month, now)
	lastMonth := p.Start(energy.Month, monthStart.Add(-time.Hour))
	yearStart := time.Date(now.In(p.Loc).Year(), 1, 1, 0, 0, 0, 0, p.Loc)
	totals := []kv{}
	for _, t := range []struct {
		label    string
		from, to time.Time
	}{{tr.T("costs.this_month"), monthStart, end}, {tr.T("costs.last_month"), lastMonth, monthStart},
		{tr.T("costs.this_year"), yearStart, end}, {tr.T("costs.all_time"), time.Unix(0, 0), end}} {
		b := p.Total(all, t.from, t.to)
		totals = append(totals, kv{t.label, money(b.Cost, cur) + " · " + fmtNum(b.KWh, "kWh", 1)})
	}

	buckets := p.Buckets(all, sel.Per, n, now)
	labelFmt := map[energy.Period]string{energy.Day: "2 Jan", energy.Week: "2 Jan", energy.Month: "Jan 2006", energy.Year: "2006"}[sel.Per]
	var bars []bar
	var rows []costRow
	maxCost := 0.0
	for _, b := range buckets {
		maxCost = max(maxCost, b.Cost)
	}
	const W, H, top, bottom = 1000.0, 260.0, 8.0, 26.0
	slot := W / float64(len(buckets))
	barW := min(slot*0.7, 120) // a few years should not fill the chart with slabs
	every := max(1, len(buckets)/6)
	for i, b := range buckets {
		h := 0.0
		if maxCost > 0 {
			h = (H - top - bottom) * b.Cost / maxCost
		}
		label := b.Start.In(p.Loc).Format(labelFmt)
		title := fmt.Sprintf("%s: %s, %.1f kWh", label, money(b.Cost, cur), b.KWh)
		br := bar{X: float64(i)*slot + (slot-barW)/2, Y: H - bottom - h, W: barW, H: h, Label: label, Title: title,
			ShowLabel: i%every == 0 || i == len(buckets)-1, LabelX: float64(i)*slot + slot/2, Anchor: "middle"}
		// Narrow slots: keep the first and last labels inside the chart.
		if slot < 100 && i == 0 {
			br.LabelX, br.Anchor = float64(i)*slot, "start"
		} else if slot < 100 && i == len(buckets)-1 {
			br.LabelX, br.Anchor = W, "end"
		}
		bars = append(bars, br)
		rows = append(rows, costRow{Period: label, KWh: fmt.Sprintf("%.1f", b.KWh), Cost: money(b.Cost, cur)})
	}
	total := p.Total(all, chartFrom, end)
	summary := tr.T("costs.summary", "period", sel.Name, "range", strings.ToLower(sel.Label),
		"total", money(total.Cost, cur), "kwh", fmt.Sprintf("%.1f", total.KWh), "max", money(maxCost, cur))

	var sessions []sessionRow
	devices, _ := s.st.Devices(ctx)
	for _, d := range devices {
		ps, err := s.st.PlugSamples(ctx, d.ID, now.Add(-90*24*time.Hour), end)
		if err != nil {
			continue
		}
		ss := energy.Sessions(ps, p)
		for i := len(ss) - 1; i >= 0 && len(sessions) < 50; i-- {
			x := ss[i]
			endTxt := x.End.In(p.Loc).Format("2 Jan 15:04")
			if x.Ongoing {
				endTxt = tr.T("costs.in_progress")
			}
			sessions = append(sessions, sessionRow{Start: x.Start.In(p.Loc).Format("Mon 2 Jan 15:04"), End: endTxt,
				Duration: fmtDuration(x.End.Sub(x.Start)), KWh: fmt.Sprintf("%.1f", x.KWh), Cost: money(x.Cost, cur),
				Peak: fmt.Sprintf("%.0f A", x.PeakA)})
		}
	}
	rate := p.RateAt(now)
	rateText := tr.T("costs.rate", "price", price(rate.Price, cur))
	if rate.HasOffPeak() {
		rateText += tr.T("costs.rate_offpeak", "price", price(*rate.OffPeakPrice, cur), "from", hhmm(rate.OffPeakStart), "to", hhmm(rate.OffPeakEnd))
	}
	if rate.MonthlyFee > 0 {
		rateText += tr.T("costs.rate_fee", "fee", money(rate.MonthlyFee, cur))
	}
	s.render(w, r, http.StatusOK, "costs", s.base(page{"Title": tr.T("costs.title"), "Totals": totals, "Bars": bars,
		"Rows": rows, "Summary": summary, "Periods": periods, "Period": sel.Key, "PeriodName": sel.Name, "PeriodLabel": sel.Label,
		"Sessions": sessions, "Rate": rateText, "TZ": time.Local.String(), "ChartW": W, "ChartH": H,
		"Baseline": H - bottom, "LabelY": H - 6}, sess, "costs"))
}

func hhmm(min int) string { return fmt.Sprintf("%02d:%02d", min/60, min%60) }

func parseClock(s string) (int, bool) {
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

func (s *Server) costsCSV(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	ctx := r.Context()
	p := s.plan(ctx)
	now := s.now()
	end := now.Add(time.Minute)
	kind := r.PathValue("kind")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="tcmon-%s-%s.csv"`, kind, now.Format("20060102")))
	cw := csv.NewWriter(w)
	defer cw.Flush()
	switch kind {
	case "daily":
		_ = cw.Write([]string{"date", "kwh", "cost"})
		for _, b := range p.Buckets(s.intervals(ctx, p, now.Add(-367*24*time.Hour), end), energy.Day, 365, now) {
			_ = cw.Write([]string{b.Start.In(p.Loc).Format(time.DateOnly), strconv.FormatFloat(b.KWh, 'f', 3, 64),
				strconv.FormatFloat(b.Cost, 'f', 2, 64)})
		}
	case "sessions":
		_ = cw.Write([]string{"device", "start", "end", "ongoing", "kwh", "cost", "peak_current_a"})
		devices, _ := s.st.Devices(ctx)
		for _, d := range devices {
			ps, _ := s.st.PlugSamples(ctx, d.ID, time.Unix(0, 0), end)
			for _, x := range energy.Sessions(ps, p) {
				_ = cw.Write([]string{d.Name, x.Start.Format(time.RFC3339), x.End.Format(time.RFC3339), strconv.FormatBool(x.Ongoing),
					strconv.FormatFloat(x.KWh, 'f', 3, 64), strconv.FormatFloat(x.Cost, 'f', 2, 64), strconv.FormatFloat(x.PeakA, 'f', 1, 64)})
			}
		}
	default:
		http.NotFound(w, r)
	}
}

// ---- Settings → Energy cost ----

type rateRow struct {
	ID                        int64
	From, Price, OffPeak, Fee string
}

func (s *Server) renderEnergy(w http.ResponseWriter, r *http.Request, sess auth.Session, status int, p page) {
	ctx := r.Context()
	cs := s.costSettings(ctx)
	rates, _ := s.st.Rates(ctx)
	var rows []rateRow
	for _, x := range rates {
		row := rateRow{ID: x.ID, From: x.EffectiveFrom.In(time.Local).Format("2 Jan 2006"), Price: price(x.Price, cs.Currency),
			OffPeak: "–", Fee: money(x.MonthlyFee, cs.Currency)}
		if x.EffectiveFrom.Unix() <= 0 {
			row.From = tr.T("energy.all_past")
		}
		if x.HasOffPeak() {
			row.OffPeak = fmt.Sprintf("%s %s–%s", price(*x.OffPeakPrice, cs.Currency), hhmm(x.OffPeakStart), hhmm(x.OffPeakEnd))
		}
		rows = append(rows, row)
	}
	cur := s.plan(ctx).RateAt(s.now())
	if p == nil {
		p = page{}
	}
	if _, ok := p["Form"]; !ok {
		f := map[string]string{"Price": strconv.FormatFloat(cur.Price, 'f', -1, 64), "Currency": cs.Currency,
			"From": s.now().In(time.Local).Format(time.DateOnly), "Fee": strconv.FormatFloat(cur.MonthlyFee, 'f', -1, 64),
			"OffStart": "23:00", "OffEnd": "06:00"}
		if cur.HasOffPeak() {
			f["OffPrice"], f["OffStart"], f["OffEnd"] = strconv.FormatFloat(*cur.OffPeakPrice, 'f', -1, 64), hhmm(cur.OffPeakStart), hhmm(cur.OffPeakEnd)
		}
		p["Form"] = f
	}
	p["Title"], p["Rates"], p["Default"] = tr.T("energy.page_title"), rows, len(rates) == 0
	s.render(w, r, status, "energy", s.base(p, sess, "settings"))
}

func (s *Server) energyPage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	s.renderEnergy(w, r, sess, http.StatusOK, nil)
}

func (s *Server) saveEnergy(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx := r.Context()
	form := map[string]string{}
	for _, k := range []string{"price", "currency", "from", "fee", "offpeak_price", "offpeak_start", "offpeak_end"} {
		form[k] = strings.TrimSpace(r.PostFormValue(k))
	}
	view := map[string]string{"Price": form["price"], "Currency": form["currency"], "From": form["from"], "Fee": form["fee"],
		"OffPrice": form["offpeak_price"], "OffStart": form["offpeak_start"], "OffEnd": form["offpeak_end"]}
	fail := func(msg string) {
		s.renderEnergy(w, r, sess, http.StatusBadRequest, page{"Error": msg, "Form": view})
	}
	price, err := strconv.ParseFloat(form["price"], 64)
	if err != nil {
		fail(tr.T("energy.err_price"))
		return
	}
	rate := energy.Rate{Price: price}
	if form["fee"] != "" {
		if rate.MonthlyFee, err = strconv.ParseFloat(form["fee"], 64); err != nil {
			fail(tr.T("energy.err_fee"))
			return
		}
	}
	if form["offpeak_price"] != "" {
		op, err := strconv.ParseFloat(form["offpeak_price"], 64)
		start, ok1 := parseClock(form["offpeak_start"])
		end, ok2 := parseClock(form["offpeak_end"])
		if err != nil || !ok1 || !ok2 || start == end {
			fail(tr.T("energy.err_offpeak"))
			return
		}
		rate.OffPeakPrice, rate.OffPeakStart, rate.OffPeakEnd = &op, start, end
	}
	if r.PostFormValue("apply_past") == "1" {
		rate.EffectiveFrom = time.Unix(0, 0)
	} else {
		d, err := time.ParseInLocation(time.DateOnly, form["from"], time.Local)
		if err != nil {
			fail(tr.T("energy.err_from"))
			return
		}
		rate.EffectiveFrom = d
	}
	cur := form["currency"]
	if n := len([]rune(cur)); n < 1 || n > 4 || strings.ContainsAny(cur, "<>\"'&0123456789") {
		fail(tr.T("energy.err_currency"))
		return
	}
	if _, err := s.st.AddRate(ctx, rate, s.now()); err != nil {
		fail(err.Error())
		return
	}
	if err := s.st.SetSetting(ctx, costKey, CostSettings{Currency: cur}, s.now()); err != nil {
		fail(tr.T("energy.err_save_currency"))
		return
	}
	s.auditUI(r, "energy_rate_saved", map[string]string{"price": form["price"]})
	http.Redirect(w, r, "/settings/energy?ok=rate-saved", http.StatusSeeOther)
}

func (s *Server) deleteRate(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	if id, err := strconv.ParseInt(r.PathValue("id"), 10, 64); err == nil && s.st.DeleteRate(r.Context(), id) == nil {
		s.auditUI(r, "energy_rate_deleted", map[string]string{"id": r.PathValue("id")})
	}
	http.Redirect(w, r, "/settings/energy?ok=rate-deleted", http.StatusSeeOther)
}
