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
	"net/http"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/energy"
)

// Solar production and the money it saved (owner decision D28): on the
// dashboard's Gateway card (today and this week) and on the Costs page
// (day, week, month, year, since tracking began and the Gateway's
// lifetime). Settings → Energy cost picks the savings method.

// savingsWarmup is the Gateway history read before a period so that the
// Powerwalls' solar share is known when it starts (they cycle daily).
const savingsWarmup = 3 * 24 * time.Hour

// SolarFields are the dashboard card's production fields, after FlowFields.
var SolarFields = []struct{ Key, Label string }{
	{"solar_today", tr.T("flow.solar_today")}, {"solar_week", tr.T("flow.solar_week")},
}

// solarValued returns the Gateway's energy intervals in [from, to) with
// the solar savings set by the configured method; nil without a Gateway.
func (s *Server) solarValued(ctx context.Context, p energy.Plan, from, to time.Time) []energy.SiteInterval {
	samples, err := s.st.SiteSamples(ctx, from, to)
	if err != nil {
		s.log.Warn("reading gateway counters", "err", err)
		return nil
	}
	batteryWh := 0.0
	if g, ok := s.firstGateway(ctx); ok {
		if gi, err := s.st.GatewayInfo(ctx, g.ID); err == nil {
			batteryWh = gi.FullPackWh
		}
	}
	return p.SolarSavings(energy.SiteIntervals(samples), s.costSettings(ctx).SolarSavings, batteryWh)
}

// producedSaved formats a period's production and savings, e.g.
// "21.4 kWh · saved $3.32".
func producedSaved(b energy.SiteBucket, cur string) string {
	return tr.T("flow.produced_saved", "kwh", kwh(b.SolarKWh), "savings", money(b.Savings, cur))
}

// solarProductionFields fills the dashboard card's SolarFields.
func (s *Server) solarProductionFields(ctx context.Context, pf *PowerFlow, now time.Time) {
	p := s.plan(ctx)
	cur := s.costSettings(ctx).Currency
	end := now.Add(time.Minute)
	week := p.Start(energy.Week, now)
	iv := s.solarValued(ctx, p, week.Add(-savingsWarmup), end)
	if len(iv) == 0 {
		return
	}
	pf.Fields["solar_today"] = producedSaved(energy.SiteTotal(iv, p.Start(energy.Day, now), end), cur)
	pf.Fields["solar_week"] = producedSaved(energy.SiteTotal(iv, week, end), cur)
}

type solarSavingsRow struct{ Period, Produced, Used, Saved string }

// solarSavingsRows is the Costs page's solar table: production and savings
// per period, and the Gateway meter's lifetime production (which tcmon
// cannot price: it only knows rates and readings since it started).
func (s *Server) solarSavingsRows(ctx context.Context, p energy.Plan, cur string, now time.Time) []solarSavingsRow {
	end := now.Add(time.Minute)
	iv := s.solarValued(ctx, p, time.Unix(0, 0), end)
	if len(iv) == 0 {
		return nil
	}
	var rows []solarSavingsRow
	add := func(label string, b energy.SiteBucket) {
		rows = append(rows, solarSavingsRow{Period: label, Produced: kwh(b.SolarKWh), Used: kwh(b.SavedKWh), Saved: money(b.Savings, cur)})
	}
	for _, x := range []struct {
		key string
		per energy.Period
	}{{"solar.today", energy.Day}, {"costs.this_week", energy.Week}, {"costs.this_month", energy.Month}, {"costs.this_year", energy.Year}} {
		add(tr.T(x.key), energy.SiteTotal(iv, p.Start(x.per, now), end))
	}
	add(tr.T("costs.solar_since", "date", iv[0].From.In(p.Loc).Format("2 Jan 2006")), energy.SiteTotal(iv, time.Unix(0, 0), end))
	if g, ok := s.firstGateway(ctx); ok {
		if r, ok, err := s.st.LatestSiteReading(ctx, g.ID); err == nil && ok && r.SolarExportedWh != nil {
			rows = append(rows, solarSavingsRow{Period: tr.T("costs.solar_lifetime"), Produced: kwh(*r.SolarExportedWh / 1000),
				Used: "–", Saved: "–"})
		}
	}
	return rows
}

// savingsText is each method's wording: the settings label and hint, and
// the explanation under the Costs page's solar table.
var savingsText = map[energy.SavingsMethod]struct{ Label, Hint, Costs string }{
	energy.SavingsUsedAtHome: {tr.T("energy.solar_used_at_home"), tr.T("energy.solar_used_at_home_hint"),
		tr.T("costs.solar_method_used_at_home")},
	energy.SavingsNetMetering: {tr.T("energy.solar_net_metering"), tr.T("energy.solar_net_metering_hint"),
		tr.T("costs.solar_method_net_metering")},
}

type savingsChoice struct {
	Value       energy.SavingsMethod
	Label, Hint string
	Checked     bool
}

func savingsChoices(cur energy.SavingsMethod) []savingsChoice {
	var out []savingsChoice
	for _, m := range energy.SavingsMethods {
		out = append(out, savingsChoice{Value: m, Label: savingsText[m].Label, Hint: savingsText[m].Hint, Checked: m == cur})
	}
	return out
}

// saveSolarSavings stores the savings method (Settings → Energy cost).
func (s *Server) saveSolarSavings(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx := r.Context()
	m := energy.SavingsMethod(r.PostFormValue("solar_savings"))
	if !m.Valid() {
		s.renderEnergy(w, r, sess, http.StatusBadRequest, page{"Error": tr.T("energy.err_solar_savings")})
		return
	}
	cs := s.costSettings(ctx)
	cs.SolarSavings = m
	if err := s.st.SetSetting(ctx, costKey, cs, s.now()); err != nil {
		s.renderEnergy(w, r, sess, http.StatusInternalServerError, page{"Error": tr.T("energy.err_save_currency")})
		return
	}
	s.auditUI(r, "solar_savings_method_saved", map[string]string{"method": string(m)})
	http.Redirect(w, r, "/settings/energy?ok=solar-savings-saved", http.StatusSeeOther)
}
