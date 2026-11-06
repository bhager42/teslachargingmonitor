// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package digest builds and schedules the optional weekly summary email
// (owner decision D19): charging energy and cost, alerts, and device health
// for the previous Monday-to-Sunday week, sent on Monday morning to the
// email channels that opted in.
package digest

import (
	"bytes"
	"cmp"
	"context"
	"embed"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"math"
	"slices"
	"strconv"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/buildinfo"
	"github.com/bhager42/teslachargingmonitor/internal/energy"
	"github.com/bhager42/teslachargingmonitor/internal/notify"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

var (
	textTpl = texttemplate.Must(texttemplate.New("digest.txt.tmpl").ParseFS(templateFS, "templates/digest.txt.tmpl"))
	htmlTpl = htmltemplate.Must(htmltemplate.New("digest.html.tmpl").ParseFS(templateFS, "templates/digest.html.tmpl"))
)

// Settings keys shared with the web UI (internal/web: costKey, displayKey).
const (
	costKey    = "cost"
	displayKey = "display"
)

// Week returns the Monday-to-Monday local week before the one containing now.
func Week(now time.Time, loc *time.Location) (from, to time.Time) {
	p := energy.NewPlan(nil, loc)
	to = p.Start(energy.Week, now)
	y, m, d := to.Date()
	return time.Date(y, m, d-7, 0, 0, 0, 0, loc), to
}

// view is the only data the templates see: preformatted strings.
type view struct {
	Subject, Range, Footer string
	Total                  string
	Devices                []deviceView
	Alerts                 []alertView
	NoDevices              bool
}

type deviceView struct {
	Name, Charging, Previous, Polls string
	Temps, Grid                     string
	Events                          []string
}

type alertView struct {
	Icon, Severity, Title, Device, Count, Last string
}

func money(v float64, cur string) string {
	return cur + strconv.FormatFloat(math.Round(v*100)/100, 'f', 2, 64)
}

func kwh(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) + " kWh" }

func temp(c *float64, unit string) string {
	if c == nil {
		return "—"
	}
	if unit == "F" {
		return fmt.Sprintf("%.1f °F", *c*9/5+32)
	}
	return fmt.Sprintf("%.1f °C", *c)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

var eventLabels = map[string]string{
	store.EventReboot:             "restart",
	store.EventFirmwareChanged:    "firmware change",
	store.EventGridProfileChanged: "grid profile change",
	store.EventIdentityMismatch:   "identity mismatch",
}

// energyIn sums priced intervals whose midpoint falls in [from, to).
// Monthly fees are left out: they belong to months, not weeks.
func energyIn(iv []energy.Interval, from, to time.Time) (kWh, cost float64) {
	for _, x := range iv {
		if m := x.Mid(); !m.Before(from) && m.Before(to) {
			kWh += x.Wh / 1000
			cost += x.Cost
		}
	}
	return kWh, cost
}

// Build gathers the week [from, to) from the store and renders the digest.
func Build(ctx context.Context, st *store.Store, from, to time.Time, loc *time.Location) (notify.Message, error) {
	if loc == nil {
		loc = time.Local
	}
	cur := struct {
		Currency string `json:"currency"`
	}{Currency: "$"}
	if err := st.GetSetting(ctx, costKey, &cur); err != nil && !errors.Is(err, store.ErrNotFound) {
		return notify.Message{}, err
	}
	if cur.Currency == "" {
		cur.Currency = "$"
	}
	disp := struct {
		TempUnit string `json:"temp_unit"`
	}{TempUnit: "C"}
	if err := st.GetSetting(ctx, displayKey, &disp); err != nil && !errors.Is(err, store.ErrNotFound) {
		return notify.Message{}, err
	}
	rates, err := st.Rates(ctx)
	if err != nil {
		return notify.Message{}, err
	}
	plan := energy.NewPlan(rates, loc)
	devices, err := st.Devices(ctx)
	if err != nil {
		return notify.Message{}, err
	}
	prevFrom := from.AddDate(0, 0, -7)

	v := view{NoDevices: len(devices) == 0}
	v.Range = from.In(loc).Format("Mon 2 Jan") + " – " + to.Add(-time.Second).In(loc).Format("Mon 2 Jan 2006")
	names := map[int64]string{}
	var totKWh, totCost float64
	totSessions := 0
	for _, d := range devices {
		names[d.ID] = d.Name
		samples, err := st.EnergySamples(ctx, d.ID, prevFrom, to)
		if err != nil {
			return notify.Message{}, err
		}
		iv := energy.Intervals(samples, plan)
		k, c := energyIn(iv, from, to)
		pk, pc := energyIn(iv, prevFrom, from)
		ps, err := st.PlugSamples(ctx, d.ID, from, to)
		if err != nil {
			return notify.Message{}, err
		}
		sessions := 0
		for _, s := range energy.Sessions(ps, plan) {
			if !s.End.Before(from) {
				sessions++
			}
		}
		totKWh, totCost, totSessions = totKWh+k, totCost+c, totSessions+sessions
		h, err := st.Health(ctx, d.ID, from, to)
		if err != nil {
			return notify.Message{}, err
		}
		dv := deviceView{Name: d.Name,
			Charging: kwh(k) + ", " + money(c, cur.Currency) + " · " + plural(sessions, "charging session", "charging sessions"),
			Previous: "Previous week: " + kwh(pk) + ", " + money(pc, cur.Currency),
			Polls:    plural(h.PollsOK, "successful poll", "successful polls") + ", " + plural(h.PollFailures, "failed attempt", "failed attempts"),
		}
		if h.Readings > 0 {
			dv.Temps = "Highest temperatures: handle " + temp(h.MaxHandleC, disp.TempUnit) + ", PCBA " +
				temp(h.MaxPCBAC, disp.TempUnit) + ", MCU " + temp(h.MaxMCUC, disp.TempUnit)
			if h.MinGridV != nil && h.MaxGridV != nil {
				dv.Grid = fmt.Sprintf("Grid voltage %.0f–%.0f V", *h.MinGridV, *h.MaxGridV)
			}
		} else {
			dv.Temps = "No readings this week."
		}
		kinds := make([]string, 0, len(h.Events))
		for k := range h.Events {
			kinds = append(kinds, k)
		}
		slices.Sort(kinds)
		for _, k := range kinds {
			label := cmp.Or(eventLabels[k], strings.ReplaceAll(k, "_", " "))
			dv.Events = append(dv.Events, plural(h.Events[k], label, label+"s"))
		}
		v.Devices = append(v.Devices, dv)
	}
	v.Total = kwh(totKWh) + ", " + money(totCost, cur.Currency) + " · " + plural(totSessions, "charging session", "charging sessions")

	alertCount, err := addAlerts(ctx, st, &v, names, from, to, loc)
	if err != nil {
		return notify.Message{}, err
	}
	v.Subject = "Weekly summary " + v.Range + ": " + kwh(totKWh) + ", " + money(totCost, cur.Currency) + ", " +
		plural(alertCount, "alert", "alerts")
	info := buildinfo.Get()
	v.Footer = "Weekly summary from Tesla Charger Monitoring " + info.Version + ". Turn it off per email channel under " +
		"Notifications in the web UI. Costs are energy only (monthly fees not included). Tesla Charger Monitoring is an " +
		"independent project, not affiliated with Tesla, Inc. Source: " + info.SourceLink()

	var tb, hb bytes.Buffer
	if err := textTpl.Execute(&tb, v); err != nil {
		return notify.Message{}, err
	}
	if err := htmlTpl.Execute(&hb, v); err != nil {
		return notify.Message{}, err
	}
	return notify.Message{Subject: v.Subject, Text: strings.TrimSpace(tb.String()) + "\n", HTML: hb.String(),
		Severity: alerts.Info}, nil
}

// maxAlertEvents bounds how much alert history one digest reads.
const maxAlertEvents = 5000

// addAlerts groups the week's alerts by rule and device, most severe first,
// and returns how many alerts fired.
func addAlerts(ctx context.Context, st *store.Store, v *view, names map[int64]string, from, to time.Time,
	loc *time.Location) (int, error) {
	evs, err := st.AlertEvents(ctx, store.AlertEventFilter{Since: from, Limit: maxAlertEvents})
	if err != nil {
		return 0, err
	}
	type key struct {
		rule   string
		device int64
	}
	type group struct {
		sev   alerts.Severity
		count int
		last  time.Time
	}
	groups := map[key]*group{}
	total := 0
	for _, e := range evs {
		if !e.TS.Before(to) {
			continue
		}
		switch e.Kind {
		case alerts.KindFiring, alerts.KindEscalated, alerts.KindEvent:
		default:
			continue // repeats and resolutions are not new alerts
		}
		sev, err := alerts.ParseSeverity(e.Severity)
		if err != nil {
			sev = alerts.Info
		}
		k := key{e.RuleKey, e.DeviceID}
		g := groups[k]
		if g == nil {
			g = &group{}
			groups[k] = g
		}
		g.count++
		g.sev = max(g.sev, sev)
		if e.TS.After(g.last) {
			g.last = e.TS
		}
		total++
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b key) int {
		ga, gb := groups[a], groups[b]
		return cmp.Or(cmp.Compare(gb.sev, ga.sev), gb.last.Compare(ga.last), cmp.Compare(a.rule, b.rule))
	})
	for _, k := range keys {
		g := groups[k]
		title := k.rule
		if def, ok := alerts.Lookup(k.rule); ok {
			title = def.Title
		}
		icon := map[alerts.Severity]string{alerts.Critical: "⛔", alerts.Warning: "⚠️"}[g.sev]
		if icon == "" {
			icon = "ℹ️"
		}
		v.Alerts = append(v.Alerts, alertView{Icon: icon, Severity: g.sev.String(), Title: title,
			Device: cmp.Or(names[k.device], "removed device"), Count: plural(g.count, "time", "times"),
			Last: g.last.In(loc).Format("Mon 2 Jan 15:04")})
	}
	return total, nil
}
