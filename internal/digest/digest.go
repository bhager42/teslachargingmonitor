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
	"github.com/bhager42/teslachargingmonitor/internal/i18n"
	"github.com/bhager42/teslachargingmonitor/internal/notify"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// tr is the catalog for the digest's text.
var tr = i18n.English()

var (
	textTpl = texttemplate.Must(texttemplate.New("digest.txt.tmpl").Funcs(tr.Funcs()).
		ParseFS(templateFS, "templates/digest.txt.tmpl"))
	htmlTpl = htmltemplate.Must(htmltemplate.New("digest.html.tmpl").Funcs(tr.Funcs()).
		ParseFS(templateFS, "templates/digest.html.tmpl"))
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

// eventCount describes n device events of one kind, e.g. "2 restarts".
func eventCount(kind string, n int) string {
	switch kind {
	case store.EventReboot:
		return tr.N("digest.event_reboot", n)
	case store.EventFirmwareChanged:
		return tr.N("digest.event_firmware_changed", n)
	case store.EventGridProfileChanged:
		return tr.N("digest.event_grid_profile_changed", n)
	case store.EventIdentityMismatch:
		return tr.N("digest.event_identity_mismatch", n)
	}
	return tr.N("digest.event_other", n, "kind", strings.ReplaceAll(kind, "_", " "))
}

// charging is "<energy>, <cost> · <n> charging sessions".
func charging(kWh, cost float64, cur string, sessions int) string {
	return tr.T("digest.charging", "energy", kwh(kWh), "cost", money(cost, cur), "sessions", tr.N("digest.sessions", sessions))
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
			Charging: charging(k, c, cur.Currency, sessions),
			Previous: tr.T("digest.previous", "energy", kwh(pk), "cost", money(pc, cur.Currency)),
			Polls: tr.T("digest.polls", "ok", tr.N("digest.polls_ok", h.PollsOK),
				"failed", tr.N("digest.polls_failed", h.PollFailures)),
		}
		if h.Readings > 0 {
			dv.Temps = tr.T("digest.temps", "handle", temp(h.MaxHandleC, disp.TempUnit),
				"pcba", temp(h.MaxPCBAC, disp.TempUnit), "mcu", temp(h.MaxMCUC, disp.TempUnit))
			if h.MinGridV != nil && h.MaxGridV != nil {
				dv.Grid = tr.T("digest.grid", "min", strconv.FormatFloat(*h.MinGridV, 'f', 0, 64),
					"max", strconv.FormatFloat(*h.MaxGridV, 'f', 0, 64))
			}
		} else {
			dv.Temps = tr.T("digest.no_readings")
		}
		kinds := make([]string, 0, len(h.Events))
		for k := range h.Events {
			kinds = append(kinds, k)
		}
		slices.Sort(kinds)
		for _, k := range kinds {
			dv.Events = append(dv.Events, eventCount(k, h.Events[k]))
		}
		v.Devices = append(v.Devices, dv)
	}
	v.Total = charging(totKWh, totCost, cur.Currency, totSessions)

	alertCount, err := addAlerts(ctx, st, &v, names, from, to, loc)
	if err != nil {
		return notify.Message{}, err
	}
	v.Subject = tr.T("digest.subject", "range", v.Range, "energy", kwh(totKWh), "cost", money(totCost, cur.Currency),
		"alerts", tr.N("digest.alerts", alertCount))
	info := buildinfo.Get()
	v.Footer = tr.T("digest.footer", "version", info.Version, "source", info.SourceLink())

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
		v.Alerts = append(v.Alerts, alertView{Icon: icon, Severity: g.sev.Label(), Title: title,
			Device: cmp.Or(names[k.device], tr.T("digest.removed_device")), Count: tr.N("digest.times", g.count),
			Last: g.last.In(loc).Format("Mon 2 Jan 15:04")})
	}
	return total, nil
}
