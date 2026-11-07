// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

type activeRow struct {
	Device, Title, Severity, Since string
}

type ruleRow struct {
	Key, Title, Description, Summary string
	Enabled, NeedsCalibration        bool
}

type snoozeRow struct {
	ID            int64
	Device, Until string
}

func paramSummary(def alerts.Definition, c alerts.Config, unit string) string {
	var parts []string
	for _, p := range def.Params {
		v := c.Params[p.Name]
		u := p.Unit
		if u == "°C" && unit == "F" {
			if strings.HasPrefix(p.Name, "hysteresis") {
				v, u = v*9/5, "°F"
			} else {
				v, u = v*9/5+32, "°F"
			}
		}
		parts = append(parts, p.Label+" "+strconv.FormatFloat(v, 'f', -1, 64)+" "+u)
	}
	return strings.Join(parts, " · ")
}

func (s *Server) alertsPage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx := r.Context()
	now := s.now()
	devices, _ := s.st.Devices(ctx)
	var active []activeRow
	var snoozes []snoozeRow
	for _, d := range devices {
		if s.alerts != nil {
			for _, a := range s.alerts.Active(d.ID) {
				active = append(active, activeRow{Device: d.Name, Title: a.Title, Severity: a.Severity.String(), Since: fmtAgo(a.Since, now)})
			}
		}
		list, _ := s.st.ActiveSnoozes(ctx, d.ID, now)
		for _, sn := range list {
			snoozes = append(snoozes, snoozeRow{ID: sn.ID, Device: d.Name, Until: sn.Until.Local().Format("Mon 2 Jan 15:04")})
		}
	}
	var history []alertRow
	evs, _ := s.st.AlertEvents(ctx, store.AlertEventFilter{Limit: 50})
	for _, e := range evs {
		title := e.RuleKey
		if def, ok := alerts.Lookup(e.RuleKey); ok {
			title = def.Title
		}
		history = append(history, alertRow{ID: e.ID, Severity: e.Severity, Kind: e.Kind, Title: title,
			When: e.TS.Local().Format("2 Jan 15:04"), Message: e.Message, Acked: e.AckedAt != nil, Notified: e.Notified})
	}
	var rules []ruleRow
	if s.alerts != nil {
		cfgs, _ := s.alerts.Configs(ctx, 0)
		unit := s.display(ctx).TempUnit
		for _, def := range alerts.Definitions() {
			c := cfgs[def.Key]
			rules = append(rules, ruleRow{Key: def.Key, Title: def.Title, Description: def.Description,
				Summary: paramSummary(def, c, unit), Enabled: c.Enabled, NeedsCalibration: def.NeedsCalibration})
		}
	}
	s.render(w, r, http.StatusOK, "alerts", s.base(page{"Title": tr.T("alerts.title"), "Active": active, "History": history,
		"Rules": rules, "Snoozes": snoozes, "Devices": devices}, sess, "alerts"))
}

func (s *Server) ackAlert(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		err = s.st.AckAlertEvent(r.Context(), id, s.now())
	}
	if err != nil {
		http.Redirect(w, r, "/alerts", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/alerts?ok=acked", http.StatusSeeOther)
}

func (s *Server) snooze(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	id, err1 := strconv.ParseInt(r.PostFormValue("device_id"), 10, 64)
	hours, err2 := strconv.Atoi(r.PostFormValue("hours"))
	if err1 != nil || err2 != nil || !slices.Contains([]int{1, 4, 24, 72, 168}, hours) {
		s.renderError(w, r, http.StatusBadRequest, tr.T("alerts.err_snooze_title"), tr.T("alerts.err_snooze_input"))
		return
	}
	if _, err := s.st.Device(r.Context(), id); err != nil {
		s.renderError(w, r, http.StatusBadRequest, tr.T("alerts.err_snooze_title"), tr.T("alerts.err_snooze_device"))
		return
	}
	now := s.now()
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if _, err := s.st.AddSnooze(r.Context(), store.Snooze{DeviceID: id, Until: now.Add(time.Duration(hours) * time.Hour), Reason: reason}, now); err != nil {
		s.renderError(w, r, http.StatusBadRequest, tr.T("alerts.err_snooze_title"), tr.T("alerts.err_snooze"))
		return
	}
	s.auditUI(r, "alerts_snoozed", map[string]string{"device_id": strconv.FormatInt(id, 10), "hours": strconv.Itoa(hours)})
	_ = sess
	http.Redirect(w, r, "/alerts?ok=snoozed", http.StatusSeeOther)
}

func (s *Server) unsnooze(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	if id, err := strconv.ParseInt(r.PathValue("id"), 10, 64); err == nil {
		_ = s.st.DeleteSnooze(r.Context(), id)
	}
	http.Redirect(w, r, "/alerts?ok=unsnoozed", http.StatusSeeOther)
}

// ---- rule editor ----

type paramField struct {
	Name, Label, Unit, Value, Min, Max, Step string
}

func (s *Server) ruleFields(def alerts.Definition, c alerts.Config, unit string) []paramField {
	var out []paramField
	for _, p := range def.Params {
		v, lo, hi, u := c.Params[p.Name], p.Min, p.Max, p.Unit
		if u == "°C" && unit == "F" {
			if strings.HasPrefix(p.Name, "hysteresis") {
				v, lo, hi = v*9/5, lo*9/5, hi*9/5
			} else {
				v, lo, hi = v*9/5+32, lo*9/5+32, hi*9/5+32
			}
			u = "°F"
		}
		f := func(x float64) string { return strconv.FormatFloat(x, 'f', -1, 64) }
		out = append(out, paramField{Name: p.Name, Label: p.Label, Unit: u, Value: f(v), Min: f(lo), Max: f(hi), Step: "any"})
	}
	return out
}

func (s *Server) ruleFromPath(w http.ResponseWriter, r *http.Request) (alerts.Definition, bool) {
	def, ok := alerts.Lookup(r.PathValue("key"))
	if !ok || s.alerts == nil {
		s.renderError(w, r, http.StatusNotFound, tr.T("error.not_found_title"), tr.T("error.no_rule"))
	}
	return def, ok && s.alerts != nil
}

func (s *Server) renderRule(w http.ResponseWriter, r *http.Request, sess auth.Session, status int, def alerts.Definition, c alerts.Config, p page) {
	if p == nil {
		p = page{}
	}
	unit := s.display(r.Context()).TempUnit
	p["Title"], p["Rule"], p["Config"], p["Fields"] = def.Title, def, c, s.ruleFields(def, c, unit)
	p["For"] = strconv.Itoa(int(c.For.Seconds()))
	p["Cooldown"] = strconv.Itoa(int(c.Cooldown.Minutes()))
	p["Repeat"] = strconv.FormatFloat(c.Repeat.Hours(), 'f', -1, 64)
	p["IsEvent"] = def.Kind == alerts.Event
	s.render(w, r, status, "rule", s.base(p, sess, "alerts"))
}

func (s *Server) ruleForm(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	def, ok := s.ruleFromPath(w, r)
	if !ok {
		return
	}
	cfgs, err := s.alerts.Configs(r.Context(), 0)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr.T("error.title"), tr.T("alerts.err_load"))
		return
	}
	s.renderRule(w, r, sess, http.StatusOK, def, cfgs[def.Key], nil)
}

// readRule parses the rule form, converting °F input back to °C.
func (s *Server) readRule(r *http.Request, def alerts.Definition, base alerts.Config) (alerts.Config, string) {
	c := base
	c.Params = maps.Clone(base.Params)
	unit := s.display(r.Context()).TempUnit
	for _, p := range def.Params {
		v, err := strconv.ParseFloat(strings.TrimSpace(r.PostFormValue("p_"+p.Name)), 64)
		if err != nil {
			return c, tr.T("rule.err_number", "field", p.Label)
		}
		if p.Unit == "°C" && unit == "F" {
			if strings.HasPrefix(p.Name, "hysteresis") {
				v = v * 5 / 9
			} else {
				v = (v - 32) * 5 / 9
			}
		}
		c.Params[p.Name] = v
	}
	c.Enabled = r.PostFormValue("enabled") == "1"
	c.NotifyResolved = r.PostFormValue("notify_resolved") == "1"
	num := func(name string) (float64, bool) {
		v, err := strconv.ParseFloat(strings.TrimSpace(r.PostFormValue(name)), 64)
		return v, err == nil && v >= 0
	}
	forS, ok1 := num("for_s")
	cool, ok2 := num("cooldown_min")
	rep, ok3 := num("repeat_h")
	ms, ok4 := num("min_samples")
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return c, tr.T("rule.err_timing")
	}
	c.For = time.Duration(forS * float64(time.Second))
	c.Cooldown = time.Duration(cool * float64(time.Minute))
	c.Repeat = time.Duration(rep * float64(time.Hour))
	c.MinSamples = int(ms)
	if err := def.Validate(c); err != nil {
		return c, err.Error()
	}
	return c, ""
}

func (s *Server) saveRule(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	def, ok := s.ruleFromPath(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if r.PostFormValue("action") == "reset" {
		_ = s.st.DeleteRuleOverride(ctx, def.Key, 0)
		s.auditUI(r, "alert_rule_reset", map[string]string{"rule": def.Key})
		http.Redirect(w, r, "/alerts?ok=rule-reset", http.StatusSeeOther)
		return
	}
	cfgs, _ := s.alerts.Configs(ctx, 0)
	c, msg := s.readRule(r, def, cfgs[def.Key])
	if msg != "" {
		s.renderRule(w, r, sess, http.StatusBadRequest, def, c, page{"Error": msg})
		return
	}
	if r.PostFormValue("action") == "preview" {
		s.previewRule(w, r, sess, def, c)
		return
	}
	if err := s.alerts.SetConfig(ctx, def.Key, 0, c, s.now()); err != nil {
		s.renderRule(w, r, sess, http.StatusBadRequest, def, c, page{"Error": err.Error()})
		return
	}
	s.auditUI(r, "alert_rule_saved", map[string]string{"rule": def.Key})
	http.Redirect(w, r, "/alerts?ok=rule-saved", http.StatusSeeOther)
}

type previewRow struct{ When, Kind, Severity, Message string }

func (s *Server) previewRule(w http.ResponseWriter, r *http.Request, sess auth.Session, def alerts.Definition, c alerts.Config) {
	ctx := r.Context()
	now := s.now()
	devices, _ := s.st.Devices(ctx)
	var rows []previewRow
	for _, d := range devices {
		evs, err := s.alerts.Preview(ctx, d, def.Key, c, now.Add(-24*time.Hour), now.Add(time.Minute))
		if err != nil {
			continue
		}
		for _, e := range evs {
			rows = append(rows, previewRow{When: d.Name + " · " + e.At.Local().Format("2 Jan 15:04"), Kind: e.Kind,
				Severity: e.Severity.String(), Message: e.Message})
		}
	}
	s.renderRule(w, r, sess, http.StatusOK, def, c, page{"Preview": rows, "Previewed": true})
}
