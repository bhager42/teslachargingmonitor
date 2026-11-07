// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/buildinfo"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

type retentionField struct {
	Name, Label, Help string
	Days              int
	Custom            bool // value is not one of the presets
}

var retentionPresets = []struct {
	Days  int
	Label string
}{{30, tr.T("settings.keep_30d")}, {90, tr.T("settings.keep_90d")}, {180, tr.T("settings.keep_6m")}, {365, tr.T("settings.keep_1y")},
	{730, tr.T("settings.keep_2y")}, {1825, tr.T("settings.keep_5y")}, {0, tr.T("settings.keep_forever")}}

func retentionFields(r store.Retention) []retentionField {
	fields := []retentionField{
		{"readings_days", tr.T("settings.keep_readings"), tr.T("settings.keep_readings_help"), r.ReadingsDays, false},
		{"raw_payloads_days", tr.T("settings.keep_raw"), tr.T("settings.keep_raw_help"), r.RawPayloadsDays, false},
		{"rollups_days", tr.T("settings.keep_rollups"), tr.T("settings.keep_rollups_help"), r.RollupsDays, false},
		{"events_days", tr.T("settings.keep_events"), "", r.EventsDays, false},
		{"poll_log_days", tr.T("settings.keep_poll_log"), "", r.PollLogDays, false},
		{"audit_days", tr.T("settings.keep_audit"), "", r.AuditDays, false},
	}
	for i := range fields {
		fields[i].Custom = true
		for _, p := range retentionPresets {
			if p.Days == fields[i].Days {
				fields[i].Custom = false
			}
		}
	}
	return fields
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	s.renderSettings(w, r, sess, http.StatusOK, page{})
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, sess auth.Session, status int, p page) {
	ctx := r.Context()
	ret, _ := s.st.Retention(ctx)
	stats, _ := s.st.Stats(ctx)
	p["Title"], p["Retention"], p["Presets"], p["Display"] = tr.T("settings.title"), retentionFields(ret), retentionPresets, s.display(ctx)
	p["DBSize"] = fmt.Sprintf("%.1f MB", float64(stats.SizeBytes)/1e6)
	if hb := s.heartbeatView(); hb != nil {
		p["Heartbeat"] = hb
	}
	if !stats.OldestReading.IsZero() {
		p["Oldest"] = stats.OldestReading.Local().Format("2 Jan 2006")
	}
	s.render(w, r, status, "settings", s.base(p, sess, "settings"))
}

func (s *Server) saveSettings(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx := r.Context()
	cur, _ := s.st.Retention(ctx)
	next := cur
	fields := map[string]*int{"readings_days": &next.ReadingsDays, "raw_payloads_days": &next.RawPayloadsDays,
		"rollups_days": &next.RollupsDays, "events_days": &next.EventsDays, "poll_log_days": &next.PollLogDays,
		"audit_days": &next.AuditDays}
	for name, dst := range fields {
		v := r.PostFormValue(name)
		if v == "custom" {
			v = r.PostFormValue(name + "_custom")
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			s.renderSettings(w, r, sess, http.StatusBadRequest, page{"Error": tr.T("settings.err_retention")})
			return
		}
		*dst = n
	}
	if err := next.Validate(); err != nil {
		s.renderSettings(w, r, sess, http.StatusBadRequest, page{"Error": err.Error()})
		return
	}
	shorter := func(a, b int) bool { return a != store.KeepForever && (b == store.KeepForever || a < b) }
	shrinking := shorter(next.ReadingsDays, cur.ReadingsDays) || shorter(next.RawPayloadsDays, cur.RawPayloadsDays) ||
		shorter(next.RollupsDays, cur.RollupsDays) || shorter(next.EventsDays, cur.EventsDays) ||
		shorter(next.PollLogDays, cur.PollLogDays) || shorter(next.AuditDays, cur.AuditDays)
	if shrinking && r.PostFormValue("confirm_delete") != "1" {
		s.renderSettings(w, r, sess, http.StatusBadRequest, page{"Error": tr.T("settings.err_confirm_delete")})
		return
	}
	unit := r.PostFormValue("temp_unit")
	if unit != "F" {
		unit = "C"
	}
	now := s.now()
	if err := s.st.SetRetention(ctx, next, now); err != nil {
		s.renderSettings(w, r, sess, http.StatusInternalServerError, page{"Error": tr.T("settings.err_save")})
		return
	}
	if err := s.st.SetSetting(ctx, displayKey, Display{TempUnit: unit}, now); err != nil {
		s.renderSettings(w, r, sess, http.StatusInternalServerError, page{"Error": tr.T("settings.err_save")})
		return
	}
	s.auditUI(r, "settings_saved", map[string]string{"readings_days": strconv.Itoa(next.ReadingsDays)})
	http.Redirect(w, r, "/settings?ok=settings-saved", http.StatusSeeOther)
}

// backup streams a consistent copy of the database.
func (s *Server) backup(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	dir, err := os.MkdirTemp(filepath.Join(s.cfg.DataDir), ".backup-")
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr.T("settings.backup_failed"), tr.T("settings.backup_err_temp"))
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "tcmon.db")
	if err := s.st.Backup(r.Context(), path); err != nil {
		s.log.Error("backup", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, tr.T("settings.backup_failed"), tr.T("error.see_log"))
		return
	}
	f, err := os.Open(path) //nolint:gosec // path built above inside the data directory
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr.T("settings.backup_failed"), tr.T("error.see_log"))
		return
	}
	defer func() { _ = f.Close() }()
	s.auditUI(r, "backup_downloaded", nil)
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="tcmon-backup-%s.db"`, s.now().Format("20060102-1504")))
	_, _ = io.Copy(w, f)
}

type diagDevice struct {
	Name     string
	Polls    []diagPoll
	Problems []string
	RawAt    string
}

type diagPoll struct{ When, Result, Took, Error string }

func (s *Server) diagnostics(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx := r.Context()
	devices, _ := s.st.Devices(ctx)
	var out []diagDevice
	for _, d := range devices {
		dd := diagDevice{Name: d.Name}
		log, _ := s.st.PollLog(ctx, d.ID, 15)
		for _, e := range log {
			res := tr.T("diagnostics.poll_ok")
			if !e.OK {
				res = tr.T("diagnostics.poll_failed", "attempt", e.Attempt)
			}
			dd.Polls = append(dd.Polls, diagPoll{When: e.TS.Local().Format("2 Jan 15:04:05"), Result: res,
				Took: e.Duration.Round(time.Millisecond).String(), Error: e.Error})
		}
		raw, at, _ := s.st.LatestRaw(ctx, d.ID)
		if !at.IsZero() {
			dd.RawAt = at.Local().Format("2 Jan 15:04")
		}
		decoders := map[string]func([]byte) (wallconnector.Report, error){
			"vitals": func(b []byte) (wallconnector.Report, error) {
				_, r, err := wallconnector.DecodeVitals(b)
				return r, err
			},
			"lifetime": func(b []byte) (wallconnector.Report, error) {
				_, r, err := wallconnector.DecodeLifetime(b)
				return r, err
			},
			"wifi_status": func(b []byte) (wallconnector.Report, error) {
				_, r, err := wallconnector.DecodeWifiStatus(b)
				return r, err
			},
			"version": func(b []byte) (wallconnector.Report, error) {
				_, r, err := wallconnector.DecodeVersion(b)
				return r, err
			},
		}
		for _, ep := range wallconnector.Endpoints {
			b, ok := raw[string(ep)]
			if !ok {
				continue
			}
			rep, err := decoders[string(ep)](b)
			if err != nil {
				dd.Problems = append(dd.Problems, ep.Path()+": "+err.Error())
				continue
			}
			for _, u := range rep.Unknown {
				dd.Problems = append(dd.Problems, tr.T("diagnostics.unknown_field", "endpoint", ep.Path(), "field", u))
			}
			for _, m := range rep.Missing {
				dd.Problems = append(dd.Problems, tr.T("diagnostics.missing_field", "endpoint", ep.Path(), "field", m))
			}
			for _, iv := range rep.Invalid {
				dd.Problems = append(dd.Problems, ep.Path()+": "+iv.String())
			}
		}
		out = append(out, dd)
	}
	stats, _ := s.st.Stats(ctx)
	ver, _ := s.st.SchemaVersion(ctx)
	info := buildinfo.Get()
	var rows []kv
	for _, t := range store.StatsTables {
		rows = append(rows, kv{t, strconv.FormatInt(stats.Rows[t], 10)})
	}
	clients := 0
	if s.hub != nil {
		clients = s.hub.Clients()
	}
	s.render(w, r, http.StatusOK, "diagnostics", s.base(page{"Title": tr.T("diagnostics.title"), "Devices": out, "Rows": rows,
		"DBSize": fmt.Sprintf("%.1f MB", float64(stats.SizeBytes)/1e6), "Schema": ver, "GoVersion": info.GoVersion,
		"LiveClients": clients, "Heartbeat": s.heartbeatView()}, sess, "diagnostics"))
}
