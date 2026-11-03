// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/notify"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
)

type channelForm struct {
	ID                                                       int64
	Name, Username, To, Host, Port, Security, From, FromName string
	MinSeverity, QuietHours                                  string
	Enabled, PasswordSet                                     bool
}

type deliveryRow struct{ When, Channel, Status, Subject, Error string }

func (s *Server) notificationsPage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if s.notify == nil {
		s.renderError(w, r, http.StatusServiceUnavailable, "Unavailable", "Notifications are not configured in this process.")
		return
	}
	ctx := r.Context()
	chs, _ := s.notify.Channels(ctx)
	names := map[int64]string{}
	for _, c := range chs {
		names[c.ID] = c.Name
	}
	var log []deliveryRow
	ds, _ := s.st.Deliveries(ctx, 0, 20)
	for _, d := range ds {
		log = append(log, deliveryRow{When: d.CreatedAt.Local().Format("2 Jan 15:04"), Channel: names[d.ChannelID],
			Status: d.Status, Subject: d.Subject, Error: d.LastError})
	}
	s.render(w, r, http.StatusOK, "notifications", s.base(page{"Title": "Notifications", "Channels": chs, "Log": log,
		"Now": s.now()}, sess, "notifications"))
}

func channelToForm(c notify.ChannelInfo) channelForm {
	return channelForm{ID: c.ID, Name: c.Name, Username: c.Email.Username, To: strings.Join(c.Email.To, ", "),
		Host: c.Email.Host, Port: strconv.Itoa(c.Email.Port), Security: c.Email.Security, From: c.Email.From,
		FromName: c.Email.FromName, MinSeverity: c.MinSeverity.String(), QuietHours: c.QuietHours, Enabled: c.Enabled,
		PasswordSet: c.PasswordSet}
}

func (s *Server) renderChannel(w http.ResponseWriter, r *http.Request, sess auth.Session, status int, f channelForm, p page) {
	if p == nil {
		p = page{}
	}
	p["Form"], p["Title"] = f, "Email notifications"
	p["Severities"] = []string{"info", "warning", "critical"}
	s.render(w, r, status, "channel", s.base(p, sess, "notifications"))
}

func (s *Server) newChannel(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	g := notify.GmailPreset("")
	s.renderChannel(w, r, sess, http.StatusOK, channelForm{Name: "Gmail", Host: g.Host, Port: strconv.Itoa(g.Port),
		Security: g.Security, FromName: g.FromName, MinSeverity: "info", Enabled: true}, nil)
}

func (s *Server) channelFromPath(w http.ResponseWriter, r *http.Request) (notify.ChannelInfo, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil && s.notify != nil {
		if c, err := s.notify.Channel(r.Context(), id); err == nil {
			return c, true
		}
	}
	s.renderError(w, r, http.StatusNotFound, "Not found", "That notification channel does not exist.")
	return notify.ChannelInfo{}, false
}

func (s *Server) editChannel(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	c, ok := s.channelFromPath(w, r)
	if !ok {
		return
	}
	s.renderChannel(w, r, sess, http.StatusOK, channelToForm(c), nil)
}

func (s *Server) saveChannel(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if s.notify == nil {
		s.renderError(w, r, http.StatusServiceUnavailable, "Unavailable", "Notifications are not configured.")
		return
	}
	ctx := r.Context()
	f := channelForm{Name: r.PostFormValue("name"), Username: strings.TrimSpace(r.PostFormValue("username")),
		To: r.PostFormValue("to"), Host: r.PostFormValue("host"), Port: r.PostFormValue("port"),
		Security: r.PostFormValue("security"), From: strings.TrimSpace(r.PostFormValue("from")),
		FromName: r.PostFormValue("from_name"), MinSeverity: r.PostFormValue("min_severity"),
		QuietHours: strings.TrimSpace(r.PostFormValue("quiet_hours")), Enabled: r.PostFormValue("enabled") == "1"}
	var existing *notify.ChannelInfo
	if r.PathValue("id") != "" {
		c, ok := s.channelFromPath(w, r)
		if !ok {
			return
		}
		existing, f.ID, f.PasswordSet = &c, c.ID, c.PasswordSet
	}
	fail := func(msg string) { s.renderChannel(w, r, sess, http.StatusBadRequest, f, page{"Error": msg}) }
	port, err := strconv.Atoi(strings.TrimSpace(f.Port))
	if err != nil {
		fail("Port must be a number.")
		return
	}
	sev, err := alerts.ParseSeverity(f.MinSeverity)
	if err != nil {
		fail("Choose a minimum severity.")
		return
	}
	from := f.From
	if from == "" {
		from = f.Username
	}
	var to []string
	for _, a := range strings.Split(f.To, ",") {
		if a = strings.TrimSpace(a); a != "" {
			to = append(to, a)
		}
	}
	// The password field is write-only; Gmail shows app passwords with spaces.
	pw := secrets.Secret(strings.Join(strings.Fields(r.PostFormValue("password")), ""))
	settings := notify.EmailSettings{Name: strings.TrimSpace(f.Name), Enabled: f.Enabled, MinSeverity: sev,
		QuietHours: f.QuietHours, Password: pw, Email: notify.EmailConfig{Host: f.Host, Port: port, Security: f.Security,
			Username: f.Username, From: from, FromName: f.FromName, To: to, SubjectPrefix: notify.DefaultSubjectPrefix}}
	var ci notify.ChannelInfo
	if existing == nil {
		ci, err = s.notify.CreateEmailChannel(ctx, settings)
	} else {
		ci, err = s.notify.UpdateEmailChannel(ctx, existing.ID, settings)
	}
	if err != nil {
		fail(err.Error()) // validation messages from notify are written for users
		return
	}
	s.auditUI(r, "notification_channel_saved", map[string]string{"channel_id": strconv.FormatInt(ci.ID, 10)})
	if r.PostFormValue("action") == "save_test" {
		if err := s.notify.Test(ctx, ci.ID); err != nil {
			f.ID, f.PasswordSet = ci.ID, ci.PasswordSet
			s.renderChannel(w, r, sess, http.StatusBadRequest, f, page{"Error": "Saved, but the test email failed: " + notify.Describe(err)})
			return
		}
		http.Redirect(w, r, "/notifications?ok=test-sent", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/notifications?ok=channel-saved", http.StatusSeeOther)
}

func (s *Server) testChannel(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	c, ok := s.channelFromPath(w, r)
	if !ok {
		return
	}
	if err := s.notify.Test(r.Context(), c.ID); err != nil {
		s.renderChannel(w, r, sess, http.StatusBadRequest, channelToForm(c), page{"Error": "Test email failed: " + notify.Describe(err)})
		return
	}
	http.Redirect(w, r, "/notifications?ok=test-sent", http.StatusSeeOther)
}

func (s *Server) deleteChannel(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	c, ok := s.channelFromPath(w, r)
	if !ok {
		return
	}
	if err := s.notify.DeleteChannel(r.Context(), c.ID); err == nil {
		s.auditUI(r, "notification_channel_deleted", map[string]string{"channel_id": strconv.FormatInt(c.ID, 10)})
	}
	http.Redirect(w, r, "/notifications?ok=channel-deleted", http.StatusSeeOther)
}
