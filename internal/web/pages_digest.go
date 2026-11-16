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
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/digest"
	"github.com/bhager42/teslachargingmonitor/internal/notify"
)

// lastDigest builds the digest for the most recent complete week or month.
func (s *Server) lastDigest(r *http.Request, per digest.Period) (notify.Message, error) {
	from, to := per.Range(s.now(), time.Local)
	return digest.Build(r.Context(), s.st, per, from, to, time.Local)
}

// digestPreview shows the plain-text version of the last weekly digest, or
// of the monthly one with ?period=monthly (the HTML email uses inline
// styles, which the page's CSP forbids).
func (s *Server) digestPreview(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	per := digest.ParsePeriod(r.URL.Query().Get("period"))
	msg, err := s.lastDigest(r, per)
	if err != nil {
		s.log.Error("building digest preview", "period", per.String(), "err", err)
		s.renderError(w, r, http.StatusInternalServerError, tr.T("digest.preview_failed"), tr.T("error.see_log"))
		return
	}
	title := tr.T("digest.title")
	if per == digest.Monthly {
		title = tr.T("digest.monthly_title")
	}
	s.render(w, r, http.StatusOK, "digest", s.base(page{"Title": title, "Subject": msg.Subject,
		"Text": msg.Text, "SendHour": digest.SendHour, "Monthly": per == digest.Monthly}, sess, "notifications"))
}

// sendDigest sends the last weekly digest (or the monthly one when the
// form has period=monthly) through one channel now.
func (s *Server) sendDigest(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	c, ok := s.channelFromPath(w, r)
	if !ok {
		return
	}
	per := digest.ParsePeriod(r.PostFormValue("period"))
	msg, err := s.lastDigest(r, per)
	if err == nil {
		err = s.notify.SendNow(r.Context(), c.ID, msg)
	}
	if err != nil {
		failed := tr.T("digest.send_failed", "error", notify.Describe(err))
		if per == digest.Monthly {
			failed = tr.T("digest.monthly_send_failed", "error", notify.Describe(err))
		}
		s.renderChannel(w, r, sess, http.StatusBadRequest, channelToForm(c), page{"Error": failed})
		return
	}
	s.auditUI(r, "digest_sent", map[string]string{"channel_id": strconv.FormatInt(c.ID, 10), "period": per.String()})
	flash := "digest-sent"
	if per == digest.Monthly {
		flash = "monthly-sent"
	}
	http.Redirect(w, r, "/notifications?ok="+flash, http.StatusSeeOther)
}
