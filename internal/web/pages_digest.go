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

// lastDigest builds the digest for the most recent complete week.
func (s *Server) lastDigest(r *http.Request) (notify.Message, error) {
	from, to := digest.Week(s.now(), time.Local)
	return digest.Build(r.Context(), s.st, from, to, time.Local)
}

// digestPreview shows the plain-text version of last week's digest (the
// HTML email uses inline styles, which the page's CSP forbids).
func (s *Server) digestPreview(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	msg, err := s.lastDigest(r)
	if err != nil {
		s.log.Error("building digest preview", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, tr.T("digest.preview_failed"), tr.T("error.see_log"))
		return
	}
	s.render(w, r, http.StatusOK, "digest", s.base(page{"Title": tr.T("digest.title"), "Subject": msg.Subject,
		"Text": msg.Text, "SendHour": digest.SendHour}, sess, "notifications"))
}

// sendDigest sends last week's digest through one channel now.
func (s *Server) sendDigest(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	c, ok := s.channelFromPath(w, r)
	if !ok {
		return
	}
	msg, err := s.lastDigest(r)
	if err == nil {
		err = s.notify.SendNow(r.Context(), c.ID, msg)
	}
	if err != nil {
		s.renderChannel(w, r, sess, http.StatusBadRequest, channelToForm(c),
			page{"Error": tr.T("digest.send_failed", "error", notify.Describe(err))})
		return
	}
	s.auditUI(r, "digest_sent", map[string]string{"channel_id": strconv.FormatInt(c.ID, 10)})
	http.Redirect(w, r, "/notifications?ok=digest-sent", http.StatusSeeOther)
}
