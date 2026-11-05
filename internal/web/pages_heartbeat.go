// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/heartbeat"
)

// heartbeatView is the dead-man's-switch state, formatted for templates.
type heartbeatView struct {
	Configured                                   bool
	Display, LastAttempt, LastSuccess, LastError string
	LastErrorAt                                  string
	Failures                                     int
}

func (s *Server) heartbeatView() *heartbeatView {
	if s.beat == nil {
		return nil
	}
	st := s.beat.Status()
	when := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Local().Format("2 Jan 15:04:05")
	}
	return &heartbeatView{Configured: st.Configured, Display: st.Display, LastAttempt: when(st.LastAttempt),
		LastSuccess: when(st.LastSuccess), LastError: st.LastError, LastErrorAt: when(st.LastErrorAt),
		Failures: st.ConsecutiveFailures}
}

// saveHeartbeat handles the dead-man's-switch form: save (optionally with a
// test ping), test the saved URL, or remove it.
func (s *Server) saveHeartbeat(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if s.beat == nil {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	fail := func(msg string) { s.renderSettings(w, r, sess, http.StatusBadRequest, page{"Error": msg}) }
	action := r.PostFormValue("action")
	raw := strings.TrimSpace(r.PostFormValue("ping_url"))
	switch action {
	case "remove":
		if err := s.beat.Clear(ctx); err != nil {
			s.renderSettings(w, r, sess, http.StatusInternalServerError, page{"Error": "Could not remove the ping URL."})
			return
		}
		s.auditUI(r, "heartbeat_removed", nil)
		http.Redirect(w, r, "/settings?ok=beat-removed#heartbeat", http.StatusSeeOther)
		return
	case "save", "test":
	default:
		fail("Unknown action.")
		return
	}
	if raw != "" {
		if err := s.beat.Set(ctx, raw); err != nil {
			if errors.Is(err, heartbeat.ErrBadURL) {
				fail("The ping URL is not valid: " + strings.TrimPrefix(err.Error(), heartbeat.ErrBadURL.Error()+": ") + ".")
			} else {
				s.log.Error("saving ping URL", "err", err)
				fail("Could not save the ping URL.")
			}
			return
		}
		s.auditUI(r, "heartbeat_saved", map[string]string{"test": strconv.FormatBool(action == "test")})
	} else if action == "save" || !s.beat.Status().Configured {
		fail("Enter the ping URL from your monitoring service.")
		return
	}
	if action == "save" {
		http.Redirect(w, r, "/settings?ok=beat-saved#heartbeat", http.StatusSeeOther)
		return
	}
	if err := s.beat.Ping(ctx); err != nil {
		prefix := "The test ping failed: "
		if raw != "" {
			prefix = "Saved, but the test ping failed: "
		}
		fail(prefix + err.Error() + ".")
		return
	}
	http.Redirect(w, r, "/settings?ok=beat-tested#heartbeat", http.StatusSeeOther)
}
