// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/buildinfo"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

type page map[string]any

// flashes maps fixed codes to messages so no user input is reflected.
var flashes = map[string]string{
	"password-changed": "Password changed. Other devices have been signed out.",
	"sessions-revoked": "All other devices have been signed out.",
	"signed-out":       "You have been signed out.",
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	info := buildinfo.Get()
	if p == nil {
		p = page{}
	}
	p["Version"], p["SourceURL"] = info.Version, info.SourceLink()
	p["InsecureHTTP"] = s.cfg.TLSMode == TLSOff && s.cfg.AllowInsecureHTTP
	p["MinLength"] = auth.MinPasswordLength
	if f, ok := flashes[r.URL.Query().Get("ok")]; ok {
		p["Flash"] = f
	}
	if _, ok := p["Title"]; !ok {
		p["Title"] = "Tesla Charger Monitoring"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.pages[name].ExecuteTemplate(w, "layout", p); err != nil {
		s.log.Error("rendering page", "page", name, "err", err)
	}
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, title, msg string) {
	s.render(w, r, status, "error", page{"Title": title, "Message": msg})
}

func (s *Server) setCookie(w http.ResponseWriter, c auth.SessionCookie) {
	// Secure is false only with TCMON_ALLOW_INSECURE_HTTP=true (explicit opt-in, warned in the UI).
	ck := &http.Cookie{Name: s.cfg.cookieName(), Value: c.Value, Path: "/", HttpOnly: true, //nolint:gosec // G124: see above
		Secure: s.cfg.secureCookies(), SameSite: http.SameSiteStrictMode}
	if c.Persist {
		ck.Expires = c.Expires
		ck.MaxAge = int(time.Until(c.Expires).Seconds())
	}
	http.SetCookie(w, ck)
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: s.cfg.cookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, //nolint:gosec // G124: as setCookie
		Secure: s.cfg.secureCookies(), SameSite: http.SameSiteStrictMode})
}

func (s *Server) session(r *http.Request) (auth.Session, bool) {
	c, err := r.Cookie(s.cfg.cookieName())
	if err != nil {
		return auth.Session{}, false
	}
	sess, err := s.auth.Session(r.Context(), c.Value)
	return sess, err == nil
}

type authedHandler func(http.ResponseWriter, *http.Request, auth.Session)

// authed requires a session; state-changing requests also need the
// session's CSRF token (defense in depth on top of CrossOriginProtection).
func (s *Server) authed(h authedHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.session(r)
		if !ok {
			if r.Method != http.MethodGet {
				s.renderError(w, r, http.StatusUnauthorized, "Signed out", "Your session has ended. Please sign in again.")
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !sess.CheckCSRF(r.PostFormValue("csrf_token")) {
			s.renderError(w, r, http.StatusForbidden, "Request blocked", "The form expired or did not come from this app. Reload the page and try again.")
			return
		}
		h(w, r, sess)
	})
}

func (s *Server) base(p page, sess auth.Session, nav string) page {
	p["SignedIn"], p["CSRF"], p["Nav"] = true, sess.CSRFToken, nav
	return p
}

// formCookie names the pre-session CSRF cookie used by the login and setup
// forms (double-submit token, on top of CrossOriginProtection).
func (s *Server) formCookie() string {
	if s.cfg.secureCookies() {
		return "__Host-tcmon_form"
	}
	return "tcmon_form"
}

// issueFormToken sets a fresh pre-session token cookie and returns it for
// the form's hidden field.
func (s *Server) issueFormToken(w http.ResponseWriter) string {
	tok := randomToken()
	http.SetCookie(w, &http.Cookie{Name: s.formCookie(), Value: tok, Path: "/", MaxAge: 3600, HttpOnly: true, //nolint:gosec // G124: Secure as setCookie
		Secure: s.cfg.secureCookies(), SameSite: http.SameSiteStrictMode})
	return tok
}

// checkFormToken verifies the double-submitted pre-session token.
func (s *Server) checkFormToken(r *http.Request) bool {
	c, err := r.Cookie(s.formCookie())
	sent := r.PostFormValue("csrf_token")
	return err == nil && len(c.Value) >= 32 && subtle.ConstantTimeCompare([]byte(c.Value), []byte(sent)) == 1
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if has, err := s.auth.HasPassword(r.Context()); err == nil && !has {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login", page{"Title": "Sign in", "FormToken": s.issueFormToken(w)})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.checkFormToken(r) {
		s.render(w, r, http.StatusForbidden, "login", page{"Title": "Sign in", "FormToken": s.issueFormToken(w),
			"Error": "The sign-in form expired. Please try again."})
		return
	}
	ip := clientIP(r).String()
	c, err := s.auth.Login(r.Context(), r.PostFormValue("password"), ip, r.UserAgent(), r.PostFormValue("remember") == "1")
	var te *auth.ThrottledError
	switch {
	case errors.As(err, &te):
		w.Header().Set("Retry-After", strconv.Itoa(int(te.RetryAfter.Seconds())+1))
		s.render(w, r, http.StatusTooManyRequests, "login", page{"Title": "Sign in", "Error": te.Error(), "FormToken": s.issueFormToken(w)})
	case errors.Is(err, auth.ErrNoPassword):
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
	case errors.Is(err, auth.ErrBadPassword):
		s.render(w, r, http.StatusUnauthorized, "login", page{"Title": "Sign in", "Error": "Incorrect password.", "FormToken": s.issueFormToken(w)})
	case err != nil:
		s.log.Error("login", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Error", "Sign-in failed because of an internal error. See the container log.")
	default:
		s.setCookie(w, c)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	if has, err := s.auth.HasPassword(r.Context()); err == nil && has {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.auth.SetupOpen(r.Context()) {
		s.render(w, r, http.StatusGone, "setup_closed", page{"Title": "Setup closed"})
		return
	}
	s.render(w, r, http.StatusOK, "setup", page{"Title": "Set your password", "FormToken": s.issueFormToken(w)})
}

func (s *Server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.checkFormToken(r) {
		s.render(w, r, http.StatusForbidden, "setup", page{"Title": "Set your password", "FormToken": s.issueFormToken(w),
			"Error": "The setup form expired. Please try again."})
		return
	}
	c, err := s.auth.CompleteSetup(r.Context(), r.PostFormValue("token"), r.PostFormValue("password"),
		r.PostFormValue("confirm"), clientIP(r).String(), r.UserAgent())
	var te *auth.ThrottledError
	switch {
	case errors.Is(err, auth.ErrSetupClosed):
		s.render(w, r, http.StatusGone, "setup_closed", page{"Title": "Setup closed"})
	case errors.As(err, &te):
		s.render(w, r, http.StatusTooManyRequests, "setup", page{"Title": "Set your password", "Error": te.Error(), "FormToken": s.issueFormToken(w)})
	case err != nil:
		msg := auth.UserMessage(err)
		if msg == "" {
			s.log.Error("setup", "err", err)
			msg = "Setup failed because of an internal error. See the container log."
		}
		s.render(w, r, http.StatusBadRequest, "setup", page{"Title": "Set your password", "Error": msg, "FormToken": s.issueFormToken(w)})
	default:
		s.setCookie(w, c)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	_ = s.auth.Logout(r.Context(), sess, clientIP(r).String())
	s.clearCookie(w)
	http.Redirect(w, r, "/login?ok=signed-out", http.StatusSeeOther)
}

type deviceRow struct{ Name, Address, LastPoll, Firmware string }
type alertRow struct{ Severity, When, Message string }

func (s *Server) home(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx := r.Context()
	var rows []deviceRow
	devices, _ := s.st.Devices(ctx)
	for _, d := range devices {
		row := deviceRow{Name: d.Name, Address: d.Address, LastPoll: "never", Firmware: "–"}
		if log, err := s.st.PollLog(ctx, d.ID, 1); err == nil && len(log) == 1 {
			status := "ok"
			if !log[0].OK {
				status = "failed"
			}
			row.LastPoll = log[0].TS.Local().Format("2 Jan 15:04") + " (" + status + ")"
		}
		if info, err := s.st.DeviceInfo(ctx, d.ID); err == nil {
			row.Firmware = info.FirmwareVersion
		}
		rows = append(rows, row)
	}
	var alerts []alertRow
	evs, _ := s.st.AlertEvents(ctx, store.AlertEventFilter{Limit: 10})
	for _, e := range evs {
		alerts = append(alerts, alertRow{Severity: e.Severity, When: e.TS.Local().Format("2 Jan 15:04"), Message: e.Message})
	}
	s.render(w, r, http.StatusOK, "home", s.base(page{"Title": "Dashboard", "Devices": rows, "Alerts": alerts}, sess, "home"))
}

func (s *Server) about(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	info := buildinfo.Get()
	p := page{"Title": "About", "Commit": info.Commit}
	if s.certs != nil {
		p["CertFingerprint"] = s.certs.Fingerprint()
	}
	s.render(w, r, http.StatusOK, "about", s.base(p, sess, "about"))
}

type auditRow struct{ When, Action, IP string }

func (s *Server) securityPage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	s.renderSecurity(w, r, sess, http.StatusOK, "")
}

func (s *Server) renderSecurity(w http.ResponseWriter, r *http.Request, sess auth.Session, status int, errMsg string) {
	n, _ := s.st.CountSessions(r.Context(), s.now())
	var audit []auditRow
	entries, _ := s.st.AuditLog(r.Context(), 15)
	for _, e := range entries {
		audit = append(audit, auditRow{When: e.TS.Local().Format("2 Jan 15:04"), Action: e.Action, IP: e.IP})
	}
	p := page{"Title": "Security", "EnvManaged": s.auth.EnvManaged(), "Sessions": n, "Audit": audit}
	if errMsg != "" {
		p["Error"] = errMsg
	}
	s.render(w, r, status, "security", s.base(p, sess, "security"))
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	c, err := s.auth.ChangePassword(r.Context(), r.PostFormValue("current"), r.PostFormValue("password"),
		r.PostFormValue("confirm"), clientIP(r).String(), r.UserAgent())
	if err != nil {
		status := http.StatusBadRequest
		var te *auth.ThrottledError
		if errors.As(err, &te) {
			status = http.StatusTooManyRequests
		}
		msg := auth.UserMessage(err)
		if msg == "" {
			s.log.Error("changing password", "err", err)
			status, msg = http.StatusInternalServerError, "The password could not be changed because of an internal error."
		}
		s.renderSecurity(w, r, sess, status, msg)
		return
	}
	s.setCookie(w, c)
	http.Redirect(w, r, "/settings/security?ok=password-changed", http.StatusSeeOther)
}

func (s *Server) revokeSessions(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	if _, err := s.auth.SignOutOthers(r.Context(), sess, clientIP(r).String()); err != nil {
		s.renderSecurity(w, r, sess, http.StatusInternalServerError, "Could not sign out other devices.")
		return
	}
	http.Redirect(w, r, "/settings/security?ok=sessions-revoked", http.StatusSeeOther)
}

func (s *Server) certificate(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	if s.certs == nil {
		s.renderError(w, r, http.StatusNotFound, "No certificate", "HTTPS is terminated by a proxy.")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="tesla-charger-monitoring.pem"`)
	_, _ = w.Write(s.certs.PEM())
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error
	return base64.RawURLEncoding.EncodeToString(b)
}
