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
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/buildinfo"
	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

// Settings → Solar Gateway (Phase 9 step 5). The owner has one Backup
// Gateway (D27), so this is one page rather than a list. Adding one takes
// two steps: the address, to read and show the certificate fingerprint
// without logging in, then the confirmation and the customer password,
// which is tested with exactly one login before anything is saved.

// gatewayTestPause is how long the page refuses another test login after
// the Gateway rejected one, so repeated clicks cannot trigger its lockout.
const gatewayTestPause = 5 * time.Minute

// gatewayGuard remembers when the last test login was rejected.
type gatewayGuard struct {
	mu    sync.Mutex
	until time.Time
}

func (g *gatewayGuard) blocked(now time.Time) (time.Time, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.until, now.Before(g.until)
}

func (g *gatewayGuard) reject(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.until = now.Add(gatewayTestPause)
}

// gatewayForm is the form's state. The password is never part of it, so
// it is never written back into the page.
type gatewayForm struct {
	ID                      int64
	Name, Address           string
	Interval, Charging      string // minutes
	Enabled, AllowNonLAN    bool
	Pin                     string // fingerprint shown for confirmation
	PinGroups               string // the same, grouped for reading
	HasPassword, NewAddress bool
}

func groupPin(p string) string {
	var parts []string
	for i := 0; i < len(p); i += 4 {
		parts = append(parts, p[i:min(i+4, len(p))])
	}
	return strings.Join(parts, " ")
}

func formFromGateway(g store.Gateway) gatewayForm {
	return gatewayForm{ID: g.ID, Name: g.Name, Address: g.Address, Enabled: g.Enabled, AllowNonLAN: g.AllowNonLAN,
		Interval: strconv.Itoa(int(g.PollInterval / time.Minute)), Charging: strconv.Itoa(int(g.ChargingInterval / time.Minute)),
		HasPassword: len(g.PasswordEnc) > 0}
}

func readGatewayForm(r *http.Request) gatewayForm {
	return gatewayForm{
		Name:        strings.TrimSpace(r.PostFormValue("name")),
		Address:     strings.TrimSpace(r.PostFormValue("address")),
		Interval:    strings.TrimSpace(r.PostFormValue("interval")),
		Charging:    strings.TrimSpace(r.PostFormValue("charging_interval")),
		Enabled:     r.PostFormValue("enabled") == "1",
		AllowNonLAN: r.PostFormValue("allow_non_lan") == "1",
		Pin:         store.NormalizePin(r.PostFormValue("pin")),
	}
}

// firstGateway returns the configured Gateway, if any.
func (s *Server) firstGateway(ctx context.Context) (store.Gateway, bool) {
	gws, err := s.st.Gateways(ctx)
	if err != nil || len(gws) == 0 {
		return store.Gateway{}, false
	}
	return gws[0], true
}

type gatewayStatus struct {
	Firmware, LastPoll, Battery, Solar, Backoff, Pending, PendingGroups string
	Log                                                                 []pollRow
}

type pollRow struct{ When, Result string }

func (s *Server) gatewayStatus(ctx context.Context, g store.Gateway) gatewayStatus {
	now := s.now()
	var st gatewayStatus
	if info, err := s.st.GatewayInfo(ctx, g.ID); err == nil {
		st.Firmware = info.FirmwareVersion
		if info.BatteryCount > 0 {
			st.Battery = tr.T("gateway.battery_summary", "count", info.BatteryCount, "kwh", fmt.Sprintf("%.1f", info.FullPackWh/1000))
		}
		if info.SolarRatingW > 0 {
			st.Solar = fmt.Sprintf("%.1f kW", info.SolarRatingW/1000)
		}
	}
	if gs, err := s.st.LatestGatewayState(ctx, g.ID); err == nil && !gs.LastSuccess.IsZero() {
		st.LastPoll = fmtAgo(gs.LastSuccess, now)
	}
	if g.Backoff.Until.After(now) {
		st.Backoff = tr.T("gateway.backoff", "until", g.Backoff.Until.Local().Format("Mon 2 Jan 15:04"))
	}
	if g.PendingPin != "" {
		st.Pending, st.PendingGroups = g.PendingPin, groupPin(g.PendingPin)
	}
	if log, err := s.st.GatewayPollLog(ctx, g.ID, 5); err == nil {
		for _, e := range log {
			res := tr.T("gateway.poll_ok", "ms", e.Duration.Milliseconds())
			if !e.OK {
				res = e.Error
			}
			st.Log = append(st.Log, pollRow{When: e.TS.Local().Format("2 Jan 15:04"), Result: res})
		}
	}
	return st
}

func (s *Server) renderGateway(w http.ResponseWriter, r *http.Request, sess auth.Session, status int, f gatewayForm, p page) {
	if p == nil {
		p = page{}
	}
	if f.Pin != "" {
		f.PinGroups = groupPin(f.Pin)
	}
	p["Title"], p["Form"] = tr.T("gateway.title"), f
	if f.ID != 0 {
		if g, err := s.st.Gateway(r.Context(), f.ID); err == nil {
			p["Status"] = s.gatewayStatus(r.Context(), g)
		}
	}
	s.render(w, r, status, "gateway", s.base(p, sess, "settings"))
}

func (s *Server) gatewayPage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	g, ok := s.firstGateway(r.Context())
	if !ok {
		def := store.NewGateway(tr.T("gateway.default_name"), "", "", nil)
		f := formFromGateway(def)
		f.HasPassword = false
		s.renderGateway(w, r, sess, http.StatusOK, f, nil)
		return
	}
	s.renderGateway(w, r, sess, http.StatusOK, formFromGateway(g), nil)
}

// findGateway reads the certificate fingerprint at an address without
// logging in, for the owner to confirm.
func (s *Server) findGateway(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx := r.Context()
	f := readGatewayForm(r)
	existing, has := s.firstGateway(ctx)
	if has {
		f.ID, f.HasPassword = existing.ID, true
	}
	hp, err := s.gatewayHostPort(f.Address, f.AllowNonLAN)
	if err != nil {
		f.Pin = ""
		s.renderGateway(w, r, sess, http.StatusBadRequest, f, page{"Error": err.Error()})
		return
	}
	fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	fp, err := gateway.Fingerprint(fctx, hp, f.AllowNonLAN)
	if err != nil {
		f.Pin = ""
		s.renderGateway(w, r, sess, http.StatusBadRequest, f, page{"Error": gatewayErrText(err, hp)})
		return
	}
	f.Address, f.Pin, f.NewAddress = hp, fp, true
	s.renderGateway(w, r, sess, http.StatusOK, f, page{"Found": true})
}

func (s *Server) gatewayHostPort(address string, allowNonLAN bool) (string, error) {
	a, err := wallconnector.ParseAddress(address, wallconnector.AddressOptions{AllowNonLAN: allowNonLAN})
	if err != nil {
		return "", err
	}
	return a.HostPort(), nil
}

// gatewayErrText explains a failed connection in the owner's terms. It
// never includes the password.
func gatewayErrText(err error, address string) string {
	var ce *gateway.CertError
	switch {
	case errors.Is(err, gateway.ErrLoginRejected):
		return tr.T("gateway.err_rejected")
	case errors.Is(err, gateway.ErrRateLimited):
		return tr.T("gateway.err_rate_limited")
	case errors.As(err, &ce):
		return tr.T("gateway.err_cert", "fingerprint", groupPin(ce.Fingerprint))
	case errors.Is(err, gateway.ErrBlockedAddress):
		return tr.T("device_form.probe_blocked")
	default:
		return tr.T("gateway.err_unreachable", "address", address)
	}
}

// testLogin logs in once and reads one snapshot, returning a summary.
func (s *Server) testLogin(ctx context.Context, address, pin string, pw secrets.Secret, allowNonLAN bool) (string, error) {
	c, err := gateway.NewClient(address, gateway.Options{Pin: pin, Password: pw, AllowNonLAN: allowNonLAN,
		UserAgent: "tcmon/" + buildinfo.Version, Timeout: 10 * time.Second})
	if err != nil {
		return "", err
	}
	defer c.Close()
	snap, err := c.Snapshot(ctx)
	if err != nil {
		return "", err
	}
	return tr.T("gateway.test_ok", "firmware", snap.Status.Firmware(), "count", len(snap.SystemStatus.BatteryBlocks),
		"pct", fmt.Sprintf("%.0f", snap.SOE.AppPercent()), "solar", fmt.Sprintf("%.0f", snap.Aggregates.Solar.InstantPower)), nil
}

func (s *Server) saveGateway(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx := r.Context()
	now := s.now()
	f := readGatewayForm(r)
	existing, has := s.firstGateway(ctx)
	if has {
		f.ID, f.HasPassword = existing.ID, true
	}
	fail := func(status int, msg string) {
		if !has || f.Address != existing.Address {
			f.NewAddress = f.Pin != ""
		}
		s.renderGateway(w, r, sess, status, f, page{"Error": msg, "Found": f.NewAddress})
	}
	if s.box == nil {
		fail(http.StatusInternalServerError, tr.T("gateway.err_no_key"))
		return
	}
	g := store.NewGateway(f.Name, f.Address, f.Pin, nil)
	if has {
		g = existing
		g.Name, g.Enabled = f.Name, f.Enabled
	}
	g.AllowNonLAN = f.AllowNonLAN
	iv, err1 := strconv.Atoi(f.Interval)
	ch, err2 := strconv.Atoi(f.Charging)
	if err1 != nil || err2 != nil {
		fail(http.StatusBadRequest, tr.T("gateway.err_interval"))
		return
	}
	g.PollInterval, g.ChargingInterval = time.Duration(iv)*time.Minute, time.Duration(ch)*time.Minute

	// A new Gateway, or a new address, needs a confirmed certificate.
	addrChanged := !has
	if has {
		hp, err := s.gatewayHostPort(f.Address, f.AllowNonLAN)
		if err != nil {
			fail(http.StatusBadRequest, err.Error())
			return
		}
		addrChanged = hp != existing.Address
		g.Address = hp
	}
	if addrChanged {
		if f.Pin == "" || r.PostFormValue("trust") != "1" {
			fail(http.StatusBadRequest, tr.T("gateway.err_confirm_cert"))
			return
		}
		g.Pin = f.Pin
	}

	pw := secrets.Secret(strings.TrimRight(r.PostFormValue("password"), "\r\n"))
	switch {
	case pw.IsSet():
		enc, err := store.SealGatewayPassword(s.box, pw)
		if err != nil {
			fail(http.StatusBadRequest, err.Error())
			return
		}
		g.PasswordEnc = enc
	case !has:
		fail(http.StatusBadRequest, tr.T("gateway_check.err_password"))
		return
	}
	if err := g.Normalize(); err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}

	// One test login when the credentials changed (new Gateway, password or
	// certificate), unless the owner skips it.
	var summary string
	if (pw.IsSet() || addrChanged) && r.PostFormValue("skip_test") != "1" {
		if until, blocked := s.gwGuard.blocked(now); blocked {
			fail(http.StatusTooManyRequests, tr.T("gateway.err_paused", "time", until.Local().Format("15:04")))
			return
		}
		testPW := pw
		if !testPW.IsSet() {
			var err error
			if testPW, err = existing.Password(s.box); err != nil {
				fail(http.StatusBadRequest, tr.T("gateway.err_no_key"))
				return
			}
		}
		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		summary, err1 = s.testLogin(tctx, g.Address, g.Pin, testPW, g.AllowNonLAN)
		cancel()
		if err1 != nil {
			if errors.Is(err1, gateway.ErrLoginRejected) || errors.Is(err1, gateway.ErrRateLimited) {
				s.gwGuard.reject(now)
			}
			fail(http.StatusBadRequest, gatewayErrText(err1, g.Address))
			return
		}
	}

	var err error
	if has {
		g, err = s.st.UpdateGateway(ctx, g, now)
	} else {
		g, err = s.st.CreateGateway(ctx, g, now)
	}
	if err != nil {
		fail(http.StatusBadRequest, tr.T("device_form.err_save", "error", err.Error()))
		return
	}
	s.auditUI(r, "gateway_saved", map[string]string{"gateway_id": strconv.FormatInt(g.ID, 10), "address": g.Address,
		"password_changed": strconv.FormatBool(pw.IsSet())})
	if s.poll != nil {
		if err := s.poll.Reload(ctx); err != nil {
			s.log.Error("reloading poller", "err", err)
		}
	}
	if summary != "" {
		s.renderGateway(w, r, sess, http.StatusOK, formFromGateway(g), page{"Flash": summary})
		return
	}
	http.Redirect(w, r, "/settings/gateway?ok=gateway-saved", http.StatusSeeOther)
}

func (s *Server) acceptGatewayCert(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx := r.Context()
	g, ok := s.firstGateway(ctx)
	if !ok {
		http.Redirect(w, r, "/settings/gateway", http.StatusSeeOther)
		return
	}
	// The form carries the fingerprint the owner saw, so a second change
	// between showing and accepting is not accepted blindly.
	if r.PostFormValue("trust") != "1" || store.NormalizePin(r.PostFormValue("pin")) != g.PendingPin {
		s.renderGateway(w, r, sess, http.StatusBadRequest, formFromGateway(g), page{"Error": tr.T("gateway.err_confirm_cert")})
		return
	}
	if err := s.st.AcceptGatewayPin(ctx, g.ID, s.now()); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr.T("error.title"), tr.T("gateway.err_accept"))
		return
	}
	s.auditUI(r, "gateway_cert_accepted", map[string]string{"gateway_id": strconv.FormatInt(g.ID, 10), "fingerprint": g.PendingPin})
	if s.poll != nil {
		_ = s.poll.Reload(ctx)
	}
	http.Redirect(w, r, "/settings/gateway?ok=gateway-cert-accepted", http.StatusSeeOther)
}

func (s *Server) pollGateway(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	g, ok := s.firstGateway(r.Context())
	code := "polling"
	if !ok || s.poll == nil {
		http.Redirect(w, r, "/settings/gateway", http.StatusSeeOther)
		return
	}
	if err := s.poll.PollGatewayNow(g.ID); err != nil {
		code = "poll-limited"
		if !errors.Is(err, poller.ErrRateLimited) {
			s.log.Warn("poll gateway now", "err", err)
		}
	}
	http.Redirect(w, r, "/settings/gateway?ok="+code, http.StatusSeeOther)
}

func (s *Server) deleteGateway(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx := r.Context()
	g, ok := s.firstGateway(ctx)
	if !ok {
		http.Redirect(w, r, "/settings/gateway", http.StatusSeeOther)
		return
	}
	if r.PostFormValue("confirm") != g.Name {
		s.renderGateway(w, r, sess, http.StatusBadRequest, formFromGateway(g), page{"Error": tr.T("device_form.err_confirm")})
		return
	}
	if err := s.st.DeleteGateway(ctx, g.ID); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr.T("error.title"), tr.T("gateway.err_delete"))
		return
	}
	s.auditUI(r, "gateway_deleted", map[string]string{"gateway_id": strconv.FormatInt(g.ID, 10)})
	if s.poll != nil {
		_ = s.poll.Reload(ctx)
	}
	http.Redirect(w, r, "/settings/gateway?ok=gateway-deleted", http.StatusSeeOther)
}
