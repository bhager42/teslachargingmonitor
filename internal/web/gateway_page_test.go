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
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gwsim"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
)

func startGatewaySim(t *testing.T) (*gwsim.Server, string) {
	t.Helper()
	sim, err := gwsim.NewServer(gwsim.Options{Scenario: "day", Password: "ABCDE"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(sim)
	srv.TLS = sim.TLSConfig()
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return sim, strings.TrimPrefix(srv.URL, "https://")
}

// Plan step 9.5: Settings → Solar Gateway adds the Gateway with a
// confirmed certificate and one test login, and manages it afterwards.
func TestGatewaySettingsPage(t *testing.T) {
	f := newFull(t)
	ctx := context.Background()
	sim, host := startGatewaySim(t)

	status, body := f.get("/settings/gateway")
	if status != 200 || !strings.Contains(body, "Find Gateway") || inlineScript.MatchString(body) || strings.Contains(body, "style=") {
		t.Fatalf("empty page = %d", status)
	}

	// Step 1: the fingerprint, without a login.
	r := f.post("/settings/gateway/find", url.Values{"address": {host}, "name": {"Powerwall"}, "interval": {"15"},
		"charging_interval": {"5"}})
	body = bodyOf(t, r)
	if r.StatusCode != 200 || !strings.Contains(body, groupPin(sim.Fingerprint())) || sim.Logins() != 0 {
		t.Fatalf("find = %d, logins %d", r.StatusCode, sim.Logins())
	}
	save := url.Values{"address": {host}, "name": {"Powerwall"}, "interval": {"15"}, "charging_interval": {"5"},
		"enabled": {"1"}, "pin": {sim.Fingerprint()}, "trust": {"1"}}

	// Without the confirmation nothing is tried.
	noTrust := cloneValues(save)
	noTrust.Del("trust")
	noTrust.Set("password", "ABCDE")
	if r := f.post("/settings/gateway", noTrust); r.StatusCode != 400 || sim.Logins() != 0 {
		t.Errorf("unconfirmed certificate = %d, logins %d", r.StatusCode, sim.Logins())
	}

	// A wrong password: one login, nothing saved, never echoed back.
	wrong := cloneValues(save)
	wrong.Set("password", "Zq9-wrong")
	r = f.post("/settings/gateway", wrong)
	body = bodyOf(t, r)
	if r.StatusCode != 400 || !strings.Contains(body, "rejected the password") || strings.Contains(body, "Zq9-wrong") || sim.Logins() != 1 {
		t.Fatalf("wrong password = %d, logins %d", r.StatusCode, sim.Logins())
	}
	if gws, _ := f.st.Gateways(ctx); len(gws) != 0 {
		t.Fatal("saved after a rejected login")
	}
	// The page waits before another test login.
	right := cloneValues(save)
	right.Set("password", "ABCDE")
	if r := f.post("/settings/gateway", right); r.StatusCode != 429 || sim.Logins() != 1 {
		t.Fatalf("second try during the pause = %d, logins %d", r.StatusCode, sim.Logins())
	}
	f.clk.add(gatewayTestPause)
	r = f.post("/settings/gateway", right)
	body = bodyOf(t, r)
	if r.StatusCode != 200 || !strings.Contains(body, "Connected: firmware 26.34.2, 2 Powerwall(s)") || sim.Logins() != 2 {
		t.Fatalf("right password = %d, logins %d", r.StatusCode, sim.Logins())
	}
	gws, _ := f.st.Gateways(ctx)
	if len(gws) != 1 || gws[0].Pin != sim.Fingerprint() || gws[0].Address != host {
		t.Fatalf("saved = %+v", gws)
	}
	key, _ := secrets.LoadOrCreateKey(f.dir+"/secret.key", nil)
	box, _ := secrets.NewBox(key)
	if pw, err := gws[0].Password(box); err != nil || pw.Reveal() != "ABCDE" {
		t.Errorf("stored password: %v", err)
	}
	if f.poll.reloads == 0 {
		t.Error("poller not reloaded")
	}

	// Renaming needs no login and keeps the password.
	edit := url.Values{"address": {host}, "name": {"Home battery"}, "interval": {"10"}, "charging_interval": {"5"}, "enabled": {"1"}}
	if r := f.post("/settings/gateway", edit); r.StatusCode != 303 || sim.Logins() != 2 {
		t.Fatalf("rename = %d, logins %d", r.StatusCode, sim.Logins())
	}
	g, _ := f.st.Gateway(ctx, gws[0].ID)
	if g.Name != "Home battery" || g.PollInterval != 10*time.Minute || string(g.PasswordEnc) != string(gws[0].PasswordEnc) {
		t.Errorf("after rename: %+v", g)
	}

	// Poll now.
	if r := f.post("/settings/gateway/poll", url.Values{}); r.StatusCode != 303 || len(f.poll.polled) == 0 {
		t.Errorf("poll now = %d %v", r.StatusCode, f.poll.polled)
	}

	// A changed certificate: shown with an accept form; the fingerprint
	// must match what was shown.
	newPin := strings.Repeat("cd", 32)
	if err := f.st.SetGatewayPendingPin(ctx, g.ID, newPin); err != nil {
		t.Fatal(err)
	}
	_, body = f.get("/settings/gateway")
	if !strings.Contains(body, groupPin(newPin)) || !strings.Contains(body, "Accept and resume polling") {
		t.Error("pending certificate not shown")
	}
	if _, d := f.get("/diagnostics"); !strings.Contains(d, "Home battery") || !strings.Contains(d, "new certificate") {
		t.Error("diagnostics lacks the Gateway")
	}
	if r := f.post("/settings/gateway/accept-cert", url.Values{"pin": {strings.Repeat("ef", 32)}, "trust": {"1"}}); r.StatusCode != 400 {
		t.Errorf("accept with another fingerprint = %d", r.StatusCode)
	}
	if r := f.post("/settings/gateway/accept-cert", url.Values{"pin": {newPin}, "trust": {"1"}}); r.StatusCode != 303 {
		t.Errorf("accept = %d", r.StatusCode)
	}
	if g, _ := f.st.Gateway(ctx, g.ID); g.Pin != newPin || g.PendingPin != "" {
		t.Errorf("after accept: %+v", g)
	}

	// Snooze its alerts from the Alerts page.
	if _, a := f.get("/alerts"); !strings.Contains(a, `value="gateway-1"`) {
		t.Error("Gateway missing from the snooze form")
	}
	if r := f.post("/alerts/snooze", url.Values{"device_id": {"gateway-1"}, "hours": {"4"}}); r.StatusCode != 303 {
		t.Errorf("snooze = %d", r.StatusCode)
	}
	if sn, _ := f.st.ActiveGatewaySnoozes(ctx, g.ID, f.clk.now()); len(sn) != 1 {
		t.Errorf("gateway snoozes = %+v", sn)
	}

	// Removal needs the name typed.
	if r := f.post("/settings/gateway/delete", url.Values{"confirm": {"nope"}}); r.StatusCode != 400 {
		t.Errorf("delete without confirm = %d", r.StatusCode)
	}
	if r := f.post("/settings/gateway/delete", url.Values{"confirm": {"Home battery"}}); r.StatusCode != 303 {
		t.Errorf("delete = %d", r.StatusCode)
	}
	if gws, _ := f.st.Gateways(ctx); len(gws) != 0 {
		t.Error("not deleted")
	}
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}
