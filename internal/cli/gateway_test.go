// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package cli

import (
	"context"
	"io"
	"log"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bhager42/teslachargingmonitor/internal/gwsim"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

func gatewaySim(t *testing.T) (*gwsim.Server, string) {
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

func TestGatewayCommands(t *testing.T) {
	dir := t.TempDir()
	vars := map[string]string{"TCMON_DATA_DIR": dir}
	sim, host := gatewaySim(t)

	r := runWith(t, vars, "", "gateway", "fingerprint", "-address", host)
	if r.code != 0 || strings.TrimSpace(r.stdout) != sim.Fingerprint() {
		t.Fatalf("fingerprint: %+v", r)
	}
	if sim.Logins() != 0 {
		t.Fatal("fingerprint logged in")
	}
	pin := sim.Fingerprint()

	// The password is never an argument.
	if r := runWith(t, vars, "", "gateway", "add", "-address", host, "-pin", pin); r.code == 0 ||
		!strings.Contains(r.stderr, "-password-stdin") {
		t.Errorf("add without a password source: %+v", r)
	}
	// A wrong password is tried once and nothing is saved.
	r = runWith(t, vars, "WRONG\n", "gateway", "add", "-address", host, "-pin", pin, "-password-stdin")
	if r.code == 0 || !strings.Contains(r.stderr, "rejected the password") || strings.Contains(r.stderr, "WRONG") {
		t.Errorf("wrong password: %+v", r)
	}
	if sim.Logins() != 1 {
		t.Errorf("logins = %d, want 1", sim.Logins())
	}
	// A wrong pin never reaches the login.
	r = runWith(t, vars, "ABCDE\n", "gateway", "add", "-address", host, "-pin", strings.Repeat("0", 64), "-password-stdin")
	if r.code == 0 || sim.Logins() != 1 {
		t.Errorf("wrong pin: %+v, logins %d", r, sim.Logins())
	}

	r = runWith(t, vars, "ABCDE\n", "gateway", "add", "-address", host, "-pin", pin, "-password-stdin", "-name", "Home")
	if r.code != 0 || !strings.Contains(r.stdout, "firmware 26.34.2, 2 Powerwall(s)") || !strings.Contains(r.stdout, "Added gateway 1") {
		t.Fatalf("add: %+v", r)
	}
	r = runWith(t, vars, "", "gateway", "list")
	if r.code != 0 || !strings.Contains(r.stdout, "Home") || !strings.Contains(r.stdout, "ok") || strings.Contains(r.stdout, "ABCDE") {
		t.Errorf("list: %+v", r)
	}

	// The stored password is sealed and opens with the data dir's key.
	st, box, err := openStoreAndBox(context.Background(), Env{Getenv: func(string) string { return "" }, Stderr: io.Discard}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := st.Gateway(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if pw, err := g.Password(box); err != nil || pw.Reveal() != "ABCDE" {
		t.Errorf("stored password: %v", err)
	}
	if err := st.SetGatewayPendingPin(context.Background(), 1, strings.Repeat("cd", 32)); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	r = runWith(t, vars, "", "gateway", "list")
	if !strings.Contains(r.stdout, "certificate changed") {
		t.Errorf("list with a pending certificate: %+v", r)
	}
	if r := runWith(t, vars, "", "gateway", "accept-cert", "1"); r.code != 0 || !strings.Contains(r.stdout, strings.Repeat("cd", 32)) {
		t.Errorf("accept-cert: %+v", r)
	}
	if r := runWith(t, vars, "", "gateway", "accept-cert", "1"); r.code == 0 {
		t.Error("accept-cert with nothing pending succeeded")
	}
	if r := runWith(t, vars, "", "gateway", "remove", "1"); r.code == 0 {
		t.Error("remove without -yes succeeded")
	}
	if r := runWith(t, vars, "", "gateway", "remove", "1", "-yes"); r.code != 0 {
		t.Errorf("remove: %+v", r)
	}
	st2, err := store.Open(context.Background(), filepath.Join(dir, "tcmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()
	if gws, _ := st2.Gateways(context.Background()); len(gws) != 0 {
		t.Errorf("gateways after remove: %d", len(gws))
	}
}
