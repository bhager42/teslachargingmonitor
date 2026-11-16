// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bhager42/teslachargingmonitor/internal/gateway/redact"
)

const (
	testPassword = "ABCDE"
	testToken    = "tok-0123456789-secret"
	testDIN      = "1232100-00-E--TG999888777666"
)

type fakeTerm struct {
	trust     bool
	confirms  int
	passwords int
}

func (f *fakeTerm) confirm(string) (bool, error) { f.confirms++; return f.trust, nil }
func (f *fakeTerm) password(string) (string, error) {
	f.passwords++
	return testPassword, nil
}

type fakeGateway struct {
	*httptest.Server
	logins   atomic.Int32
	loginOK  bool
	badToken atomic.Int32
}

func newFakeGateway(t *testing.T, loginOK bool) *fakeGateway {
	t.Helper()
	g := &fakeGateway{loginOK: loginOK}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"din":"`+testDIN+`","version":"26.34.2 4f1a2b3c","up_time_seconds":"72h1m"}`)
	})
	mux.HandleFunc("POST /api/login/Basic", func(w http.ResponseWriter, r *http.Request) {
		g.logins.Add(1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !g.loginOK || body["username"] != "customer" || body["password"] != testPassword {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"code":401,"error":"bad credentials","message":"Login Error"}`)
			return
		}
		_, _ = io.WriteString(w, `{"email":"owner@home.net","firstname":"Pat","lastname":"Owner","roles":["Home_Owner"],"token":"`+testToken+`","provider":"Basic","loginTime":"2026-11-16T10:00:00Z"}`)
	})
	authed := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+testToken {
				g.badToken.Add(1)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = io.WriteString(w, body)
		}
	}
	mux.HandleFunc("GET /api/meters/aggregates", authed(`{"site":{"instant_power":-812.5,"energy_imported":123456789012.25},"solar":{"instant_power":3400,"energy_exported":98765432101}}`))
	mux.HandleFunc("GET /api/system_status/soe", authed(`{"percentage":81.123}`))
	mux.HandleFunc("GET /api/site_info", authed(`{"site_name":"Owner's Home","timezone":"America/Chicago","note":"gw TG999888777666 at 192.168.1.246"}`))
	mux.HandleFunc("GET /api/solars", authed(`[{"brand":"Tesla","serial_number":"SN1234567"}]`))
	mux.HandleFunc("GET /api/sitemaster", authed(`not json`))
	mux.HandleFunc("GET /api/logout", authed(``))
	g.Server = httptest.NewTLSServer(mux)
	t.Cleanup(g.Close)
	return g
}

func (g *fakeGateway) host() string { return strings.TrimPrefix(g.URL, "https://") }

func (g *fakeGateway) pin() string { return fingerprint(g.Certificate().Raw) }

func TestRunCapturesRedactedFixtures(t *testing.T) {
	g := newFakeGateway(t, true)
	out := t.TempDir()
	term := &fakeTerm{trust: true}
	var stdout bytes.Buffer
	cfg := config{host: g.host(), label: "day", out: out}
	if err := run(context.Background(), cfg, term, &stdout); err != nil {
		t.Fatalf("run: %v\n%s", err, stdout.String())
	}
	if g.logins.Load() != 1 || term.confirms != 1 || term.passwords != 1 {
		t.Errorf("logins=%d confirms=%d passwords=%d, want 1 each", g.logins.Load(), term.confirms, term.passwords)
	}
	if g.badToken.Load() != 0 {
		t.Errorf("%d authenticated requests lacked the token", g.badToken.Load())
	}

	dir := filepath.Join(out, "26.34.2")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	all.WriteString(stdout.String())
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // test temp dir
		if err != nil {
			t.Fatal(err)
		}
		all.Write(raw)
		var v any
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if err := d.Decode(&v); err != nil {
			t.Errorf("%s: invalid JSON: %v", e.Name(), err)
		}
		if p := redact.Check(v); len(p) != 0 {
			t.Errorf("%s: %v", e.Name(), p)
		}
	}
	text := all.String()
	for _, secret := range []string{testPassword, testToken, "TG999888777666", "owner@home.net", "Pat", "Owner's Home", "192.168.1.246", "SN1234567"} {
		if strings.Contains(text, secret) {
			t.Errorf("output or fixtures contain %q", secret)
		}
	}
	for _, want := range []string{"status.day.json", "meters_aggregates.day.json", "system_status_soe.day.json", "site_info.day.json", "solars.day.json", "index.day.json"} {
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Errorf("missing %s", want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "sitemaster.day.json")); err == nil {
		t.Error("a non-JSON response was written as a fixture")
	}
	// Large counters keep full precision; the timezone is kept.
	agg, _ := os.ReadFile(filepath.Join(dir, "meters_aggregates.day.json")) //nolint:gosec // test temp dir
	if !bytes.Contains(agg, []byte("123456789012.25")) {
		t.Errorf("energy counter lost precision:\n%s", agg)
	}
	site, _ := os.ReadFile(filepath.Join(dir, "site_info.day.json")) //nolint:gosec // test temp dir
	if !bytes.Contains(site, []byte("America/Chicago")) {
		t.Errorf("timezone was redacted:\n%s", site)
	}
	var index map[string]map[string]any
	idx, _ := os.ReadFile(filepath.Join(dir, "index.day.json")) //nolint:gosec // test temp dir
	if err := json.Unmarshal(idx, &index); err != nil {
		t.Fatal(err)
	}
	if index["/api/sitemaster"]["json"] != false || index["/api/operation"]["status"] != float64(404) {
		t.Errorf("index = %v", index)
	}
}

func TestRunWithPinSkipsConfirm(t *testing.T) {
	g := newFakeGateway(t, true)
	term := &fakeTerm{}
	cfg := config{host: g.host(), pin: g.pin(), out: t.TempDir()}
	if err := run(context.Background(), cfg, term, io.Discard); err != nil {
		t.Fatal(err)
	}
	if term.confirms != 0 {
		t.Error("asked to confirm although -pin was given")
	}
}

func TestRunStopsBeforeLogin(t *testing.T) {
	for name, cfg := range map[string]func(g *fakeGateway) (config, *fakeTerm){
		"declined": func(g *fakeGateway) (config, *fakeTerm) { return config{host: g.host()}, &fakeTerm{trust: false} },
		"wrong pin": func(g *fakeGateway) (config, *fakeTerm) {
			return config{host: g.host(), pin: strings.Repeat("0", 64)}, &fakeTerm{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := newFakeGateway(t, true)
			c, term := cfg(g)
			c.out = t.TempDir()
			if err := run(context.Background(), c, term, io.Discard); err == nil {
				t.Fatal("run succeeded")
			}
			if g.logins.Load() != 0 || term.passwords != 0 {
				t.Errorf("logins=%d passwords=%d, want 0", g.logins.Load(), term.passwords)
			}
		})
	}
}

func TestRunLogsInOnlyOnce(t *testing.T) {
	g := newFakeGateway(t, false)
	out := t.TempDir()
	err := run(context.Background(), config{host: g.host(), pin: g.pin(), out: out}, &fakeTerm{}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not retrying") {
		t.Fatalf("err = %v", err)
	}
	if g.logins.Load() != 1 {
		t.Errorf("logins = %d, want exactly 1", g.logins.Load())
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Error("files were written after a failed login")
	}
}

func TestRunRefusesNonLAN(t *testing.T) {
	// 192.0.2.1 is a documentation address: not LAN, so the dial is refused
	// before any packet is sent.
	err := run(context.Background(), config{host: "192.0.2.1", out: t.TempDir()}, &fakeTerm{trust: true}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not on the local network") {
		t.Fatalf("err = %v", err)
	}
}

func TestParseFlags(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"-host", "192.168.1.2", "hunter2"},
		{"-host", "http://192.168.1.2"},
		{"-host", "192.168.1.2", "-label", "Day Time"},
	} {
		if _, err := parseFlags(args, io.Discard); err == nil {
			t.Errorf("parseFlags(%q) succeeded", args)
		}
	}
	c, err := parseFlags([]string{"-host", "gw.lan", "-label", "night", "-pin", "AB:CD"}, io.Discard)
	if err != nil || c.pin != "abcd" || c.label != "night" {
		t.Errorf("parseFlags = %+v, %v", c, err)
	}
}

func TestFirmwareDir(t *testing.T) {
	for v, want := range map[string]string{"26.34.2 4f1a2b3c": "26.34.2", "23.44.0": "23.44.0", "x": "", "../../etc": ""} {
		got, _ := firmwareDir(map[string]any{"version": v})
		if got != want {
			t.Errorf("firmwareDir(%q) = %q, want %q", v, got, want)
		}
	}
}
