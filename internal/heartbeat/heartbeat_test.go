// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package heartbeat

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

const token = "0b7c5a9e-3f1d-4c2b-9a8e-6d5f4e3c2b1a" //nolint:gosec // fake token for tests

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type env struct {
	st    *store.Store
	box   *secrets.Box
	clk   *clock
	srv   *httptest.Server
	hits  atomic.Int32
	code  atomic.Int32
	agent atomic.Value
	p     *Pinger
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, "tcmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	key, _ := secrets.LoadOrCreateKey(filepath.Join(dir, "secret.key"), nil)
	box, _ := secrets.NewBox(key)
	e := &env{st: st, box: box, clk: &clock{t: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}}
	e.code.Store(200)
	e.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ping/" + token:
			e.hits.Add(1)
			e.agent.Store(r.UserAgent())
			w.WriteHeader(int(e.code.Load()))
		case "/to-http":
			http.Redirect(w, r, "http://example.com/ping/"+token, http.StatusFound)
		case "/slow":
			time.Sleep(300 * time.Millisecond)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(e.srv.Close)
	e.p = e.newPinger()
	return e
}

func (e *env) newPinger() *Pinger {
	roots := x509.NewCertPool()
	roots.AddCert(e.srv.Certificate())
	return New(e.st, e.box, Config{Now: e.clk.now, RootCAs: roots, UserAgent: "tcmon/test", Timeout: 200 * time.Millisecond})
}

func (e *env) url(path string) string { return e.srv.URL + path }

func TestValidate(t *testing.T) {
	good := []string{"https://hc-ping.com/" + token, "  https://kuma.lan:3001/api/push/abc?status=up&msg=OK  ",
		"https://[2001:db8::1]/ping"}
	for _, u := range good {
		if _, err := Validate(u); err != nil {
			t.Errorf("Validate(%q) = %v", u, err)
		}
	}
	bad := []string{"", "   ", "http://hc-ping.com/x", "ftp://x/y", "hc-ping.com/x", "https:///path", "https:opaque",
		"https://hc-ping.com/x#frag", "https://hc-ping.com/\x00", "https://" + strings.Repeat("a", MaxURLLength)}
	for _, u := range bad {
		if _, err := Validate(u); !errors.Is(err, ErrBadURL) {
			t.Errorf("Validate(%q) = %v, want ErrBadURL", u, err)
		}
	}
}

func TestSetLoadPingClear(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.p.Ping(ctx); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("Ping without URL = %v", err)
	}
	if err := e.p.Set(ctx, "http://insecure/"+token); !errors.Is(err, ErrBadURL) {
		t.Fatalf("Set(http) = %v", err)
	}
	if err := e.p.Set(ctx, e.url("/ping/"+token)); err != nil {
		t.Fatal(err)
	}
	if err := e.p.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	st := e.p.Status()
	if !st.Configured || st.LastSuccess.IsZero() || st.ConsecutiveFailures != 0 || e.hits.Load() != 1 {
		t.Errorf("status after ping = %+v, hits %d", st, e.hits.Load())
	}
	if strings.Contains(st.Display, token) || !strings.HasPrefix(st.Display, "https://127.0.0.1:") {
		t.Errorf("Display = %q", st.Display)
	}
	if ua, _ := e.agent.Load().(string); ua != "tcmon/test" {
		t.Errorf("User-Agent = %q", ua)
	}

	// Stored encrypted: the token is not in the database in clear text.
	var s stored
	if err := e.st.GetSetting(ctx, settingKey, &s); err != nil || len(s.URLEnc) == 0 ||
		strings.Contains(string(s.URLEnc), token) {
		t.Fatalf("stored = %v, %v", s, err)
	}

	// A fresh Pinger (restart) reads it back.
	p2 := e.newPinger()
	if err := p2.Load(ctx); err != nil || !p2.Status().Configured {
		t.Fatalf("Load = %v, %+v", err, p2.Status())
	}
	if err := p2.Ping(ctx); err != nil || e.hits.Load() != 2 {
		t.Fatalf("Ping after Load = %v, hits %d", err, e.hits.Load())
	}

	if err := e.p.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	p3 := e.newPinger()
	if err := p3.Load(ctx); err != nil || p3.Status().Configured {
		t.Fatalf("after Clear: %v, %+v", err, p3.Status())
	}
}

func TestFailuresNeverRevealTheURL(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cases := []struct {
		name, url, want string
		code            int
	}{
		{"status", e.url("/ping/" + token), "HTTP 503", 503},
		{"redirect to http", e.url("/to-http?t=" + token), "non-HTTPS", 200},
		{"timeout", e.url("/slow?t=" + token), "no answer within", 200},
		{"unknown CA", e.url("/ping/" + token), "certificate", 200},
	}
	for _, c := range cases {
		e.code.Store(int32(c.code)) //nolint:gosec // small HTTP status codes
		p := e.p
		if c.name == "unknown CA" {
			p = New(e.st, e.box, Config{Now: e.clk.now}) // system roots only: the test CA is untrusted
		}
		if err := p.Set(ctx, c.url); err != nil {
			t.Fatal(err)
		}
		err := p.Ping(ctx)
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), token) {
			t.Errorf("%s: err = %v", c.name, err)
		}
		st := p.Status()
		if st.ConsecutiveFailures != 1 || strings.Contains(st.LastError, token) || st.LastErrorAt.IsZero() {
			t.Errorf("%s: status = %+v", c.name, st)
		}
	}
	// A success after failures resets the counter.
	e.code.Store(200)
	_ = e.p.Set(ctx, e.url("/ping/"+token))
	e.code.Store(500)
	_ = e.p.Ping(ctx)
	_ = e.p.Ping(ctx)
	if st := e.p.Status(); st.ConsecutiveFailures != 2 {
		t.Errorf("failures = %d", st.ConsecutiveFailures)
	}
	e.code.Store(200)
	if err := e.p.Ping(ctx); err != nil || e.p.Status().ConsecutiveFailures != 0 || e.p.Status().LastError != "" {
		t.Errorf("recovery: %v %+v", err, e.p.Status())
	}
}

func TestUndecryptableURL(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.p.Set(ctx, e.url("/ping/"+token)); err != nil {
		t.Fatal(err)
	}
	otherKey := make([]byte, secrets.KeySize)
	box, _ := secrets.NewBox(otherKey)
	p := New(e.st, box, Config{})
	if err := p.Load(ctx); err == nil {
		t.Fatal("Load with the wrong key succeeded")
	}
	if st := p.Status(); st.Configured || !strings.Contains(st.LastError, "Enter it again") {
		t.Errorf("status = %+v", st)
	}
}

func TestRunPingsAfterSuccessfulPolls(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates := make(chan poller.Update)
	done := make(chan struct{})
	go func() { e.p.Run(ctx, updates); close(done) }()

	send := func(err error) {
		updates <- poller.Update{Err: err}
		updates <- poller.Update{Err: errors.New("sync")} // Run has finished the previous update
	}
	send(nil) // not configured yet: nothing sent
	if err := e.p.Set(ctx, e.url("/ping/"+token)); err != nil {
		t.Fatal(err)
	}
	send(errors.New("unreachable")) // failed poll: nothing sent
	if n := e.hits.Load(); n != 0 {
		t.Fatalf("hits = %d before any successful poll", n)
	}
	send(nil)
	if n := e.hits.Load(); n != 1 {
		t.Fatalf("hits = %d after a successful poll", n)
	}
	send(nil) // within MinGap of the last ping
	if n := e.hits.Load(); n != 1 {
		t.Fatalf("hits = %d, want MinGap to suppress the second ping", n)
	}
	e.clk.add(time.Minute)
	send(nil)
	if n := e.hits.Load(); n != 2 {
		t.Fatalf("hits = %d after MinGap", n)
	}
	close(updates)
	<-done
}
