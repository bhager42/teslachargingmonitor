// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/store"
)

const pw = "purple otter kayak sunrise"

type mclock struct{ t time.Time }

func (c *mclock) now() time.Time { return c.t }

func newManager(t *testing.T) (*Manager, *store.Store, *mclock) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "tcmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	clk := &mclock{t: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}
	return NewManager(st, Config{Params: fast, Now: clk.now}), st, clk
}

func TestSetupAndLogin(t *testing.T) {
	ctx := context.Background()
	m, st, clk := newManager(t)
	if _, err := m.Login(ctx, pw, "ip", "ua", false); !errors.Is(err, ErrNoPassword) {
		t.Errorf("login before setup = %v", err)
	}
	tok, err := m.Init(ctx, Bootstrap{})
	if err != nil || len(tok) != 32 || !m.SetupOpen(ctx) {
		t.Fatalf("init = %q %v", tok, err)
	}
	if _, err := m.CompleteSetup(ctx, "nope", pw, pw, "ip", "ua"); !errors.Is(err, ErrBadSetupToken) {
		t.Errorf("bad token = %v", err)
	}
	spaced := strings.ToLower(tok[:8]) + " " + tok[8:] // tolerant of case and spaces
	c, err := m.CompleteSetup(ctx, spaced, pw, pw, "ip", "ua")
	if err != nil || c.Value == "" || c.Persist {
		t.Fatalf("setup = %+v %v", c, err)
	}
	if m.SetupOpen(ctx) {
		t.Error("setup still open")
	}
	if _, err := m.CompleteSetup(ctx, tok, pw, pw, "ip", "ua"); !errors.Is(err, ErrSetupClosed) {
		t.Errorf("second setup = %v", err)
	}
	s, err := m.Session(ctx, c.Value)
	if err != nil || !s.CheckCSRF(s.CSRFToken) || s.CheckCSRF("") || s.CheckCSRF("x") {
		t.Errorf("session = %+v %v", s, err)
	}
	if _, err := m.Session(ctx, ""); !errors.Is(err, ErrNoSession) {
		t.Error("empty cookie accepted")
	}
	if _, err := m.Session(ctx, strings.Repeat("a", 200)); !errors.Is(err, ErrNoSession) {
		t.Error("oversized cookie accepted")
	}

	rc, err := m.Login(ctx, pw, "ip", "ua", true)
	if err != nil || !rc.Persist || rc.Expires.Sub(clk.t) != 30*24*time.Hour {
		t.Errorf("remember login = %+v %v", rc, err)
	}
	if _, err := m.Login(ctx, "wrong password!!", "ip", "ua", false); !errors.Is(err, ErrBadPassword) {
		t.Errorf("wrong password = %v", err)
	}
	n, err := m.SignOutOthers(ctx, s, "ip")
	if err != nil || n != 1 {
		t.Errorf("sign out others = %d %v", n, err)
	}
	if _, err := m.Session(ctx, rc.Value); !errors.Is(err, ErrNoSession) {
		t.Error("other session survived")
	}
	if err := m.Logout(ctx, s, "ip"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Session(ctx, c.Value); !errors.Is(err, ErrNoSession) {
		t.Error("session survived logout")
	}
	log, _ := st.AuditLog(ctx, 20)
	if len(log) < 6 {
		t.Errorf("audit entries = %d", len(log))
	}
}

func TestSetupTokenExpiresAndThrottles(t *testing.T) {
	ctx := context.Background()
	m, _, clk := newManager(t)
	tok, _ := m.Init(ctx, Bootstrap{})
	for range 5 {
		_, _ = m.CompleteSetup(ctx, "wrong", pw, pw, "attacker", "")
	}
	var te *ThrottledError
	if _, err := m.CompleteSetup(ctx, tok, pw, pw, "attacker", ""); !errors.As(err, &te) {
		t.Errorf("token guessing not throttled: %v", err)
	}
	clk.t = clk.t.Add(31 * time.Minute)
	if _, err := m.CompleteSetup(ctx, tok, pw, pw, "owner", ""); !errors.Is(err, ErrSetupClosed) {
		t.Errorf("expired token = %v", err)
	}
	if _, err := m.CompleteSetup(ctx, tok, pw, pw+"x", "owner", ""); err == nil {
		t.Error("expected error")
	}
}

func TestSetupValidation(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	tok, _ := m.Init(ctx, Bootstrap{})
	if _, err := m.CompleteSetup(ctx, tok, pw, pw+"x", "ip", ""); !errors.Is(err, ErrPasswordsDiffer) {
		t.Errorf("mismatch = %v", err)
	}
	var pe *PolicyError
	if _, err := m.CompleteSetup(ctx, tok, "short", "short", "ip", ""); !errors.As(err, &pe) {
		t.Errorf("weak = %v", err)
	}
}

func TestChangeAndResetPassword(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	tok, _ := m.Init(ctx, Bootstrap{})
	c, _ := m.CompleteSetup(ctx, tok, pw, pw, "ip", "")
	next := "granite lantern meadow 42"
	if _, err := m.ChangePassword(ctx, "wrong current pw", next, next, "ip", ""); !errors.Is(err, ErrBadPassword) {
		t.Errorf("wrong current = %v", err)
	}
	if _, err := m.ChangePassword(ctx, pw, next, next+"x", "ip", ""); !errors.Is(err, ErrPasswordsDiffer) {
		t.Errorf("mismatch = %v", err)
	}
	if _, err := m.ChangePassword(ctx, pw, "short", "short", "ip", ""); err == nil {
		t.Error("weak new password accepted")
	}
	nc, err := m.ChangePassword(ctx, pw, next, next, "ip", "")
	if err != nil || nc.Value == c.Value {
		t.Fatalf("change = %v", err)
	}
	if _, err := m.Session(ctx, c.Value); !errors.Is(err, ErrNoSession) {
		t.Error("old session survived password change")
	}
	if _, err := m.Session(ctx, nc.Value); err != nil {
		t.Error("new session invalid")
	}
	if err := m.ResetPassword(ctx, "short"); err == nil {
		t.Error("weak reset accepted")
	}
	if err := m.ResetPassword(ctx, "violet harbor quantum 7"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Session(ctx, nc.Value); !errors.Is(err, ErrNoSession) {
		t.Error("session survived reset")
	}
	if _, err := m.Login(ctx, "violet harbor quantum 7", "ip", "", false); err != nil {
		t.Errorf("login after reset = %v", err)
	}
}

func TestRehashOnLogin(t *testing.T) {
	ctx := context.Background()
	m, st, _ := newManager(t)
	weak, _ := Hash(pw, Params{MemoryKiB: 8 * 1024, Time: 1, Threads: 1})
	_ = st.SetPasswordHash(ctx, weak, time.Now())
	strong := NewManager(st, Config{Params: Params{MemoryKiB: 16 * 1024, Time: 2, Threads: 1}})
	if _, err := strong.Login(ctx, pw, "ip", "", false); err != nil {
		t.Fatal(err)
	}
	h, _, _ := st.PasswordHash(ctx)
	if !strings.Contains(h, "m=16384,t=2") {
		t.Errorf("not rehashed: %s", h)
	}
	_ = m
}

func TestInitFromEnvironment(t *testing.T) {
	ctx := context.Background()
	m, _, clk := newManager(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "pw")
	_ = os.WriteFile(file, []byte(pw+"\n"), 0o600)
	if tok, err := m.Init(ctx, Bootstrap{PasswordFile: file}); err != nil || tok != "" || !m.EnvManaged() {
		t.Fatalf("password file: %q %v", tok, err)
	}
	c, err := m.Login(ctx, pw, "ip", "", false)
	if err != nil {
		t.Fatal(err)
	}
	// Same file on restart: sessions are kept.
	m2 := NewManager(m.st, Config{Params: fast, Now: clk.now})
	if _, err := m2.Init(ctx, Bootstrap{PasswordFile: file}); err != nil {
		t.Fatal(err)
	}
	if _, err := m2.Session(ctx, c.Value); err != nil {
		t.Errorf("unchanged password file revoked sessions: %v", err)
	}
	if _, err := m2.ChangePassword(ctx, pw, "x", "x", "", ""); !errors.Is(err, ErrEnvManaged) {
		t.Errorf("env-managed change = %v", err)
	}
	for _, b := range []Bootstrap{{PasswordFile: filepath.Join(dir, "missing")}, {PasswordHashFile: filepath.Join(dir, "missing")}} {
		if _, err := NewManager(m.st, Config{Params: fast}).Init(ctx, b); err == nil {
			t.Errorf("missing file accepted: %+v", b)
		}
	}
	h, _ := Hash("another long passphrase", fast)
	m3 := NewManager(m.st, Config{Params: fast})
	if _, err := m3.Init(ctx, Bootstrap{PasswordHash: h}); err != nil {
		t.Fatal(err)
	}
	if _, err := m3.Login(ctx, "another long passphrase", "ip", "", false); err != nil {
		t.Errorf("hash from env: %v", err)
	}
	// An existing password and no bootstrap: no setup token.
	if tok, err := NewManager(m.st, Config{Params: fast}).Init(ctx, Bootstrap{}); err != nil || tok != "" {
		t.Errorf("token issued with a password set: %q %v", tok, err)
	}
	if has, _ := m3.HasPassword(ctx); !has {
		t.Error("HasPassword false")
	}
}

func TestSessionTimeouts(t *testing.T) {
	ctx := context.Background()
	m, _, clk := newManager(t)
	tok, _ := m.Init(ctx, Bootstrap{})
	c, _ := m.CompleteSetup(ctx, tok, pw, pw, "ip", "")
	clk.t = clk.t.Add(12*time.Hour + time.Minute)
	if _, err := m.Session(ctx, c.Value); !errors.Is(err, ErrNoSession) {
		t.Error("idle timeout not enforced")
	}
	if _, err := m.Login(ctx, pw, "ip", "", false); err != nil {
		t.Fatal(err)
	}
	m2 := NewManager(m.st, Config{Params: fast, Now: clk.now, IdleTimeout: 10 * 24 * time.Hour})
	c2, _ := m2.Login(ctx, pw, "ip", "", false)
	clk.t = clk.t.Add(7*24*time.Hour + time.Minute)
	if _, err := m2.Session(ctx, c2.Value); !errors.Is(err, ErrNoSession) {
		t.Error("absolute timeout not enforced")
	}
}
