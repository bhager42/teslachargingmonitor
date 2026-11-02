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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// Errors returned to the web layer. Messages are safe to show.
var (
	ErrBadPassword     = errors.New("incorrect password")
	ErrNoPassword      = errors.New("no password has been set yet")
	ErrSetupClosed     = errors.New("setup is not available (a password is already set, or the setup token expired — restart the app for a new one)")
	ErrBadSetupToken   = errors.New("incorrect setup token")
	ErrEnvManaged      = errors.New("the password is managed by the TCMON_PASSWORD_FILE / TCMON_PASSWORD_HASH setting and cannot be changed here")
	ErrNoSession       = errors.New("not signed in")
	ErrPasswordsDiffer = errors.New("the two new passwords do not match")
)

// UserMessage returns err's text when it is safe and useful to show in the
// UI, and "" for internal errors (which must only be logged).
func UserMessage(err error) string {
	var pe *PolicyError
	var te *ThrottledError
	switch {
	case errors.As(err, &pe), errors.As(err, &te),
		errors.Is(err, ErrBadPassword), errors.Is(err, ErrBadSetupToken), errors.Is(err, ErrPasswordsDiffer),
		errors.Is(err, ErrEnvManaged), errors.Is(err, ErrSetupClosed), errors.Is(err, ErrNoPassword):
		return err.Error()
	}
	return ""
}

// ThrottledError means too many failed attempts.
type ThrottledError struct{ RetryAfter time.Duration }

func (e *ThrottledError) Error() string {
	return fmt.Sprintf("too many failed attempts; try again in %s", e.RetryAfter.Round(time.Second))
}

// Config tunes the Manager. Zero values select defaults.
type Config struct {
	Params        Params
	IdleTimeout   time.Duration // default 12 h
	MaxAge        time.Duration // default 7 days
	RememberAge   time.Duration // default 30 days
	SetupTokenTTL time.Duration // default 30 min
	Now           func() time.Time
	Logger        *slog.Logger
}

// Manager owns the password, the setup token and browser sessions.
type Manager struct {
	st       *store.Store
	cfg      Config
	throttle *Throttle

	mu           sync.Mutex
	setupToken   string
	setupExpires time.Time
	envManaged   bool
}

// NewManager returns a Manager.
func NewManager(st *store.Store, cfg Config) *Manager {
	if cfg.Params == (Params{}) {
		cfg.Params = DefaultParams
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 12 * time.Hour
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 7 * 24 * time.Hour
	}
	if cfg.RememberAge == 0 {
		cfg.RememberAge = 30 * 24 * time.Hour
	}
	if cfg.SetupTokenTTL == 0 {
		cfg.SetupTokenTTL = 30 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Manager{st: st, cfg: cfg, throttle: NewThrottle(cfg.Now)}
}

// Bootstrap is how the initial password may be provided (plan §9).
type Bootstrap struct {
	PasswordHash     string // TCMON_PASSWORD_HASH (PHC string)
	PasswordHashFile string // TCMON_PASSWORD_HASH_FILE
	PasswordFile     string // TCMON_PASSWORD_FILE (plaintext secret file)
	PlainPasswordSet bool   // TCMON_PASSWORD was set: refused
}

func readTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-configured secret file
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// Init applies a configured password or, when none exists, opens setup mode
// and returns a one-time setup token to print in the log.
func (m *Manager) Init(ctx context.Context, b Bootstrap) (setupToken string, err error) {
	if b.PlainPasswordSet {
		return "", errors.New("TCMON_PASSWORD is not supported because environment variables are visible in `docker inspect`; " +
			"use TCMON_PASSWORD_FILE (a Docker/TrueNAS secret file) or TCMON_PASSWORD_HASH from `tcmon hash-password`")
	}
	hash := b.PasswordHash
	if b.PasswordHashFile != "" {
		if hash, err = readTrimmed(b.PasswordHashFile); err != nil {
			return "", fmt.Errorf("reading TCMON_PASSWORD_HASH_FILE: %w", err)
		}
	}
	current, _, err := m.st.PasswordHash(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	now := m.cfg.Now()
	switch {
	case hash != "":
		if !ValidHash(hash) {
			return "", errors.New("TCMON_PASSWORD_HASH is not an Argon2id hash; generate one with `tcmon hash-password`")
		}
		m.envManaged = true
		if hash != current {
			if err := m.st.SetPasswordHash(ctx, hash, now); err != nil {
				return "", err
			}
			m.audit(ctx, "", "password_set_from_env", nil)
		}
		return "", nil
	case b.PasswordFile != "":
		pw, err := readTrimmed(b.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("reading TCMON_PASSWORD_FILE: %w", err)
		}
		if err := CheckPolicy(pw); err != nil {
			return "", fmt.Errorf("TCMON_PASSWORD_FILE: %w", err)
		}
		m.envManaged = true
		if current != "" {
			if ok, _, _ := Verify(current, pw, m.cfg.Params); ok {
				return "", nil
			}
		}
		h, err := Hash(pw, m.cfg.Params)
		if err != nil {
			return "", err
		}
		if err := m.st.SetPasswordHash(ctx, h, now); err != nil {
			return "", err
		}
		m.audit(ctx, "", "password_set_from_env", nil)
		return "", nil
	case current != "":
		return "", nil
	}
	tok := make([]byte, 20)
	if _, err := rand.Read(tok); err != nil {
		return "", err
	}
	m.mu.Lock()
	m.setupToken = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(tok)
	m.setupExpires = now.Add(m.cfg.SetupTokenTTL)
	setupToken = m.setupToken
	m.mu.Unlock()
	m.audit(ctx, "", "setup_token_issued", map[string]string{"expires": m.setupExpires.UTC().Format(time.RFC3339)})
	return setupToken, nil
}

// EnvManaged reports whether the password comes from the environment.
func (m *Manager) EnvManaged() bool { return m.envManaged }

// HasPassword reports whether a password is set.
func (m *Manager) HasPassword(ctx context.Context) (bool, error) {
	_, _, err := m.st.PasswordHash(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// SetupOpen reports whether the setup form may be used.
func (m *Manager) SetupOpen(ctx context.Context) bool {
	m.mu.Lock()
	open := m.setupToken != "" && m.cfg.Now().Before(m.setupExpires)
	m.mu.Unlock()
	has, err := m.HasPassword(ctx)
	return open && err == nil && !has
}

func (m *Manager) audit(ctx context.Context, ip, action string, details map[string]string) {
	if err := m.st.Audit(ctx, store.AuditEntry{TS: m.cfg.Now(), IP: ip, Action: action, Details: details}); err != nil {
		m.cfg.Logger.Error("writing audit log", "err", err)
	}
	m.cfg.Logger.Info("audit", "action", action, "ip", ip, "details", details)
}

// Session is a validated browser session.
type Session struct {
	IDHash    []byte
	CSRFToken string
	ExpiresAt time.Time
}

// SessionCookie is a new session's secret value and lifetime.
type SessionCookie struct {
	Value   string
	Expires time.Time
	Persist bool // "remember me": send Expires; otherwise a browser-session cookie
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashID(value string) []byte {
	h := sha256.Sum256([]byte(value))
	return h[:]
}

func (m *Manager) newSession(ctx context.Context, ip, ua string, remember bool) (SessionCookie, error) {
	value, err := randomToken(32)
	if err != nil {
		return SessionCookie{}, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return SessionCookie{}, err
	}
	now := m.cfg.Now()
	age := m.cfg.MaxAge
	if remember {
		age = m.cfg.RememberAge
	}
	ws := store.WebSession{IDHash: hashID(value), CSRFToken: csrf, CreatedAt: now, LastSeen: now,
		ExpiresAt: now.Add(age), IP: ip, UserAgent: ua}
	if err := m.st.CreateSession(ctx, ws); err != nil {
		return SessionCookie{}, err
	}
	return SessionCookie{Value: value, Expires: ws.ExpiresAt, Persist: remember}, nil
}

// Login verifies the password and starts a new session.
func (m *Manager) Login(ctx context.Context, password, ip, ua string, remember bool) (SessionCookie, error) {
	if wait := m.throttle.Blocked(ip); wait > 0 {
		m.audit(ctx, ip, "login_throttled", nil)
		return SessionCookie{}, &ThrottledError{RetryAfter: wait}
	}
	hash, _, err := m.st.PasswordHash(ctx)
	if errors.Is(err, store.ErrNotFound) {
		VerifyDummy(password, m.cfg.Params)
		return SessionCookie{}, ErrNoPassword
	}
	if err != nil {
		return SessionCookie{}, err
	}
	ok, rehash, err := Verify(hash, password, m.cfg.Params)
	if err != nil {
		return SessionCookie{}, err
	}
	if !ok {
		m.throttle.Fail(ip)
		m.audit(ctx, ip, "login_failed", nil)
		return SessionCookie{}, ErrBadPassword
	}
	m.throttle.Success(ip)
	if rehash && !m.envManaged {
		if h, err := Hash(password, m.cfg.Params); err == nil {
			_ = m.st.UpdatePasswordHash(ctx, h)
		}
	}
	c, err := m.newSession(ctx, ip, ua, remember)
	if err == nil {
		m.audit(ctx, ip, "login", map[string]string{"remember": fmt.Sprint(remember)})
	}
	return c, err
}

// CompleteSetup sets the first password using the setup token and signs in.
func (m *Manager) CompleteSetup(ctx context.Context, token, password, confirm, ip, ua string) (SessionCookie, error) {
	if wait := m.throttle.Blocked(ip); wait > 0 {
		return SessionCookie{}, &ThrottledError{RetryAfter: wait}
	}
	if !m.SetupOpen(ctx) {
		return SessionCookie{}, ErrSetupClosed
	}
	m.mu.Lock()
	want := m.setupToken
	m.mu.Unlock()
	given := strings.ToUpper(strings.Join(strings.Fields(token), ""))
	if subtle.ConstantTimeCompare([]byte(given), []byte(want)) != 1 {
		m.throttle.Fail(ip)
		m.audit(ctx, ip, "setup_failed", nil)
		return SessionCookie{}, ErrBadSetupToken
	}
	if password != confirm {
		return SessionCookie{}, ErrPasswordsDiffer
	}
	if err := CheckPolicy(password); err != nil {
		return SessionCookie{}, err
	}
	h, err := Hash(password, m.cfg.Params)
	if err != nil {
		return SessionCookie{}, err
	}
	if err := m.st.SetPasswordHash(ctx, h, m.cfg.Now()); err != nil {
		return SessionCookie{}, err
	}
	m.mu.Lock()
	m.setupToken = ""
	m.mu.Unlock()
	m.audit(ctx, ip, "password_set_setup", nil)
	return m.newSession(ctx, ip, ua, false)
}

// Session validates a cookie value (absolute and idle expiry).
func (m *Manager) Session(ctx context.Context, value string) (Session, error) {
	if value == "" || len(value) > 100 {
		return Session{}, ErrNoSession
	}
	id := hashID(value)
	ws, err := m.st.Session(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, err
	}
	now := m.cfg.Now()
	if !now.Before(ws.ExpiresAt) || now.Sub(ws.LastSeen) > m.cfg.IdleTimeout {
		_ = m.st.DeleteSession(ctx, id)
		return Session{}, ErrNoSession
	}
	if now.Sub(ws.LastSeen) > time.Minute {
		_ = m.st.TouchSession(ctx, id, now)
	}
	return Session{IDHash: id, CSRFToken: ws.CSRFToken, ExpiresAt: ws.ExpiresAt}, nil
}

// CheckCSRF compares a submitted form token with the session's.
func (s Session) CheckCSRF(token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.CSRFToken)) == 1
}

// Logout ends a session.
func (m *Manager) Logout(ctx context.Context, s Session, ip string) error {
	m.audit(ctx, ip, "logout", nil)
	return m.st.DeleteSession(ctx, s.IDHash)
}

// SignOutOthers ends every other session.
func (m *Manager) SignOutOthers(ctx context.Context, s Session, ip string) (int64, error) {
	n, err := m.st.DeleteOtherSessions(ctx, s.IDHash)
	if err == nil {
		m.audit(ctx, ip, "sessions_revoked", map[string]string{"count": fmt.Sprint(n)})
	}
	return n, err
}

// ChangePassword verifies the current password, sets the new one, signs
// out every session and returns a fresh session for the caller.
func (m *Manager) ChangePassword(ctx context.Context, current, next, confirm, ip, ua string) (SessionCookie, error) {
	if m.envManaged {
		return SessionCookie{}, ErrEnvManaged
	}
	if wait := m.throttle.Blocked(ip); wait > 0 {
		return SessionCookie{}, &ThrottledError{RetryAfter: wait}
	}
	hash, _, err := m.st.PasswordHash(ctx)
	if err != nil {
		return SessionCookie{}, err
	}
	if ok, _, err := Verify(hash, current, m.cfg.Params); err != nil || !ok {
		m.throttle.Fail(ip)
		m.audit(ctx, ip, "password_change_failed", nil)
		return SessionCookie{}, ErrBadPassword
	}
	if next != confirm {
		return SessionCookie{}, ErrPasswordsDiffer
	}
	if err := CheckPolicy(next); err != nil {
		return SessionCookie{}, err
	}
	h, err := Hash(next, m.cfg.Params)
	if err != nil {
		return SessionCookie{}, err
	}
	if err := m.st.SetPasswordHash(ctx, h, m.cfg.Now()); err != nil { // revokes all sessions
		return SessionCookie{}, err
	}
	m.audit(ctx, ip, "password_changed", nil)
	return m.newSession(ctx, ip, ua, false)
}

// ResetPassword sets a new password without the old one (CLI recovery,
// run inside the container) and signs out every session.
func (m *Manager) ResetPassword(ctx context.Context, next string) error {
	if err := CheckPolicy(next); err != nil {
		return err
	}
	h, err := Hash(next, m.cfg.Params)
	if err != nil {
		return err
	}
	if err := m.st.SetPasswordHash(ctx, h, m.cfg.Now()); err != nil {
		return err
	}
	m.audit(ctx, "", "password_reset_cli", nil)
	return nil
}
