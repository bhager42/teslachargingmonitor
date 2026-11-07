// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package heartbeat is the optional dead-man's switch (owner decision D20):
// after each successful poll it sends an HTTPS GET to an owner-entered URL
// (a healthchecks.io check, an Uptime Kuma push monitor, ...), so the owner's
// monitoring service raises the alarm if tcmon itself stops working.
//
// The URL usually contains a secret token, so it is stored encrypted
// (secrets.Box), never shown back in full, and never included in errors or
// logs.
package heartbeat

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/i18n"
	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

const settingKey = "heartbeat"

// aad binds the sealed URL to its purpose.
var aad = []byte("tcmon/heartbeat/v1")

// MaxURLLength bounds the URL the settings form accepts.
const MaxURLLength = 2048

// tr is the catalog for errors shown in Settings and Diagnostics.
var tr = i18n.English()

// ErrNotConfigured is returned by Ping when no URL is set.
var ErrNotConfigured = tr.Err("heartbeat.err_not_configured")

// ErrBadURL wraps validation failures; the reason is an *i18n.Error
// written for users.
var ErrBadURL = tr.Err("heartbeat.err_bad_url")

type stored struct {
	URLEnc []byte `json:"url_enc"`
}

// Status is the ping state shown in Settings and Diagnostics. Times are zero
// until the first attempt since the app started.
type Status struct {
	Configured          bool
	Display             string // scheme and host only; the path holds the token
	LastAttempt         time.Time
	LastSuccess         time.Time
	LastError           string
	LastErrorAt         time.Time
	ConsecutiveFailures int
}

// Config tunes a Pinger. Zero values select production defaults.
type Config struct {
	Logger    *slog.Logger
	Now       func() time.Time
	UserAgent string
	// RootCAs adds to the system roots (nil uses the system roots only).
	RootCAs *x509.CertPool
	// Timeout bounds each ping (default 10 s).
	Timeout time.Duration
	// MinGap is the minimum spacing of automatic pings, so several devices
	// or a burst of "Poll now" clicks send one ping (default 1 min).
	MinGap time.Duration
}

// Pinger sends the pings and remembers how the last ones went.
type Pinger struct {
	st     *store.Store
	box    *secrets.Box
	cfg    Config
	client *http.Client

	mu     sync.Mutex
	url    secrets.Secret
	status Status
}

// New returns a Pinger; call Load before use.
func New(st *store.Store, box *secrets.Box, cfg Config) *Pinger {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MinGap == 0 {
		cfg.MinGap = time.Minute
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs}
	client := &http.Client{Transport: transport, Timeout: cfg.Timeout, CheckRedirect: checkRedirect}
	return &Pinger{st: st, box: box, cfg: cfg, client: client}
}

// checkRedirect follows at most three redirects, and only to HTTPS.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return tr.Err("heartbeat.err_redirects")
	}
	if req.URL.Scheme != "https" {
		return tr.Err("heartbeat.err_redirect_http")
	}
	return nil
}

// badURL wraps ErrBadURL with the reason, the catalog message key.
func badURL(key string, args ...any) error {
	return fmt.Errorf("%w: %w", ErrBadURL, tr.Err(key, args...))
}

// Validate checks a URL entered in the settings form and returns it trimmed.
func Validate(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", badURL("heartbeat.err_url_empty")
	}
	if len(raw) > MaxURLLength {
		return "", badURL("heartbeat.err_url_long", "max", MaxURLLength)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", badURL("heartbeat.err_url_invalid")
	}
	if u.Scheme != "https" {
		return "", badURL("heartbeat.err_url_https")
	}
	if u.Hostname() == "" || u.Opaque != "" {
		return "", badURL("heartbeat.err_url_host")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return "", badURL("heartbeat.err_url_fragment")
	}
	return raw, nil
}

// display shows where pings go without revealing the token in the path.
func display(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return "https://" + u.Host + "/…"
}

// Load reads the stored URL. A URL that cannot be decrypted (the key file
// was replaced) is reported in Status and must be entered again.
func (p *Pinger) Load(ctx context.Context) error {
	var s stored
	err := p.st.GetSetting(ctx, settingKey, &s)
	if errors.Is(err, store.ErrNotFound) || err == nil && len(s.URLEnc) == 0 {
		p.mu.Lock()
		p.url, p.status = "", Status{}
		p.mu.Unlock()
		return nil
	}
	if err != nil {
		return err
	}
	pt, err := p.box.Open(s.URLEnc, aad)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.url = ""
		p.status = Status{LastError: "The saved ping URL cannot be decrypted (was secret.key replaced?). Enter it again.",
			LastErrorAt: p.cfg.Now()}
		return err
	}
	p.url = secrets.Secret(pt)
	p.status = Status{Configured: true, Display: display(string(pt))}
	return nil
}

// Set validates, encrypts and stores a new URL, resetting the status.
func (p *Pinger) Set(ctx context.Context, raw string) error {
	v, err := Validate(raw)
	if err != nil {
		return err
	}
	enc, err := p.box.Seal([]byte(v), aad)
	if err != nil {
		return err
	}
	if err := p.st.SetSetting(ctx, settingKey, stored{URLEnc: enc}, p.cfg.Now()); err != nil {
		return err
	}
	p.mu.Lock()
	p.url, p.status = secrets.Secret(v), Status{Configured: true, Display: display(v)}
	p.mu.Unlock()
	return nil
}

// Clear removes the URL, turning pings off.
func (p *Pinger) Clear(ctx context.Context) error {
	if err := p.st.SetSetting(ctx, settingKey, stored{}, p.cfg.Now()); err != nil {
		return err
	}
	p.mu.Lock()
	p.url, p.status = "", Status{}
	p.mu.Unlock()
	return nil
}

// Status returns the current state.
func (p *Pinger) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

// Ping sends one ping now and records the outcome. The returned error's
// text never contains the URL.
func (p *Pinger) Ping(ctx context.Context) error {
	p.mu.Lock()
	u := p.url
	p.mu.Unlock()
	if !u.IsSet() {
		return ErrNotConfigured
	}
	start := p.cfg.Now()
	err := p.send(ctx, u)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.url != u {
		return err // the URL changed meanwhile; this outcome is stale
	}
	p.status.LastAttempt = start
	if err != nil {
		p.status.LastError, p.status.LastErrorAt = err.Error(), start
		p.status.ConsecutiveFailures++
		return err
	}
	p.status.LastSuccess, p.status.LastError, p.status.LastErrorAt = start, "", time.Time{}
	p.status.ConsecutiveFailures = 0
	return nil
}

func (p *Pinger) send(ctx context.Context, u secrets.Secret) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.Reveal(), nil)
	if err != nil {
		return tr.Err("heartbeat.err_url_not_valid")
	}
	if p.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", p.cfg.UserAgent)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return describe(err, p.cfg.Timeout)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return tr.Err("heartbeat.err_http_status", "status", resp.StatusCode)
	}
	return nil
}

// describe strips the URL (and its token) that net/http puts in errors.
func describe(err error, timeout time.Duration) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Timeout() {
			return tr.Err("heartbeat.err_timeout", "timeout", timeout)
		}
		err = ue.Err
	}
	return errors.New(err.Error())
}

// Run pings after each successful poll until ctx is canceled or updates is
// closed. Failed polls send nothing, so the monitoring service also notices
// when no Wall Connector can be reached.
func (p *Pinger) Run(ctx context.Context, updates <-chan poller.Update) {
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-updates:
			if !ok {
				return
			}
			if u.Err != nil || !p.Status().Configured {
				continue
			}
			if now := p.cfg.Now(); !last.IsZero() && now.Sub(last) < p.cfg.MinGap {
				continue
			}
			last = p.cfg.Now()
			if err := p.Ping(ctx); err != nil && ctx.Err() == nil {
				p.cfg.Logger.Warn("dead-man's-switch ping failed", "err", err.Error())
			}
		}
	}
}
