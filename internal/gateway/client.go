// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/netguard"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
)

// Endpoint is a Gateway API path.
type Endpoint string

// The endpoints tcmon reads. All are GETs; only the login is a POST.
const (
	EndpointStatus       Endpoint = "/api/status"
	EndpointAggregates   Endpoint = "/api/meters/aggregates"
	EndpointSOE          Endpoint = "/api/system_status/soe"
	EndpointGridStatus   Endpoint = "/api/system_status/grid_status"
	EndpointSystemStatus Endpoint = "/api/system_status"
	EndpointOperation    Endpoint = "/api/operation"
	EndpointSitemaster   Endpoint = "/api/sitemaster"
	EndpointSiteInfo     Endpoint = "/api/site_info"
	EndpointSolars       Endpoint = "/api/solars"
	EndpointLogin        Endpoint = "/api/login/Basic"
)

// SnapshotEndpoints are fetched by every poll, in this order.
var SnapshotEndpoints = []Endpoint{
	EndpointStatus, EndpointAggregates, EndpointSOE, EndpointGridStatus,
	EndpointSystemStatus, EndpointOperation, EndpointSitemaster,
}

// Defaults and the login back-off policy (ADR 0007).
const (
	DefaultTimeout      = 10 * time.Second
	DefaultMaxBodyBytes = 1 << 20
	BackoffMin          = 5 * time.Minute
	BackoffMax          = 6 * time.Hour
	// loginEmail is required by the login form but not checked by the
	// Gateway; the owner's email is never sent.
	loginEmail = "tcmon@example.com"
)

// Errors returned by the Client. They wrap underlying causes; use errors.Is.
var (
	ErrRedirect       = errors.New("gateway: redirects are not followed")
	ErrBodyTooLarge   = errors.New("gateway: response body too large")
	ErrNotJSON        = errors.New("gateway: response is not JSON")
	ErrNoPin          = errors.New("gateway: no certificate fingerprint pinned")
	ErrNoPassword     = errors.New("gateway: no customer password set")
	ErrLoginRejected  = errors.New("gateway: login rejected (wrong customer password?)")
	ErrRateLimited    = errors.New("gateway: login rate limited by the Gateway")
	ErrCertChanged    = errors.New("gateway: certificate does not match the pinned fingerprint")
	ErrNotAuthorized  = errors.New("gateway: request not authorized after a fresh login")
	ErrBlockedAddress = netguard.ErrBlockedAddress
)

// StatusError reports an unexpected HTTP status.
type StatusError struct {
	Endpoint   Endpoint
	StatusCode int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("gateway: %s: unexpected HTTP status %d", e.Endpoint, e.StatusCode)
}

// CertError is returned when the Gateway presents a certificate other than
// the pinned one. Fingerprint is the new certificate's, for the owner to
// confirm (gateway_cert_changed). errors.Is(err, ErrCertChanged) holds.
type CertError struct{ Fingerprint string }

func (e *CertError) Error() string { return ErrCertChanged.Error() }

// Unwrap makes errors.Is(err, ErrCertChanged) work.
func (e *CertError) Unwrap() error { return ErrCertChanged }

// BackoffError is returned without contacting the Gateway while logins are
// suspended after a rejected or rate-limited login.
type BackoffError struct {
	Until time.Time
	Cause error // ErrLoginRejected or ErrRateLimited
}

func (e *BackoffError) Error() string {
	return fmt.Sprintf("gateway: login suspended until %s after: %v", e.Until.Format(time.RFC3339), e.Cause)
}

func (e *BackoffError) Unwrap() error { return e.Cause }

// Backoff is the login back-off state. The poller persists it so a restart
// does not reset it (step 9.2).
type Backoff struct {
	Failures int       // consecutive rejected or rate-limited logins
	Until    time.Time // no login before this time
	Cause    string    // "rejected" or "rate_limited"
}

// Options configures a Client.
type Options struct {
	// Pin is the hex SHA-256 fingerprint of the Gateway's certificate, as
	// returned by Fingerprint and confirmed by the owner. Required.
	Pin      string
	Password secrets.Secret // the Gateway's customer password
	Timeout  time.Duration  // per request; default DefaultTimeout
	// MaxBodyBytes caps each response; default DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// AllowNonLAN disables the connect-time check that the Gateway resolves
	// to a private/loopback address.
	AllowNonLAN bool
	UserAgent   string
	Now         func() time.Time // clock for the back-off; default time.Now
}

// Client reads one Backup Gateway. It logs in once and reuses the session
// token until the Gateway rejects it, then logs in again at most once per
// call. A rejected or rate-limited login suspends logins with exponential
// back-off (BackoffMin doubling to BackoffMax). It never uses a proxy, never
// follows redirects, and sends one request at a time.
type Client struct {
	base    string
	hc      *http.Client
	pw      secrets.Secret
	timeout time.Duration
	maxBody int64
	ua      string
	now     func() time.Time

	mu      sync.Mutex
	token   string
	backoff Backoff
}

// NewClient returns a Client for hostPort ("192.168.1.20" or "gw.lan:443").
func NewClient(hostPort string, opts Options) (*Client, error) {
	pin := normalizePin(opts.Pin)
	if len(pin) != sha256.Size*2 {
		return nil, ErrNoPin
	}
	if !opts.Password.IsSet() {
		return nil, ErrNoPassword
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "tcmon"
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Client{
		base:    baseURL(hostPort),
		hc:      newHTTPClient(opts.Timeout, opts.AllowNonLAN, pinVerifier(pin)),
		pw:      opts.Password,
		timeout: opts.Timeout,
		maxBody: opts.MaxBodyBytes,
		ua:      opts.UserAgent,
		now:     opts.Now,
	}, nil
}

func normalizePin(p string) string { return strings.ToLower(strings.ReplaceAll(p, ":", "")) }

func baseURL(hostPort string) string {
	if strings.Count(hostPort, ":") > 1 && !strings.HasPrefix(hostPort, "[") {
		return "https://[" + hostPort + "]"
	}
	return "https://" + hostPort
}

// fingerprintOf is the hex SHA-256 of a DER certificate.
func fingerprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// pinVerifier checks the leaf certificate against pin. It replaces chain
// verification, which a self-signed Gateway certificate cannot pass.
func pinVerifier(pin string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("gateway: no certificate presented")
		}
		if fp := fingerprintOf(cs.PeerCertificates[0].Raw); fp != pin {
			return &CertError{Fingerprint: fp}
		}
		return nil
	}
}

func newHTTPClient(timeout time.Duration, allowNonLAN bool, verify func(tls.ConnectionState) error) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, ControlContext: netguard.DialControl(allowNonLAN)}
	tr := &http.Transport{
		Proxy:                  nil, // the Gateway is on the LAN; never route via a proxy
		DialContext:            dialer.DialContext,
		DisableCompression:     true,
		MaxIdleConns:           1,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: 16 << 10,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// The Gateway's certificate is self-signed: chain verification is
			// replaced by the pin check in VerifyConnection (ADR 0007).
			InsecureSkipVerify: true, //nolint:gosec // pinned in VerifyConnection
			VerifyConnection:   verify,
		},
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirect },
	}
}

// Fingerprint connects to the Gateway without logging in and returns the
// SHA-256 fingerprint of its certificate, for the owner to confirm before
// it is pinned (trust on first use).
func Fingerprint(ctx context.Context, hostPort string, allowNonLAN bool) (string, error) {
	var fp string
	hc := newHTTPClient(DefaultTimeout, allowNonLAN, func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("gateway: no certificate presented")
		}
		fp = fingerprintOf(cs.PeerCertificates[0].Raw)
		return nil
	})
	defer hc.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL(hostPort)+string(EndpointStatus), nil)
	if err != nil {
		return "", fmt.Errorf("gateway: building request: %w", err)
	}
	resp, err := hc.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, DefaultMaxBodyBytes))
		_ = resp.Body.Close()
	}
	if fp == "" {
		if err == nil {
			err = errors.New("gateway: no certificate presented")
		}
		return "", fmt.Errorf("gateway: connecting: %w", err)
	}
	return fp, nil
}

// Backoff returns the current login back-off state.
func (c *Client) Backoff() Backoff {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backoff
}

// RestoreBackoff sets the back-off state, e.g. after a restart.
func (c *Client) RestoreBackoff(b Backoff) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.backoff = b
}

// ResetBackoff clears the back-off, e.g. after the owner saves a new
// password. The next call logs in at once.
func (c *Client) ResetBackoff() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.backoff = Backoff{}
}

// Close drops the session and idle connections.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = ""
	c.hc.CloseIdleConnections()
}

// Fetch returns the raw body of ep, logging in first when needed.
func (c *Client) Fetch(ctx context.Context, ep Endpoint) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fetchLocked(ctx, ep)
}

func (c *Client) fetchLocked(ctx context.Context, ep Endpoint) ([]byte, error) {
	if ep == EndpointStatus {
		return c.getLocked(ctx, ep, "")
	}
	relogged := false
	if c.token == "" {
		if err := c.loginLocked(ctx); err != nil {
			return nil, err
		}
		relogged = true
	}
	body, err := c.getLocked(ctx, ep, c.token)
	if !isAuthStatus(err) {
		return body, err
	}
	// The session expired. Log in again, at most once per call.
	c.token = ""
	if relogged {
		return nil, fmt.Errorf("%w: %w", ErrNotAuthorized, err)
	}
	if err := c.loginLocked(ctx); err != nil {
		return nil, err
	}
	body, err = c.getLocked(ctx, ep, c.token)
	if isAuthStatus(err) {
		c.token = ""
		return nil, fmt.Errorf("%w: %w", ErrNotAuthorized, err)
	}
	return body, err
}

func isAuthStatus(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && (se.StatusCode == http.StatusUnauthorized || se.StatusCode == http.StatusForbidden)
}

// loginLocked logs in once, honoring and updating the back-off.
func (c *Client) loginLocked(ctx context.Context) error {
	now := c.now()
	if now.Before(c.backoff.Until) {
		cause := ErrLoginRejected
		if c.backoff.Cause == "rate_limited" {
			cause = ErrRateLimited
		}
		return &BackoffError{Until: c.backoff.Until, Cause: cause}
	}
	body, err := json.Marshal(map[string]any{
		"username": "customer", "password": c.pw.Reveal(),
		"email": loginEmail, "force_sm_off": false,
	})
	if err != nil {
		return fmt.Errorf("gateway: encoding login: %w", err)
	}
	status, resp, err := c.doLocked(ctx, http.MethodPost, EndpointLogin, bytes.NewReader(body), "")
	if err != nil {
		return err // network or TLS problem: not a password failure, no back-off
	}
	var cause error
	switch {
	case status == http.StatusTooManyRequests:
		cause = ErrRateLimited
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		cause = ErrLoginRejected
	case status != http.StatusOK:
		return &StatusError{Endpoint: EndpointLogin, StatusCode: status}
	}
	if cause == nil {
		// Only the token is read; the response's name and email are dropped.
		var lr struct {
			Token string `json:"token"`
		}
		if json.Unmarshal(resp, &lr) != nil || lr.Token == "" {
			return fmt.Errorf("%w: login response has no token", ErrNotJSON)
		}
		c.token = lr.Token
		c.backoff = Backoff{}
		return nil
	}
	c.backoff.Failures++
	wait := BackoffMin << min(c.backoff.Failures-1, 20)
	if wait > BackoffMax || wait <= 0 {
		wait = BackoffMax
	}
	c.backoff.Until = now.Add(wait)
	c.backoff.Cause = "rejected"
	if errors.Is(cause, ErrRateLimited) {
		c.backoff.Cause = "rate_limited"
	}
	return &BackoffError{Until: c.backoff.Until, Cause: cause}
}

func (c *Client) getLocked(ctx context.Context, ep Endpoint, token string) ([]byte, error) {
	status, body, err := c.doLocked(ctx, http.MethodGet, ep, nil, token)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &StatusError{Endpoint: ep, StatusCode: status}
	}
	if t := bytes.TrimSpace(body); len(t) == 0 || (t[0] != '{' && t[0] != '[') {
		return nil, fmt.Errorf("%w: %s", ErrNotJSON, ep)
	}
	return body, nil
}

func (c *Client) doLocked(ctx context.Context, method string, ep Endpoint, body io.Reader, token string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.base+string(ep), body)
	if err != nil {
		return 0, nil, fmt.Errorf("gateway: building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		var ce *CertError
		if errors.As(err, &ce) {
			c.token = ""
			return 0, nil, ce
		}
		return 0, nil, fmt.Errorf("gateway: %s %s: %w", method, ep, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return 0, nil, fmt.Errorf("gateway: reading %s: %w", ep, err)
	}
	if int64(len(data)) > c.maxBody {
		return 0, nil, fmt.Errorf("%w: %s: more than %d bytes", ErrBodyTooLarge, ep, c.maxBody)
	}
	return resp.StatusCode, data, nil
}

// Snapshot is the result of one poll.
type Snapshot struct {
	FetchedAt    time.Time
	Status       Status
	Aggregates   Aggregates
	SOE          SOE
	GridStatus   GridStatus
	SystemStatus SystemStatus
	Operation    Operation
	Sitemaster   Sitemaster
	Reports      map[Endpoint]Report
	Raw          map[Endpoint][]byte
}

// Snapshot fetches SnapshotEndpoints in order. On error it returns the
// partially filled snapshot together with the first error.
func (c *Client) Snapshot(ctx context.Context) (*Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.hc.CloseIdleConnections()
	s := &Snapshot{
		FetchedAt: c.now(),
		Reports:   make(map[Endpoint]Report, len(SnapshotEndpoints)),
		Raw:       make(map[Endpoint][]byte, len(SnapshotEndpoints)),
	}
	for _, ep := range SnapshotEndpoints {
		body, err := c.fetchLocked(ctx, ep)
		if err != nil {
			return s, err
		}
		s.Raw[ep] = body
		var rep Report
		switch ep {
		case EndpointStatus:
			s.Status, rep, err = DecodeStatus(body)
		case EndpointAggregates:
			s.Aggregates, rep, err = DecodeAggregates(body)
		case EndpointSOE:
			s.SOE, rep, err = DecodeSOE(body)
		case EndpointGridStatus:
			s.GridStatus, rep, err = DecodeGridStatus(body)
		case EndpointSystemStatus:
			s.SystemStatus, rep, err = DecodeSystemStatus(body)
		case EndpointOperation:
			s.Operation, rep, err = DecodeOperation(body)
		case EndpointSitemaster:
			s.Sitemaster, rep, err = DecodeSitemaster(body)
		}
		s.Reports[ep] = rep
		if err != nil {
			return s, fmt.Errorf("gateway: decoding %s: %w", ep, err)
		}
	}
	return s, nil
}

// Info is the slowly changing site description.
type Info struct {
	SiteInfo SiteInfo
	Solars   []Solar
	Reports  []Report
}

// Info fetches /api/site_info and /api/solars.
func (c *Client) Info(ctx context.Context) (*Info, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.hc.CloseIdleConnections()
	var in Info
	body, err := c.fetchLocked(ctx, EndpointSiteInfo)
	if err != nil {
		return nil, err
	}
	si, rep, err := DecodeSiteInfo(body)
	if err != nil {
		return nil, fmt.Errorf("gateway: decoding %s: %w", EndpointSiteInfo, err)
	}
	in.SiteInfo, in.Reports = si, append(in.Reports, rep)
	body, err = c.fetchLocked(ctx, EndpointSolars)
	if err != nil {
		return nil, err
	}
	sol, rep, err := DecodeSolars(body)
	if err != nil {
		return nil, fmt.Errorf("gateway: decoding %s: %w", EndpointSolars, err)
	}
	in.Solars, in.Reports = sol, append(in.Reports, rep)
	return &in, nil
}
