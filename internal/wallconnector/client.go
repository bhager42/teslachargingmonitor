// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package wallconnector

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/netguard"
)

// Endpoint names a Wall Connector API endpoint.
type Endpoint string

// The endpoints of the local API.
const (
	EndpointVitals     Endpoint = "vitals"
	EndpointLifetime   Endpoint = "lifetime"
	EndpointWifiStatus Endpoint = "wifi_status"
	EndpointVersion    Endpoint = "version"
)

// Endpoints lists all endpoints in the order a Snapshot fetches them.
var Endpoints = []Endpoint{EndpointVersion, EndpointVitals, EndpointLifetime, EndpointWifiStatus}

// Path returns the request path, e.g. "/api/1/vitals".
func (e Endpoint) Path() string { return "/api/1/" + string(e) }

// Defaults. The device is a small embedded controller: keep requests short
// and small.
const (
	DefaultTimeout      = 5 * time.Second
	DefaultMaxBodyBytes = 64 << 10
)

// Errors returned by the Client. They wrap underlying causes; use errors.Is.
var (
	ErrRedirect         = errors.New("wallconnector: redirects are not followed")
	ErrBodyTooLarge     = errors.New("wallconnector: response body too large")
	ErrNotJSON          = errors.New("wallconnector: response is not JSON")
	ErrNotWallConnector = errors.New("wallconnector: device does not look like a Tesla Wall Connector")
	ErrBlockedAddress   = netguard.ErrBlockedAddress
)

// StatusError reports a non-200 HTTP response.
type StatusError struct{ StatusCode int }

func (e *StatusError) Error() string {
	return fmt.Sprintf("wallconnector: unexpected HTTP status %d", e.StatusCode)
}

// Options configures a Client. Zero values select safe defaults.
type Options struct {
	Timeout      time.Duration // per request; default DefaultTimeout
	MaxBodyBytes int64         // default DefaultMaxBodyBytes
	// AllowNonLAN disables the connect-time check that the device resolves
	// to a private/loopback address.
	AllowNonLAN bool
	UserAgent   string
}

// Client fetches data from one Wall Connector. It never uses an HTTP proxy,
// never follows redirects, does not keep connections open between polls, and
// sends at most one request to the device at a time.
type Client struct {
	addr    Address
	hc      *http.Client
	timeout time.Duration
	maxBody int64
	ua      string
	mu      sync.Mutex
}

// NewClient returns a Client for addr.
func NewClient(addr Address, opts Options) *Client {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "tcmon"
	}
	dialer := &net.Dialer{Timeout: opts.Timeout, ControlContext: netguard.DialControl(opts.AllowNonLAN)}
	tr := &http.Transport{
		Proxy:                  nil, // the device is on the LAN; never route via a proxy
		DialContext:            dialer.DialContext,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ResponseHeaderTimeout:  opts.Timeout,
		MaxResponseHeaderBytes: 16 << 10,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &Client{
		addr: addr,
		hc: &http.Client{
			Transport:     tr,
			Timeout:       opts.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirect },
		},
		timeout: opts.Timeout,
		maxBody: opts.MaxBodyBytes,
		ua:      opts.UserAgent,
	}
}

// Address returns the device address.
func (c *Client) Address() Address { return c.addr }

// Fetch returns the raw body of one endpoint after transport-level checks.
func (c *Client) Fetch(ctx context.Context, ep Endpoint) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.addr.BaseURL()+ep.Path(), nil)
	if err != nil {
		return nil, fmt.Errorf("wallconnector: building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wallconnector: GET %s: %w", ep.Path(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, c.maxBody))
		return nil, &StatusError{StatusCode: resp.StatusCode}
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err == nil && (mt == "text/html" || mt == "application/xhtml+xml") {
			return nil, fmt.Errorf("%w: content type %s", ErrNotJSON, mt)
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("wallconnector: reading %s: %w", ep.Path(), err)
	}
	if int64(len(body)) > c.maxBody {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrBodyTooLarge, c.maxBody)
	}
	if trimmed := bytes.TrimSpace(body); len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, ErrNotJSON
	}
	return body, nil
}

// Vitals fetches and decodes /api/1/vitals.
func (c *Client) Vitals(ctx context.Context) (Vitals, Report, error) {
	return fetchDecode(ctx, c, EndpointVitals, DecodeVitals)
}

// Lifetime fetches and decodes /api/1/lifetime.
func (c *Client) Lifetime(ctx context.Context) (Lifetime, Report, error) {
	return fetchDecode(ctx, c, EndpointLifetime, DecodeLifetime)
}

// WifiStatus fetches and decodes /api/1/wifi_status.
func (c *Client) WifiStatus(ctx context.Context) (WifiStatus, Report, error) {
	return fetchDecode(ctx, c, EndpointWifiStatus, DecodeWifiStatus)
}

// Version fetches and decodes /api/1/version.
func (c *Client) Version(ctx context.Context) (Version, Report, error) {
	return fetchDecode(ctx, c, EndpointVersion, DecodeVersion)
}

func fetchDecode[T any](ctx context.Context, c *Client, ep Endpoint, dec func([]byte) (T, Report, error)) (T, Report, error) {
	var zero T
	body, err := c.Fetch(ctx, ep)
	if err != nil {
		return zero, Report{Endpoint: ep}, err
	}
	return dec(body)
}

// Snapshot is the result of one poll of all endpoints.
type Snapshot struct {
	FetchedAt  time.Time
	Version    Version
	Vitals     Vitals
	Lifetime   Lifetime
	WifiStatus WifiStatus
	Reports    map[Endpoint]Report
	Raw        map[Endpoint][]byte
}

// Snapshot fetches all four endpoints sequentially. On error it returns the
// partially filled snapshot together with the first error.
func (c *Client) Snapshot(ctx context.Context) (*Snapshot, error) {
	s := &Snapshot{
		FetchedAt: time.Now(),
		Reports:   make(map[Endpoint]Report, len(Endpoints)),
		Raw:       make(map[Endpoint][]byte, len(Endpoints)),
	}
	for _, ep := range Endpoints {
		body, err := c.Fetch(ctx, ep)
		if err != nil {
			return s, err
		}
		s.Raw[ep] = body
		var rep Report
		switch ep {
		case EndpointVersion:
			s.Version, rep, err = DecodeVersion(body)
		case EndpointVitals:
			s.Vitals, rep, err = DecodeVitals(body)
		case EndpointLifetime:
			s.Lifetime, rep, err = DecodeLifetime(body)
		case EndpointWifiStatus:
			s.WifiStatus, rep, err = DecodeWifiStatus(body)
		}
		s.Reports[ep] = rep
		if err != nil {
			return s, fmt.Errorf("wallconnector: decoding %s: %w", ep, err)
		}
	}
	return s, nil
}

// ProbeResult is what the web UI's "Test connection" button shows.
type ProbeResult struct {
	Version      Version
	Firmware     FirmwareVersion
	MaskedSerial string
	Vitals       Vitals
	Reports      []Report
}

// Probe checks that the address hosts a Wall Connector by reading
// /api/1/version and /api/1/vitals.
func (c *Client) Probe(ctx context.Context) (*ProbeResult, error) {
	ver, vrep, err := c.Version(ctx)
	if err != nil {
		if errors.Is(err, ErrNotObject) || errors.Is(err, ErrNotJSON) || isStatus(err, http.StatusNotFound) {
			return nil, fmt.Errorf("%w (%w)", ErrNotWallConnector, err)
		}
		return nil, err
	}
	if vrep.IsMissing("firmware_version") || vrep.IsMissing("serial_number") || vrep.IsMissing("part_number") {
		return nil, ErrNotWallConnector
	}
	fw, err := ver.Firmware()
	if err != nil {
		return nil, fmt.Errorf("%w (%w)", ErrNotWallConnector, err)
	}
	vit, vitRep, err := c.Vitals(ctx)
	if err != nil {
		return nil, err
	}
	return &ProbeResult{
		Version:      ver,
		Firmware:     fw,
		MaskedSerial: MaskSerial(ver.SerialNumber),
		Vitals:       vit,
		Reports:      []Report{vrep, vitRep},
	}, nil
}

func isStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.StatusCode == code
}
