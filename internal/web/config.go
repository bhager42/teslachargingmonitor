// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// TLS modes.
const (
	TLSAuto = "auto" // self-signed certificate managed by the app (default)
	TLSFile = "file" // operator-provided certificate and key
	TLSOff  = "off"  // plain HTTP: behind a TLS proxy, or explicitly insecure
)

// Config is the web server configuration (from TCMON_* variables).
type Config struct {
	Listen            string // default ":8443"
	TLSMode           string
	TLSCertFile       string
	TLSKeyFile        string
	TLSMinVersion     string   // "1.3" (default) or "1.2"
	PublicHostnames   []string // extra allowed Host values and certificate SANs
	TrustedProxies    []netip.Prefix
	AllowedClients    []netip.Prefix // default: loopback, private and link-local ranges
	AllowInsecureHTTP bool
	HSTS              bool
	DataDir           string
}

// DefaultAllowedClients are the LAN-only defaults (owner decision D12).
var DefaultAllowedClients = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
}

// ParsePrefixes parses a comma-separated CIDR list (single IPs allowed).
func ParsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.Contains(f, "/") {
			a, err := netip.ParseAddr(f)
			if err != nil {
				return nil, fmt.Errorf("invalid address %q", f)
			}
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", f)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// Normalize fills defaults and validates.
func (c *Config) Normalize() error {
	if c.Listen == "" {
		c.Listen = ":8443"
	}
	if c.TLSMode == "" {
		c.TLSMode = TLSAuto
	}
	if c.TLSMinVersion == "" {
		c.TLSMinVersion = "1.3"
	}
	if c.TLSMinVersion != "1.3" && c.TLSMinVersion != "1.2" {
		return errors.New("TCMON_TLS_MIN_VERSION must be 1.3 or 1.2")
	}
	if len(c.AllowedClients) == 0 {
		c.AllowedClients = DefaultAllowedClients
	}
	for i, h := range c.PublicHostnames {
		c.PublicHostnames[i] = strings.ToLower(strings.TrimSpace(h))
	}
	switch c.TLSMode {
	case TLSAuto:
	case TLSFile:
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return errors.New("TCMON_TLS=file needs TCMON_TLS_CERT_FILE and TCMON_TLS_KEY_FILE")
		}
	case TLSOff:
		if len(c.TrustedProxies) == 0 && !c.AllowInsecureHTTP {
			return errors.New("TCMON_TLS=off sends your password unencrypted; set TCMON_TRUSTED_PROXIES to the " +
				"TLS-terminating reverse proxy, or TCMON_ALLOW_INSECURE_HTTP=true to accept the risk")
		}
	default:
		return fmt.Errorf("TCMON_TLS must be auto, file or off (got %q)", c.TLSMode)
	}
	return nil
}

// secureCookies reports whether the browser reaches us over HTTPS (directly
// or through a TLS-terminating proxy).
func (c *Config) secureCookies() bool { return c.TLSMode != TLSOff || !c.AllowInsecureHTTP }

// cookieName uses the __Host- prefix whenever cookies are Secure.
func (c *Config) cookieName() string {
	if c.secureCookies() {
		return "__Host-tcmon_session"
	}
	return "tcmon_session"
}
