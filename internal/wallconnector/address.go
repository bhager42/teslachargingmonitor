// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package wallconnector

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/bhager42/teslachargingmonitor/internal/netguard"
)

// ErrBadAddress is returned for device addresses that cannot be used.
var ErrBadAddress = errors.New("invalid Wall Connector address")

const maxAddressLen = 260

// Address is a validated Wall Connector location, entered by the user in the
// web UI as an IP address or hostname with an optional port and scheme.
type Address struct {
	Scheme string // "http" (default) or "https"
	Host   string // hostname or IP literal, without brackets
	Port   int    // 0 means the scheme default
}

// AddressOptions controls ParseAddress.
type AddressOptions struct {
	// AllowNonLAN permits IP literals outside the private/loopback ranges.
	// Hostnames are always checked again at connect time by the client.
	AllowNonLAN bool
}

// ParseAddress validates user input such as "192.168.1.17",
// "192.168.1.17:8080", "wallconnector.lan", "http://[fd00::17]" or
// "fd00::17". Paths, queries, fragments, credentials and IPv6 zones are
// rejected.
func ParseAddress(input string, opts AddressOptions) (Address, error) {
	s := strings.TrimSpace(input)
	if s == "" || len(s) > maxAddressLen {
		return Address{}, fmt.Errorf("%w: enter an IP address or hostname", ErrBadAddress)
	}
	// A bare IPv6 literal ("fd00::17") is not parseable as a URL host.
	if ip, err := netip.ParseAddr(s); err == nil {
		return finishIP(Address{Scheme: "http"}, ip, opts)
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return Address{}, fmt.Errorf("%w: %v", ErrBadAddress, err) //nolint:errorlint // url errors are not part of our API
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return Address{}, fmt.Errorf("%w: only http:// or https:// are supported", ErrBadAddress)
	case u.User != nil:
		return Address{}, fmt.Errorf("%w: credentials are not allowed", ErrBadAddress)
	case (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return Address{}, fmt.Errorf("%w: enter only the address, without a path", ErrBadAddress)
	}
	a := Address{Scheme: u.Scheme}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Address{}, fmt.Errorf("%w: port must be 1-65535", ErrBadAddress)
		}
		a.Port = n
	}
	host := u.Hostname()
	if strings.Contains(host, "%") {
		return Address{}, fmt.Errorf("%w: IPv6 zone identifiers are not supported", ErrBadAddress)
	}
	host = strings.TrimSuffix(host, ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		return finishIP(a, ip, opts)
	}
	if looksNumeric(host) {
		// e.g. "2130706433", "0x7f.1", "127.1": some resolvers treat these as
		// IPv4 addresses, which would bypass the LAN check above.
		return Address{}, fmt.Errorf("%w: %q is not a valid IP address", ErrBadAddress, host)
	}
	if !validHostname(host) {
		return Address{}, fmt.Errorf("%w: %q is not a valid hostname", ErrBadAddress, host)
	}
	a.Host = strings.ToLower(host)
	return a, nil
}

func finishIP(a Address, ip netip.Addr, opts AddressOptions) (Address, error) {
	if ip.Zone() != "" {
		return Address{}, fmt.Errorf("%w: IPv6 zone identifiers are not supported", ErrBadAddress)
	}
	ip = ip.Unmap()
	if !opts.AllowNonLAN && !netguard.IsLAN(ip) {
		return Address{}, fmt.Errorf("%w: %s is not a local network address", ErrBadAddress, ip)
	}
	a.Host = ip.String()
	return a, nil
}

// looksNumeric reports whether the last label of h is numeric or hex, which
// per the WHATWG URL standard means h is an (unusual) IPv4 spelling.
func looksNumeric(h string) bool {
	last := h[strings.LastIndexByte(h, '.')+1:]
	if last == "" {
		return false
	}
	if l := strings.ToLower(last); strings.HasPrefix(l, "0x") {
		return true
	}
	return strings.TrimLeft(last, "0123456789") == ""
}

func validHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for label := range strings.SplitSeq(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !isAlnum(r) && r != '-' {
				return false
			}
		}
	}
	return true
}

// HostPort returns host[:port] suitable for a URL authority.
func (a Address) HostPort() string {
	if a.Port == 0 {
		if strings.Contains(a.Host, ":") {
			return "[" + a.Host + "]"
		}
		return a.Host
	}
	return net.JoinHostPort(a.Host, strconv.Itoa(a.Port))
}

// BaseURL returns e.g. "http://192.168.1.17".
func (a Address) BaseURL() string { return a.Scheme + "://" + a.HostPort() }

func (a Address) String() string { return a.BaseURL() }
