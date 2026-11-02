// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package netguard decides which network addresses count as "LAN" for the
// purposes of SSRF protection (outbound device connections) and, in later
// phases, LAN-only enforcement of inbound web clients.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// ErrBlockedAddress is returned when a connection target is not a LAN address.
var ErrBlockedAddress = errors.New("address is not on the local network")

// IsLAN reports whether ip is a loopback, RFC 1918 / RFC 4193 private, or IPv6
// link-local unicast address. IPv4 link-local (169.254.0.0/16) is excluded on
// purpose: it hosts cloud metadata services and a Wall Connector normally gets
// a DHCP address.
func IsLAN(ip netip.Addr) bool {
	ip = ip.Unmap()
	switch {
	case !ip.IsValid(), ip.IsUnspecified(), ip.IsMulticast():
		return false
	case ip.IsLoopback(), ip.IsPrivate():
		return true
	case ip.Is6() && ip.IsLinkLocalUnicast():
		return true
	default:
		return false
	}
}

// DialControl returns a net.Dialer ControlContext hook that refuses to
// connect to non-LAN addresses. Because it runs after DNS resolution, it also
// defeats DNS-rebinding tricks where a hostname later resolves elsewhere.
// When allowNonLAN is true the hook permits everything.
func DialControl(allowNonLAN bool) func(ctx context.Context, network, address string, c syscall.RawConn) error {
	return func(_ context.Context, _, address string, _ syscall.RawConn) error {
		if allowNonLAN {
			return nil
		}
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("%w: %q", ErrBlockedAddress, address)
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !IsLAN(ip) {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, host)
		}
		return nil
	}
}
