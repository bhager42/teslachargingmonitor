// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package netguard

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestIsLAN(t *testing.T) {
	tests := map[string]bool{
		"192.168.1.17":       true,
		"10.0.0.1":           true,
		"172.16.5.4":         true,
		"127.0.0.1":          true,
		"::1":                true,
		"fd12:3456::1":       true,
		"fe80::1":            true,
		"::ffff:192.168.1.1": true,
		"8.8.8.8":            false,
		"169.254.169.254":    false,
		"100.64.0.1":         false,
		"0.0.0.0":            false,
		"224.0.0.1":          false,
		"2001:db8::1":        false,
	}
	for in, want := range tests {
		if got := IsLAN(netip.MustParseAddr(in)); got != want {
			t.Errorf("IsLAN(%s) = %v, want %v", in, got, want)
		}
	}
	if IsLAN(netip.Addr{}) {
		t.Error("zero Addr must not be LAN")
	}
}

func TestDialControl(t *testing.T) {
	ctx := context.Background()
	guard := DialControl(false)
	if err := guard(ctx, "tcp", "192.168.1.17:80", nil); err != nil {
		t.Errorf("LAN address blocked: %v", err)
	}
	for _, addr := range []string{"8.8.8.8:80", "[2001:db8::1]:80", "garbage", "example.com:80"} {
		if err := guard(ctx, "tcp", addr, nil); !errors.Is(err, ErrBlockedAddress) {
			t.Errorf("%s: err = %v, want ErrBlockedAddress", addr, err)
		}
	}
	if err := DialControl(true)(ctx, "tcp", "8.8.8.8:80", nil); err != nil {
		t.Errorf("allowNonLAN should permit: %v", err)
	}
}
