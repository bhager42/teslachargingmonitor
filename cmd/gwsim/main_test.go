// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
)

func TestServesTheGatewayAPI(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan int, 1)
	env := map[string]string{"GWSIM_PASSWORD": "TESTPW"}
	go func() {
		done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-scenario", "night"}, func(k string) string { return env[k] },
			io.Discard, io.Discard, ready)
	}()
	addr := <-ready
	fp, err := gateway.Fingerprint(ctx, addr, false)
	if err != nil {
		t.Fatal(err)
	}
	c, err := gateway.NewClient(addr, gateway.Options{Pin: fp, Password: secrets.Secret("TESTPW")})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := c.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Aggregates.Solar.InstantPower != 0 || snap.Aggregates.Battery.InstantPower != 1100 {
		t.Errorf("night scenario: %+v", snap.Aggregates)
	}
	c.Close()
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("did not stop")
	}
}

func TestList(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), []string{"-list"}, func(string) string { return "" }, &out, io.Discard, nil); code != 0 ||
		!strings.Contains(out.String(), "cert-changed") {
		t.Errorf("list = %d %q", code, out.String())
	}
}
