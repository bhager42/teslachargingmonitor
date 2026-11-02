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
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func noenv(string) string { return "" }

func TestList(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-list"}, noenv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{"idle", "charging", "[provisional]", "offline"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("-list output missing %q", want)
		}
	}
}

func TestBadInput(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-scenario", "nope"}, noenv, &out, &errOut); code != 2 {
		t.Errorf("unknown scenario exit = %d", code)
	}
	env := func(k string) string {
		if k == "WCSIM_SPEED" {
			return "fast"
		}
		return ""
	}
	if code := run(context.Background(), nil, env, &out, &errOut); code != 2 {
		t.Errorf("bad WCSIM_SPEED exit = %d", code)
	}
}

func TestServeAndShutdown(t *testing.T) {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	var out, errOut bytes.Buffer
	env := func(k string) string {
		if k == "WCSIM_SCENARIO" {
			return "charging"
		}
		return ""
	}
	go func() { done <- run(ctx, []string{"-listen", addr}, env, &out, &errOut) }()

	var resp *http.Response
	for range 50 {
		resp, err = http.Get("http://" + addr + "/_sim") //nolint:noctx // test
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("simulator never came up: %v", err)
	}
	var body bytes.Buffer
	_, _ = body.ReadFrom(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(body.String(), `"scenario":"charging"`) {
		t.Errorf("status = %s", body.String())
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit %d: %s", code, errOut.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not shut down")
	}
}
