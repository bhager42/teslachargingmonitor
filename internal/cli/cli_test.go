// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wcsim"
)

type result struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, ctx context.Context, dataDir string, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	env := Env{
		Getenv: func(k string) string {
			switch k {
			case "TCMON_DATA_DIR":
				return dataDir
			case "TCMON_LISTEN":
				return "127.0.0.1:0"
			}
			return ""
		},
		Stdout: &out, Stderr: &errOut,
	}
	code := Run(ctx, args, env)
	return result{code, out.String(), errOut.String()}
}

func simURL(t *testing.T, scenario string) string {
	t.Helper()
	sim, err := wcsim.NewServer(wcsim.Options{Scenario: scenario})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(sim)
	t.Cleanup(ts.Close)
	return ts.URL
}

func TestBasicCommands(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	tests := []struct {
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{[]string{"version"}, 0, "AGPL-3.0-or-later", ""},
		{[]string{"help"}, 0, "Usage: tcmon", ""},
		{nil, 2, "", "Usage: tcmon"},
		{[]string{"bogus"}, 2, "", `unknown command "bogus"`},
		{[]string{"migrate"}, 0, "schema version 5", ""},
		{[]string{"device"}, 2, "", "tcmon device add"},
		{[]string{"device", "list"}, 0, "No devices", ""},
		{[]string{"device", "add"}, 2, "", "-address is required"},
		{[]string{"device", "add", "-address", "8.8.8.8"}, 1, "", "not a local network address"},
		{[]string{"device", "remove", "1"}, 1, "", "-yes"},
		{[]string{"backup"}, 2, "", "Usage: tcmon backup"},
		{[]string{"alerts"}, 2, "", "tcmon alerts rules"},
		{[]string{"alerts", "rules"}, 0, "false (needs calibration)", ""},
		{[]string{"alerts", "history"}, 0, "No alerts recorded", ""},
	}
	for _, tc := range tests {
		r := runCLI(t, ctx, dir, tc.args...)
		if r.code != tc.code || !strings.Contains(r.stdout, tc.stdout) || !strings.Contains(r.stderr, tc.stderr) {
			t.Errorf("tcmon %v = %d\nstdout: %s\nstderr: %s", tc.args, r.code, r.stdout, r.stderr)
		}
	}
}

func TestDeviceLifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	url := simURL(t, "idle")

	r := runCLI(t, ctx, dir, "device", "add", "-name", "Garage", "-address", url, "-breaker", "60")
	if r.code != 0 || !strings.Contains(r.stdout, "firmware 26.26.10") || !strings.Contains(r.stdout, "Added device 1") {
		t.Fatalf("add: %+v", r)
	}
	// Adding a non-Wall-Connector fails the connection test.
	r = runCLI(t, ctx, dir, "device", "add", "-address", "127.0.0.1:1")
	if r.code != 1 || !strings.Contains(r.stderr, "connection test failed") {
		t.Errorf("add unreachable: %+v", r)
	}
	r = runCLI(t, ctx, dir, "device", "add", "-address", "127.0.0.1:1", "-skip-test", "-name", "Spare")
	if r.code != 0 {
		t.Errorf("add -skip-test: %+v", r)
	}

	r = runCLI(t, ctx, dir, "device", "list")
	if r.code != 0 || !strings.Contains(r.stdout, "Garage") || !strings.Contains(r.stdout, "48") ||
		!strings.Contains(r.stdout, "1h0m0s") || !strings.Contains(r.stdout, "5m0s") {
		t.Errorf("list: %+v", r)
	}

	r = runCLI(t, ctx, dir, "device", "update", "1", "-interval", "30m", "-fast-when-plugged=false")
	if r.code != 0 {
		t.Fatalf("update: %+v", r)
	}
	st, err := store.Open(ctx, filepath.Join(dir, "tcmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	d, _ := st.Device(ctx, 1)
	_ = st.Close()
	if d.PollInterval != 30*time.Minute || d.FastWhenPlugged || d.Name != "Garage" || d.MaxCurrentA != 48 {
		t.Errorf("after update: %+v", d)
	}
	r = runCLI(t, ctx, dir, "device", "update", "1", "-address", "127.0.0.1:1")
	if r.code != 1 || !strings.Contains(r.stderr, "connection test failed") {
		t.Errorf("update to unreachable address: %+v", r)
	}
	r = runCLI(t, ctx, dir, "device", "update", "99", "-name", "x")
	if r.code != 1 {
		t.Errorf("update missing: %+v", r)
	}

	r = runCLI(t, ctx, dir, "device", "test", url)
	if r.code != 0 || !strings.Contains(r.stdout, "Found Wall Connector") {
		t.Errorf("test: %+v", r)
	}

	backup := filepath.Join(t.TempDir(), "b.db")
	if r = runCLI(t, ctx, dir, "backup", backup); r.code != 0 {
		t.Errorf("backup: %+v", r)
	}

	if r = runCLI(t, ctx, dir, "device", "remove", "2", "-yes"); r.code != 0 {
		t.Errorf("remove: %+v", r)
	}
	if r = runCLI(t, ctx, dir, "device", "remove", "2", "-yes"); r.code != 1 {
		t.Errorf("remove twice: %+v", r)
	}
}

func TestServePollsAndStops(t *testing.T) {
	dir := t.TempDir()
	url := simURL(t, "overcurrent")
	if r := runCLI(t, context.Background(), dir, "device", "add", "-address", url, "-skip-test", "-breaker", "60"); r.code != 0 {
		t.Fatal(r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan result, 1)
	go func() { done <- runCLI(t, ctx, dir, "serve") }()

	st, err := store.Open(context.Background(), filepath.Join(dir, "tcmon.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		log, _ := st.PollLog(context.Background(), 1, 1)
		if len(log) == 1 && log[0].OK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("serve never polled the device")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Wait for the alert engine to record the overcurrent alert.
	for {
		evs, _ := st.AlertEvents(context.Background(), store.AlertEventFilter{})
		if len(evs) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no alert recorded")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if r := runCLI(t, context.Background(), dir, "alerts", "history"); !strings.Contains(r.stdout, "overcurrent") {
		t.Errorf("alerts history: %+v", r)
	}
	cancel()
	select {
	case r := <-done:
		if r.code != 0 || !strings.Contains(r.stdout, `"msg":"polled wall connector"`) ||
			!strings.Contains(r.stdout, `"msg":"ALERT"`) || !strings.Contains(r.stdout, `"rule":"Overcurrent"`) ||
			!strings.Contains(r.stdout, `"source":"https://github.com/bhager42/teslachargingmonitor`) {
			t.Errorf("serve: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
}

func TestServeBadLogLevel(t *testing.T) {
	var out, errOut bytes.Buffer
	env := Env{Getenv: func(k string) string {
		if k == "TCMON_LOG_LEVEL" {
			return "loud"
		}
		return ""
	}, Stdout: &out, Stderr: &errOut}
	if code := Run(context.Background(), []string{"serve", "-data-dir", t.TempDir()}, env); code != 1 {
		t.Errorf("exit %d", code)
	}
}

func TestNextMaintenance(t *testing.T) {
	loc := time.FixedZone("CST", -6*3600)
	tests := []struct{ now, want time.Time }{
		{time.Date(2026, 11, 2, 1, 0, 0, 0, loc), time.Date(2026, 11, 2, 3, 17, 0, 0, loc)},
		{time.Date(2026, 11, 2, 3, 17, 0, 0, loc), time.Date(2026, 11, 3, 3, 17, 0, 0, loc)},
		{time.Date(2026, 12, 31, 23, 0, 0, 0, loc), time.Date(2027, 1, 1, 3, 17, 0, 0, loc)},
	}
	for _, tc := range tests {
		if got := nextMaintenance(tc.now); !got.Equal(tc.want) {
			t.Errorf("nextMaintenance(%v) = %v, want %v", tc.now, got, tc.want)
		}
	}
}

func TestPermissionHint(t *testing.T) {
	err := fmt.Errorf("store: creating database file: %w", &fs.PathError{Op: "open", Path: "/data/tcmon.db", Err: fs.ErrPermission})
	if h := permissionHint(err, "/data"); !strings.Contains(h, "chown -R") || !strings.Contains(h, "/data") {
		t.Errorf("hint = %q", h)
	}
	if h := permissionHint(errors.New("disk full"), "/data"); h != "" {
		t.Errorf("unrelated error got a hint: %q", h)
	}
}
