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
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/notify/smtpmock"
)

const appPassword = "abcd efgh ijkl mnop" // as Gmail displays it

func runWith(t *testing.T, vars map[string]string, stdin string, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	env := Env{Getenv: func(k string) string { return vars[k] }, Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errOut}
	code := Run(context.Background(), args, env)
	return result{code, out.String(), errOut.String()}
}

func TestNotifyCommands(t *testing.T) {
	dir := t.TempDir()
	srv, err := smtpmock.Start(smtpmock.Options{Username: "owner@gmail.com", Password: "abcdefghijklmnop"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ca := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(ca, srv.CAPEM, 0o600)
	vars := map[string]string{"TCMON_DATA_DIR": dir, "TCMON_SMTP_CA_FILE": ca}
	port := strings.TrimPrefix(srv.Addr, "127.0.0.1:")

	r := runWith(t, vars, "", "notify", "list")
	if r.code != 0 || !strings.Contains(r.stdout, "No notification channels") {
		t.Fatalf("empty list: %+v", r)
	}
	// A password on the command line is not an option; without one, Gmail setup fails.
	r = runWith(t, vars, "", "notify", "add-email", "-username", "owner@gmail.com", "-to", "me@example.com",
		"-host", "localhost", "-port", port, "-skip-test")
	if r.code != 1 || !strings.Contains(r.stderr, "password") {
		t.Errorf("missing password: %+v", r)
	}

	r = runWith(t, vars, appPassword+"\n", "notify", "add-email", "-name", "Gmail", "-username", "owner@gmail.com",
		"-to", "me@example.com, partner@example.com", "-host", "localhost", "-port", port, "-password-stdin")
	if r.code != 0 || !strings.Contains(r.stdout, "Test email sent") {
		t.Fatalf("add-email: %+v", r)
	}
	if len(srv.Messages()) != 1 || srv.Messages()[0].Auth != "owner@gmail.com" {
		t.Errorf("test email not received: %+v", srv.Messages())
	}
	if _, err := os.Stat(filepath.Join(dir, "secret.key")); err != nil {
		t.Errorf("secret key not created: %v", err)
	}

	r = runWith(t, vars, "", "notify", "list")
	if r.code != 0 || !strings.Contains(r.stdout, "localhost:"+port+"/starttls") || !strings.Contains(r.stdout, "set") ||
		strings.Contains(r.stdout, "abcd") {
		t.Errorf("list: %+v", r)
	}

	r = runWith(t, vars, "", "notify", "update", "1", "-min-severity", "warning", "-quiet-hours", "22:00-07:00", "-skip-test")
	if r.code != 0 {
		t.Fatalf("update: %+v", r)
	}
	if r = runWith(t, vars, "", "notify", "test", "1"); r.code != 0 {
		t.Errorf("test after update (password kept): %+v", r)
	}
	pwFile := filepath.Join(dir, "pw")
	_ = os.WriteFile(pwFile, []byte("wrong-password"), 0o600)
	r = runWith(t, vars, "", "notify", "update", "1", "-password-file", pwFile)
	if r.code != 1 || !strings.Contains(r.stderr, "app password") {
		t.Errorf("wrong password should fail the test email with a hint: %+v", r)
	}
	if r = runWith(t, vars, "", "notify", "update", "1", "-min-severity", "loud"); r.code != 1 {
		t.Errorf("bad severity: %+v", r)
	}
	if r = runWith(t, vars, "x", "notify", "update", "1", "-password-stdin", "-password-file", pwFile); r.code != 1 {
		t.Errorf("both password flags: %+v", r)
	}

	r = runWith(t, vars, "", "notify", "log")
	if r.code != 0 || !strings.Contains(r.stdout, "No notifications sent yet") {
		t.Errorf("log: %+v", r) // test emails are not queued deliveries
	}
	if r = runWith(t, vars, "", "notify", "remove", "1"); r.code != 1 {
		t.Errorf("remove without -yes: %+v", r)
	}
	if r = runWith(t, vars, "", "notify", "remove", "1", "-yes"); r.code != 0 {
		t.Errorf("remove: %+v", r)
	}
	if r = runWith(t, vars, "", "notify"); r.code != 2 {
		t.Errorf("usage: %+v", r)
	}
	bad := map[string]string{"TCMON_DATA_DIR": dir, "TCMON_SMTP_CA_FILE": pwFile}
	if r = runWith(t, bad, "", "notify", "list"); r.code != 1 || !strings.Contains(r.stderr, "no PEM certificates") {
		t.Errorf("bad CA file: %+v", r)
	}
}

// End to end through `tcmon serve`: an overcurrent alert is emailed.
func TestServeEmailsAlerts(t *testing.T) {
	dir := t.TempDir()
	srv, err := smtpmock.Start(smtpmock.Options{Username: "owner@gmail.com", Password: "abcdefghijklmnop"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ca := filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(ca, srv.CAPEM, 0o600)
	vars := map[string]string{"TCMON_DATA_DIR": dir, "TCMON_SMTP_CA_FILE": ca, "TCMON_LISTEN": "127.0.0.1:0"}
	port := strings.TrimPrefix(srv.Addr, "127.0.0.1:")
	if r := runWith(t, vars, appPassword, "notify", "add-email", "-username", "owner@gmail.com", "-to", "me@example.com",
		"-host", "localhost", "-port", port, "-password-stdin", "-skip-test"); r.code != 0 {
		t.Fatal(r)
	}
	if r := runWith(t, vars, "", "device", "add", "-address", simURL(t, "overcurrent"), "-breaker", "60", "-skip-test"); r.code != 0 {
		t.Fatal(r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan result, 1)
	go func() {
		var out, errOut bytes.Buffer
		code := Run(ctx, []string{"serve"}, Env{Getenv: func(k string) string { return vars[k] }, Stdout: &out, Stderr: &errOut})
		done <- result{code, out.String(), errOut.String()}
	}()
	deadline := time.Now().Add(15 * time.Second)
	for len(srv.Messages()) == 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("no alert email; serve output: %+v", <-done)
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	r := <-done
	msg := string(srv.Messages()[0].Data)
	if r.code != 0 || !strings.Contains(msg, "Overcurrent") || !strings.Contains(r.stdout, `"msg":"notification sent"`) ||
		strings.Contains(r.stdout, "abcdefghijklmnop") {
		t.Errorf("serve = %d\nemail: %s\nlog: %s", r.code, msg, r.stdout)
	}
}

func TestPasswordCommands(t *testing.T) {
	dir := t.TempDir()
	vars := map[string]string{"TCMON_DATA_DIR": dir}
	r := runWith(t, vars, "purple otter kayak sunrise\n", "hash-password")
	if r.code != 0 || !strings.HasPrefix(r.stdout, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatalf("hash-password: %+v", r)
	}
	if r := runWith(t, vars, "short\n", "hash-password"); r.code != 1 || !strings.Contains(r.stderr, "at least 12") {
		t.Errorf("weak hash-password: %+v", r)
	}
	if r := runWith(t, vars, "", "hash-password", "extra"); r.code != 2 {
		t.Errorf("args: %+v", r)
	}
	r = runWith(t, vars, "granite lantern meadow 42\n", "reset-password")
	if r.code != 0 || !strings.Contains(r.stdout, "signed out") {
		t.Fatalf("reset-password: %+v", r)
	}
	if r := runWith(t, vars, "password1234\n", "reset-password"); r.code != 1 || !strings.Contains(r.stderr, "commonly used") {
		t.Errorf("weak reset: %+v", r)
	}
	envVars := map[string]string{"TCMON_DATA_DIR": dir, "TCMON_PASSWORD_FILE": "/run/secrets/x"} //nolint:gosec // G101: a path, not a credential
	if r := runWith(t, envVars, "granite lantern meadow 43\n", "reset-password"); !strings.Contains(r.stdout, "will replace this password") {
		t.Errorf("env warning missing: %+v", r)
	}
}

func TestServeWebAndHealthcheck(t *testing.T) {
	dir := t.TempDir()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	vars := map[string]string{"TCMON_DATA_DIR": dir, "TCMON_LISTEN": addr}

	if r := runWith(t, vars, "", "healthcheck"); r.code != 1 || !strings.Contains(r.stderr, "unhealthy") {
		t.Errorf("healthcheck with no server: %+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var out syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"serve"}, Env{Getenv: func(k string) string { return vars[k] }, Stdout: &out, Stderr: &out})
	}()
	deadline := time.Now().Add(10 * time.Second)
	for runWith(t, vars, "", "healthcheck").code != 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("server never became healthy:\n%s", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Errorf("serve exit %d:\n%s", code, out.String())
	}
	logs := out.String()
	for _, want := range []string{"FIRST-RUN SETUP", `"setup_token":"`, `"msg":"HTTPS certificate"`, `"sha256":"`, "web UI listening"} {
		if !strings.Contains(logs, want) {
			t.Errorf("serve log missing %q", want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "tls", "cert.pem")); err != nil {
		t.Errorf("certificate not created: %v", err)
	}
	if r := runWith(t, map[string]string{"TCMON_DATA_DIR": dir, "TCMON_PASSWORD": "x", "TCMON_LISTEN": addr}, "", "serve"); r.code != 1 ||
		!strings.Contains(r.stdout, "docker inspect") {
		t.Errorf("TCMON_PASSWORD accepted: %+v", r)
	}
	if r := runWith(t, map[string]string{"TCMON_DATA_DIR": dir, "TCMON_TLS": "off", "TCMON_LISTEN": addr}, "", "serve"); r.code != 1 ||
		!strings.Contains(r.stdout, "unencrypted") {
		t.Errorf("plain HTTP without opt-in accepted: %+v", r)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
