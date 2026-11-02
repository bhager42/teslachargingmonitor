// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package cli

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/web"
)

// webConfig builds the web server configuration from TCMON_* variables.
func webConfig(env Env, dataDir string) (web.Config, error) {
	c := web.Config{
		Listen:            env.Getenv("TCMON_LISTEN"),
		TLSMode:           strings.ToLower(env.Getenv("TCMON_TLS")),
		TLSCertFile:       env.Getenv("TCMON_TLS_CERT_FILE"),
		TLSKeyFile:        env.Getenv("TCMON_TLS_KEY_FILE"),
		TLSMinVersion:     env.Getenv("TCMON_TLS_MIN_VERSION"),
		AllowInsecureHTTP: env.Getenv("TCMON_ALLOW_INSECURE_HTTP") == "true",
		HSTS:              env.Getenv("TCMON_HSTS") == "true",
		DataDir:           dataDir,
	}
	for _, h := range strings.Split(env.Getenv("TCMON_PUBLIC_HOSTNAMES"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			c.PublicHostnames = append(c.PublicHostnames, h)
		}
	}
	var err error
	if c.TrustedProxies, err = web.ParsePrefixes(env.Getenv("TCMON_TRUSTED_PROXIES")); err != nil {
		return c, fmt.Errorf("TCMON_TRUSTED_PROXIES: %w", err)
	}
	if c.AllowedClients, err = web.ParsePrefixes(env.Getenv("TCMON_ALLOWED_CLIENT_CIDRS")); err != nil {
		return c, fmt.Errorf("TCMON_ALLOWED_CLIENT_CIDRS: %w", err)
	}
	return c, c.Normalize()
}

func bootstrapFromEnv(env Env) auth.Bootstrap {
	return auth.Bootstrap{
		PasswordHash:     env.Getenv("TCMON_PASSWORD_HASH"),
		PasswordHashFile: env.Getenv("TCMON_PASSWORD_HASH_FILE"),
		PasswordFile:     env.Getenv("TCMON_PASSWORD_FILE"),
		PlainPasswordSet: env.Getenv("TCMON_PASSWORD") != "",
	}
}

// readSecretLine reads one secret from stdin (trailing newline removed).
func readSecretLine(env Env) (string, error) {
	if env.Stdin == nil {
		return "", fmt.Errorf("no standard input")
	}
	line, err := bufio.NewReader(io.LimitReader(env.Stdin, 4096)).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func runHashPassword(_ context.Context, args []string, env Env) int {
	if len(args) > 0 {
		_, _ = fmt.Fprintln(env.Stderr, "Usage: echo 'your password' | tcmon hash-password   (prints a TCMON_PASSWORD_HASH value)")
		return 2
	}
	pw, err := readSecretLine(env)
	if err != nil {
		return fail(env, "%v", err)
	}
	if err := auth.CheckPolicy(pw); err != nil {
		return fail(env, "%v", err)
	}
	h, err := auth.Hash(pw, auth.DefaultParams)
	if err != nil {
		return fail(env, "%v", err)
	}
	_, _ = fmt.Fprintln(env.Stdout, h)
	return 0
}

func runResetPassword(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("reset-password", env)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	_, _ = fmt.Fprintf(env.Stderr, "Enter the new password (at least %d characters) and press Enter:\n", auth.MinPasswordLength)
	pw, err := readSecretLine(env)
	if err != nil {
		return fail(env, "%v", err)
	}
	st, err := openStore(ctx, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	if err := auth.NewManager(st, auth.Config{}).ResetPassword(ctx, pw); err != nil {
		return fail(env, "%v", err)
	}
	_, _ = fmt.Fprintln(env.Stdout, "Password changed; every browser session has been signed out.")
	if env.Getenv("TCMON_PASSWORD_FILE") != "" || env.Getenv("TCMON_PASSWORD_HASH") != "" || env.Getenv("TCMON_PASSWORD_HASH_FILE") != "" {
		_, _ = fmt.Fprintln(env.Stdout, "Note: TCMON_PASSWORD_FILE / TCMON_PASSWORD_HASH is set and will replace this password at the next restart.")
	}
	return 0
}

// runHealthcheck is the container HEALTHCHECK: GET /healthz on loopback.
func runHealthcheck(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("healthcheck", env)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := webConfig(env, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	_, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fail(env, "bad TCMON_LISTEN: %v", err)
	}
	scheme := "https"
	if cfg.TLSMode == web.TLSOff {
		scheme = "http"
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			// Loopback only: the self-signed certificate is not verified here.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // loopback liveness probe
		},
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://127.0.0.1:"+port+"/healthz", nil)
	req.Host = "localhost"
	resp, err := client.Do(req)
	if err != nil {
		return fail(env, "unhealthy: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fail(env, "unhealthy: HTTP %d", resp.StatusCode)
	}
	return 0
}
