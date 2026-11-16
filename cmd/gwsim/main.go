// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Command gwsim runs a simulated Tesla Backup Gateway 2 local API over HTTPS
// with a fresh self-signed certificate, for development and the e2e tests.
//
//	gwsim [-listen 127.0.0.1:8443] [-scenario day] [-speed 1] [-list]
//
// The customer password is GWSIM_PASSWORD (default SIMPW); it is a test
// value, never a real one. Switch scenarios at runtime with:
//
//	curl -k -d name=night https://127.0.0.1:8443/_sim/scenario
//
// The control endpoints are unauthenticated: keep the simulator on loopback.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gwsim"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr, nil))
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer, ready chan<- string) int {
	fs := flag.NewFlagSet("gwsim", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", envOr(getenv, "GWSIM_LISTEN", "127.0.0.1:8443"), "address to listen on")
	scenario := fs.String("scenario", envOr(getenv, "GWSIM_SCENARIO", "day"), "initial scenario (see -list)")
	speedDefault, err := strconv.ParseFloat(envOr(getenv, "GWSIM_SPEED", "1"), 64)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "gwsim: invalid GWSIM_SPEED: %v\n", err)
		return 2
	}
	speed := fs.Float64("speed", speedDefault, "simulated seconds per real second")
	list := fs.Bool("list", false, "list scenarios and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *list {
		for _, s := range gwsim.Scenarios() {
			_, _ = fmt.Fprintf(stdout, "%-15s %s\n", s.Name, s.Description)
		}
		return 0
	}
	sim, err := gwsim.NewServer(gwsim.Options{Scenario: *scenario, Speed: *speed, Password: envOr(getenv, "GWSIM_PASSWORD", "SIMPW")})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *listen)
	if err != nil {
		logger.Error("listen", "err", err)
		return 1
	}
	srv := &http.Server{
		Handler:           sim,
		TLSConfig:         sim.TLSConfig(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	logger.Info("backup gateway simulator listening", "addr", ln.Addr().String(), "scenario", *scenario,
		"speed", *speed, "fingerprint", sim.Fingerprint())
	if ready != nil {
		ready <- ln.Addr().String()
	}
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "err", err)
			return 1
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx) //nolint:contextcheck // parent is already canceled
	}
	return 0
}

func envOr(getenv func(string) string, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}
