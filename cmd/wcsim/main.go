// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Command wcsim runs a simulated Tesla Universal Wall Connector local API for
// development and testing.
//
//	wcsim [-listen 127.0.0.1:8099] [-scenario idle] [-speed 1] [-list]
//
// Flags can also be set with WCSIM_LISTEN, WCSIM_SCENARIO and WCSIM_SPEED.
// Switch scenarios at runtime with:
//
//	curl -d name=overheat http://127.0.0.1:8099/_sim/scenario
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
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/wcsim"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wcsim", flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", envOr(getenv, "WCSIM_LISTEN", "127.0.0.1:8099"), "address to listen on")
	scenario := fs.String("scenario", envOr(getenv, "WCSIM_SCENARIO", "idle"), "initial scenario (see -list)")
	speedDefault, err := strconv.ParseFloat(envOr(getenv, "WCSIM_SPEED", "1"), 64)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "wcsim: invalid WCSIM_SPEED: %v\n", err)
		return 2
	}
	speed := fs.Float64("speed", speedDefault, "simulated seconds per real second (e.g. 60 = 1 min per second)")
	list := fs.Bool("list", false, "list scenarios and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *list {
		for _, s := range wcsim.Scenarios() {
			mark := ""
			if s.Provisional {
				mark = " [provisional]"
			}
			_, _ = fmt.Fprintf(stdout, "%-18s %s%s\n", s.Name, s.Description, mark)
		}
		return 0
	}

	sim, err := wcsim.NewServer(wcsim.Options{Scenario: *scenario, Speed: *speed})
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	srv := &http.Server{
		Addr:              *listen,
		Handler:           sim,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	logger.Info("wall connector simulator listening", "addr", *listen, "scenario", *scenario, "speed", *speed)

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
