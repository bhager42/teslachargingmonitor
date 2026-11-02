// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/buildinfo"
	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// maintenanceAt is the local time of day for nightly maintenance.
const maintenanceAt = 3*time.Hour + 17*time.Minute

func newLogger(env Env) (*slog.Logger, error) {
	var level slog.Level
	if s := env.Getenv("TCMON_LOG_LEVEL"); s != "" {
		if err := level.UnmarshalText([]byte(strings.ToUpper(s))); err != nil {
			return nil, fmt.Errorf("invalid TCMON_LOG_LEVEL %q", s)
		}
	}
	return slog.New(slog.NewJSONHandler(env.Stdout, &slog.HandlerOptions{Level: level})), nil
}

func runServe(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("serve", env)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	log, err := newLogger(env)
	if err != nil {
		return fail(env, "%v", err)
	}
	info := buildinfo.Get()
	log.Info("starting Tesla Charger Monitoring", "version", info.Version, "commit", info.Commit,
		"license", "AGPL-3.0-or-later", "source", info.SourceLink(), "data_dir", *dir)

	st, err := openStore(ctx, *dir)
	if err != nil {
		log.Error("opening database", "err", err)
		return 1
	}
	defer func() { _ = st.Close() }()

	devices, err := st.Devices(ctx)
	if err != nil {
		log.Error("reading devices", "err", err)
		return 1
	}
	if len(devices) == 0 {
		log.Warn("no Wall Connector configured yet; add one with `tcmon device add -address <ip>` " +
			"(the web UI will replace this step)")
	}

	m := poller.New(st, poller.Config{Logger: log, UserAgent: "tcmon/" + info.Version})
	done := make(chan struct{})
	go func() {
		defer close(done)
		runMaintenance(ctx, st, log, time.Now)
	}()
	_ = m.Run(ctx)
	<-done
	log.Info("stopped")
	return 0
}

// nextMaintenance returns the next local maintenanceAt after now.
func nextMaintenance(now time.Time) time.Time {
	y, mo, d := now.Date()
	t := time.Date(y, mo, d, 0, 0, 0, 0, now.Location()).Add(maintenanceAt)
	if !t.After(now) {
		t = time.Date(y, mo, d+1, 0, 0, 0, 0, now.Location()).Add(maintenanceAt)
	}
	return t
}

// runMaintenance runs once shortly after start and then nightly.
func runMaintenance(ctx context.Context, st *store.Store, log *slog.Logger, now func() time.Time) {
	wait := time.Minute
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		res, err := st.Maintain(ctx, now())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Error("database maintenance failed", "err", err)
		} else {
			stats, _ := st.Stats(ctx)
			log.Info("database maintenance done", "rolled_up", res.RolledUp, "pruned", res.Pruned,
				"db_bytes", stats.SizeBytes)
		}
		n := now()
		wait = nextMaintenance(n).Sub(n)
	}
}
