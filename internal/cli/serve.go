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
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/buildinfo"
	"github.com/bhager42/teslachargingmonitor/internal/notify"
	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/web"
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
		if hint := permissionHint(err, *dir); hint != "" {
			log.Error(hint)
		}
		return 1
	}
	defer func() { _ = st.Close() }()

	devices, err := st.Devices(ctx)
	if err != nil {
		log.Error("reading devices", "err", err)
		return 1
	}
	if len(devices) == 0 {
		log.Warn("no Wall Connector configured yet; add one in the web UI under Settings → Wall Connectors")
	}

	m := poller.New(st, poller.Config{Logger: log, UserAgent: "tcmon/" + info.Version})
	engine := alerts.New(st, log)
	if err := engine.Load(ctx); err != nil {
		log.Error("loading alert state", "err", err)
		return 1
	}
	updates, unsubUpdates := m.Subscribe(32)
	defer unsubUpdates()
	notifications, unsubNotes := engine.Subscribe(32)
	defer unsubNotes()
	toDeliver, unsubDeliver := engine.Subscribe(32)
	defer unsubDeliver()

	keyPath := secretKeyPath(env, *dir)
	key, err := secrets.LoadOrCreateKey(keyPath, func(m string) { log.Warn(m) })
	if err != nil {
		log.Error("loading credential encryption key", "path", keyPath, "err", err)
		return 1
	}
	box, err := secrets.NewBox(key)
	if err != nil {
		log.Error("credential encryption key", "err", err)
		return 1
	}
	roots, err := smtpRoots(env)
	if err != nil {
		log.Error("SMTP CA bundle", "err", err)
		return 1
	}
	dispatcher := notify.New(st, box, notify.Config{Logger: log, RootCAs: roots})
	if chs, err := dispatcher.Channels(ctx); err == nil && len(chs) == 0 {
		log.Warn("no notification channel configured; alerts are only logged. add Gmail in the web UI under Notifications")
	}

	webCfg, err := webConfig(env, *dir)
	if err != nil {
		log.Error("web configuration", "err", err)
		return 1
	}
	authMgr := auth.NewManager(st, auth.Config{Logger: log})
	token, err := authMgr.Init(ctx, bootstrapFromEnv(env))
	if err != nil {
		log.Error("password configuration", "err", err)
		return 1
	}
	if token != "" {
		log.Warn("FIRST-RUN SETUP: open the web UI at https://<this-host>"+portSuffix(webCfg.Listen)+"/setup and enter this one-time token",
			"setup_token", token, "valid_for", "30m")
	}
	webSrv, err := web.New(webCfg, web.Options{Store: st, Auth: authMgr, Logger: log, Alerts: engine,
		Notify: dispatcher, Poll: m})
	if err != nil {
		log.Error("starting web server", "err", err)
		return 1
	}
	ctx, stop := context.WithCancel(ctx)
	defer stop()

	var wg sync.WaitGroup
	wg.Go(func() {
		if err := webSrv.Run(ctx); err != nil {
			log.Error("web server stopped", "err", err)
			stop()
		}
	})
	wg.Go(func() { runMaintenance(ctx, st, log, time.Now) })
	wg.Go(func() { engine.Run(ctx, updates) })
	wg.Go(func() { logNotifications(ctx, log, notifications) })
	wg.Go(func() { dispatcher.Run(ctx, toDeliver) })
	liveUpdates, unsubLive := m.Subscribe(32)
	defer unsubLive()
	liveAlerts, unsubLiveAlerts := engine.Subscribe(32)
	defer unsubLiveAlerts()
	wg.Go(func() { feedLive(ctx, webSrv, liveUpdates, liveAlerts) })
	_ = m.Run(ctx)
	wg.Wait()
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

// logNotifications records every alert notification in the log (delivery
// itself is done by the notify.Dispatcher).
func logNotifications(ctx context.Context, log *slog.Logger, ch <-chan []alerts.Notification) {
	for {
		select {
		case <-ctx.Done():
			return
		case batch, ok := <-ch:
			if !ok {
				return
			}
			for _, n := range batch {
				log.Warn("ALERT", "device", n.DeviceName, "rule", n.RuleTitle, "kind", n.Kind,
					"severity", n.Severity.String(), "message", n.Message)
			}
		}
	}
}

func portSuffix(listen string) string {
	if i := strings.LastIndexByte(listen, ':'); i >= 0 {
		return listen[i:]
	}
	return ""
}

// feedLive forwards poll results and alert notifications to the browsers
// connected to the web UI.
func feedLive(ctx context.Context, w *web.Server, updates <-chan poller.Update, notes <-chan []alerts.Notification) {
	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-updates:
			if !ok {
				return
			}
			// Give the alert engine a moment so the card shows new alerts too.
			time.Sleep(200 * time.Millisecond)
			w.HandleUpdate(u)
		case b, ok := <-notes:
			if !ok {
				return
			}
			w.HandleAlerts(b)
		}
	}
}

// permissionHint explains the usual container mistake: the data directory
// (a bind mount) is not owned by the user the container runs as.
func permissionHint(err error, dir string) string {
	if !errors.Is(err, fs.ErrPermission) {
		return ""
	}
	return fmt.Sprintf("the data directory %s must be writable by the user tcmon runs as (UID %d, GID %d); "+
		"on the host run: chown -R %d:%d <host folder mounted at %s>", dir, os.Getuid(), os.Getgid(),
		os.Getuid(), os.Getgid(), dir)
}
