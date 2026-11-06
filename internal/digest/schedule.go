// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package digest

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/notify"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// SendHour is the local hour on Monday when the digest is queued.
const SendHour = 8

// lastKey stores the start of the last week a digest was queued for, so a
// restart neither repeats nor skips it.
const lastKey = "digest_last_week"

// Queue is where digests go (notify.Dispatcher).
type Queue interface {
	EnqueueDigest(ctx context.Context, msg notify.Message) (int, error)
}

// Config tunes a Scheduler. Zero values select production defaults.
type Config struct {
	Location *time.Location
	Now      func() time.Time
	Logger   *slog.Logger
}

// Scheduler queues the previous week's digest every Monday at SendHour. If
// tcmon was not running then, it catches up later the same week.
type Scheduler struct {
	st  *store.Store
	q   Queue
	cfg Config
}

// NewScheduler returns a Scheduler; call Run to start it.
func NewScheduler(st *store.Store, q Queue, cfg Config) *Scheduler {
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Scheduler{st: st, q: q, cfg: cfg}
}

// dueAt is the send time in the week that starts at weekStart (a Monday).
func dueAt(weekStart time.Time) time.Time {
	y, m, d := weekStart.Date()
	return time.Date(y, m, d, SendHour, 0, 0, 0, weekStart.Location())
}

// Tick queues last week's digest if it is due and not yet queued, and
// returns how many channels it was queued for (-1 when nothing was due).
func (s *Scheduler) Tick(ctx context.Context) (int, error) {
	now := s.cfg.Now().In(s.cfg.Location)
	from, to := Week(now, s.cfg.Location)
	if now.Before(dueAt(to)) {
		return -1, nil
	}
	var last time.Time
	if err := s.st.GetSetting(ctx, lastKey, &last); err != nil && !errors.Is(err, store.ErrNotFound) {
		return -1, err
	}
	if !last.Before(from) {
		return -1, nil
	}
	msg, err := Build(ctx, s.st, from, to, s.cfg.Location)
	if err != nil {
		return -1, err
	}
	n, err := s.q.EnqueueDigest(ctx, msg)
	if err != nil {
		return -1, err
	}
	// Recorded even when no channel opted in, so turning the digest on
	// mid-week does not send last week's summary immediately.
	if err := s.st.SetSetting(ctx, lastKey, from, now); err != nil {
		return n, err
	}
	if n > 0 {
		s.cfg.Logger.Info("weekly digest queued", "week_start", from.Format(time.DateOnly), "channels", n)
	}
	return n, nil
}

// next returns when to check again: the next send time, but at least
// hourly so clock and time-zone changes are picked up.
func (s *Scheduler) next() time.Duration {
	now := s.cfg.Now().In(s.cfg.Location)
	_, to := Week(now, s.cfg.Location)
	due := dueAt(to)
	if !now.Before(due) {
		y, m, d := to.Date()
		due = dueAt(time.Date(y, m, d+7, 0, 0, 0, 0, s.cfg.Location))
	}
	return min(max(due.Sub(now), time.Second), time.Hour)
}

// Run checks at start-up and then at each send time until ctx ends.
func (s *Scheduler) Run(ctx context.Context) {
	for {
		if _, err := s.Tick(ctx); err != nil && ctx.Err() == nil {
			s.cfg.Logger.Error("weekly digest", "err", err)
		}
		t := time.NewTimer(s.next())
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
