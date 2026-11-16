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

	"github.com/bhager42/teslachargingmonitor/internal/energy"
	"github.com/bhager42/teslachargingmonitor/internal/notify"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// SendHour is the local hour (on Monday, or on the 1st for the monthly
// summary) when a digest is queued.
const SendHour = 8

// lastKey stores the start of the last period a digest was queued for, so
// a restart neither repeats nor skips it.
func lastKey(per Period) string {
	if per == Monthly {
		return "digest_last_month"
	}
	return "digest_last_week"
}

// Queue is where digests go (notify.Dispatcher).
type Queue interface {
	EnqueueDigest(ctx context.Context, msg notify.Message, monthly bool) (int, error)
}

// Config tunes a Scheduler. Zero values select production defaults.
type Config struct {
	Location *time.Location
	Now      func() time.Time
	Logger   *slog.Logger
}

// Scheduler queues the previous week's digest every Monday at SendHour and
// the previous month's on the 1st at SendHour. If tcmon was not running
// then, it catches up later in the same week or month.
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

// dueAt is the send time in the period that starts at start (a Monday or
// the 1st of a month).
func dueAt(start time.Time) time.Time {
	y, m, d := start.Date()
	return time.Date(y, m, d, SendHour, 0, 0, 0, start.Location())
}

// Tick queues the previous period's digest if it is due and not yet
// queued, and returns how many channels it was queued for (-1 when nothing
// was due).
func (s *Scheduler) Tick(ctx context.Context, per Period) (int, error) {
	now := s.cfg.Now().In(s.cfg.Location)
	from, to := per.Range(now, s.cfg.Location)
	if now.Before(dueAt(to)) {
		return -1, nil
	}
	var last time.Time
	if err := s.st.GetSetting(ctx, lastKey(per), &last); err != nil && !errors.Is(err, store.ErrNotFound) {
		return -1, err
	}
	if !last.Before(from) {
		return -1, nil
	}
	msg, err := Build(ctx, s.st, per, from, to, s.cfg.Location)
	if err != nil {
		return -1, err
	}
	n, err := s.q.EnqueueDigest(ctx, msg, per == Monthly)
	if err != nil {
		return -1, err
	}
	// Recorded even when no channel opted in, so turning the digest on
	// later does not send an old summary immediately.
	if err := s.st.SetSetting(ctx, lastKey(per), from, now); err != nil {
		return n, err
	}
	if n > 0 {
		s.cfg.Logger.Info("digest queued", "period", per.String(), "start", from.Format(time.DateOnly), "channels", n)
	}
	return n, nil
}

// next returns when to check again: the next send time, but at least
// hourly so clock and time-zone changes are picked up.
func (s *Scheduler) next() time.Duration {
	now := s.cfg.Now().In(s.cfg.Location)
	p := energy.NewPlan(nil, s.cfg.Location)
	due := time.Time{}
	for _, per := range []energy.Period{energy.Week, energy.Month} {
		d := dueAt(p.Next(per, p.Start(per, now)))
		if start := dueAt(p.Start(per, now)); now.Before(start) {
			d = start
		}
		if due.IsZero() || d.Before(due) {
			due = d
		}
	}
	return min(max(due.Sub(now), time.Second), time.Hour)
}

// Run checks at start-up and then at each send time until ctx ends.
func (s *Scheduler) Run(ctx context.Context) {
	for {
		for _, per := range []Period{Weekly, Monthly} {
			if _, err := s.Tick(ctx, per); err != nil && ctx.Err() == nil {
				s.cfg.Logger.Error("digest", "period", per.String(), "err", err)
			}
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
