// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package poller polls every enabled Wall Connector on its schedule (60 min
// by default, 5 min while a car is plugged in), retries failures, stores the
// results and publishes updates to subscribers (the alert engine and, later,
// the live web UI).
package poller

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

// ErrRateLimited is returned by PollNow when called too often.
var ErrRateLimited = errors.New("poller: poll-now requested too soon")

// ErrUnknownDevice is returned by PollNow for devices that are not polled.
var ErrUnknownDevice = errors.New("poller: device is not being polled")

// Update is published after every poll (successful or finally failed).
type Update struct {
	Device   store.Device
	Snapshot *wallconnector.Snapshot // nil when Err != nil
	Err      error                   // set when all retries failed
	Events   []store.DeviceEvent
	Attempts int
	At       time.Time
	Next     time.Time // when the next scheduled poll will run
}

// Config tunes the poller. Zero values select production defaults.
type Config struct {
	// RetryDelays are the waits before each retry of a failed poll
	// (default 30 s, 2 min, 5 min).
	RetryDelays []time.Duration
	// PollNowGap is the minimum spacing of manual "Poll now" requests.
	PollNowGap time.Duration
	// SyncEvery is how often device configuration is re-read from the store.
	SyncEvery time.Duration
	// MaxJitter caps the random ±2 % schedule jitter.
	MaxJitter time.Duration
	// IntervalOverride replaces every device interval (tests and soak runs).
	IntervalOverride time.Duration
	Now              func() time.Time
	Logger           *slog.Logger
	UserAgent        string
	Client           wallconnector.Options
}

func (c *Config) defaults() {
	if c.RetryDelays == nil {
		c.RetryDelays = []time.Duration{30 * time.Second, 2 * time.Minute, 5 * time.Minute}
	}
	if c.PollNowGap == 0 {
		c.PollNowGap = 10 * time.Second
	}
	if c.SyncEvery == 0 {
		c.SyncEvery = time.Minute
	}
	if c.MaxJitter == 0 {
		c.MaxJitter = time.Minute
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.Client.UserAgent == "" {
		c.Client.UserAgent = c.UserAgent
	}
}

// Manager runs one worker per enabled device.
type Manager struct {
	st  *store.Store
	cfg Config

	mu      sync.Mutex // guards workers; held while starting/stopping them
	workers map[int64]*worker
	wg      sync.WaitGroup

	subsMu sync.Mutex // separate lock so workers can publish while Sync waits for them
	subs   map[chan Update]struct{}
}

type worker struct {
	device  store.Device
	cancel  context.CancelFunc
	done    chan struct{}
	trigger chan struct{}
	lastNow time.Time
}

// New returns a Manager. Call Run to start polling.
func New(st *store.Store, cfg Config) *Manager {
	cfg.defaults()
	return &Manager{st: st, cfg: cfg, workers: map[int64]*worker{}, subs: map[chan Update]struct{}{}}
}

// Subscribe returns a channel of updates. Slow subscribers miss updates
// rather than blocking polling. Call the returned function to unsubscribe.
func (m *Manager) Subscribe(buffer int) (<-chan Update, func()) {
	ch := make(chan Update, buffer)
	m.subsMu.Lock()
	m.subs[ch] = struct{}{}
	m.subsMu.Unlock()
	return ch, func() {
		m.subsMu.Lock()
		defer m.subsMu.Unlock()
		if _, ok := m.subs[ch]; ok {
			delete(m.subs, ch)
			close(ch)
		}
	}
}

func (m *Manager) publish(u Update) {
	m.subsMu.Lock()
	defer m.subsMu.Unlock()
	for ch := range m.subs {
		select {
		case ch <- u:
		default:
			m.cfg.Logger.Warn("dropping poll update for slow subscriber", "device_id", u.Device.ID)
		}
	}
}

// Run polls until ctx is canceled, re-reading device configuration every
// SyncEvery so devices added or edited elsewhere are picked up.
func (m *Manager) Run(ctx context.Context) error {
	defer m.stopAll()
	if err := m.Sync(ctx); err != nil {
		m.cfg.Logger.Error("loading devices", "err", err)
	}
	t := time.NewTicker(m.cfg.SyncEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := m.Sync(ctx); err != nil && ctx.Err() == nil {
				m.cfg.Logger.Error("reloading devices", "err", err)
			}
		}
	}
}

// Sync starts, stops or restarts workers to match the stored devices.
func (m *Manager) Sync(ctx context.Context) error {
	devices, err := m.st.Devices(ctx)
	if err != nil {
		return err
	}
	want := map[int64]store.Device{}
	for _, d := range devices {
		if d.Enabled {
			want[d.ID] = d
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, w := range m.workers {
		if d, ok := want[id]; !ok || !d.UpdatedAt.Equal(w.device.UpdatedAt) {
			m.stopLocked(id)
		}
	}
	for id, d := range want {
		if _, running := m.workers[id]; !running {
			m.startLocked(ctx, d)
		}
	}
	return nil
}

// Reload applies device changes immediately (after a GUI edit).
func (m *Manager) Reload(ctx context.Context) error { return m.Sync(ctx) }

func (m *Manager) startLocked(ctx context.Context, d store.Device) {
	wctx, cancel := context.WithCancel(ctx)
	w := &worker{device: d, cancel: cancel, done: make(chan struct{}), trigger: make(chan struct{}, 1)}
	m.workers[d.ID] = w
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer close(w.done)
		m.runWorker(wctx, w)
	}()
	m.cfg.Logger.Info("polling device", "device_id", d.ID, "name", d.Name, "address", d.Address,
		"interval", d.PollInterval, "plugged_interval", d.PluggedInterval, "fast_when_plugged", d.FastWhenPlugged)
}

func (m *Manager) stopLocked(id int64) {
	w := m.workers[id]
	delete(m.workers, id)
	w.cancel()
	<-w.done
}

func (m *Manager) stopAll() {
	m.mu.Lock()
	for id := range m.workers {
		m.stopLocked(id)
	}
	m.mu.Unlock()
	m.wg.Wait()
}

// Devices returns the IDs currently being polled.
func (m *Manager) Devices() []int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]int64, 0, len(m.workers))
	for id := range m.workers {
		ids = append(ids, id)
	}
	return ids
}

// PollNow asks a device's worker to poll immediately.
func (m *Manager) PollNow(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.workers[id]
	if !ok {
		return ErrUnknownDevice
	}
	now := m.cfg.Now()
	if !w.lastNow.IsZero() && now.Sub(w.lastNow) < m.cfg.PollNowGap {
		return ErrRateLimited
	}
	w.lastNow = now
	select {
	case w.trigger <- struct{}{}:
	default:
	}
	return nil
}

func (m *Manager) runWorker(ctx context.Context, w *worker) {
	d := w.device
	log := m.cfg.Logger.With("device_id", d.ID, "device", d.Name)
	addr, err := d.ParsedAddress()
	if err != nil {
		log.Error("invalid device address; not polling", "err", err)
		return
	}
	opts := m.cfg.Client
	opts.AllowNonLAN = d.AllowNonLAN
	client := wallconnector.NewClient(addr, opts)

	state, err := m.st.LatestState(ctx, d.ID)
	if err != nil {
		log.Error("loading previous state", "err", err)
	}

	for {
		state = m.pollOnce(ctx, w, client, state, log)
		if ctx.Err() != nil {
			return
		}
		wait := m.interval(d, state)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-w.trigger:
			timer.Stop()
		}
	}
}

// interval chooses the next delay: the plugged-in cadence while a car is
// connected (if enabled), otherwise the normal interval, with jitter.
func (m *Manager) interval(d store.Device, st store.DeviceState) time.Duration {
	base := d.PollInterval
	if d.FastWhenPlugged && st.LastPlugged {
		base = d.PluggedInterval
	}
	if m.cfg.IntervalOverride > 0 {
		return m.cfg.IntervalOverride
	}
	j := min(time.Duration(float64(base)*0.02), m.cfg.MaxJitter)
	if j <= 0 {
		return base
	}
	return base - j + time.Duration(rand.Int64N(int64(2*j)+1)) //nolint:gosec // scheduling jitter, not security
}

// pollOnce polls with retries, stores the outcome and publishes an update.
func (m *Manager) pollOnce(ctx context.Context, w *worker, client *wallconnector.Client, prev store.DeviceState, log *slog.Logger) store.DeviceState {
	d := w.device
	var lastErr error
	for attempt := 1; ; attempt++ {
		start := m.cfg.Now()
		snap, err := client.Snapshot(ctx)
		took := m.cfg.Now().Sub(start)
		if ctx.Err() != nil {
			return prev
		}
		if err == nil {
			snap.FetchedAt = start
			events := detectEvents(prev, snap)
			if serr := m.st.SaveSnapshot(ctx, d.ID, snap, events, attempt, took); serr != nil {
				log.Error("saving poll", "err", serr)
			}
			next := nextState(prev, snap)
			logReading(log, snap, events, attempt, took)
			m.publish(Update{Device: d, Snapshot: snap, Events: events, Attempts: attempt, At: start,
				Next: start.Add(m.interval(d, next))})
			return next
		}
		lastErr = err
		if lerr := m.st.RecordPollFailure(ctx, d.ID, start, attempt, took, err); lerr != nil && ctx.Err() == nil {
			log.Error("recording poll failure", "err", lerr)
		}
		if attempt > len(m.cfg.RetryDelays) {
			break
		}
		delay := m.cfg.RetryDelays[attempt-1]
		log.Warn("poll failed; will retry", "attempt", attempt, "retry_in", delay, "err", err)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return prev
		case <-timer.C:
		case <-w.trigger:
			timer.Stop()
		}
	}
	attempts := len(m.cfg.RetryDelays) + 1
	log.Error("device unreachable after retries", "attempts", attempts, "err", lastErr)
	now := m.cfg.Now()
	m.publish(Update{Device: d, Err: lastErr, Attempts: attempts, At: now, Next: now.Add(m.interval(d, prev))})
	return prev
}

func logReading(log *slog.Logger, s *wallconnector.Snapshot, events []store.DeviceEvent, attempt int, took time.Duration) {
	v := s.Vitals
	attrs := []any{
		"attempt", attempt, "took", took.Round(time.Millisecond).String(),
		"state", wallconnector.EVSEStateInfo(v.EVSEState).Label,
		"vehicle_connected", v.VehicleConnected, "contactor_closed", v.ContactorClosed,
		"grid_v", v.GridV, "grid_hz", v.GridHz, "current_a", v.VehicleCurrentA,
		"handle_temp_c", v.HandleTempC, "pcba_temp_c", v.PCBATempC, "mcu_temp_c", v.MCUTempC,
		"session_energy_wh", v.SessionEnergyWh, "lifetime_energy_wh", s.Lifetime.EnergyWh,
		"firmware", s.Version.FirmwareVersion,
	}
	for ep, rep := range s.Reports {
		if !rep.Clean() {
			attrs = append(attrs, string(ep)+"_unknown", rep.Unknown, string(ep)+"_missing", rep.Missing,
				string(ep)+"_invalid", len(rep.Invalid))
		}
	}
	log.Info("polled wall connector", attrs...)
	for _, ev := range events {
		log.Warn("device event", "kind", ev.Kind, "details", ev.Details)
	}
}
