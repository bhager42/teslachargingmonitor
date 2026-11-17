// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package poller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strconv"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// ErrGatewayConfig wraps problems with a Gateway's stored settings that
// stop it from being polled at all (no key, an undecryptable password).
var ErrGatewayConfig = errors.New("poller: gateway settings unusable")

// ErrNoBox is reported for a Gateway when the poller has no credential box
// to decrypt its password.
var ErrNoBox = fmt.Errorf("%w: no credential key to decrypt the Gateway password", ErrGatewayConfig)

// gatewayInfoEvery is how often the slowly changing site description
// (/api/site_info, /api/solars) is refreshed.
const gatewayInfoEvery = 24 * time.Hour

// GatewayUpdate is published after every Gateway poll (successful or
// finally failed). Gateway never carries the sealed password.
type GatewayUpdate struct {
	Gateway  store.Gateway
	Snapshot *gateway.Snapshot // nil when Err != nil
	// Err is set when the poll failed. It may be a *gateway.BackoffError
	// (login rejected or rate limited) or a *gateway.CertError (polling
	// stopped until the owner accepts the new certificate).
	Err      error
	Events   []store.GatewayEvent
	Attempts int
	At       time.Time
	Next     time.Time // zero when polling stopped
}

type gwWorker struct {
	gw      store.Gateway
	cancel  context.CancelFunc
	done    chan struct{}
	trigger chan struct{}
	lastNow time.Time
}

// SubscribeGateways returns a channel of Gateway updates; see Subscribe.
func (m *Manager) SubscribeGateways(buffer int) (<-chan GatewayUpdate, func()) {
	ch := make(chan GatewayUpdate, buffer)
	m.subsMu.Lock()
	m.gwSubs[ch] = struct{}{}
	m.subsMu.Unlock()
	return ch, func() {
		m.subsMu.Lock()
		defer m.subsMu.Unlock()
		if _, ok := m.gwSubs[ch]; ok {
			delete(m.gwSubs, ch)
			close(ch)
		}
	}
}

func (m *Manager) publishGateway(u GatewayUpdate) {
	u.Gateway.PasswordEnc = nil
	m.subsMu.Lock()
	defer m.subsMu.Unlock()
	for ch := range m.gwSubs {
		select {
		case ch <- u:
		default:
			m.cfg.Logger.Warn("dropping gateway update for slow subscriber", "gateway_id", u.Gateway.ID)
		}
	}
}

// syncGatewaysLocked starts, stops or restarts Gateway workers to match the
// stored Gateways. m.mu must be held.
func (m *Manager) syncGatewaysLocked(ctx context.Context, gws []store.Gateway) {
	want := map[int64]store.Gateway{}
	for _, g := range gws {
		if g.Enabled {
			want[g.ID] = g
		}
	}
	for id, w := range m.gwWorkers {
		if g, ok := want[id]; !ok || !g.UpdatedAt.Equal(w.gw.UpdatedAt) {
			m.stopGatewayLocked(id)
		}
	}
	for id, g := range want {
		if _, running := m.gwWorkers[id]; running {
			continue
		}
		parent := m.runCtx
		if parent == nil {
			parent = context.WithoutCancel(ctx) // as in Sync
		}
		wctx, cancel := context.WithCancel(parent)
		w := &gwWorker{gw: g, cancel: cancel, done: make(chan struct{}), trigger: make(chan struct{}, 1)}
		m.gwWorkers[id] = w
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			defer close(w.done)
			m.runGatewayWorker(wctx, w)
		}()
		m.cfg.Logger.Info("polling gateway", "gateway_id", g.ID, "name", g.Name, "address", g.Address,
			"interval", g.PollInterval, "charging_interval", g.ChargingInterval)
	}
}

func (m *Manager) stopGatewayLocked(id int64) {
	w := m.gwWorkers[id]
	delete(m.gwWorkers, id)
	w.cancel()
	<-w.done
}

// Gateways returns the IDs of the Gateways currently being polled.
func (m *Manager) Gateways() []int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]int64, 0, len(m.gwWorkers))
	for id := range m.gwWorkers {
		ids = append(ids, id)
	}
	return ids
}

// PollGatewayNow asks a Gateway's worker to poll immediately. A login
// back-off still applies: the poll then fails without a login attempt.
func (m *Manager) PollGatewayNow(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	w, ok := m.gwWorkers[id]
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

func (m *Manager) runGatewayWorker(ctx context.Context, w *gwWorker) {
	g := w.gw
	log := m.cfg.Logger.With("gateway_id", g.ID, "gateway", g.Name)
	stopped := func(err error) {
		m.publishGateway(GatewayUpdate{Gateway: g, Err: err, At: m.cfg.Now()})
	}
	if g.PendingPin != "" {
		// Polling resumes when the owner accepts the new certificate, which
		// changes updated_at and restarts this worker.
		log.Warn("gateway certificate changed; not polling until the owner confirms it")
		stopped(&gateway.CertError{Fingerprint: g.PendingPin})
		return
	}
	if m.cfg.Box == nil {
		log.Error("cannot decrypt the gateway password; not polling", "err", ErrNoBox)
		stopped(ErrNoBox)
		return
	}
	pw, err := g.Password(m.cfg.Box)
	if err != nil {
		log.Error("cannot decrypt the gateway password; enter it again", "err", err)
		stopped(fmt.Errorf("%w: %w", ErrGatewayConfig, err))
		return
	}
	opts := m.cfg.Gateway
	opts.Pin, opts.Password, opts.AllowNonLAN, opts.Now = g.Pin, pw, g.AllowNonLAN, m.cfg.Now
	if opts.UserAgent == "" {
		opts.UserAgent = m.cfg.UserAgent
	}
	client, err := gateway.NewClient(g.Address, opts)
	if err != nil {
		log.Error("invalid gateway settings; not polling", "err", err)
		stopped(fmt.Errorf("%w: %w", ErrGatewayConfig, err))
		return
	}
	defer client.Close()
	client.RestoreBackoff(g.Backoff)

	state, err := m.st.LatestGatewayState(ctx, g.ID)
	if err != nil {
		log.Error("loading previous gateway state", "err", err)
	}
	gp := &gwPoll{m: m, w: w, client: client, log: log, saved: g.Backoff}
	for {
		var stop bool
		state, stop = gp.pollOnce(ctx, state)
		if stop || ctx.Err() != nil {
			return
		}
		timer := time.NewTimer(m.gatewayInterval(ctx, g))
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

// gatewayInterval is the charging cadence while any Wall Connector reports
// a car plugged in, otherwise the normal interval, with ±2 % jitter.
func (m *Manager) gatewayInterval(ctx context.Context, g store.Gateway) time.Duration {
	if m.cfg.IntervalOverride > 0 {
		return m.cfg.IntervalOverride
	}
	base := g.PollInterval
	if plugged, err := m.st.AnyVehiclePlugged(ctx); err == nil && plugged {
		base = g.ChargingInterval
	}
	j := min(time.Duration(float64(base)*0.02), m.cfg.MaxJitter)
	if j <= 0 {
		return base
	}
	return base - j + time.Duration(rand.Int64N(int64(2*j)+1)) //nolint:gosec // scheduling jitter, not security
}

type gwPoll struct {
	m      *Manager
	w      *gwWorker
	client *gateway.Client
	log    *slog.Logger
	saved  gateway.Backoff // last back-off written to the store
	info   *gateway.Info
	infoAt time.Time
}

// retryable reports whether a failed poll is worth retrying soon. Login
// problems and certificate changes are not: retrying them is exactly what
// the back-off and the pin exist to prevent.
func retryable(err error) bool {
	var be *gateway.BackoffError
	return !errors.As(err, &be) && !errors.Is(err, gateway.ErrCertChanged) &&
		!errors.Is(err, gateway.ErrNotAuthorized) && !errors.Is(err, ErrGatewayConfig)
}

// persistBackoff writes the client's back-off when it changed, so a restart
// keeps it.
func (p *gwPoll) persistBackoff(ctx context.Context) {
	b := p.client.Backoff()
	if b == p.saved {
		return
	}
	if err := p.m.st.SetGatewayBackoff(ctx, p.w.gw.ID, b); err != nil {
		p.log.Error("saving login back-off", "err", err)
		return
	}
	p.saved = b
}

// pollOnce polls with retries, stores the outcome and publishes an update.
// stop is true when polling must stop (certificate changed).
func (p *gwPoll) pollOnce(ctx context.Context, prev store.GatewayState) (store.GatewayState, bool) {
	m, g := p.m, p.w.gw
	var lastErr error
	attempts := 0
	for attempt := 1; ; attempt++ {
		attempts = attempt
		start := m.cfg.Now()
		snap, err := p.client.Snapshot(ctx)
		if err == nil && (p.info == nil || start.Sub(p.infoAt) >= gatewayInfoEvery) {
			if in, ierr := p.client.Info(ctx); ierr == nil {
				p.info, p.infoAt = in, start
			} else if ctx.Err() == nil {
				p.log.Warn("reading gateway site info", "err", ierr)
			}
		}
		took := m.cfg.Now().Sub(start)
		p.persistBackoff(ctx)
		if ctx.Err() != nil {
			return prev, true
		}
		if err == nil {
			snap.FetchedAt = start
			events := detectGatewayEvents(prev, snap)
			var info *gateway.Info
			if p.infoAt.Equal(start) {
				info = p.info
			}
			if serr := m.st.SaveGatewaySnapshot(ctx, g.ID, snap, info, events, attempt, took); serr != nil {
				p.log.Error("saving gateway poll", "err", serr)
			}
			next := nextGatewayState(prev, snap)
			logGatewayReading(p.log, snap, events, attempt, took)
			m.publishGateway(GatewayUpdate{Gateway: g, Snapshot: snap, Events: events, Attempts: attempt,
				At: start, Next: start.Add(m.gatewayInterval(ctx, g))})
			return next, false
		}
		lastErr = err
		if lerr := m.st.RecordGatewayPollFailure(ctx, g.ID, start, attempt, took, err); lerr != nil && ctx.Err() == nil {
			p.log.Error("recording gateway poll failure", "err", lerr)
		}
		var ce *gateway.CertError
		if errors.As(err, &ce) {
			p.certChanged(ctx, ce)
			return prev, true
		}
		if !retryable(err) || attempt > len(m.cfg.RetryDelays) {
			break
		}
		delay := m.cfg.RetryDelays[attempt-1]
		p.log.Warn("gateway poll failed; will retry", "attempt", attempt, "retry_in", delay, "err", err)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return prev, true
		case <-timer.C:
		case <-p.w.trigger:
			timer.Stop()
		}
	}
	now := m.cfg.Now()
	var be *gateway.BackoffError
	if errors.As(lastErr, &be) {
		p.log.Error("gateway login suspended", "until", be.Until, "err", lastErr)
	} else {
		p.log.Error("gateway unreachable", "attempts", attempts, "err", lastErr)
	}
	m.publishGateway(GatewayUpdate{Gateway: g, Err: lastErr, Attempts: attempts, At: now,
		Next: now.Add(m.gatewayInterval(ctx, g))})
	return prev, false
}

func (p *gwPoll) certChanged(ctx context.Context, ce *gateway.CertError) {
	m, g := p.m, p.w.gw
	now := m.cfg.Now()
	p.log.Error("gateway certificate changed; polling stopped until the owner confirms the new fingerprint",
		"fingerprint", ce.Fingerprint)
	if err := m.st.SetGatewayPendingPin(ctx, g.ID, ce.Fingerprint); err != nil {
		p.log.Error("saving the new certificate fingerprint", "err", err)
	}
	ev := store.GatewayEvent{TS: now, Kind: store.GatewayEventCertChanged,
		Details: map[string]string{"fingerprint": ce.Fingerprint}}
	if err := m.st.RecordGatewayEvent(ctx, g.ID, ev); err != nil {
		p.log.Error("recording gateway event", "err", err)
	}
	m.publishGateway(GatewayUpdate{Gateway: g, Err: ce, Events: []store.GatewayEvent{ev}, Attempts: 1, At: now})
}

// detectGatewayEvents compares a poll with the remembered state. Fields
// the decoder flagged never produce events.
func detectGatewayEvents(prev store.GatewayState, s *gateway.Snapshot) []store.GatewayEvent {
	var out []store.GatewayEvent
	add := func(kind string, details map[string]string) {
		out = append(out, store.GatewayEvent{TS: s.FetchedAt, Kind: kind, Details: details})
	}
	st, rep := s.Status, s.Reports[gateway.EndpointStatus]
	if info := prev.Info; info != nil {
		if fw := st.Firmware(); fw != "" && !rep.Untrusted("version") && info.FirmwareVersion != "" && fw != info.FirmwareVersion {
			add(store.GatewayEventFirmwareChanged, map[string]string{"from": info.FirmwareVersion, "to": fw})
		}
		if up, err := st.Uptime(); err == nil && !rep.Untrusted("up_time_seconds") && info.HasUptime &&
			int64(up/time.Second) < info.UptimeS {
			add(store.GatewayEventReboot, map[string]string{
				"previous_uptime_s": strconv.FormatInt(info.UptimeS, 10),
				"uptime_s":          strconv.FormatInt(int64(up/time.Second), 10),
			})
		}
	}
	gs, grep := s.GridStatus.GridStatus, s.Reports[gateway.EndpointGridStatus]
	if prev.GridStatus != "" && gs != "" && !grep.Untrusted("grid_status") && gs != prev.GridStatus {
		add(store.GatewayEventGridChanged, map[string]string{"from": prev.GridStatus, "to": gs})
	}
	return out
}

// nextGatewayState is the state remembered after a successful poll.
func nextGatewayState(prev store.GatewayState, s *gateway.Snapshot) store.GatewayState {
	next := store.GatewayState{LastSuccess: s.FetchedAt, GridStatus: prev.GridStatus}
	if gs := s.GridStatus.GridStatus; gs != "" && !s.Reports[gateway.EndpointGridStatus].Untrusted("grid_status") {
		next.GridStatus = gs
	}
	info := store.GatewayInfo{}
	if prev.Info != nil {
		info = *prev.Info
	}
	rep := s.Reports[gateway.EndpointStatus]
	if fw := s.Status.Firmware(); fw != "" && !rep.Untrusted("version") {
		if fw != info.FirmwareVersion {
			info.FirmwareSince = s.FetchedAt
		}
		info.FirmwareVersion = fw
	}
	if up, err := s.Status.Uptime(); err == nil && !rep.Untrusted("up_time_seconds") {
		info.UptimeS, info.HasUptime = int64(up/time.Second), true
	}
	next.Info = &info
	return next
}

func logGatewayReading(log *slog.Logger, s *gateway.Snapshot, events []store.GatewayEvent, attempt int, took time.Duration) {
	a := s.Aggregates
	attrs := []any{
		"attempt", attempt, "took", took.Round(time.Millisecond).String(),
		"solar_w", a.Solar.InstantPower, "load_w", a.Load.InstantPower, "site_w", a.Site.InstantPower,
		"battery_w", a.Battery.InstantPower, "battery_pct", s.SOE.AppPercent(),
		"grid", s.GridStatus.GridStatus, "firmware", s.Status.Firmware(),
	}
	for ep, rep := range s.Reports {
		if !rep.Clean() {
			attrs = append(attrs, string(ep)+"_unknown", rep.Unknown, string(ep)+"_missing", rep.Missing,
				string(ep)+"_invalid", len(rep.Invalid))
		}
	}
	log.Info("polled gateway", attrs...)
	for _, ev := range events {
		log.Warn("gateway event", "kind", ev.Kind, "details", ev.Details)
	}
}
