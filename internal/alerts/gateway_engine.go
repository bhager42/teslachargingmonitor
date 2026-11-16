// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package alerts

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// RunGateways processes Gateway poll updates until the channel closes or
// ctx ends.
func (e *Engine) RunGateways(ctx context.Context, updates <-chan poller.GatewayUpdate) {
	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-updates:
			if !ok {
				return
			}
			if _, err := e.ProcessGateway(ctx, u); err != nil && ctx.Err() == nil {
				e.log.Error("evaluating gateway alert rules", "gateway_id", u.Gateway.ID, "err", err)
			}
		}
	}
}

// ProcessGateway evaluates every enabled Gateway rule for one Gateway poll
// update; see Process. Gateway rules use the all-devices configuration.
func (e *Engine) ProcessGateway(ctx context.Context, u poller.GatewayUpdate) ([]Notification, error) {
	cfgs, err := e.Configs(ctx, 0)
	if err != nil {
		return nil, err
	}
	snoozes, err := e.st.ActiveGatewaySnoozes(ctx, u.Gateway.ID, u.At)
	if err != nil {
		return nil, err
	}
	in := Input{At: u.At, Err: u.Err, Gateway: u.Gateway, GatewaySnap: u.Snapshot, GatewayEvents: u.Events}
	return e.evaluate(ctx, SubjectGateway, subject{gateway: u.Gateway.ID, name: u.Gateway.Name}, cfgs, snoozes, in)
}

// ActiveGateway returns the firing Gateway rules, most severe first.
func (e *Engine) ActiveGateway(gatewayID int64) []ActiveAlert {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []ActiveAlert
	for _, def := range definitions {
		st, ok := e.states[stateKey{def.Key, 0, gatewayID}]
		if !ok || st.Status != StatusFiring {
			continue
		}
		out = append(out, ActiveAlert{RuleKey: def.Key, Title: def.Title, Severity: st.Severity, Since: st.BreachStart,
			Notified: st.Notified})
	}
	slices.SortStableFunc(out, func(a, b ActiveAlert) int { return int(b.Severity) - int(a.Severity) })
	return out
}

// PreviewGateway replays a Gateway's stored readings in [from, to) through
// one Gateway rule with a fresh state, like Preview. Failed polls are not
// stored as readings, so gateway_unreachable, gateway_auth_failed and
// gateway_cert_changed cannot be previewed.
func (e *Engine) PreviewGateway(ctx context.Context, g store.Gateway, ruleKey string, cfg Config, from, to time.Time) ([]PreviewEvent, error) {
	def, ok := Lookup(ruleKey)
	if !ok || def.Subject != SubjectGateway {
		return nil, ErrUnknownRule
	}
	merged := def.DefaultConfig()
	maps.Copy(merged.Params, cfg.Params)
	cfg.Params = merged.Params
	if cfg.MinSamples < 1 {
		cfg.MinSamples = 1
	}
	if err := def.Validate(cfg); err != nil {
		return nil, err
	}
	hist, err := e.st.GatewayHistory(ctx, g.ID, from, to)
	if err != nil {
		return nil, err
	}
	st := newState()
	var out []PreviewEvent
	for _, h := range hist {
		in := Input{At: h.Snapshot.FetchedAt, Gateway: g, GatewaySnap: h.Snapshot, GatewayEvents: h.Events}
		for _, n := range step(def, cfg, in, st, false) {
			out = append(out, PreviewEvent{At: in.At, Kind: n.kind, Severity: n.sev, Message: n.msg, Notified: n.notify})
		}
	}
	return out, nil
}
