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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// Status of a condition rule for one device.
type Status string

// Statuses.
const (
	StatusOK      Status = "ok"
	StatusPending Status = "pending" // breaching, waiting for "for"/min samples
	StatusFiring  Status = "firing"
)

// State is the persisted per-(rule, device) state.
type State struct {
	Status      Status             `json:"status"`
	Severity    Severity           `json:"severity"`
	BreachStart time.Time          `json:"breach_start,omitzero"`
	GapOK       bool               `json:"gap_ok,omitempty"`
	Samples     int                `json:"samples,omitempty"`
	Notified    bool               `json:"notified,omitempty"` // firing notice sent this episode
	LastNotify  time.Time          `json:"last_notify,omitzero"`
	LastSample  time.Time          `json:"last_sample,omitzero"`
	Counter     int                `json:"counter,omitempty"`
	Baseline    map[string]float64 `json:"baseline,omitempty"`
}

func newState() *State { return &State{Status: StatusOK} }

// current is the severity hysteresis should compare against.
func (s *State) current() Severity {
	if s.Status == StatusFiring {
		return s.Severity
	}
	return None
}

func (s *State) setBaseline(k string, v float64) {
	if s.Baseline == nil {
		s.Baseline = map[string]float64{}
	}
	s.Baseline[k] = v
}

// Notice kinds.
const (
	KindFiring    = "firing"
	KindEscalated = "escalated"
	KindRepeat    = "repeat"
	KindResolved  = "resolved"
	KindEvent     = "event"
)

// KindLabel names a notice kind for display; unknown kinds are returned as is.
func KindLabel(kind string) string {
	switch kind {
	case KindFiring:
		return tr.T("alert_kind.firing")
	case KindEscalated:
		return tr.T("alert_kind.escalated")
	case KindRepeat:
		return tr.T("alert_kind.repeat")
	case KindResolved:
		return tr.T("alert_kind.resolved")
	case KindEvent:
		return tr.T("alert_kind.event")
	}
	return kind
}

// Notification is an alert event that should be delivered to channels.
type Notification struct {
	EventID    int64
	RuleKey    string
	RuleTitle  string
	DeviceID   int64
	DeviceName string
	Kind       string
	Severity   Severity
	Message    string
	Value      *float64
	At         time.Time
}

type stateKey struct {
	rule   string
	device int64
}

// Engine evaluates rules for every poll update.
type Engine struct {
	st  *store.Store
	log *slog.Logger

	mu     sync.Mutex
	states map[stateKey]*State

	subsMu sync.Mutex
	subs   map[chan []Notification]struct{}
}

// New returns an Engine; call Load before Process.
func New(st *store.Store, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Engine{st: st, log: log, states: map[stateKey]*State{}, subs: map[chan []Notification]struct{}{}}
}

// Load restores rule states persisted by a previous run.
func (e *Engine) Load(ctx context.Context) error {
	rows, err := e.st.AlertStates(ctx)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range rows {
		s := newState()
		if err := json.Unmarshal(r.JSON, s); err != nil {
			e.log.Warn("discarding unreadable alert state", "rule", r.RuleKey, "device_id", r.DeviceID, "err", err)
			continue
		}
		e.states[stateKey{r.RuleKey, r.DeviceID}] = s
	}
	return nil
}

// Subscribe receives each poll's notifications as one batch (so channels
// can send a single email per poll). Slow subscribers miss batches.
func (e *Engine) Subscribe(buffer int) (<-chan []Notification, func()) {
	ch := make(chan []Notification, buffer)
	e.subsMu.Lock()
	e.subs[ch] = struct{}{}
	e.subsMu.Unlock()
	return ch, func() {
		e.subsMu.Lock()
		defer e.subsMu.Unlock()
		if _, ok := e.subs[ch]; ok {
			delete(e.subs, ch)
			close(ch)
		}
	}
}

func (e *Engine) publish(batch []Notification) {
	e.subsMu.Lock()
	defer e.subsMu.Unlock()
	for ch := range e.subs {
		select {
		case ch <- batch:
		default:
			e.log.Warn("dropping alert batch for slow subscriber", "notifications", len(batch))
		}
	}
}

// Configs returns every rule's effective configuration for a device:
// defaults, then all-device overrides, then device-specific overrides.
func (e *Engine) Configs(ctx context.Context, deviceID int64) (map[string]Config, error) {
	overrides, err := e.st.RuleOverrides(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]Config{}
	for _, d := range definitions {
		out[d.Key] = d.DefaultConfig()
	}
	scopes := []int64{0}
	if deviceID != 0 {
		scopes = append(scopes, deviceID)
	}
	for _, scope := range scopes {
		for _, o := range overrides {
			def, ok := Lookup(o.RuleKey)
			if !ok || o.DeviceID != scope {
				continue
			}
			c := out[o.RuleKey]
			c.Enabled, c.For, c.Cooldown, c.Repeat = o.Enabled, o.For, o.Cooldown, o.Repeat
			c.MinSamples, c.NotifyResolved = o.MinSamples, o.NotifyResolved
			c.Params = maps.Clone(c.Params)
			maps.Copy(c.Params, o.Params)
			if err := def.Validate(c); err != nil {
				e.log.Warn("ignoring invalid rule override", "rule", o.RuleKey, "device_id", o.DeviceID, "err", err)
				continue
			}
			out[o.RuleKey] = c
		}
	}
	return out, nil
}

// SetConfig validates and stores a rule override (deviceID 0 = all devices).
func (e *Engine) SetConfig(ctx context.Context, ruleKey string, deviceID int64, c Config, now time.Time) error {
	def, ok := Lookup(ruleKey)
	if !ok {
		return fmt.Errorf("alerts: unknown rule %q", ruleKey)
	}
	merged := def.DefaultConfig()
	maps.Copy(merged.Params, c.Params)
	c.Params = merged.Params
	if err := def.Validate(c); err != nil {
		return err
	}
	return e.st.SaveRuleOverride(ctx, store.RuleOverride{
		RuleKey: ruleKey, DeviceID: deviceID, Enabled: c.Enabled, Params: c.Params, For: c.For,
		Cooldown: c.Cooldown, Repeat: c.Repeat, MinSamples: c.MinSamples, NotifyResolved: c.NotifyResolved,
	}, now)
}

// Run processes poller updates until the channel closes or ctx ends.
func (e *Engine) Run(ctx context.Context, updates <-chan poller.Update) {
	for {
		select {
		case <-ctx.Done():
			return
		case u, ok := <-updates:
			if !ok {
				return
			}
			if _, err := e.Process(ctx, u); err != nil && ctx.Err() == nil {
				e.log.Error("evaluating alert rules", "device_id", u.Device.ID, "err", err)
			}
		}
	}
}

// Process evaluates every enabled rule for one poll update, persists state
// and history, publishes and returns the notifications to deliver.
func (e *Engine) Process(ctx context.Context, u poller.Update) ([]Notification, error) {
	cfgs, err := e.Configs(ctx, u.Device.ID)
	if err != nil {
		return nil, err
	}
	snoozes, err := e.st.ActiveSnoozes(ctx, u.Device.ID, u.At)
	if err != nil {
		return nil, err
	}
	in := Input{Device: u.Device, At: u.At, Snapshot: u.Snapshot, Err: u.Err, Events: u.Events}

	e.mu.Lock()
	defer e.mu.Unlock()
	var rows []store.AlertStateRow
	var events []store.AlertEvent
	var batch []Notification
	for _, def := range definitions {
		cfg := cfgs[def.Key]
		if !cfg.Enabled {
			continue
		}
		k := stateKey{def.Key, u.Device.ID}
		prev, ok := e.states[k]
		if !ok {
			prev = newState()
		}
		st := cloneState(prev)
		notices := step(def, cfg, in, st, snoozed(snoozes, def.Key))
		for _, n := range notices {
			events = append(events, store.AlertEvent{RuleKey: def.Key, DeviceID: u.Device.ID, TS: u.At, Kind: n.kind,
				Severity: n.sev.String(), Message: n.msg, Value: n.value, Notified: n.notify})
		}
		js, err := json.Marshal(st)
		if err != nil {
			return nil, err
		}
		rows = append(rows, store.AlertStateRow{RuleKey: def.Key, DeviceID: u.Device.ID, JSON: js})
		e.states[k] = st
	}
	if err := e.st.SaveAlertResult(ctx, rows, events, u.At); err != nil {
		return nil, err
	}
	for _, ev := range events {
		def, _ := Lookup(ev.RuleKey)
		sev, _ := ParseSeverity(ev.Severity)
		e.log.Info("alert", "rule", ev.RuleKey, "device", u.Device.Name, "kind", ev.Kind, "severity", ev.Severity,
			"notified", ev.Notified, "message", ev.Message)
		if ev.Notified {
			batch = append(batch, Notification{EventID: ev.ID, RuleKey: ev.RuleKey, RuleTitle: def.Title,
				DeviceID: u.Device.ID, DeviceName: u.Device.Name, Kind: ev.Kind, Severity: sev,
				Message: ev.Message, Value: ev.Value, At: ev.TS})
		}
	}
	if len(batch) > 0 {
		e.publish(batch)
	}
	return batch, nil
}

func cloneState(s *State) *State {
	c := *s
	c.Baseline = maps.Clone(s.Baseline)
	return &c
}

func snoozed(list []store.Snooze, rule string) bool {
	for _, s := range list {
		if s.RuleKey == "" || s.RuleKey == rule {
			return true
		}
	}
	return false
}

type notice struct {
	kind   string
	sev    Severity
	msg    string
	value  *float64
	notify bool // false: recorded in history only (cooldown/snooze)
}

// step advances one rule's state for one poll and returns the notices it
// produced. It is pure apart from mutating st, which makes it easy to test
// and to replay history for previews.
func step(def Definition, cfg Config, in Input, st *State, isSnoozed bool) []notice {
	res := def.Eval(in, cfg.Params, st)
	if res.Skip {
		return nil
	}
	now := in.At
	var out []notice

	if def.Kind == Event {
		for _, h := range res.Hits {
			ok := !isSnoozed && (st.LastNotify.IsZero() || now.Sub(st.LastNotify) >= cfg.Cooldown)
			if ok {
				st.LastNotify = now
			}
			out = append(out, notice{KindEvent, def.EventSeverity, h.Message, h.Value, ok})
		}
		st.LastSample = now
		return out
	}

	gap := now.Sub(st.LastSample)
	firstSample := st.LastSample.IsZero()
	st.LastSample = now

	if res.Severity == None {
		if st.Status == StatusFiring && cfg.NotifyResolved && st.Notified {
			out = append(out, notice{KindResolved, st.Severity, def.Title + " resolved. " + res.Message, res.Value, !isSnoozed})
		}
		counter, baseline := st.Counter, st.Baseline
		*st = State{Status: StatusOK, LastSample: now, LastNotify: st.LastNotify, Counter: counter, Baseline: baseline}
		return out
	}

	canFire := func() bool {
		return !isSnoozed && (st.LastNotify.IsZero() || now.Sub(st.LastNotify) >= cfg.Cooldown)
	}

	switch st.Status {
	case StatusOK, "":
		st.Status, st.BreachStart, st.Samples = StatusPending, now, 0
		// With sampling slower than "for", one breaching sample is enough.
		st.GapOK = firstSample || gap >= cfg.For
		fallthrough
	case StatusPending:
		st.Samples++
		if st.Samples < cfg.MinSamples || (now.Sub(st.BreachStart) < cfg.For && !st.GapOK) {
			return out
		}
		st.Status, st.Severity, st.Notified = StatusFiring, res.Severity, false
		n := notice{KindFiring, res.Severity, res.Message, res.Value, canFire()}
		if n.notify {
			st.Notified, st.LastNotify = true, now
		}
		out = append(out, n)
	case StatusFiring:
		switch {
		case res.Severity > st.Severity:
			st.Severity = res.Severity
			n := notice{KindEscalated, res.Severity, res.Message, res.Value, !isSnoozed}
			if n.notify {
				st.Notified, st.LastNotify = true, now
			}
			out = append(out, n)
		case !st.Notified && canFire():
			// Firing notice was held back by cooldown or snooze; send it now.
			st.Severity = res.Severity
			st.Notified, st.LastNotify = true, now
			out = append(out, notice{KindFiring, res.Severity, res.Message, res.Value, true})
		case st.Notified && cfg.Repeat > 0 && res.Severity == Critical && now.Sub(st.LastNotify) >= cfg.Repeat:
			st.Severity = res.Severity
			st.LastNotify = now
			out = append(out, notice{KindRepeat, res.Severity, "Still active: " + res.Message, res.Value, !isSnoozed})
		default:
			st.Severity = res.Severity // de-escalation is silent
		}
	}
	return out
}

// PreviewEvent is a notice a rule would have produced in the past.
type PreviewEvent struct {
	At       time.Time
	Kind     string
	Severity Severity
	Message  string
	Notified bool
}

// ErrUnknownRule is returned for rule keys that do not exist.
var ErrUnknownRule = errors.New("alerts: unknown rule")

// Preview replays stored polls in [from, to) through one rule with the
// given configuration and a fresh state ("Test rule against last 24 h").
// Failed polls are not stored as readings, so device_unreachable cannot be
// previewed.
func (e *Engine) Preview(ctx context.Context, device store.Device, ruleKey string, cfg Config, from, to time.Time) ([]PreviewEvent, error) {
	def, ok := Lookup(ruleKey)
	if !ok {
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
	hist, err := e.st.History(ctx, device.ID, from, to)
	if err != nil {
		return nil, err
	}
	st := newState()
	var out []PreviewEvent
	for _, h := range hist {
		in := Input{Device: device, At: h.Snapshot.FetchedAt, Snapshot: h.Snapshot, Events: h.Events}
		for _, n := range step(def, cfg, in, st, false) {
			out = append(out, PreviewEvent{At: in.At, Kind: n.kind, Severity: n.sev, Message: n.msg, Notified: n.notify})
		}
	}
	return out, nil
}

// ActiveAlert is a condition rule currently firing for a device.
type ActiveAlert struct {
	RuleKey  string
	Title    string
	Severity Severity
	Since    time.Time
	Notified bool
}

// Active returns the firing condition rules for a device, most severe first.
func (e *Engine) Active(deviceID int64) []ActiveAlert {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []ActiveAlert
	for _, def := range definitions {
		st, ok := e.states[stateKey{def.Key, deviceID}]
		if !ok || st.Status != StatusFiring {
			continue
		}
		out = append(out, ActiveAlert{RuleKey: def.Key, Title: def.Title, Severity: st.Severity, Since: st.BreachStart,
			Notified: st.Notified})
	}
	slices.SortStableFunc(out, func(a, b ActiveAlert) int { return int(b.Severity) - int(a.Severity) })
	return out
}
