// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package alerts

import (
	"errors"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// Backup Gateway rules (Phase 9, plan "Alert rules"). They run on Gateway
// polls only (Subject = SubjectGateway) and read the Gateway fields of
// Input; Wall Connector rules never see a Gateway poll.

// gw reports whether field of Gateway endpoint ep decoded cleanly.
func (in Input) gw(ep gateway.Endpoint, field string) bool {
	return in.GatewaySnap != nil && !in.GatewaySnap.Reports[ep].Untrusted(field)
}

func (in Input) loc() *time.Location {
	if in.Loc != nil {
		return in.Loc
	}
	return time.Local
}

// islanded reports whether the Gateway trustworthily reports no grid.
func (in Input) islanded() bool {
	return in.gw(gateway.EndpointGridStatus, "grid_status") && !in.GatewaySnap.GridStatus.OnGrid()
}

// loginOrCertError reports whether a failed Gateway poll reached the
// Gateway but was stopped by the login back-off or a certificate change.
func loginOrCertError(err error) bool {
	var be *gateway.BackoffError
	return errors.As(err, &be) || errors.Is(err, gateway.ErrCertChanged)
}

func gatewayEventRule(key, title, desc, kind string, sev Severity, format func(store.GatewayEvent) string) Definition {
	return Definition{
		Key: key, Title: title, Description: desc,
		Subject: SubjectGateway, Kind: Event, EventSeverity: sev, Defaults: event(true),
		Eval: func(in Input, _ Params, _ *State) Result {
			var r Result
			for _, ev := range in.GatewayEvents {
				if ev.Kind == kind {
					r.Hits = append(r.Hits, Hit{Message: format(ev)})
				}
			}
			return r
		},
	}
}

// dayNumber identifies t's local calendar day (days since 1970-01-01).
func dayNumber(t time.Time, loc *time.Location) float64 {
	y, m, d := t.In(loc).Date()
	return float64(time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Unix() / 86400)
}

// productionHistory is how many past days solar_production_low keeps; at
// least minProductionDays are needed before it compares.
const (
	productionHistory = 14
	minProductionDays = 7
)

func median(v []float64) float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

var gatewayDefinitions = []Definition{
	{
		Key: "gateway_unreachable", Title: tr.T("alert_rule.gateway_unreachable.title"), Kind: Condition,
		Subject:     SubjectGateway,
		Description: tr.T("alert_rule.gateway_unreachable.desc"),
		Params:      []ParamSpec{{"critical_after", tr.T("alert_param.critical_after"), tr.T("alert_param.unit_polls"), 1, 100, 3}},
		Defaults:    cond(true, 0, 1, criticalRepeat),
		Eval: func(in Input, p Params, st *State) Result {
			switch {
			case in.Err == nil, loginOrCertError(in.Err):
				// It answered: a login or certificate problem has its own rule.
				st.Counter = 0
				return Result{}
			case errors.Is(in.Err, poller.ErrGatewayConfig):
				return Result{Skip: true} // not polled at all; see gateway_auth_failed
			}
			st.Counter++
			sev := Warning
			if float64(st.Counter) >= p["critical_after"] {
				sev = Critical
			}
			return Result{Severity: sev, Value: f(float64(st.Counter)),
				Message: tr.T("alert_rule.gateway_unreachable.message", "address", in.Gateway.Address, "count", st.Counter)}
		},
	},
	{
		Key: "gateway_auth_failed", Title: tr.T("alert_rule.gateway_auth_failed.title"), Kind: Condition,
		Subject:     SubjectGateway,
		Description: tr.T("alert_rule.gateway_auth_failed.desc"),
		Defaults:    cond(true, 0, 1, 24*time.Hour),
		Eval: func(in Input, _ Params, _ *State) Result {
			var be *gateway.BackoffError
			switch {
			case in.Err == nil:
				return Result{}
			case errors.Is(in.Err, poller.ErrGatewayConfig):
				return Result{Severity: Critical, Message: tr.T("alert_rule.gateway_auth_failed.message_config")}
			case !errors.As(in.Err, &be):
				return Result{Skip: true}
			}
			key := "alert_rule.gateway_auth_failed.message"
			if errors.Is(be.Cause, gateway.ErrRateLimited) {
				key = "alert_rule.gateway_auth_failed.message_rate_limited"
			}
			return Result{Severity: Critical,
				Message: tr.T(key, "until", be.Until.In(in.loc()).Format("Mon 2 Jan 15:04"))}
		},
	},
	{
		Key: "gateway_cert_changed", Title: tr.T("alert_rule.gateway_cert_changed.title"), Kind: Condition,
		Subject:     SubjectGateway,
		Description: tr.T("alert_rule.gateway_cert_changed.desc"),
		Defaults:    cond(true, 0, 1, 24*time.Hour),
		Eval: func(in Input, _ Params, _ *State) Result {
			var ce *gateway.CertError
			switch {
			case in.Err == nil:
				return Result{}
			case !errors.As(in.Err, &ce):
				return Result{Skip: true}
			}
			return Result{Severity: Critical, Message: tr.T("alert_rule.gateway_cert_changed.message",
				"fingerprint", ce.Fingerprint, "id", in.Gateway.ID)}
		},
	},
	{
		Key: "grid_outage", Title: tr.T("alert_rule.grid_outage.title"), Kind: Condition,
		Subject:     SubjectGateway,
		Description: tr.T("alert_rule.grid_outage.desc"),
		Defaults:    cond(true, 0, 1, 0),
		Eval: func(in Input, _ Params, _ *State) Result {
			if !in.gw(gateway.EndpointGridStatus, "grid_status") {
				return Result{Skip: true}
			}
			s := in.GatewaySnap
			if s.GridStatus.OnGrid() {
				return Result{Message: tr.T("alert_rule.grid_outage.message_restored")}
			}
			if in.gw(gateway.EndpointSOE, "percentage") {
				pct := s.SOE.AppPercent()
				return Result{Severity: Warning, Value: f(pct), Message: tr.T("alert_rule.grid_outage.message",
					"status", s.GridStatus.GridStatus, "pct", num(pct, 0))}
			}
			return Result{Severity: Warning, Message: tr.T("alert_rule.grid_outage.message_no_battery",
				"status", s.GridStatus.GridStatus)}
		},
	},
	{
		Key: "battery_low", Title: tr.T("alert_rule.battery_low.title"), Kind: Condition,
		Subject:     SubjectGateway,
		Description: tr.T("alert_rule.battery_low.desc"),
		Params: []ParamSpec{
			{"pct", tr.T("alert_param.below"), "%", 1, 99, 20},
			{"hysteresis_pct", tr.T("alert_param.hysteresis"), "%", 0, 20, 2},
		},
		Defaults: cond(true, 0, 2, 0),
		Eval: func(in Input, p Params, st *State) Result {
			if !in.gw(gateway.EndpointSOE, "percentage") {
				return Result{Skip: true}
			}
			pct := in.GatewaySnap.SOE.AppPercent()
			// Lowness grows as the level falls: compare negated values.
			if levels(-pct, -p["pct"], 0, p["hysteresis_pct"], st.current()) == None {
				return Result{Value: f(pct), Message: tr.T("alert_rule.battery_low.message_ok", "pct", num(pct, 0))}
			}
			if in.islanded() {
				return Result{Severity: Warning, Value: f(pct),
					Message: tr.T("alert_rule.battery_low.message_islanded", "pct", num(pct, 0), "threshold", num(p["pct"], 0))}
			}
			return Result{Severity: Info, Value: f(pct),
				Message: tr.T("alert_rule.battery_low.message", "pct", num(pct, 0), "threshold", num(p["pct"], 0))}
		},
	},
	{
		// A fixed window rather than sunrise and sunset, so tcmon needs no
		// location (plan §15.2 S8).
		Key: "solar_zero_daytime", Title: tr.T("alert_rule.solar_zero_daytime.title"), Kind: Condition,
		Subject:     SubjectGateway,
		Description: tr.T("alert_rule.solar_zero_daytime.desc"),
		Params: []ParamSpec{
			{"start_h", tr.T("alert_param.window_from"), tr.T("alert_param.unit_hour"), 0, 23, 10},
			{"end_h", tr.T("alert_param.window_to"), tr.T("alert_param.unit_hour"), 1, 24, 15},
			{"min_w", tr.T("alert_param.below"), "W", 0, 1000, 50},
		},
		// Leaving the window ends the episode, which says nothing about the
		// panels, so no "resolved" notice by default.
		Defaults: Config{Enabled: true, For: 2 * time.Hour, MinSamples: 1, Cooldown: defaultCooldown},
		Eval: func(in Input, p Params, _ *State) Result {
			if !in.gw(gateway.EndpointAggregates, "solar.instant_power") {
				return Result{Skip: true}
			}
			lt := in.At.In(in.loc())
			h := float64(lt.Hour()) + float64(lt.Minute())/60
			w := in.GatewaySnap.Aggregates.Solar.InstantPower
			if h < p["start_h"] || h >= p["end_h"] || w >= p["min_w"] {
				return Result{Value: f(w)}
			}
			return Result{Severity: Warning, Value: f(w), Message: tr.T("alert_rule.solar_zero_daytime.message",
				"watts", num(w, 0), "from", num(p["start_h"], 0), "to", num(p["end_h"], 0))}
		},
	},
	{
		// Evaluated once a day, on the first poll after midnight, from the
		// solar meter's lifetime counter; the daily totals live in the
		// rule's state so Preview can replay them.
		Key: "solar_production_low", Title: tr.T("alert_rule.solar_production_low.title"), Kind: Event,
		EventSeverity: Info, Subject: SubjectGateway,
		Description: tr.T("alert_rule.solar_production_low.desc"),
		Params:      []ParamSpec{{"pct", tr.T("alert_param.below_median"), "%", 1, 99, 30}},
		Defaults:    event(false),
		Eval: func(in Input, p Params, st *State) Result {
			if !in.gw(gateway.EndpointAggregates, "solar.energy_exported") {
				return Result{Skip: true}
			}
			v := in.GatewaySnap.Aggregates.Solar.EnergyExported
			day := dayNumber(in.At, in.loc())
			b := st.Baseline
			cur, seen := b["day"]
			switch {
			case !seen:
				st.setBaseline("day", day)
				st.setBaseline("start", v)
				st.setBaseline("last", v)
				st.setBaseline("partial", 1) // tcmon started during this day
				return Result{}
			case v < b["last"]: // counter reset: today's total is unknowable
				st.setBaseline("start", v)
				st.setBaseline("last", v)
				st.setBaseline("partial", 1)
				return Result{}
			case day == cur:
				st.setBaseline("last", v)
				return Result{}
			}
			// The first poll of a new day closes the previous one.
			prod, partial := b["last"]-b["start"], b["partial"] == 1 || day-cur > 1
			n := int(b["n"])
			hist := make([]float64, 0, productionHistory)
			for i := range n {
				hist = append(hist, b["h"+strconv.Itoa(i)])
			}
			st.setBaseline("day", day)
			st.setBaseline("start", b["last"])
			st.setBaseline("last", v)
			st.setBaseline("partial", 0)
			if partial {
				return Result{}
			}
			var r Result
			if len(hist) >= minProductionDays {
				if med := median(hist); med > 0 && prod < med*p["pct"]/100 {
					date := time.Unix(int64(cur)*86400, 0).UTC().Format("Mon 2 Jan")
					r.Hits = []Hit{{Value: f(prod / 1000), Message: tr.T("alert_rule.solar_production_low.message",
						"kwh", num(prod/1000, 1), "date", date, "pct", num(100*prod/med, 0), "median", num(med/1000, 1))}}
				}
			}
			hist = append(hist, prod)
			if len(hist) > productionHistory {
				hist = hist[len(hist)-productionHistory:]
			}
			for i, x := range hist {
				st.setBaseline("h"+strconv.Itoa(i), x)
			}
			st.setBaseline("n", float64(len(hist)))
			return r
		},
	},
	{
		Key: "battery_capacity_drop", Title: tr.T("alert_rule.battery_capacity_drop.title"), Kind: Condition,
		Subject:     SubjectGateway,
		Description: tr.T("alert_rule.battery_capacity_drop.desc"),
		Params:      []ParamSpec{{"pct", tr.T("alert_param.below_first"), "%", 50, 99, 80}},
		// Full-pack energy wobbles from poll to poll; require a few.
		Defaults: cond(true, 0, 3, 0),
		Eval: func(in Input, p Params, st *State) Result {
			if !in.gw(gateway.EndpointSystemStatus, "nominal_full_pack_energy") || !in.gw(gateway.EndpointSystemStatus, "battery_blocks") {
				return Result{Skip: true}
			}
			sys := in.GatewaySnap.SystemStatus
			v, blocks := sys.NominalFullPackEnergy, float64(len(sys.BatteryBlocks))
			first, seen := st.Baseline["first_full_pack"]
			// A Powerwall added or removed changes what "full" means.
			if !seen || st.Baseline["blocks"] != blocks || first <= 0 {
				st.setBaseline("first_full_pack", v)
				st.setBaseline("blocks", blocks)
				return Result{}
			}
			pct := 100 * v / first
			if pct >= p["pct"] {
				return Result{Value: f(pct)}
			}
			return Result{Severity: Info, Value: f(pct), Message: tr.T("alert_rule.battery_capacity_drop.message",
				"now", num(v/1000, 1), "pct", num(pct, 0), "first", num(first/1000, 1))}
		},
	},
	gatewayEventRule("gateway_firmware_changed", tr.T("alert_rule.gateway_firmware_changed.title"),
		tr.T("alert_rule.gateway_firmware_changed.desc"), store.GatewayEventFirmwareChanged, Info, func(e store.GatewayEvent) string {
			return tr.T("alert_rule.gateway_firmware_changed.message", "from", e.Details["from"], "to", e.Details["to"])
		}),
	gatewayEventRule("gateway_reboot", tr.T("alert_rule.gateway_reboot.title"),
		tr.T("alert_rule.gateway_reboot.desc"), store.GatewayEventReboot, Info, func(e store.GatewayEvent) string {
			up, _ := strconv.ParseFloat(e.Details["uptime_s"], 64)
			return tr.T("alert_rule.gateway_reboot.message", "uptime", (time.Duration(math.Max(up, 0)) * time.Second).String())
		}),
}

func init() { definitions = append(definitions, gatewayDefinitions...) }
