// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package alerts

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/i18n"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

// Kind distinguishes rules with a firing/resolved lifecycle from one-shot
// event rules (counter increments, firmware changes, ...).
type Kind int

// Rule kinds.
const (
	Condition Kind = iota
	Event
)

// ParamSpec describes one numeric rule parameter (used for validation and
// to render the rule editor in the web UI).
type ParamSpec struct {
	Name    string
	Label   string
	Unit    string
	Min     float64
	Max     float64
	Default float64
}

// Params are a rule's numeric parameters by name.
type Params map[string]float64

// Input is everything a rule may look at for one poll.
type Input struct {
	Device   store.Device
	At       time.Time
	Snapshot *wallconnector.Snapshot // nil when the poll failed
	Err      error
	Events   []store.DeviceEvent
}

// valid reports whether field of endpoint ep decoded cleanly.
func (in Input) valid(ep wallconnector.Endpoint, field string) bool {
	if in.Snapshot == nil {
		return false
	}
	r := in.Snapshot.Reports[ep]
	return !r.IsInvalid(field) && !r.IsMissing(field)
}

func (in Input) vital(field string) bool { return in.valid(wallconnector.EndpointVitals, field) }

// Result is a rule's verdict for one poll.
type Result struct {
	Skip     bool     // not enough valid data: leave the state unchanged
	Severity Severity // None = not breaching (condition rules)
	Value    *float64
	Message  string
	Hits     []Hit // event rules: one notification per hit
}

// Hit is one occurrence reported by an event rule.
type Hit struct {
	Message string
	Value   *float64
}

// Definition is a built-in rule.
type Definition struct {
	Key         string
	Title       string
	Description string
	Kind        Kind
	// EventSeverity is the severity of every hit of an event rule.
	EventSeverity Severity
	Params        []ParamSpec
	Defaults      Config
	// NeedsCalibration marks rules whose thresholds have not been
	// calibrated against real charging data (issue #1); they ship disabled.
	NeedsCalibration bool
	Eval             func(in Input, p Params, st *State) Result
}

// Config is a rule's effective configuration for one device.
type Config struct {
	Enabled        bool
	Params         Params
	For            time.Duration // must breach this long (or for one sampling gap)
	MinSamples     int           // consecutive breaching polls required
	Cooldown       time.Duration // min gap between firing notifications
	Repeat         time.Duration // re-notify while critical; 0 = never
	NotifyResolved bool
}

const (
	defaultCooldown = 30 * time.Minute
	criticalRepeat  = 6 * time.Hour
)

func cond(enabled bool, forD time.Duration, minSamples int, repeat time.Duration) Config {
	return Config{Enabled: enabled, For: forD, MinSamples: minSamples, Cooldown: defaultCooldown,
		Repeat: repeat, NotifyResolved: true}
}

func event(enabled bool) Config {
	return Config{Enabled: enabled, MinSamples: 1, Cooldown: 0}
}

func f(v float64) *float64 { return &v }

// tr is the catalog for rule titles, descriptions, parameter labels and
// alert messages (messages are stored when an alert fires).
var tr = i18n.English()

// num formats v with prec decimals, like %.<prec>f.
func num(v float64, prec int) string { return strconv.FormatFloat(v, 'f', prec, 64) }

// levels maps a value to a severity with hysteresis: once at a level, the
// value must fall below threshold-hysteresis to drop out of it.
func levels(v, warn, crit, hyst float64, current Severity) Severity {
	switch {
	case crit > 0 && v >= crit, current == Critical && crit > 0 && v >= crit-hyst:
		return Critical
	case v >= warn, current != None && v >= warn-hyst:
		return Warning
	default:
		return None
	}
}

func tempRule(key, field, title, desc, msgKey string, warn, crit float64) Definition {
	return Definition{
		Key: key, Title: title, Kind: Condition,
		Description: desc,
		Params: []ParamSpec{
			{"warn_c", tr.T("alert_param.warning_at"), "°C", 30, 150, warn},
			{"crit_c", tr.T("alert_param.critical_at"), "°C", 30, 150, crit},
			{"hysteresis_c", tr.T("alert_param.resolve_below"), "°C", 0, 30, 5},
		},
		Defaults: cond(true, time.Minute, 1, criticalRepeat),
		Eval: func(in Input, p Params, st *State) Result {
			if !in.vital(field) {
				return Result{Skip: true}
			}
			v := map[string]float64{
				"handle_temp_c": in.Snapshot.Vitals.HandleTempC,
				"pcba_temp_c":   in.Snapshot.Vitals.PCBATempC,
				"mcu_temp_c":    in.Snapshot.Vitals.MCUTempC,
			}[field]
			sev := levels(v, p["warn_c"], p["crit_c"], p["hysteresis_c"], st.current())
			return Result{Severity: sev, Value: f(v), Message: tr.T(msgKey, "value", num(v, 1))}
		},
	}
}

// counterRule fires an event each time a lifetime counter increases. The
// first reading only sets the baseline; a decrease (device replaced or
// reset) silently re-baselines.
func counterRule(key, title, desc, field string, sev Severity, get func(wallconnector.Lifetime) int64, msgKey string) Definition {
	return Definition{
		Key: key, Title: title, Description: desc, Kind: Event, EventSeverity: sev,
		Defaults: event(true),
		Eval: func(in Input, _ Params, st *State) Result {
			if !in.valid(wallconnector.EndpointLifetime, field) {
				return Result{Skip: true}
			}
			v := float64(get(in.Snapshot.Lifetime))
			prev, seen := st.Baseline[field]
			st.setBaseline(field, v)
			if !seen || v <= prev {
				return Result{}
			}
			return Result{Hits: []Hit{{Message: tr.T(msgKey, "count", num(v-prev, 0), "total", num(v, 0)), Value: f(v)}}}
		},
	}
}

// deviceEventRule turns a poller-detected device event into a notification.
func deviceEventRule(key, title, desc, kind string, sev Severity, format func(store.DeviceEvent) string) Definition {
	return Definition{
		Key: key, Title: title, Description: desc, Kind: Event, EventSeverity: sev,
		Defaults: event(true),
		Eval: func(in Input, _ Params, _ *State) Result {
			var r Result
			for _, ev := range in.Events {
				if ev.Kind == kind {
					r.Hits = append(r.Hits, Hit{Message: format(ev)})
				}
			}
			return r
		},
	}
}

func codes(list []int, info func(int) wallconnector.CodeInfo) string {
	parts := make([]string, 0, len(list))
	for _, c := range list {
		parts = append(parts, info(c).Label)
	}
	return strings.Join(parts, ", ")
}

func threePhase(d store.Device) bool { return d.NominalVoltageV == 400 || d.NominalVoltageV == 480 }

// Definitions returns the built-in rules in display order.
func Definitions() []Definition { return slices.Clone(definitions) }

// Lookup returns a built-in rule by key.
func Lookup(key string) (Definition, bool) {
	i := slices.IndexFunc(definitions, func(d Definition) bool { return d.Key == key })
	if i < 0 {
		return Definition{}, false
	}
	return definitions[i], true
}

var definitions = []Definition{
	{
		Key: "device_unreachable", Title: tr.T("alert_rule.device_unreachable.title"), Kind: Condition,
		Description: tr.T("alert_rule.device_unreachable.desc"),
		Params:      []ParamSpec{{"critical_after", tr.T("alert_param.critical_after"), tr.T("alert_param.unit_polls"), 1, 100, 3}},
		Defaults:    cond(true, 0, 1, criticalRepeat),
		Eval: func(in Input, p Params, st *State) Result {
			if in.Err == nil {
				st.Counter = 0
				return Result{}
			}
			st.Counter++
			sev := Warning
			if float64(st.Counter) >= p["critical_after"] {
				sev = Critical
			}
			return Result{Severity: sev, Value: f(float64(st.Counter)),
				Message: tr.T("alert_rule.device_unreachable.message", "address", in.Device.Address, "count", st.Counter)}
		},
	},
	tempRule("handle_temp_high", "handle_temp_c", tr.T("alert_rule.handle_temp_high.title"),
		tr.T("alert_rule.handle_temp_high.desc"), "alert_rule.handle_temp_high.message", 55, 70),
	tempRule("pcba_temp_high", "pcba_temp_c", tr.T("alert_rule.pcba_temp_high.title"),
		tr.T("alert_rule.pcba_temp_high.desc"), "alert_rule.pcba_temp_high.message", 70, 85),
	tempRule("mcu_temp_high", "mcu_temp_c", tr.T("alert_rule.mcu_temp_high.title"),
		tr.T("alert_rule.mcu_temp_high.desc"), "alert_rule.mcu_temp_high.message", 70, 85),
	counterRule("thermal_foldback", tr.T("alert_rule.thermal_foldback.title"), tr.T("alert_rule.thermal_foldback.desc"),
		"thermal_foldbacks", Warning, func(l wallconnector.Lifetime) int64 { return l.ThermalFoldbacks },
		"alert_rule.thermal_foldback.message"),
	{
		Key: "device_alert_active", Title: tr.T("alert_rule.device_alert_active.title"), Kind: Condition,
		Description: tr.T("alert_rule.device_alert_active.desc"),
		Defaults:    cond(true, 0, 1, 0),
		Eval: func(in Input, _ Params, _ *State) Result {
			if !in.vital("current_alerts") {
				return Result{Skip: true}
			}
			a := in.Snapshot.Vitals.CurrentAlerts
			if len(a) == 0 {
				return Result{}
			}
			return Result{Severity: Warning, Value: f(float64(len(a))),
				Message: tr.T("alert_rule.device_alert_active.message", "codes", codes(a, wallconnector.AlertInfo))}
		},
	},
	counterRule("device_alert_count_up", tr.T("alert_rule.device_alert_count_up.title"), tr.T("alert_rule.device_alert_count_up.desc"),
		"alert_count", Warning, func(l wallconnector.Lifetime) int64 { return l.AlertCount },
		"alert_rule.device_alert_count_up.message"),
	{
		Key: "not_ready_reasons", Title: tr.T("alert_rule.not_ready_reasons.title"), Kind: Condition,
		Description: tr.T("alert_rule.not_ready_reasons.desc"),
		Defaults:    cond(true, 2*time.Minute, 1, 0),
		Eval: func(in Input, _ Params, _ *State) Result {
			if !in.vital("vehicle_connected") || !in.vital("contactor_closed") || !in.vital("evse_not_ready_reasons") {
				return Result{Skip: true}
			}
			v := in.Snapshot.Vitals
			// A UWC (fw 26.26.10) reports [1] while charging normally, so a
			// closed contactor means the car is evidently ready.
			if !v.VehicleConnected || v.ContactorClosed || len(v.EVSENotReadyReasons) == 0 {
				return Result{}
			}
			// [1] is also reported with a car plugged in but idle (fw 26.34.0:
			// charge complete or waiting for a schedule), so only other
			// reasons are worth an alert.
			if !slices.ContainsFunc(v.EVSENotReadyReasons, func(c int) bool {
				return !slices.Contains(wallconnector.ConnectedNotReadyReasons, c)
			}) {
				return Result{}
			}
			return Result{Severity: Warning, Message: tr.T("alert_rule.not_ready_reasons.message",
				"codes", codes(v.EVSENotReadyReasons, wallconnector.NotReadyReasonInfo))}
		},
	},
	{
		Key: "grid_voltage_out_of_range", Title: tr.T("alert_rule.grid_voltage_out_of_range.title"), Kind: Condition,
		Description: tr.T("alert_rule.grid_voltage_out_of_range.desc"),
		Params: []ParamSpec{
			{"warn_pct", tr.T("alert_param.warning_at_deviation"), "%", 1, 50, 5},
			{"crit_pct", tr.T("alert_param.critical_at_deviation"), "%", 1, 50, 10},
			{"hysteresis_pct", tr.T("alert_param.hysteresis"), "%", 0, 10, 1},
		},
		Defaults: cond(true, 0, 1, criticalRepeat),
		Eval: func(in Input, p Params, st *State) Result {
			if !in.vital("grid_v") || in.Device.NominalVoltageV <= 0 {
				return Result{Skip: true}
			}
			v, nom := in.Snapshot.Vitals.GridV, in.Device.NominalVoltageV
			dev := math.Abs(v-nom) / nom * 100
			sev := levels(dev, p["warn_pct"], p["crit_pct"], p["hysteresis_pct"], st.current())
			key := "alert_rule.grid_voltage_out_of_range.message_above"
			if v < nom {
				key = "alert_rule.grid_voltage_out_of_range.message_below"
			}
			return Result{Severity: sev, Value: f(v),
				Message: tr.T(key, "value", num(v, 1), "deviation", num(dev, 1), "nominal", num(nom, 0))}
		},
	},
	{
		Key: "grid_freq_out_of_range", Title: tr.T("alert_rule.grid_freq_out_of_range.title"), Kind: Condition,
		Description: tr.T("alert_rule.grid_freq_out_of_range.desc"),
		Params: []ParamSpec{
			{"warn_hz", tr.T("alert_param.warning_at_deviation"), "Hz", 0.05, 5, 0.5},
			{"hysteresis_hz", tr.T("alert_param.hysteresis"), "Hz", 0, 1, 0.1},
		},
		Defaults: cond(true, 0, 1, 0),
		Eval: func(in Input, p Params, st *State) Result {
			if !in.vital("grid_hz") {
				return Result{Skip: true}
			}
			v := in.Snapshot.Vitals.GridHz
			dev := math.Abs(v - in.Device.NominalHz)
			sev := levels(dev, p["warn_hz"], 0, p["hysteresis_hz"], st.current())
			return Result{Severity: sev, Value: f(v),
				Message: tr.T("alert_rule.grid_freq_out_of_range.message", "value", num(v, 3), "nominal", num(in.Device.NominalHz, 0))}
		},
	},
	{
		Key: "phase_current_imbalance", Title: tr.T("alert_rule.phase_current_imbalance.title"), Kind: Condition,
		Description: tr.T("alert_rule.phase_current_imbalance.desc"),
		Params:      []ParamSpec{{"imbalance_pct", tr.T("alert_param.imbalance_above"), "%", 5, 100, 20}},
		Defaults:    cond(false, 0, 2, 0),
		Eval: func(in Input, p Params, _ *State) Result {
			if !threePhase(in.Device) || !in.vital("currentA_a") || !in.vital("currentB_a") || !in.vital("currentC_a") {
				return Result{Skip: true}
			}
			v := in.Snapshot.Vitals
			hi := max(v.CurrentAA, v.CurrentBA, v.CurrentCA)
			lo := min(v.CurrentAA, v.CurrentBA, v.CurrentCA)
			if hi < 5 {
				return Result{}
			}
			pct := (hi - lo) / hi * 100
			if pct <= p["imbalance_pct"] {
				return Result{}
			}
			return Result{Severity: Info, Value: f(pct),
				Message: tr.T("alert_rule.phase_current_imbalance.message", "pct", num(pct, 0),
					"a", num(v.CurrentAA, 1), "b", num(v.CurrentBA, 1), "c", num(v.CurrentCA, 1))}
		},
	},
	{
		Key: "overcurrent", Title: tr.T("alert_rule.overcurrent.title"), Kind: Condition,
		Description: tr.T("alert_rule.overcurrent.desc"),
		Params:      []ParamSpec{{"margin_pct", tr.T("alert_param.margin_above_max"), "%", 0, 50, 5}},
		Defaults:    cond(true, 30*time.Second, 1, criticalRepeat),
		Eval: func(in Input, p Params, _ *State) Result {
			if in.Device.MaxCurrentA <= 0 || !in.vital("vehicle_current_a") {
				return Result{Skip: true}
			}
			v := in.Snapshot.Vitals
			cur := v.VehicleCurrentA
			for _, ph := range []struct {
				name string
				val  float64
			}{{"currentA_a", v.CurrentAA}, {"currentB_a", v.CurrentBA}, {"currentC_a", v.CurrentCA}} {
				if in.vital(ph.name) {
					cur = max(cur, ph.val)
				}
			}
			limit := in.Device.MaxCurrentA * (1 + p["margin_pct"]/100)
			if cur <= limit {
				return Result{Value: f(cur)}
			}
			return Result{Severity: Critical, Value: f(cur),
				Message: tr.T("alert_rule.overcurrent.message", "current", num(cur, 1), "max", num(in.Device.MaxCurrentA, 0), "limit", num(limit, 1))}
		},
	},
	{
		Key: "current_near_limit", Title: tr.T("alert_rule.current_near_limit.title"), Kind: Condition,
		Description: tr.T("alert_rule.current_near_limit.desc"),
		Params:      []ParamSpec{{"margin_pct", tr.T("alert_param.upper_margin"), "%", 0, 50, 5}},
		Defaults:    cond(false, 0, 2, 0),
		Eval: func(in Input, p Params, _ *State) Result {
			if in.Device.MaxCurrentA <= 0 || !in.vital("vehicle_current_a") {
				return Result{Skip: true}
			}
			cur, maxA := in.Snapshot.Vitals.VehicleCurrentA, in.Device.MaxCurrentA
			if cur < maxA || cur > maxA*(1+p["margin_pct"]/100) {
				return Result{Value: f(cur)}
			}
			return Result{Severity: Info, Value: f(cur), Message: tr.T("alert_rule.current_near_limit.message", "current", num(cur, 1), "max", num(maxA, 0))}
		},
	},
	{
		Key: "charging_stalled", Title: tr.T("alert_rule.charging_stalled.title"), Kind: Condition,
		Description: tr.T("alert_rule.charging_stalled.desc"),
		Params:      []ParamSpec{{"min_current_a", tr.T("alert_param.below"), "A", 0.1, 10, 1}},
		Defaults:    cond(true, 0, 2, 0),
		Eval: func(in Input, p Params, _ *State) Result {
			if !in.vital("vehicle_current_a") || !in.vital("contactor_closed") || !in.vital("vehicle_connected") {
				return Result{Skip: true}
			}
			v := in.Snapshot.Vitals
			if !v.ContactorClosed || !v.VehicleConnected || v.VehicleCurrentA >= p["min_current_a"] {
				return Result{}
			}
			return Result{Severity: Info, Value: f(v.VehicleCurrentA),
				Message: tr.T("alert_rule.charging_stalled.message", "current", num(v.VehicleCurrentA, 1))}
		},
	},
	{
		Key: "relay_voltage_abnormal", Title: tr.T("alert_rule.relay_voltage_abnormal.title"), Kind: Condition,
		Description:      tr.T("alert_rule.relay_voltage_abnormal.desc"),
		NeedsCalibration: true,
		Params: []ParamSpec{
			{"closed_min_v", tr.T("alert_param.closed_min"), "V", 0, 60, 9},
			{"closed_max_v", tr.T("alert_param.closed_max"), "V", 0, 60, 15},
			{"open_max_v", tr.T("alert_param.open_max"), "V", 0, 60, 1},
			{"k1_k2_diff_v", tr.T("alert_param.k1_k2_diff"), "V", 0, 60, 2},
		},
		Defaults: cond(false, 0, 2, 0),
		Eval: func(in Input, p Params, _ *State) Result {
			if in.Snapshot == nil || !in.vital("contactor_closed") {
				return Result{Skip: true}
			}
			v := in.Snapshot.Vitals
			var relays []float64
			for _, r := range []struct {
				name string
				val  *float64
			}{{"relay_k1_v", v.RelayK1V}, {"relay_k2_v", v.RelayK2V}, {"relay_coil_v", v.RelayCoilV}} {
				if r.val != nil && in.vital(r.name) {
					relays = append(relays, *r.val)
				}
			}
			if len(relays) == 0 {
				return Result{Skip: true}
			}
			hi, lo := slices.Max(relays), slices.Min(relays)
			switch {
			case !v.ContactorClosed && hi > p["open_max_v"]:
				return Result{Severity: Warning, Value: f(hi), Message: tr.T("alert_rule.relay_voltage_abnormal.message_open", "voltage", num(hi, 1))}
			case v.ContactorClosed && (lo < p["closed_min_v"] || hi > p["closed_max_v"]):
				return Result{Severity: Warning, Value: f(lo), Message: tr.T("alert_rule.relay_voltage_abnormal.message_band", "low", num(lo, 1), "high", num(hi, 1),
					"min", num(p["closed_min_v"], 1), "max", num(p["closed_max_v"], 1))}
			case len(relays) > 1 && hi-lo > p["k1_k2_diff_v"]:
				return Result{Severity: Warning, Value: f(hi - lo), Message: tr.T("alert_rule.relay_voltage_abnormal.message_diff", "diff", num(hi-lo, 1))}
			}
			return Result{}
		},
	},
	{
		Key: "wifi_weak", Title: tr.T("alert_rule.wifi_weak.title"), Kind: Condition,
		Description: tr.T("alert_rule.wifi_weak.desc"),
		Params: []ParamSpec{
			{"rssi_dbm", tr.T("alert_param.below"), "dBm", -100, -30, -75},
			{"hysteresis_db", tr.T("alert_param.hysteresis"), "dB", 0, 20, 3},
		},
		Defaults: cond(true, 0, 2, 0),
		Eval: func(in Input, p Params, st *State) Result {
			if !in.valid(wallconnector.EndpointWifiStatus, "wifi_rssi") {
				return Result{Skip: true}
			}
			rssi := float64(in.Snapshot.WifiStatus.WifiRSSI)
			// Weakness grows as RSSI falls: compare negated values.
			sev := levels(-rssi, -p["rssi_dbm"], 0, p["hysteresis_db"], st.current())
			if sev > Info {
				sev = Info
			}
			return Result{Severity: sev, Value: f(rssi), Message: tr.T("alert_rule.wifi_weak.message", "rssi", num(rssi, 0))}
		},
	},
	{
		Key: "wifi_no_internet", Title: tr.T("alert_rule.wifi_no_internet.title"), Kind: Condition,
		Description: tr.T("alert_rule.wifi_no_internet.desc"),
		Defaults:    cond(true, 0, 2, 0),
		Eval: func(in Input, _ Params, _ *State) Result {
			if !in.valid(wallconnector.EndpointWifiStatus, "internet") {
				return Result{Skip: true}
			}
			if in.Snapshot.WifiStatus.Internet {
				return Result{}
			}
			return Result{Severity: Info, Message: tr.T("alert_rule.wifi_no_internet.message")}
		},
	},
	deviceEventRule("unexpected_reboot", tr.T("alert_rule.unexpected_reboot.title"), tr.T("alert_rule.unexpected_reboot.desc"),
		store.EventReboot, Info, func(e store.DeviceEvent) string {
			return tr.T("alert_rule.unexpected_reboot.message", "uptime", e.Details["uptime_s"])
		}),
	deviceEventRule("firmware_changed", tr.T("alert_rule.firmware_changed.title"), tr.T("alert_rule.firmware_changed.desc"),
		store.EventFirmwareChanged, Info, func(e store.DeviceEvent) string {
			return tr.T("alert_rule.firmware_changed.message", "from", e.Details["from"], "to", e.Details["to"])
		}),
	deviceEventRule("grid_profile_changed", tr.T("alert_rule.grid_profile_changed.title"), tr.T("alert_rule.grid_profile_changed.desc"),
		store.EventGridProfileChanged, Warning, func(e store.DeviceEvent) string {
			return tr.T("alert_rule.grid_profile_changed.message",
				"vf_trips_from", e.Details["vf_trips_from"], "vf_trips_to", e.Details["vf_trips_to"],
				"ride_thru_from", e.Details["ride_thru_from"], "ride_thru_to", e.Details["ride_thru_to"],
				"combined_from", e.Details["combined_from"], "combined_to", e.Details["combined_to"])
		}),
	deviceEventRule("identity_mismatch", tr.T("alert_rule.identity_mismatch.title"), tr.T("alert_rule.identity_mismatch.desc"),
		store.EventIdentityMismatch, Warning, func(e store.DeviceEvent) string {
			return tr.T("alert_rule.identity_mismatch.message", "serial", e.Details["serial"], "previous", e.Details["previous_serial"])
		}),
	{
		Key: "contactor_wear", Title: tr.T("alert_rule.contactor_wear.title"), Kind: Event, EventSeverity: Info,
		Description: tr.T("alert_rule.contactor_wear.desc"),
		Params:      []ParamSpec{{"milestone", tr.T("alert_param.every"), tr.T("alert_param.unit_cycles"), 100, 1000000, 10000}},
		Defaults:    event(true),
		Eval: func(in Input, p Params, st *State) Result {
			if !in.valid(wallconnector.EndpointLifetime, "contactor_cycles_loaded") {
				return Result{Skip: true}
			}
			v := float64(in.Snapshot.Lifetime.ContactorCyclesLoaded)
			prev, seen := st.Baseline["contactor_cycles_loaded"]
			st.setBaseline("contactor_cycles_loaded", v)
			m := p["milestone"]
			if !seen || v <= prev || math.Floor(v/m) == math.Floor(prev/m) {
				return Result{}
			}
			return Result{Hits: []Hit{{Value: f(v),
				Message: tr.T("alert_rule.contactor_wear.message", "cycles", num(math.Floor(v/m)*m, 0))}}}
		},
	},
}

// defaultParams returns each ParamSpec's default.
func (d Definition) defaultParams() Params {
	p := Params{}
	for _, s := range d.Params {
		p[s.Name] = s.Default
	}
	return p
}

// DefaultConfig returns the rule's built-in configuration.
func (d Definition) DefaultConfig() Config {
	c := d.Defaults
	c.Params = d.defaultParams()
	if c.MinSamples < 1 {
		c.MinSamples = 1
	}
	return c
}

// Validate checks a configuration against the rule's parameter specs.
func (d Definition) Validate(c Config) error {
	for name, v := range c.Params {
		i := slices.IndexFunc(d.Params, func(s ParamSpec) bool { return s.Name == name })
		if i < 0 {
			return fmt.Errorf("rule %s has no parameter %q", d.Key, name)
		}
		if s := d.Params[i]; v < s.Min || v > s.Max || math.IsNaN(v) {
			return tr.Err("alert_rule.err_range", "param", s.Label, "min", strconv.FormatFloat(s.Min, 'g', -1, 64),
				"max", strconv.FormatFloat(s.Max, 'g', -1, 64), "unit", s.Unit)
		}
	}
	if c.For < 0 || c.For > 24*time.Hour || c.Cooldown < 0 || c.Cooldown > 7*24*time.Hour ||
		c.Repeat < 0 || c.Repeat > 7*24*time.Hour || (c.Repeat > 0 && c.Repeat < 15*time.Minute) {
		return tr.Err("alert_rule.err_timing", "rule", d.Key)
	}
	if c.MinSamples < 1 || c.MinSamples > 100 {
		return tr.Err("alert_rule.err_min_samples", "rule", d.Key)
	}
	if w, ok := c.Params["warn_c"]; ok && w >= c.Params["crit_c"] {
		return tr.Err("alert_rule.err_warn_above_crit", "rule", d.Key)
	}
	if w, ok := c.Params["warn_pct"]; ok && w >= c.Params["crit_pct"] {
		return tr.Err("alert_rule.err_warn_above_crit", "rule", d.Key)
	}
	return nil
}
