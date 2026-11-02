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
	"strings"
	"time"

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
	// NeedsCalibration marks rules whose thresholds still need a real
	// charging capture (issue #1); they ship disabled.
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

func tempRule(key, title, field, sensor string, warn, crit float64) Definition {
	return Definition{
		Key: key, Title: title, Kind: Condition,
		Description: fmt.Sprintf("%s temperature above the warning or critical threshold.", sensor),
		Params: []ParamSpec{
			{"warn_c", "Warning at", "°C", 30, 150, warn},
			{"crit_c", "Critical at", "°C", 30, 150, crit},
			{"hysteresis_c", "Resolve below threshold minus", "°C", 0, 30, 5},
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
			return Result{Severity: sev, Value: f(v), Message: fmt.Sprintf("%s temperature is %.1f °C", sensor, v)}
		},
	}
}

// counterRule fires an event each time a lifetime counter increases. The
// first reading only sets the baseline; a decrease (device replaced or
// reset) silently re-baselines.
func counterRule(key, title, desc, field string, sev Severity, get func(wallconnector.Lifetime) int64, msg string) Definition {
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
			return Result{Hits: []Hit{{Message: fmt.Sprintf(msg, v-prev, v), Value: f(v)}}}
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
		Key: "device_unreachable", Title: "Wall Connector unreachable", Kind: Condition,
		Description: "A poll failed after all retries. Escalates to critical after several consecutive failed polls.",
		Params:      []ParamSpec{{"critical_after", "Critical after consecutive failed polls", "polls", 1, 100, 3}},
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
				Message: fmt.Sprintf("No response from %s (%d failed poll(s)). If its IP address changed, update it in Settings.",
					in.Device.Address, st.Counter)}
		},
	},
	tempRule("handle_temp_high", "Handle temperature high", "handle_temp_c", "Handle", 55, 70),
	tempRule("pcba_temp_high", "Circuit board temperature high", "pcba_temp_c", "Circuit board (PCBA)", 70, 85),
	tempRule("mcu_temp_high", "Controller temperature high", "mcu_temp_c", "Controller (MCU)", 70, 85),
	counterRule("thermal_foldback", "Thermal foldback", "The Wall Connector reduced charging current because it got too hot.",
		"thermal_foldbacks", Warning, func(l wallconnector.Lifetime) int64 { return l.ThermalFoldbacks },
		"%.0f new thermal foldback(s) — charging current was reduced due to heat (lifetime total %.0f)"),
	{
		Key: "device_alert_active", Title: "Wall Connector reports an alert", Kind: Condition,
		Description: "The device's current_alerts list is not empty.",
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
				Message: "Active device alert(s): " + codes(a, wallconnector.AlertInfo)}
		},
	},
	counterRule("device_alert_count_up", "New device alert recorded", "The lifetime alert counter increased.",
		"alert_count", Warning, func(l wallconnector.Lifetime) int64 { return l.AlertCount },
		"%.0f new alert(s) recorded by the Wall Connector (lifetime total %.0f)"),
	{
		Key: "not_ready_reasons", Title: "Car plugged in but not ready", Kind: Condition,
		Description: "The Wall Connector reports not-ready reasons while a car is connected. (Reasons reported while unplugged are normal and ignored.)",
		Defaults:    cond(true, 2*time.Minute, 1, 0),
		Eval: func(in Input, _ Params, _ *State) Result {
			if !in.vital("vehicle_connected") || !in.vital("evse_not_ready_reasons") {
				return Result{Skip: true}
			}
			v := in.Snapshot.Vitals
			if !v.VehicleConnected || len(v.EVSENotReadyReasons) == 0 {
				return Result{}
			}
			return Result{Severity: Warning, Message: "Car connected but not ready: " +
				codes(v.EVSENotReadyReasons, wallconnector.NotReadyReasonInfo)}
		},
	},
	{
		Key: "grid_voltage_out_of_range", Title: "Grid voltage out of range", Kind: Condition,
		Description: "Grid voltage deviates from the configured nominal voltage.",
		Params: []ParamSpec{
			{"warn_pct", "Warning at deviation", "%", 1, 50, 5},
			{"crit_pct", "Critical at deviation", "%", 1, 50, 10},
			{"hysteresis_pct", "Hysteresis", "%", 0, 10, 1},
		},
		Defaults: cond(true, 0, 1, criticalRepeat),
		Eval: func(in Input, p Params, st *State) Result {
			if !in.vital("grid_v") || in.Device.NominalVoltageV <= 0 {
				return Result{Skip: true}
			}
			v, nom := in.Snapshot.Vitals.GridV, in.Device.NominalVoltageV
			dev := math.Abs(v-nom) / nom * 100
			sev := levels(dev, p["warn_pct"], p["crit_pct"], p["hysteresis_pct"], st.current())
			dir := "above"
			if v < nom {
				dir = "below"
			}
			return Result{Severity: sev, Value: f(v),
				Message: fmt.Sprintf("Grid voltage %.1f V is %.1f %% %s nominal %.0f V", v, dev, dir, nom)}
		},
	},
	{
		Key: "grid_freq_out_of_range", Title: "Grid frequency out of range", Kind: Condition,
		Description: "Grid frequency deviates from nominal (50/60 Hz).",
		Params: []ParamSpec{
			{"warn_hz", "Warning at deviation", "Hz", 0.05, 5, 0.5},
			{"hysteresis_hz", "Hysteresis", "Hz", 0, 1, 0.1},
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
				Message: fmt.Sprintf("Grid frequency %.3f Hz (nominal %.0f Hz)", v, in.Device.NominalHz)}
		},
	},
	{
		Key: "phase_current_imbalance", Title: "Phase current imbalance", Kind: Condition,
		Description: "Three-phase installations only: phase currents differ while charging.",
		Params:      []ParamSpec{{"imbalance_pct", "Imbalance above", "%", 5, 100, 20}},
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
				Message: fmt.Sprintf("Phase currents differ by %.0f %% (A %.1f / B %.1f / C %.1f A)", pct, v.CurrentAA, v.CurrentBA, v.CurrentCA)}
		},
	},
	{
		Key: "overcurrent", Title: "Overcurrent", Kind: Condition,
		Description: "Charging current exceeds the configured maximum current plus a margin.",
		Params:      []ParamSpec{{"margin_pct", "Margin above max current", "%", 0, 50, 5}},
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
				Message: fmt.Sprintf("Current %.1f A exceeds the %.0f A maximum (limit %.1f A)", cur, in.Device.MaxCurrentA, limit)}
		},
	},
	{
		Key: "current_near_limit", Title: "Charging at maximum current", Kind: Condition,
		Description: "Informational: charging at or just above the configured maximum current.",
		Params:      []ParamSpec{{"margin_pct", "Upper margin", "%", 0, 50, 5}},
		Defaults:    cond(false, 0, 2, 0),
		Eval: func(in Input, p Params, _ *State) Result {
			if in.Device.MaxCurrentA <= 0 || !in.vital("vehicle_current_a") {
				return Result{Skip: true}
			}
			cur, maxA := in.Snapshot.Vitals.VehicleCurrentA, in.Device.MaxCurrentA
			if cur < maxA || cur > maxA*(1+p["margin_pct"]/100) {
				return Result{Value: f(cur)}
			}
			return Result{Severity: Info, Value: f(cur), Message: fmt.Sprintf("Charging at %.1f A (maximum %.0f A)", cur, maxA)}
		},
	},
	{
		Key: "charging_stalled", Title: "Charging stalled", Kind: Condition,
		Description: "Contactor closed and car connected, but almost no current flows.",
		Params:      []ParamSpec{{"min_current_a", "Below", "A", 0.1, 10, 1}},
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
				Message: fmt.Sprintf("Charging session active but current is only %.1f A", v.VehicleCurrentA)}
		},
	},
	{
		Key: "relay_voltage_abnormal", Title: "Relay voltage abnormal", Kind: Condition,
		Description: "Relay drive voltage (UWC: K1/K2, Gen 3: coil) outside the expected band, the two relays disagree, " +
			"or a relay shows voltage while the contactor is open (possible stuck relay). Needs calibration from a real charging capture.",
		NeedsCalibration: true,
		Params: []ParamSpec{
			{"closed_min_v", "Closed: minimum", "V", 0, 60, 9},
			{"closed_max_v", "Closed: maximum", "V", 0, 60, 15},
			{"open_max_v", "Open: maximum", "V", 0, 60, 1},
			{"k1_k2_diff_v", "K1/K2 difference above", "V", 0, 60, 2},
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
				return Result{Severity: Warning, Value: f(hi), Message: fmt.Sprintf("Relay shows %.1f V while the contactor is open (possible stuck relay)", hi)}
			case v.ContactorClosed && (lo < p["closed_min_v"] || hi > p["closed_max_v"]):
				return Result{Severity: Warning, Value: f(lo), Message: fmt.Sprintf("Relay voltage %.1f–%.1f V outside %.1f–%.1f V", lo, hi, p["closed_min_v"], p["closed_max_v"])}
			case len(relays) > 1 && hi-lo > p["k1_k2_diff_v"]:
				return Result{Severity: Warning, Value: f(hi - lo), Message: fmt.Sprintf("Relay K1/K2 voltages differ by %.1f V", hi-lo)}
			}
			return Result{}
		},
	},
	{
		Key: "wifi_weak", Title: "Weak Wi-Fi signal", Kind: Condition,
		Description: "Wi-Fi RSSI below the threshold on consecutive polls.",
		Params: []ParamSpec{
			{"rssi_dbm", "Below", "dBm", -100, -30, -75},
			{"hysteresis_db", "Hysteresis", "dB", 0, 20, 3},
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
			return Result{Severity: sev, Value: f(rssi), Message: fmt.Sprintf("Wi-Fi signal is weak (%.0f dBm)", rssi)}
		},
	},
	{
		Key: "wifi_no_internet", Title: "No internet connection", Kind: Condition,
		Description: "The Wall Connector reports no internet access (needed for firmware updates).",
		Defaults:    cond(true, 0, 2, 0),
		Eval: func(in Input, _ Params, _ *State) Result {
			if !in.valid(wallconnector.EndpointWifiStatus, "internet") {
				return Result{Skip: true}
			}
			if in.Snapshot.WifiStatus.Internet {
				return Result{}
			}
			return Result{Severity: Info, Message: "The Wall Connector has no internet connection"}
		},
	},
	deviceEventRule("unexpected_reboot", "Wall Connector rebooted", "The device uptime reset since the previous poll.",
		store.EventReboot, Info, func(e store.DeviceEvent) string {
			return fmt.Sprintf("The Wall Connector restarted (uptime now %s s)", e.Details["uptime_s"])
		}),
	deviceEventRule("firmware_changed", "Firmware updated", "The firmware version changed.",
		store.EventFirmwareChanged, Info, func(e store.DeviceEvent) string {
			return fmt.Sprintf("Firmware changed from %s to %s", e.Details["from"], e.Details["to"])
		}),
	deviceEventRule("grid_profile_changed", "Grid profile changed", "An IEEE 1547 grid-interconnection checksum changed (trip/ride-through settings).",
		store.EventGridProfileChanged, Warning, func(e store.DeviceEvent) string {
			return fmt.Sprintf("Grid profile (IEEE 1547) settings changed: VfTrips %s→%s, RideThru %s→%s, Combined %s→%s",
				e.Details["vf_trips_from"], e.Details["vf_trips_to"], e.Details["ride_thru_from"], e.Details["ride_thru_to"],
				e.Details["combined_from"], e.Details["combined_to"])
		}),
	deviceEventRule("identity_mismatch", "Different Wall Connector at this address", "The serial number at the configured address changed.",
		store.EventIdentityMismatch, Warning, func(e store.DeviceEvent) string {
			return fmt.Sprintf("A different Wall Connector (serial %s, was %s) answered at this address — check the IP address in Settings",
				e.Details["serial"], e.Details["previous_serial"])
		}),
	{
		Key: "contactor_wear", Title: "Contactor wear milestone", Kind: Event, EventSeverity: Info,
		Description: "The number of contactor cycles under load crossed a milestone.",
		Params:      []ParamSpec{{"milestone", "Every", "cycles", 100, 1000000, 10000}},
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
				Message: fmt.Sprintf("Contactor has completed %.0f switching cycles under load", math.Floor(v/m)*m)}}}
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
			return fmt.Errorf("%s must be between %g and %g %s", s.Label, s.Min, s.Max, s.Unit)
		}
	}
	if c.For < 0 || c.For > 24*time.Hour || c.Cooldown < 0 || c.Cooldown > 7*24*time.Hour ||
		c.Repeat < 0 || c.Repeat > 7*24*time.Hour || (c.Repeat > 0 && c.Repeat < 15*time.Minute) {
		return fmt.Errorf("rule %s: for ≤ 24 h, cooldown/repeat ≤ 7 days, repeat ≥ 15 min", d.Key)
	}
	if c.MinSamples < 1 || c.MinSamples > 100 {
		return fmt.Errorf("rule %s: min samples must be 1-100", d.Key)
	}
	if w, ok := c.Params["warn_c"]; ok && w >= c.Params["crit_c"] {
		return fmt.Errorf("rule %s: warning threshold must be below critical", d.Key)
	}
	if w, ok := c.Params["warn_pct"]; ok && w >= c.Params["crit_pct"] {
		return fmt.Errorf("rule %s: warning threshold must be below critical", d.Key)
	}
	return nil
}
