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
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
	"github.com/bhager42/teslachargingmonitor/internal/wcsim"
)

var t0 = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func device() store.Device {
	d := store.NewDevice("Garage", "192.168.1.17")
	d.ID, d.BreakerA, d.MaxCurrentA = 1, 60, 48
	return d
}

// idle returns an input built from the simulator's idle state at time at.
func idle(at time.Time) Input { return scenario("idle", 0, at) }

func scenario(name string, e time.Duration, at time.Time) Input {
	sc, _ := wcsim.Lookup(name)
	st, _ := sc.State(e)
	return Input{Device: device(), At: at, Snapshot: &wallconnector.Snapshot{
		FetchedAt: at, Version: st.Version, Vitals: st.Vitals, Lifetime: st.Lifetime, WifiStatus: st.WifiStatus,
		Reports: map[wallconnector.Endpoint]wallconnector.Report{},
	}}
}

func withHandle(in Input, c float64) Input {
	in.Snapshot.Vitals.HandleTempC = c
	return in
}

type sample struct {
	in      Input
	snoozed bool
}

func kinds(ns []notice) string {
	var parts []string
	for _, n := range ns {
		k := n.kind + ":" + n.sev.String()
		if !n.notify {
			k += "(suppressed)"
		}
		parts = append(parts, k)
	}
	return strings.Join(parts, ",")
}

func mustRule(t *testing.T, key string) Definition {
	t.Helper()
	d, ok := Lookup(key)
	if !ok {
		t.Fatalf("no rule %s", key)
	}
	return d
}

// run feeds samples through step and returns the notices per sample.
func run(t *testing.T, key string, mod func(*Config), samples []sample) []string {
	t.Helper()
	def := mustRule(t, key)
	cfg := def.DefaultConfig()
	cfg.Enabled = true
	if mod != nil {
		mod(&cfg)
	}
	if err := def.Validate(cfg); err != nil {
		t.Fatal(err)
	}
	st := newState()
	out := make([]string, len(samples))
	for i, s := range samples {
		out[i] = kinds(step(def, cfg, s.in, st, s.snoozed))
	}
	return out
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("notices\n got: %q\nwant: %q", got, want)
	}
}

func TestHandleTempLifecycle(t *testing.T) {
	m := time.Minute
	got := run(t, "handle_temp_high", nil, []sample{
		{in: withHandle(idle(t0), 40)},
		{in: withHandle(idle(t0.Add(5*m)), 56)},  // gap 5 min ≥ for 60 s → fires
		{in: withHandle(idle(t0.Add(10*m)), 60)}, // still warning
		{in: withHandle(idle(t0.Add(15*m)), 72)}, // escalates
		{in: withHandle(idle(t0.Add(20*m)), 67)}, // within critical hysteresis (70-5)
		{in: withHandle(idle(t0.Add(25*m)), 64)}, // de-escalates silently to warning
		{in: withHandle(idle(t0.Add(30*m)), 51)}, // within warning hysteresis (55-5)
		{in: withHandle(idle(t0.Add(35*m)), 49)}, // resolved
	})
	eq(t, got, []string{"", "firing:warning", "", "escalated:critical", "", "", "", "resolved:warning"})
}

func TestDebounceWithFastSampling(t *testing.T) {
	s := 10 * time.Second
	got := run(t, "handle_temp_high", nil, []sample{
		{in: withHandle(idle(t0), 40)},
		{in: withHandle(idle(t0.Add(s)), 60)},    // gap 10 s < for 60 s: pending
		{in: withHandle(idle(t0.Add(3*s)), 60)},  // 20 s into breach
		{in: withHandle(idle(t0.Add(5*s)), 40)},  // recovers before 60 s: no alert
		{in: withHandle(idle(t0.Add(6*s)), 60)},  // new breach
		{in: withHandle(idle(t0.Add(13*s)), 60)}, // 70 s in → fires
		{in: withHandle(idle(t0.Add(14*s)), 60)},
	})
	eq(t, got, []string{"", "", "", "", "", "firing:warning", ""})
}

func TestMinSamples(t *testing.T) {
	weak := func(at time.Time, rssi int) Input {
		in := idle(at)
		in.Snapshot.WifiStatus.WifiRSSI = rssi
		return in
	}
	h := time.Hour
	got := run(t, "wifi_weak", nil, []sample{
		{in: weak(t0, -80)},
		{in: weak(t0.Add(h), -60)}, // single weak poll: nothing
		{in: weak(t0.Add(2*h), -80)},
		{in: weak(t0.Add(3*h), -77)}, // second consecutive → fires
		{in: weak(t0.Add(4*h), -73)}, // within 3 dB hysteresis
		{in: weak(t0.Add(5*h), -70)}, // resolved
	})
	eq(t, got, []string{"", "", "", "firing:info", "", "resolved:info"})
}

func TestCooldownDefersFiring(t *testing.T) {
	m := time.Minute
	got := run(t, "handle_temp_high", nil, []sample{
		{in: withHandle(idle(t0), 60)},           // fires
		{in: withHandle(idle(t0.Add(5*m)), 40)},  // resolves
		{in: withHandle(idle(t0.Add(10*m)), 60)}, // fires again within 30 min cooldown: held
		{in: withHandle(idle(t0.Add(20*m)), 60)}, // still in cooldown
		{in: withHandle(idle(t0.Add(31*m)), 60)}, // cooldown over: late firing notice
		{in: withHandle(idle(t0.Add(40*m)), 40)}, // resolved (was notified)
	})
	eq(t, got, []string{"firing:warning", "resolved:warning", "firing:warning(suppressed)", "", "firing:warning", "resolved:warning"})

	// A firing that was never notified also resolves silently.
	got = run(t, "handle_temp_high", nil, []sample{
		{in: withHandle(idle(t0), 60)},
		{in: withHandle(idle(t0.Add(5*m)), 40)},
		{in: withHandle(idle(t0.Add(10*m)), 60)},
		{in: withHandle(idle(t0.Add(15*m)), 40)},
	})
	eq(t, got, []string{"firing:warning", "resolved:warning", "firing:warning(suppressed)", ""})
}

func TestRepeatWhileCritical(t *testing.T) {
	h := time.Hour
	got := run(t, "handle_temp_high", nil, []sample{
		{in: withHandle(idle(t0), 60)},
		{in: withHandle(idle(t0.Add(h)), 75)},
		{in: withHandle(idle(t0.Add(4*h)), 75)},
		{in: withHandle(idle(t0.Add(7*h)), 75)}, // 6 h since escalation
		{in: withHandle(idle(t0.Add(8*h)), 60)}, // warning: no repeats
		{in: withHandle(idle(t0.Add(20*h)), 60)},
	})
	eq(t, got, []string{"firing:warning", "escalated:critical", "", "repeat:critical", "", ""})

	got = run(t, "handle_temp_high", func(c *Config) { c.Repeat = 0 }, []sample{
		{in: withHandle(idle(t0), 75)},
		{in: withHandle(idle(t0.Add(24*h)), 75)},
	})
	eq(t, got, []string{"firing:critical", ""})
}

func TestSnooze(t *testing.T) {
	m := time.Minute
	got := run(t, "handle_temp_high", nil, []sample{
		{in: withHandle(idle(t0), 60), snoozed: true},          // recorded, not sent
		{in: withHandle(idle(t0.Add(5*m)), 60), snoozed: true}, // still snoozed
		{in: withHandle(idle(t0.Add(10*m)), 60)},               // snooze over → notify
		{in: withHandle(idle(t0.Add(15*m)), 75), snoozed: true},
		{in: withHandle(idle(t0.Add(20*m)), 40), snoozed: true},
	})
	eq(t, got, []string{"firing:warning(suppressed)", "", "firing:warning", "escalated:critical(suppressed)", "resolved:critical(suppressed)"})
}

func TestResolvedNoticeOptional(t *testing.T) {
	got := run(t, "handle_temp_high", func(c *Config) { c.NotifyResolved = false }, []sample{
		{in: withHandle(idle(t0), 60)},
		{in: withHandle(idle(t0.Add(time.Hour)), 40)},
	})
	eq(t, got, []string{"firing:warning", ""})
}

func TestInvalidFieldsDoNotDriveAlerts(t *testing.T) {
	in := withHandle(idle(t0), 99)
	in.Snapshot.Reports[wallconnector.EndpointVitals] = wallconnector.Report{
		Invalid: []wallconnector.FieldError{{Field: "handle_temp_c", Reason: "out of range"}},
	}
	got := run(t, "handle_temp_high", nil, []sample{{in: withHandle(idle(t0.Add(-time.Hour)), 60)}, {in: in}})
	eq(t, got, []string{"firing:warning", ""}) // skipped: still firing, nothing new
}

func TestDeviceUnreachable(t *testing.T) {
	h := time.Hour
	fail := func(at time.Time) Input {
		return Input{Device: device(), At: at, Err: errors.New("timeout")}
	}
	got := run(t, "device_unreachable", nil, []sample{
		{in: fail(t0)},
		{in: fail(t0.Add(h))},
		{in: fail(t0.Add(2 * h))}, // third consecutive → critical
		{in: idle(t0.Add(3 * h))},
		{in: fail(t0.Add(4 * h))}, // counter reset; cooldown 30 min passed
	})
	eq(t, got, []string{"firing:warning", "", "escalated:critical", "resolved:critical", "firing:warning"})
	// Other rules ignore failed polls.
	got = run(t, "handle_temp_high", nil, []sample{{in: fail(t0)}})
	eq(t, got, []string{""})
}

func TestCounterRules(t *testing.T) {
	h := time.Hour
	at := func(n int, foldbacks, alerts int64) Input {
		in := idle(t0.Add(time.Duration(n) * h))
		in.Snapshot.Lifetime.ThermalFoldbacks = foldbacks
		in.Snapshot.Lifetime.AlertCount = alerts
		return in
	}
	// First sighting with alert_count already 3 sets a baseline only.
	got := run(t, "device_alert_count_up", nil, []sample{{in: at(0, 0, 3)}, {in: at(1, 0, 3)}, {in: at(2, 0, 5)}, {in: at(3, 0, 1)}, {in: at(4, 0, 2)}})
	eq(t, got, []string{"", "", "event:warning", "", "event:warning"})
	got = run(t, "thermal_foldback", nil, []sample{{in: at(0, 0, 0)}, {in: at(1, 1, 0)}})
	eq(t, got, []string{"", "event:warning"})
}

func TestEventCooldown(t *testing.T) {
	reboot := func(at time.Time) Input {
		in := idle(at)
		in.Events = []store.DeviceEvent{{Kind: store.EventReboot, TS: at, Details: map[string]string{"uptime_s": "5"}}}
		return in
	}
	got := run(t, "unexpected_reboot", func(c *Config) { c.Cooldown = time.Hour }, []sample{
		{in: reboot(t0)}, {in: reboot(t0.Add(10 * time.Minute))}, {in: reboot(t0.Add(2 * time.Hour))},
	})
	eq(t, got, []string{"event:info", "event:info(suppressed)", "event:info"})
}

func TestContactorWear(t *testing.T) {
	at := func(n int, cycles int64) Input {
		in := idle(t0.Add(time.Duration(n) * time.Hour))
		in.Snapshot.Lifetime.ContactorCyclesLoaded = cycles
		return in
	}
	got := run(t, "contactor_wear", func(c *Config) { c.Params["milestone"] = 100 }, []sample{
		{in: at(0, 95)}, {in: at(1, 99)}, {in: at(2, 101)}, {in: at(3, 150)}, {in: at(4, 205)},
	})
	eq(t, got, []string{"", "", "event:info", "", "event:info"})
}

func TestRuleEvaluations(t *testing.T) {
	h := time.Hour
	type tc struct {
		rule string
		in   Input
		want Severity
		skip bool
	}
	mod := func(in Input, f func(*Input)) Input { f(&in); return in }
	cases := []tc{
		{"grid_voltage_out_of_range", idle(t0), None, false},
		{"grid_voltage_out_of_range", scenario("grid-low-voltage", 0, t0), Critical, false},
		{"grid_voltage_out_of_range", mod(idle(t0), func(i *Input) { i.Snapshot.Vitals.GridV = 254 }), Warning, false},
		{"grid_freq_out_of_range", scenario("grid-low-voltage", 0, t0), Warning, false},
		{"grid_freq_out_of_range", idle(t0), None, false},
		{"overcurrent", scenario("overcurrent", time.Minute, t0), Critical, false},
		{"overcurrent", scenario("charging", time.Minute, t0), None, false},
		{"overcurrent", mod(scenario("overcurrent", time.Minute, t0), func(i *Input) { i.Device.MaxCurrentA = 0 }), None, true},
		{"current_near_limit", mod(scenario("charging", time.Minute, t0), func(i *Input) { i.Snapshot.Vitals.VehicleCurrentA = 48.5 }), Info, false},
		{"charging_stalled", mod(scenario("charging", time.Minute, t0), func(i *Input) { i.Snapshot.Vitals.VehicleCurrentA = 0.2 }), Info, false},
		{"charging_stalled", scenario("charging", time.Minute, t0), None, false},
		{"device_alert_active", scenario("device-alert", 0, t0), Warning, false},
		{"device_alert_active", idle(t0), None, false},
		{"not_ready_reasons", idle(t0), None, false}, // [2,4,8] while unplugged is normal
		{"not_ready_reasons", mod(idle(t0), func(i *Input) { i.Snapshot.Vitals.VehicleConnected = true }), Warning, false},
		{"wifi_no_internet", scenario("wifi-weak", 0, t0), Info, false},
		{"wifi_weak", scenario("wifi-weak", 0, t0), Info, false},
		{"pcba_temp_high", scenario("overheat", 20*time.Minute, t0), Warning, false},
		{"pcba_temp_high", scenario("overheat", 30*time.Minute, t0), Critical, false},
		{"mcu_temp_high", idle(t0), None, false},
		{"phase_current_imbalance", scenario("charging", time.Minute, t0), None, true}, // split-phase: n/a
		{"phase_current_imbalance", mod(scenario("charging", time.Minute, t0), func(i *Input) {
			i.Device.NominalVoltageV = 400
			i.Snapshot.Vitals.CurrentCA = 20
		}), Info, false},
		{"relay_voltage_abnormal", idle(t0), None, false},
		{"relay_voltage_abnormal", mod(idle(t0), func(i *Input) { v := 5.0; i.Snapshot.Vitals.RelayK1V = &v }), Warning, false},
		{"relay_voltage_abnormal", mod(scenario("charging", time.Minute, t0), func(i *Input) { v := 6.0; i.Snapshot.Vitals.RelayK2V = &v }), Warning, false},
		{"relay_voltage_abnormal", scenario("charging", time.Minute, t0), None, false},
		{"device_unreachable", idle(t0.Add(h)), None, false},
	}
	for _, c := range cases {
		def := mustRule(t, c.rule)
		res := def.Eval(c.in, def.DefaultConfig().Params, newState())
		if res.Skip != c.skip || (!c.skip && res.Severity != c.want) {
			t.Errorf("%s: got severity=%v skip=%v (%s), want %v skip=%v", c.rule, res.Severity, res.Skip, res.Message, c.want, c.skip)
		}
	}
}

func TestDeviceEventRules(t *testing.T) {
	in := idle(t0)
	in.Events = []store.DeviceEvent{
		{Kind: store.EventFirmwareChanged, Details: map[string]string{"from": "26.26.10", "to": "26.30.4"}},
		{Kind: store.EventGridProfileChanged, Details: map[string]string{"vf_trips_from": "A", "vf_trips_to": "B"}},
		{Kind: store.EventIdentityMismatch, Details: map[string]string{"serial": "••01", "previous_serial": "••02"}},
	}
	for key, want := range map[string]string{
		"firmware_changed":     "26.26.10 to 26.30.4",
		"grid_profile_changed": "VfTrips A→B",
		"identity_mismatch":    "check the IP address",
		"unexpected_reboot":    "",
	} {
		def := mustRule(t, key)
		res := def.Eval(in, nil, newState())
		if want == "" {
			if len(res.Hits) != 0 {
				t.Errorf("%s: unexpected hits", key)
			}
			continue
		}
		if len(res.Hits) != 1 || !strings.Contains(res.Hits[0].Message, want) {
			t.Errorf("%s: hits = %+v", key, res.Hits)
		}
	}
}

func TestDefinitionsAreValid(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range Definitions() {
		if seen[d.Key] {
			t.Errorf("duplicate rule %s", d.Key)
		}
		seen[d.Key] = true
		if d.Title == "" || d.Description == "" || d.Eval == nil {
			t.Errorf("rule %s incomplete", d.Key)
		}
		if err := d.Validate(d.DefaultConfig()); err != nil {
			t.Errorf("rule %s defaults invalid: %v", d.Key, err)
		}
		if d.NeedsCalibration && d.Defaults.Enabled {
			t.Errorf("rule %s needs calibration and must ship disabled", d.Key)
		}
	}
	d := mustRule(t, "handle_temp_high")
	bad := []func(*Config){
		func(c *Config) { c.Params["warn_c"] = 200 },
		func(c *Config) { c.Params["warn_c"], c.Params["crit_c"] = 80, 70 },
		func(c *Config) { c.Params["nope"] = 1 },
		func(c *Config) { c.Repeat = time.Minute },
		func(c *Config) { c.MinSamples = 0 },
		func(c *Config) { c.For = 48 * time.Hour },
	}
	for i, m := range bad {
		c := d.DefaultConfig()
		m(&c)
		if d.Validate(c) == nil {
			t.Errorf("bad config %d accepted", i)
		}
	}
}

func TestQuietHours(t *testing.T) {
	q, err := ParseQuietHours("22:00-07:00")
	if err != nil {
		t.Fatal(err)
	}
	loc := time.FixedZone("CST", -6*3600)
	at := func(h, m int) time.Time { return time.Date(2026, 11, 2, h, m, 0, 0, loc) }
	for _, c := range []struct {
		t      time.Time
		active bool
	}{{at(21, 59), false}, {at(22, 0), true}, {at(3, 0), true}, {at(6, 59), true}, {at(7, 0), false}, {at(12, 0), false}} {
		if q.Active(c.t) != c.active {
			t.Errorf("Active(%v) = %v", c.t, !c.active)
		}
	}
	if q.Allows(Warning, at(23, 0)) || !q.Allows(Critical, at(23, 0)) || !q.Allows(Info, at(12, 0)) {
		t.Error("Allows wrong")
	}
	day, _ := ParseQuietHours("09:30-17:00")
	if !day.Active(at(10, 0)) || day.Active(at(18, 0)) {
		t.Error("daytime window wrong")
	}
	if (QuietHours{}).Active(at(23, 0)) {
		t.Error("disabled quiet hours active")
	}
	for _, s := range []string{"", "25:00-07:00", "22:00-22:00", "22-7", "10:61-11:00"} {
		if _, err := ParseQuietHours(s); err == nil {
			t.Errorf("ParseQuietHours(%q) accepted", s)
		}
	}
}

func TestSeverityJSON(t *testing.T) {
	b, _ := Critical.MarshalJSON()
	var s Severity
	if err := s.UnmarshalJSON(b); err != nil || s != Critical || string(b) != `"critical"` {
		t.Errorf("round trip %s -> %v %v", b, s, err)
	}
	if err := s.UnmarshalJSON([]byte(`"loud"`)); err == nil {
		t.Error("bad severity accepted")
	}
}
