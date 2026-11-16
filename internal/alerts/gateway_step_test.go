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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/poller"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

func gwStore() store.Gateway {
	g := store.NewGateway("Powerwall", "192.168.1.20", strings.Repeat("ab", 32), nil)
	g.ID = 7
	return g
}

// gwOK is a successful Gateway poll like the owner's capture (day, grid
// connected, battery raw 35 %, solar 3730 W), adjusted by mod.
func gwOK(at time.Time, mod func(*gateway.Snapshot)) Input {
	s := &gateway.Snapshot{FetchedAt: at, Reports: map[gateway.Endpoint]gateway.Report{}}
	s.Status.Version, s.Status.UpTimeSeconds = "26.34.2 56d7ba06", "420h"
	s.Aggregates.Solar.InstantPower, s.Aggregates.Solar.EnergyExported = 3730, 46977764
	s.Aggregates.Load.InstantPower, s.Aggregates.Site.InstantPower, s.Aggregates.Battery.InstantPower = 2380, -49, -1290
	s.SOE.Percentage = 35
	s.GridStatus.GridStatus = gateway.GridConnected
	s.SystemStatus.NominalFullPackEnergy = 27217
	s.SystemStatus.BatteryBlocks = make([]gateway.BatteryBlock, 2)
	if mod != nil {
		mod(s)
	}
	return Input{At: at, Gateway: gwStore(), GatewaySnap: s, Loc: time.UTC}
}

func gwErr(at time.Time, err error) Input {
	return Input{At: at, Gateway: gwStore(), Err: err, Loc: time.UTC}
}

func soe(raw float64) func(*gateway.Snapshot) {
	return func(s *gateway.Snapshot) { s.SOE.Percentage = raw }
}

func islanded(raw float64) func(*gateway.Snapshot) {
	return func(s *gateway.Snapshot) {
		s.SOE.Percentage = raw
		s.GridStatus.GridStatus = "SystemIslandedActive"
	}
}

func at(h int) time.Time { return t0.Add(time.Duration(h) * time.Hour) }

var (
	errNet      = errors.New("gateway: GET /api/status: connection refused")
	rejected    = &gateway.BackoffError{Until: t0.Add(5 * time.Minute), Cause: gateway.ErrLoginRejected}
	rateLimited = &gateway.BackoffError{Until: t0.Add(5 * time.Minute), Cause: gateway.ErrRateLimited}
	certErr     = &gateway.CertError{Fingerprint: strings.Repeat("cd", 32)}
	errConfig   = fmt.Errorf("%w: decrypt failed", poller.ErrGatewayConfig)
)

func TestGatewayRulesAreGatewayOnly(t *testing.T) {
	for _, key := range []string{"gateway_unreachable", "gateway_auth_failed", "gateway_cert_changed", "grid_outage",
		"battery_low", "solar_zero_daytime", "solar_production_low", "battery_capacity_drop",
		"gateway_firmware_changed", "gateway_reboot"} {
		def := mustRule(t, key)
		if def.Subject != SubjectGateway {
			t.Errorf("%s is not a Gateway rule", key)
		}
		if err := def.Validate(def.DefaultConfig()); err != nil {
			t.Errorf("%s defaults: %v", key, err)
		}
	}
	if mustRule(t, "device_unreachable").Subject != SubjectDevice {
		t.Error("device_unreachable is not a device rule")
	}
	enabled := map[string]bool{}
	for _, d := range Definitions() {
		enabled[d.Key] = d.DefaultConfig().Enabled
	}
	if enabled["solar_production_low"] || !enabled["grid_outage"] {
		t.Error("plan defaults: solar_production_low off, the rest on")
	}
}

func TestGatewayUnreachable(t *testing.T) {
	eq(t, run(t, "gateway_unreachable", nil, []sample{
		{in: gwErr(at(0), errNet)},
		{in: gwErr(at(1), errNet)},
		{in: gwErr(at(2), errNet)},
		{in: gwErr(at(3), errConfig)}, // not polled: no change
		{in: gwErr(at(4), rejected)},  // it answered
	}), []string{"firing:warning", "", "escalated:critical", "", "resolved:critical"})
}

func TestGatewayAuthFailed(t *testing.T) {
	eq(t, run(t, "gateway_auth_failed", nil, []sample{
		{in: gwOK(at(0), nil)},
		{in: gwErr(at(1), rejected)},
		{in: gwErr(at(2), errNet)}, // unknown: keep firing
		{in: gwErr(at(3), rateLimited)},
		{in: gwOK(at(4), nil)},
		{in: gwErr(at(5), errConfig)},
	}), []string{"", "firing:critical", "", "", "resolved:critical", "firing:critical"})

	def := mustRule(t, "gateway_auth_failed")
	for err, want := range map[error]string{rejected: "rejected the customer password", rateLimited: "limiting logins",
		errConfig: "cannot use the stored"} {
		r := def.Eval(gwErr(t0, err), def.DefaultConfig().Params, newState())
		if !strings.Contains(r.Message, want) || strings.Contains(r.Message, "{") {
			t.Errorf("%v: message %q", err, r.Message)
		}
	}
}

func TestGatewayCertChanged(t *testing.T) {
	eq(t, run(t, "gateway_cert_changed", nil, []sample{
		{in: gwErr(at(0), certErr)},
		{in: gwErr(at(1), certErr)},
		{in: gwOK(at(2), nil)},
	}), []string{"firing:critical", "", "resolved:critical"})
	def := mustRule(t, "gateway_cert_changed")
	r := def.Eval(gwErr(t0, certErr), nil, newState())
	if !strings.Contains(r.Message, certErr.Fingerprint) || !strings.Contains(r.Message, "accept-cert 7") {
		t.Errorf("message %q", r.Message)
	}
}

func TestGridOutage(t *testing.T) {
	got := run(t, "grid_outage", nil, []sample{
		{in: gwOK(at(0), nil)},
		{in: gwOK(at(1), islanded(80))},
		{in: gwOK(at(2), islanded(70))},
		{in: gwOK(at(3), func(s *gateway.Snapshot) { // flagged: no verdict
			s.GridStatus.GridStatus = ""
			s.Reports[gateway.EndpointGridStatus] = gateway.Report{Missing: []string{"grid_status"}}
		})},
		{in: gwOK(at(4), nil)},
	})
	eq(t, got, []string{"", "firing:warning", "", "", "resolved:warning"})
	def := mustRule(t, "grid_outage")
	if r := def.Eval(gwOK(t0, islanded(80)), nil, newState()); !strings.Contains(r.Message, "Battery at 79 %") {
		t.Errorf("message %q (want the app's battery %%)", r.Message)
	}
}

func TestBatteryLow(t *testing.T) {
	// App % = (raw − 5) / 0.95: raw 20 → 15.8 %, raw 25 → 21.1 %, raw 30 → 26.3 %.
	eq(t, run(t, "battery_low", nil, []sample{
		{in: gwOK(at(0), soe(30))},
		{in: gwOK(at(1), soe(20))},      // 1 of 2 samples
		{in: gwOK(at(2), soe(20))},      // fires: info
		{in: gwOK(at(3), islanded(20))}, // grid down: warning
		{in: gwOK(at(4), soe(25))},      // 21.1 % < 20 + 2 hysteresis: still low
		{in: gwOK(at(5), soe(30))},
	}), []string{"", "", "firing:info", "escalated:warning", "", "resolved:info"})
}

func TestSolarZeroDaytime(t *testing.T) {
	dark := func(s *gateway.Snapshot) { s.Aggregates.Solar.InstantPower = 0 }
	day := time.Date(2026, 6, 20, 0, 0, 0, 0, time.UTC)
	h := func(hour int, mod func(*gateway.Snapshot)) sample {
		return sample{in: gwOK(day.Add(time.Duration(hour)*time.Hour), mod)}
	}
	// Hourly samples (polls are every 15 min; a gap of "for" or more would
	// fire on one breaching sample, as for every condition rule).
	eq(t, run(t, "solar_zero_daytime", nil, []sample{
		h(8, dark), h(9, dark), // before the window
		h(10, dark), // breach starts
		h(11, dark),
		h(12, dark), // 2 h: fires
		h(13, dark),
		h(15, dark), // window over: ends quietly
		h(33, dark), // next day 09:00
		h(34, dark), // a new breach, not yesterday's
		h(35, dark),
		h(36, dark),
	}), []string{"", "", "", "", "firing:warning", "", "", "", "", "", "firing:warning"})
	eq(t, run(t, "solar_zero_daytime", nil, []sample{h(10, dark), h(11, nil), h(12, dark), h(13, dark)}),
		[]string{"firing:warning", "", "", ""})
	if err := mustRule(t, "solar_zero_daytime").Validate(Config{MinSamples: 1, Params: Params{"start_h": 15, "end_h": 10, "min_w": 50}}); err == nil {
		t.Error("a window ending before it starts was accepted")
	}
}

func TestSolarProductionLow(t *testing.T) {
	enable := func(c *Config) { c.Enabled = true }
	day := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	counter := 4e7
	var samples []sample
	poll := func(d int, h, m int, add float64) {
		counter += add
		v := counter
		samples = append(samples, sample{in: gwOK(day.AddDate(0, 0, d).Add(time.Duration(h)*time.Hour+time.Duration(m)*time.Minute),
			func(s *gateway.Snapshot) { s.Aggregates.Solar.EnergyExported = v })})
	}
	poll(0, 12, 0, 0) // tcmon starts mid-day 0: day 0 is partial
	for d := 1; d <= 8; d++ {
		poll(d, 0, 30, 0)
		poll(d, 12, 0, 20000)
	}
	poll(9, 0, 30, 0)
	poll(9, 12, 0, 4000) // a dull day 9
	poll(10, 0, 30, 0)   // closes day 9
	got := run(t, "solar_production_low", enable, samples)
	want := make([]string, len(samples))
	want[len(want)-1] = "event:info"
	eq(t, got, want)

	def := mustRule(t, "solar_production_low")
	st := newState()
	cfg := def.DefaultConfig()
	var last Result
	for _, s := range samples {
		last = def.Eval(s.in, cfg.Params, st)
	}
	if len(last.Hits) != 1 || !strings.Contains(last.Hits[0].Message, "4.0 kWh on Wed 10 Jun, 20 % of the usual 20.0 kWh") {
		t.Errorf("hit = %+v", last.Hits)
	}

	// A counter reset or a missed day makes the day unknowable, not low.
	reset := append([]sample{}, samples[:len(samples)-2]...)
	reset = append(reset, sample{in: gwOK(day.AddDate(0, 0, 9).Add(12*time.Hour),
		func(s *gateway.Snapshot) { s.Aggregates.Solar.EnergyExported = 100 })})
	reset = append(reset, sample{in: gwOK(day.AddDate(0, 0, 10).Add(30*time.Minute),
		func(s *gateway.Snapshot) { s.Aggregates.Solar.EnergyExported = 200 })})
	if got := run(t, "solar_production_low", enable, reset); got[len(got)-1] != "" {
		t.Errorf("reset day alerted: %q", got[len(got)-1])
	}
	gap := append([]sample{}, samples[:len(samples)-1]...)
	gap = append(gap, sample{in: gwOK(day.AddDate(0, 0, 12).Add(30*time.Minute),
		func(s *gateway.Snapshot) { s.Aggregates.Solar.EnergyExported = counter })})
	if got := run(t, "solar_production_low", enable, gap); got[len(got)-1] != "" {
		t.Errorf("a multi-day gap alerted: %q", got[len(got)-1])
	}
}

func TestBatteryCapacityDrop(t *testing.T) {
	full := func(wh float64, blocks int) func(*gateway.Snapshot) {
		return func(s *gateway.Snapshot) {
			s.SystemStatus.NominalFullPackEnergy = wh
			s.SystemStatus.BatteryBlocks = make([]gateway.BatteryBlock, blocks)
		}
	}
	eq(t, run(t, "battery_capacity_drop", nil, []sample{
		{in: gwOK(at(0), full(27217, 2))}, // baseline
		{in: gwOK(at(1), full(26000, 2))}, // 95.5 %
		{in: gwOK(at(2), full(21000, 2))}, // 77 %: 1 of 3
		{in: gwOK(at(3), full(21000, 2))},
		{in: gwOK(at(4), full(21000, 2))}, // fires
		{in: gwOK(at(5), full(13000, 1))}, // a Powerwall removed: new baseline
		{in: gwOK(at(6), full(13000, 1))},
	}), []string{"", "", "", "", "firing:info", "resolved:info", ""})
}

func TestGatewayEventRules(t *testing.T) {
	in := gwOK(t0, nil)
	in.GatewayEvents = []store.GatewayEvent{
		{TS: t0, Kind: store.GatewayEventFirmwareChanged, Details: map[string]string{"from": "26.30.1", "to": "26.34.2"}},
		{TS: t0, Kind: store.GatewayEventReboot, Details: map[string]string{"uptime_s": "300"}},
		{TS: t0, Kind: store.GatewayEventGridChanged},
	}
	fw := mustRule(t, "gateway_firmware_changed").Eval(in, nil, newState())
	rb := mustRule(t, "gateway_reboot").Eval(in, nil, newState())
	if len(fw.Hits) != 1 || fw.Hits[0].Message != "Backup Gateway firmware changed from 26.30.1 to 26.34.2" {
		t.Errorf("firmware hits = %+v", fw.Hits)
	}
	if len(rb.Hits) != 1 || !strings.Contains(rb.Hits[0].Message, "5m0s ago") {
		t.Errorf("reboot hits = %+v", rb.Hits)
	}
}
