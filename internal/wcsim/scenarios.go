// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package wcsim

import (
	"math"
	"slices"
	"time"
)

// Behavior is how the simulated device answers HTTP requests.
type Behavior int

// Behaviors.
const (
	Normal    Behavior = iota // 200 with the scenario's JSON
	Offline                   // connection is dropped without a response
	Slow                      // response delayed past the client timeout
	Malformed                 // 200 with invalid JSON
)

// Scenario evolves the device state over simulated elapsed time.
type Scenario struct {
	Name        string
	Description string
	// Provisional marks scenarios that depend on charging-state values not
	// yet verified on real hardware.
	Provisional bool
	State       func(elapsed time.Duration) (State, Behavior)
}

// EventAfter is the simulated time after which one-off events (reboot,
// firmware change, foldback) happen in the scenarios that have them.
const EventAfter = 10 * time.Minute

// Owner's installation: 60 A circuit, 48 A max charging current, 240 V.
const (
	chargeCurrentA = 47.9
	chargeVoltage  = 239.4
)

var scenarios = []Scenario{
	{
		Name:        "idle",
		Description: "Unplugged and idle — the real UWC capture.",
		State: func(e time.Duration) (State, Behavior) {
			s := Baseline()
			tick(&s, e)
			return s, Normal
		},
	},
	{
		Name:        "charging",
		Description: "Charging at 48 A with gently rising temperatures.",
		Provisional: true,
		State: func(e time.Duration) (State, Behavior) {
			s := charging(e, chargeCurrentA)
			return s, Normal
		},
	},
	{
		Name:        "overheat",
		Description: "Charging while the handle and PCBA heat ~2 °C/min up to 90 °C.",
		Provisional: true,
		State: func(e time.Duration) (State, Behavior) {
			s := charging(e, chargeCurrentA)
			rise := math.Min(e.Minutes()*2, 60)
			s.Vitals.HandleTempC = round1(30 + rise)
			s.Vitals.PCBATempC = round1(35 + rise*0.9)
			return s, Normal
		},
	},
	{
		Name:        "thermal-foldback",
		Description: "Charging; after 10 min a thermal foldback halves the current and increments the counter.",
		Provisional: true,
		State: func(e time.Duration) (State, Behavior) {
			if e < EventAfter {
				s := charging(e, chargeCurrentA)
				s.Vitals.HandleTempC = 62
				return s, Normal
			}
			s := charging(e, chargeCurrentA/2)
			s.Vitals.HandleTempC = 71
			s.Lifetime.ThermalFoldbacks++
			return s, Normal
		},
	},
	{
		Name:        "device-alert",
		Description: "Idle with a synthetic device alert code (255) and an increased lifetime alert count.",
		State: func(e time.Duration) (State, Behavior) {
			s := Baseline()
			tick(&s, e)
			s.Vitals.CurrentAlerts = []int{255}
			s.Lifetime.AlertCount++
			return s, Normal
		},
	},
	{
		Name:        "grid-low-voltage",
		Description: "Idle with grid voltage sagging to 211 V (−12 %) and frequency at 59.3 Hz.",
		State: func(e time.Duration) (State, Behavior) {
			s := Baseline()
			tick(&s, e)
			s.Vitals.GridV = 211.0
			s.Vitals.GridHz = 59.3
			return s, Normal
		},
	},
	{
		Name:        "overcurrent",
		Description: "Charging at 52 A, above the 48 A limit plus 5 %.",
		Provisional: true,
		State: func(e time.Duration) (State, Behavior) {
			return charging(e, 52.0), Normal
		},
	},
	{
		Name:        "reboot",
		Description: "Idle; the device reboots every 10 min (uptime resets).",
		State: func(e time.Duration) (State, Behavior) {
			s := Baseline()
			tick(&s, e)
			s.Vitals.UptimeS = int64((e % EventAfter).Seconds())
			return s, Normal
		},
	},
	{
		Name:        "firmware-change",
		Description: "Idle; after 10 min the firmware and the IEEE 1547 grid profile change.",
		State: func(e time.Duration) (State, Behavior) {
			s := Baseline()
			tick(&s, e)
			if e >= EventAfter {
				s.Version.FirmwareVersion = "26.30.4+g0000000sim"
				s.Version.IEEE1547VfTripsCrc = "0BADC0DE"
				s.Vitals.UptimeS = int64((e - EventAfter).Seconds())
			}
			return s, Normal
		},
	},
	{
		Name:        "wifi-weak",
		Description: "Idle with a weak Wi-Fi signal (−82 dBm) and no internet.",
		State: func(e time.Duration) (State, Behavior) {
			s := Baseline()
			tick(&s, e)
			s.WifiStatus.WifiRSSI = -82
			s.WifiStatus.WifiSignalStrength = 18
			s.WifiStatus.WifiSNR = 6
			s.WifiStatus.Internet = false
			return s, Normal
		},
	},
	{
		Name:        "offline",
		Description: "Device unreachable: connections are dropped.",
		State:       func(time.Duration) (State, Behavior) { return Baseline(), Offline },
	},
	{
		Name:        "slow",
		Description: "Device answers slower than the client timeout.",
		State:       func(time.Duration) (State, Behavior) { return Baseline(), Slow },
	},
	{
		Name:        "malformed",
		Description: "Device returns truncated, invalid JSON.",
		State:       func(time.Duration) (State, Behavior) { return Baseline(), Malformed },
	},
}

// Scenarios returns all scenarios in display order.
func Scenarios() []Scenario { return slices.Clone(scenarios) }

// Lookup finds a scenario by name.
func Lookup(name string) (Scenario, bool) {
	i := slices.IndexFunc(scenarios, func(s Scenario) bool { return s.Name == name })
	if i < 0 {
		return Scenario{}, false
	}
	return scenarios[i], true
}

// tick advances clocks that move in every scenario.
func tick(s *State, e time.Duration) {
	secs := int64(e.Seconds())
	s.Vitals.UptimeS += secs
	s.Lifetime.UptimeS += secs
}

// charging builds a PROVISIONAL charging state at the given current.
func charging(e time.Duration, amps float64) State {
	s := Baseline()
	tick(&s, e)
	secs := e.Seconds()
	wh := chargeVoltage * amps * secs / 3600

	v := &s.Vitals
	v.VehicleConnected = true
	v.ContactorClosed = true
	v.SessionS = int64(secs)
	v.GridV = chargeVoltage
	v.VehicleCurrentA = amps
	v.CurrentAA = amps
	v.CurrentBA = amps
	v.VoltageAV = chargeVoltage / 2
	v.VoltageBV = chargeVoltage / 2
	v.VoltageCV = 0
	v.RelayK1V = f64(11.9) // provisional
	v.RelayK2V = f64(11.9) // provisional
	v.PilotHighV = 6.0     // J1772 state C
	v.PilotLowV = -12.0
	v.ProxV = 1.5
	v.EVSEState = 11 // provisional: Gen 3 reports 11 while charging
	v.EVSENotReadyReasons = []int{}
	v.SessionEnergyWh = round1(wh)
	v.HandleTempC = round1(20.1 + 15*(1-math.Exp(-e.Minutes()/30)))
	v.PCBATempC = round1(22.2 + 18*(1-math.Exp(-e.Minutes()/30)))
	v.MCUTempC = round1(28.7 + 8*(1-math.Exp(-e.Minutes()/30)))

	l := &s.Lifetime
	l.ChargeStarts++
	l.ContactorCycles++
	l.ContactorCyclesLoaded++
	l.ConnectorCycles++
	l.EnergyWh += int64(wh)
	l.ChargingTimeS += int64(secs)
	return s
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }
