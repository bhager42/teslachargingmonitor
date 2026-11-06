// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package wcsim simulates a Tesla Universal Wall Connector's local API for
// development and tests. Scenarios (idle, charging, overheating, offline, …)
// evolve with simulated time so alert rules can be exercised end to end.
//
// The idle baseline and the charging values reproduce the real UWC fixtures
// (firmware 26.26.10). Plugged-in-but-not-charging was captured on fw 26.34.0
// (testdata/fixtures/uwc/26.34.0) but has no scenario yet.
package wcsim

import "github.com/bhager42/teslachargingmonitor/internal/wallconnector"

// State is everything the simulated device reports.
type State struct {
	Version    wallconnector.Version
	Vitals     wallconnector.Vitals
	Lifetime   wallconnector.Lifetime
	WifiStatus wallconnector.WifiStatus
}

func f64(v float64) *float64 { return &v }

// Baseline returns the idle, unplugged UWC exactly as captured in
// testdata/fixtures/uwc/26.26.10 (identifiers redacted).
func Baseline() State {
	return State{
		Version: wallconnector.Version{
			FirmwareVersion:                       "26.26.10+g42855ec9b9cd1",
			GitBranch:                             "HEAD",
			PartNumber:                            "1734412-52-F",
			SerialNumber:                          "REDACTED00000",
			WebService:                            "h3-hermes-prd.sn.tesla.services",
			IEEE1547VfTripsCrc:                    "BB5EABC5",
			IEEE1547RideThruMomentaryCessationCrc: "753C17D3",
			IEEE1547CombinedComplianceCrc:         "81DD267F",
		},
		Vitals: wallconnector.Vitals{
			GridV:               240.1,
			GridHz:              59.798,
			VoltageAV:           0.1,
			VoltageCV:           0.1,
			RelayK1V:            f64(0),
			RelayK2V:            f64(0),
			PCBATempC:           22.2,
			HandleTempC:         20.1,
			MCUTempC:            28.7,
			UptimeS:             16,
			InputThermopileUV:   -827,
			PilotHighV:          12.0,
			PilotLowV:           12.0,
			ConfigStatus:        5,
			EVSEState:           1,
			CurrentAlerts:       []int{},
			EVSENotReadyReasons: []int{2, 4, 8},
		},
		Lifetime: wallconnector.Lifetime{
			ContactorCycles:       42,
			ContactorCyclesLoaded: 3,
			AlertCount:            3,
			ChargeStarts:          42,
			EnergyWh:              433293,
			ConnectorCycles:       24,
			UptimeS:               1695417,
			ChargingTimeS:         137862,
		},
		WifiStatus: wallconnector.WifiStatus{
			WifiSSIDBase64:     "UkVEQUNURUQ=",
			WifiSignalStrength: 86,
			WifiRSSI:           -47,
			WifiSNR:            35,
			WifiConnected:      true,
			WifiInfraIP:        "192.0.2.17",
			Internet:           true,
			WifiMAC:            "02:00:00:00:00:00",
		},
	}
}
