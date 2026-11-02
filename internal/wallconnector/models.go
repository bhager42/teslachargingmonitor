// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package wallconnector

import (
	"encoding/base64"
	"fmt"
)

// Struct tags:
//
//	json:"name"            the device's field name
//	wc:"optional"          absence is normal (model-specific field)
//	wc:"range=MIN:MAX"     physically plausible range; values outside it are
//	                       kept but reported as invalid
//
// Fields without wc:"optional" are reported as missing when absent.

// Vitals is the live state from GET /api/1/vitals.
type Vitals struct {
	ContactorClosed  bool    `json:"contactor_closed"`
	VehicleConnected bool    `json:"vehicle_connected"`
	SessionS         int64   `json:"session_s" wc:"range=0:31622400"`
	GridV            float64 `json:"grid_v" wc:"range=0:600"`
	GridHz           float64 `json:"grid_hz" wc:"range=0:100"`
	VehicleCurrentA  float64 `json:"vehicle_current_a" wc:"range=-5:120"`
	CurrentAA        float64 `json:"currentA_a" wc:"range=-5:120"`
	CurrentBA        float64 `json:"currentB_a" wc:"range=-5:120"`
	CurrentCA        float64 `json:"currentC_a" wc:"range=-5:120"`
	CurrentNA        float64 `json:"currentN_a" wc:"range=-5:120"`
	VoltageAV        float64 `json:"voltageA_v" wc:"range=0:600"`
	VoltageBV        float64 `json:"voltageB_v" wc:"range=0:600"`
	VoltageCV        float64 `json:"voltageC_v" wc:"range=0:600"`
	// RelayK1V and RelayK2V are reported by the Universal Wall Connector.
	RelayK1V *float64 `json:"relay_k1_v,omitempty" wc:"optional,range=-1:60"`
	RelayK2V *float64 `json:"relay_k2_v,omitempty" wc:"optional,range=-1:60"`
	// RelayCoilV is reported by the Gen 3 Wall Connector instead of K1/K2.
	RelayCoilV          *float64 `json:"relay_coil_v,omitempty" wc:"optional,range=-1:60"`
	PCBATempC           float64  `json:"pcba_temp_c" wc:"range=-60:200"`
	HandleTempC         float64  `json:"handle_temp_c" wc:"range=-60:200"`
	MCUTempC            float64  `json:"mcu_temp_c" wc:"range=-60:200"`
	UptimeS             int64    `json:"uptime_s" wc:"range=0:3162240000"`
	InputThermopileUV   int64    `json:"input_thermopile_uv" wc:"range=-10000000:10000000"`
	ProxV               float64  `json:"prox_v" wc:"range=-1:20"`
	PilotHighV          float64  `json:"pilot_high_v" wc:"range=-15:15"`
	PilotLowV           float64  `json:"pilot_low_v" wc:"range=-15:15"`
	SessionEnergyWh     float64  `json:"session_energy_wh" wc:"range=0:10000000"`
	ConfigStatus        int      `json:"config_status"`
	EVSEState           int      `json:"evse_state"`
	CurrentAlerts       []int    `json:"current_alerts"`
	EVSENotReadyReasons []int    `json:"evse_not_ready_reasons"`
}

// Lifetime holds the cumulative counters from GET /api/1/lifetime.
type Lifetime struct {
	ContactorCycles       int64   `json:"contactor_cycles" wc:"range=0:100000000"`
	ContactorCyclesLoaded int64   `json:"contactor_cycles_loaded" wc:"range=0:100000000"`
	AlertCount            int64   `json:"alert_count" wc:"range=0:100000000"`
	ThermalFoldbacks      int64   `json:"thermal_foldbacks" wc:"range=0:100000000"`
	AvgStartupTemp        float64 `json:"avg_startup_temp" wc:"range=-60:200"`
	ChargeStarts          int64   `json:"charge_starts" wc:"range=0:100000000"`
	EnergyWh              int64   `json:"energy_wh" wc:"range=0:100000000000"`
	ConnectorCycles       int64   `json:"connector_cycles" wc:"range=0:100000000"`
	UptimeS               int64   `json:"uptime_s" wc:"range=0:3162240000"`
	ChargingTimeS         int64   `json:"charging_time_s" wc:"range=0:3162240000"`
}

// WifiStatus is the network state from GET /api/1/wifi_status.
type WifiStatus struct {
	// WifiSSIDBase64 is the SSID as sent by the device (base64). Use SSID().
	WifiSSIDBase64     string `json:"wifi_ssid"`
	WifiSignalStrength int    `json:"wifi_signal_strength" wc:"range=0:100"`
	WifiRSSI           int    `json:"wifi_rssi" wc:"range=-127:0"`
	WifiSNR            int    `json:"wifi_snr" wc:"range=-20:100"`
	WifiConnected      bool   `json:"wifi_connected"`
	WifiInfraIP        string `json:"wifi_infra_ip"`
	Internet           bool   `json:"internet"`
	WifiMAC            string `json:"wifi_mac"`
}

// maxSSIDBytes is the 802.11 SSID length limit.
const maxSSIDBytes = 32

// SSID decodes the base64 SSID. The result is untrusted text and must be
// escaped before display.
func (w WifiStatus) SSID() (string, error) {
	if base64.StdEncoding.DecodedLen(len(w.WifiSSIDBase64)) > maxSSIDBytes+3 {
		return "", fmt.Errorf("wifi_ssid too long")
	}
	b, err := base64.StdEncoding.DecodeString(w.WifiSSIDBase64)
	if err != nil {
		return "", fmt.Errorf("wifi_ssid is not valid base64: %w", err)
	}
	if len(b) > maxSSIDBytes {
		return "", fmt.Errorf("wifi_ssid longer than %d bytes", maxSSIDBytes)
	}
	return string(b), nil
}

// Version is the identity block from GET /api/1/version.
type Version struct {
	FirmwareVersion string `json:"firmware_version"`
	GitBranch       string `json:"git_branch" wc:"optional"`
	PartNumber      string `json:"part_number"`
	SerialNumber    string `json:"serial_number"`
	WebService      string `json:"web_service" wc:"optional"`
	// IEEE 1547 grid-interconnection profile checksums (Universal Wall
	// Connector). A change means grid trip / ride-through settings changed.
	IEEE1547VfTripsCrc                    string `json:"IEEE1547VfTripsCrc,omitempty" wc:"optional"`
	IEEE1547RideThruMomentaryCessationCrc string `json:"IEEE1547RideThruMomentaryCessationCrc,omitempty" wc:"optional"`
	IEEE1547CombinedComplianceCrc         string `json:"IEEE1547CombinedComplianceCrc,omitempty" wc:"optional"`
}

// Firmware parses FirmwareVersion.
func (v Version) Firmware() (FirmwareVersion, error) { return ParseFirmware(v.FirmwareVersion) }

// GridProfile returns the IEEE 1547 CRCs as one comparable value.
func (v Version) GridProfile() GridProfile {
	return GridProfile{
		VfTrips:            v.IEEE1547VfTripsCrc,
		RideThru:           v.IEEE1547RideThruMomentaryCessationCrc,
		CombinedCompliance: v.IEEE1547CombinedComplianceCrc,
	}
}

// GridProfile identifies the device's grid-interconnection configuration.
type GridProfile struct {
	VfTrips, RideThru, CombinedCompliance string
}

// IsZero reports whether the device did not report any IEEE 1547 CRC.
func (g GridProfile) IsZero() bool { return g == GridProfile{} }

// MaskSerial hides all but the last four characters of a serial number.
func MaskSerial(s string) string {
	r := []rune(s)
	if len(r) <= 4 {
		return "••••"
	}
	masked := make([]rune, 0, len(r))
	for range r[:len(r)-4] {
		masked = append(masked, '•')
	}
	return string(append(masked, r[len(r)-4:]...))
}
