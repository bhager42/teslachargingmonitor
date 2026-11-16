// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package gateway

import (
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"time"
)

// Struct tags, as in internal/wallconnector:
//
//	json:"name"            the Gateway's field name
//	gw:"optional"          absence is normal
//	gw:"range=MIN:MAX"     physically plausible range; values outside it are
//	                       kept but reported as invalid
//
// Nested structs and slices of structs are decoded recursively; problems
// are reported with dotted paths ("site.instant_power",
// "battery_blocks[1].nominal_full_pack_energy"). Keys a type knows about
// but deliberately does not model are listed by its ignoredKeys method so
// they are not reported as unknown.
//
// Field meanings were verified on the owner's Gateway (firmware 26.34.2,
// testdata/fixtures/gateway); see the Phase 9 verification table in
// docs/DEVELOPMENT_PLAN.md.

// Status is GET /api/status, the only endpoint that needs no login.
type Status struct {
	DIN             string `json:"din"` // contains the serial number: never log it
	Version         string `json:"version"`
	GitHash         string `json:"git_hash" gw:"optional"`
	DeviceType      string `json:"device_type" gw:"optional"`
	UpTimeSeconds   string `json:"up_time_seconds"` // a Go duration string, e.g. "420h27m56.4s"
	CommissionCount int    `json:"commission_count" gw:"optional"`
}

func (Status) ignoredKeys() []string {
	// start_time uses a fixed +0800 offset unrelated to the site's zone.
	return []string{"can_reboot", "cellular_disabled", "is_new", "start_time", "sync_type", "teg_type"}
}

var reFirmware = regexp.MustCompile(`^\d+(\.\d+){1,3}`)

// Firmware returns the version number without the build suffix
// ("26.34.2 56d7ba06" → "26.34.2"), or "" when it has an unexpected form.
func (s Status) Firmware() string { return reFirmware.FindString(s.Version) }

// ErrBadUptime means up_time_seconds is not a valid, non-negative duration.
var ErrBadUptime = errors.New("gateway: up_time_seconds is not a valid duration")

// Uptime parses UpTimeSeconds.
func (s Status) Uptime() (time.Duration, error) {
	d, err := time.ParseDuration(s.UpTimeSeconds)
	if err != nil || d < 0 {
		return 0, ErrBadUptime
	}
	return d, nil
}

// Meter is one entry of /api/meters/aggregates. Power is in watts and the
// energy counters are lifetime watt-hours. Signs: site < 0 means exporting
// to the grid, battery < 0 means charging the Powerwalls.
type Meter struct {
	InstantPower          float64 `json:"instant_power" gw:"range=-1000000:1000000"`
	EnergyImported        float64 `json:"energy_imported" gw:"range=0:1e13"`
	EnergyExported        float64 `json:"energy_exported" gw:"range=0:1e13"`
	InstantAverageVoltage float64 `json:"instant_average_voltage" gw:"optional,range=0:1000"`
	Frequency             float64 `json:"frequency" gw:"optional,range=0:100"`
	LastCommunicationTime string  `json:"last_communication_time" gw:"optional"`
	// NumMetersAggregated is absent from the load meter.
	NumMetersAggregated *int `json:"num_meters_aggregated" gw:"optional,range=0:100"`
}

func (Meter) ignoredKeys() []string {
	return []string{
		"i_a_current", "i_b_current", "i_c_current", "instant_apparent_power",
		"instant_average_current", "instant_reactive_power", "instant_total_current",
		"last_phase_energy_communication_time", "last_phase_power_communication_time",
		"last_phase_voltage_communication_time", "timeout",
	}
}

// Aggregates is GET /api/meters/aggregates. Load is the home, including
// the Wall Connector (owner-confirmed, §15.2 S4).
type Aggregates struct {
	Site    Meter `json:"site"`
	Battery Meter `json:"battery"`
	Load    Meter `json:"load"`
	Solar   Meter `json:"solar"`
}

// SOE is GET /api/system_status/soe.
type SOE struct {
	// Percentage is the raw state of energy, nominal_energy_remaining /
	// nominal_full_pack_energy. The Tesla app shows AppPercent instead.
	Percentage float64 `json:"percentage" gw:"range=0:100"`
}

// AppPercent converts a raw Gateway percentage to the Tesla app's scale,
// which hides the bottom 5 %: (raw − 5) / 0.95, clamped to 0–100. Verified
// with the owner's backup reserve (raw 33.5 = 30 % in the app).
func AppPercent(raw float64) float64 {
	return math.Max(0, math.Min(100, (raw-5)/0.95))
}

// AppPercent returns the battery level as the Tesla app shows it.
func (s SOE) AppPercent() float64 { return AppPercent(s.Percentage) }

// GridConnected is the only grid_status value observed so far. Other values
// (islanded, transitioning) come from community reports and are kept as raw
// strings until a capture confirms them.
const GridConnected = "SystemGridConnected"

// GridStatus is GET /api/system_status/grid_status.
type GridStatus struct {
	GridStatus         string `json:"grid_status"`
	GridServicesActive bool   `json:"grid_services_active" gw:"optional"`
}

// OnGrid reports whether the site is connected to the grid.
func (g GridStatus) OnGrid() bool { return g.GridStatus == GridConnected }

// BatteryBlock is one Powerwall in /api/system_status. Energies are in Wh,
// power in W (p_out < 0 means charging).
type BatteryBlock struct {
	PackagePartNumber      string            `json:"PackagePartNumber"`
	PackageSerialNumber    string            `json:"PackageSerialNumber"` // never log it
	NominalFullPackEnergy  float64           `json:"nominal_full_pack_energy" gw:"range=0:100000"`
	NominalEnergyRemaining float64           `json:"nominal_energy_remaining" gw:"range=0:100000"`
	EnergyCharged          float64           `json:"energy_charged" gw:"optional,range=0:1e12"`
	EnergyDischarged       float64           `json:"energy_discharged" gw:"optional,range=0:1e12"`
	POut                   float64           `json:"p_out" gw:"optional,range=-50000:50000"`
	BackupReady            bool              `json:"backup_ready" gw:"optional"`
	OffGrid                bool              `json:"off_grid" gw:"optional"`
	PinvState              string            `json:"pinv_state" gw:"optional"`
	PinvGridState          string            `json:"pinv_grid_state" gw:"optional"`
	DisabledReasons        []json.RawMessage `json:"disabled_reasons" gw:"optional"`
	Version                string            `json:"version" gw:"optional"`
}

func (BatteryBlock) ignoredKeys() []string {
	return []string{
		"Manufacturer", "OpSeqState", "Type", "charge_power_clamped", "f_out", "i_out",
		"q_out", "v_out", "vf_mode", "wobble_detected",
	}
}

// SystemStatus is GET /api/system_status.
type SystemStatus struct {
	NominalFullPackEnergy  float64           `json:"nominal_full_pack_energy" gw:"range=0:1000000"`
	NominalEnergyRemaining float64           `json:"nominal_energy_remaining" gw:"range=0:1000000"`
	AvailableBlocks        int               `json:"available_blocks" gw:"optional,range=0:100"`
	SystemIslandState      string            `json:"system_island_state" gw:"optional"`
	GridFaults             []json.RawMessage `json:"grid_faults" gw:"optional"`
	BatteryBlocks          []BatteryBlock    `json:"battery_blocks"`
	MaxChargePower         float64           `json:"max_charge_power" gw:"optional,range=0:1000000"`
	MaxDischargePower      float64           `json:"max_discharge_power" gw:"optional,range=0:1000000"`
}

func (SystemStatus) ignoredKeys() []string {
	return []string{
		"all_enable_lines_high", "auxiliary_load", "available_charger_blocks", "battery_target_power",
		"battery_target_reactive_power", "blocks_controlled", "can_reboot", "command_source",
		"expected_energy_remaining", "ffr_power_availability_high", "ffr_power_availability_low",
		"grid_services_power", "hardware_capability_adjusted_charge_power",
		"hardware_capability_charge_power", "hardware_capability_discharge_power",
		"instantaneous_max_apparent_power", "instantaneous_max_charge_power",
		"instantaneous_max_discharge_power", "inverter_nominal_usable_power", "last_toggle_timestamp",
		"load_charge_constraint", "max_apparent_power", "max_power_energy_remaining",
		"max_power_energy_to_be_charged", "max_sustained_ramp_rate", "primary", "score",
		"smart_inv_delta_p", "smart_inv_delta_q", "solar_real_power_limit",
		"system_adjusted_charge_power_capability_design_pf", "system_adjusted_charge_power_capability_unity_pf",
		"system_available_charge_power_design_pf", "system_available_charge_power_unity_pf",
		"system_available_discharge_power_design_pf", "system_available_discharge_power_unity_pf",
		"system_charge_power_capability_design_pf", "system_charge_power_capability_unity_pf",
		"system_discharge_power_capability_design_pf", "system_discharge_power_capability_unity_pf",
	}
}

// Operation is GET /api/operation (display only; tcmon never changes it).
type Operation struct {
	RealMode             string  `json:"real_mode"`
	BackupReservePercent float64 `json:"backup_reserve_percent" gw:"range=0:100"`
}

func (Operation) ignoredKeys() []string {
	return []string{"freq_shift_load_shed_delta_f", "freq_shift_load_shed_soe"}
}

// AppReservePercent returns the backup reserve as the Tesla app shows it.
func (o Operation) AppReservePercent() float64 { return AppPercent(o.BackupReservePercent) }

// Sitemaster is GET /api/sitemaster.
type Sitemaster struct {
	Running bool   `json:"running"`
	Status  string `json:"status" gw:"optional"`
	// ConnectedToTesla is unreliable: it read false on the owner's Gateway
	// while the Tesla app showed live data. Diagnostics only, never alerts.
	ConnectedToTesla bool `json:"connected_to_tesla" gw:"optional"`
}

func (Sitemaster) ignoredKeys() []string { return []string{"can_reboot", "power_supply_mode"} }

// SiteInfo is GET /api/site_info.
type SiteInfo struct {
	NominalSystemEnergyKWh float64 `json:"nominal_system_energy_kWh" gw:"range=0:10000"`
	NominalSystemPowerKW   float64 `json:"nominal_system_power_kW" gw:"optional,range=0:10000"`
	MaxSystemEnergyKWh     float64 `json:"max_system_energy_kWh" gw:"optional,range=0:10000"`
	MaxSystemPowerKW       float64 `json:"max_system_power_kW" gw:"optional,range=0:10000"`
	PanelMaxCurrent        float64 `json:"panel_max_current" gw:"optional,range=0:10000"`
	Timezone               string  `json:"timezone" gw:"optional"`
}

func (SiteInfo) ignoredKeys() []string {
	// site_name and grid_code (country, state, utility) identify the owner.
	return []string{"grid_code", "max_site_meter_power_kW", "min_site_meter_power_kW", "site_name"}
}

// Solar is one entry of GET /api/solars.
type Solar struct {
	Brand            string  `json:"brand" gw:"optional"`
	Model            string  `json:"model" gw:"optional"`
	PowerRatingWatts float64 `json:"power_rating_watts" gw:"range=0:1000000"`
}
