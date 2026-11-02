// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

// DeviceInfo is the identity last reported by a device.
type DeviceInfo struct {
	DeviceID        int64
	FirmwareVersion string
	GitBranch       string
	PartNumber      string
	SerialNumber    string
	WebService      string
	GridProfile     wallconnector.GridProfile
	FirstSeen       time.Time
	LastSeen        time.Time
}

// DeviceEvent is a device-reported change detected by the poller.
type DeviceEvent struct {
	ID       int64
	DeviceID int64
	TS       time.Time
	Kind     string
	Details  map[string]string
}

// Event kinds.
const (
	EventReboot             = "reboot"
	EventFirmwareChanged    = "firmware_changed"
	EventGridProfileChanged = "grid_profile_changed"
	EventIdentityMismatch   = "identity_mismatch"
)

// DeviceState is what the poller needs to know about the previous poll.
type DeviceState struct {
	Info        *DeviceInfo // nil until the first successful poll
	LastSuccess time.Time   // zero if never
	LastUptimeS int64
	HasUptime   bool
	LastPlugged bool
}

// field returns v, or nil (SQL NULL) when the decoder flagged the field.
func field(rep wallconnector.Report, name string, v any) any {
	if rep.IsInvalid(name) || rep.IsMissing(name) {
		return nil
	}
	return v
}

func ptr(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func jsonList[T any](v []T) string {
	if v == nil {
		v = []T{}
	}
	b, _ := json.Marshal(v) //nolint:errchkjson // slices of ints/strings always marshal
	return string(b)
}

func invalidNames(rep wallconnector.Report) []string {
	names := make([]string, 0, len(rep.Invalid))
	for _, fe := range rep.Invalid {
		names = append(names, fe.Field)
	}
	return names
}

// SaveSnapshot stores one successful poll atomically: readings, raw
// payloads, device identity, detected events and a poll-log entry.
func (s *Store) SaveSnapshot(ctx context.Context, deviceID int64, snap *wallconnector.Snapshot,
	events []DeviceEvent, attempt int, took time.Duration,
) error {
	ts := ms(snap.FetchedAt)
	return s.withTx(ctx, func(tx *sql.Tx) error {
		v, vr := snap.Vitals, snap.Reports[wallconnector.EndpointVitals]
		if _, err := tx.ExecContext(ctx, `INSERT INTO readings_vitals (device_id, ts, contactor_closed, vehicle_connected,
			session_s, grid_v, grid_hz, vehicle_current_a, current_a_a, current_b_a, current_c_a, current_n_a,
			voltage_a_v, voltage_b_v, voltage_c_v, relay_k1_v, relay_k2_v, relay_coil_v, pcba_temp_c, handle_temp_c,
			mcu_temp_c, uptime_s, input_thermopile_uv, prox_v, pilot_high_v, pilot_low_v, session_energy_wh,
			config_status, evse_state, alerts_json, not_ready_json, invalid_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			deviceID, ts, b2i(v.ContactorClosed), b2i(v.VehicleConnected),
			field(vr, "session_s", v.SessionS), field(vr, "grid_v", v.GridV), field(vr, "grid_hz", v.GridHz),
			field(vr, "vehicle_current_a", v.VehicleCurrentA), field(vr, "currentA_a", v.CurrentAA),
			field(vr, "currentB_a", v.CurrentBA), field(vr, "currentC_a", v.CurrentCA), field(vr, "currentN_a", v.CurrentNA),
			field(vr, "voltageA_v", v.VoltageAV), field(vr, "voltageB_v", v.VoltageBV), field(vr, "voltageC_v", v.VoltageCV),
			field(vr, "relay_k1_v", ptr(v.RelayK1V)), field(vr, "relay_k2_v", ptr(v.RelayK2V)),
			field(vr, "relay_coil_v", ptr(v.RelayCoilV)), field(vr, "pcba_temp_c", v.PCBATempC),
			field(vr, "handle_temp_c", v.HandleTempC), field(vr, "mcu_temp_c", v.MCUTempC),
			field(vr, "uptime_s", v.UptimeS), field(vr, "input_thermopile_uv", v.InputThermopileUV),
			field(vr, "prox_v", v.ProxV), field(vr, "pilot_high_v", v.PilotHighV), field(vr, "pilot_low_v", v.PilotLowV),
			field(vr, "session_energy_wh", v.SessionEnergyWh), field(vr, "config_status", v.ConfigStatus),
			field(vr, "evse_state", v.EVSEState), jsonList(v.CurrentAlerts), jsonList(v.EVSENotReadyReasons),
			jsonList(invalidNames(vr))); err != nil {
			return fmt.Errorf("store: inserting vitals: %w", err)
		}

		l, lr := snap.Lifetime, snap.Reports[wallconnector.EndpointLifetime]
		if _, err := tx.ExecContext(ctx, `INSERT INTO readings_lifetime (device_id, ts, contactor_cycles,
			contactor_cycles_loaded, alert_count, thermal_foldbacks, avg_startup_temp, charge_starts, energy_wh,
			connector_cycles, uptime_s, charging_time_s, invalid_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			deviceID, ts, field(lr, "contactor_cycles", l.ContactorCycles),
			field(lr, "contactor_cycles_loaded", l.ContactorCyclesLoaded), field(lr, "alert_count", l.AlertCount),
			field(lr, "thermal_foldbacks", l.ThermalFoldbacks), field(lr, "avg_startup_temp", l.AvgStartupTemp),
			field(lr, "charge_starts", l.ChargeStarts), field(lr, "energy_wh", l.EnergyWh),
			field(lr, "connector_cycles", l.ConnectorCycles), field(lr, "uptime_s", l.UptimeS),
			field(lr, "charging_time_s", l.ChargingTimeS), jsonList(invalidNames(lr))); err != nil {
			return fmt.Errorf("store: inserting lifetime: %w", err)
		}

		w, wr := snap.WifiStatus, snap.Reports[wallconnector.EndpointWifiStatus]
		if _, err := tx.ExecContext(ctx, `INSERT INTO readings_wifi (device_id, ts, rssi, snr, signal_strength,
			connected, internet, infra_ip, invalid_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			deviceID, ts, field(wr, "wifi_rssi", w.WifiRSSI), field(wr, "wifi_snr", w.WifiSNR),
			field(wr, "wifi_signal_strength", w.WifiSignalStrength), b2i(w.WifiConnected), b2i(w.Internet),
			w.WifiInfraIP, jsonList(invalidNames(wr))); err != nil {
			return fmt.Errorf("store: inserting wifi: %w", err)
		}

		for _, ep := range wallconnector.Endpoints {
			if body, ok := snap.Raw[ep]; ok {
				if _, err := tx.ExecContext(ctx, "INSERT INTO raw_payloads (device_id, ts, endpoint, body) VALUES (?, ?, ?, ?)",
					deviceID, ts, string(ep), body); err != nil {
					return fmt.Errorf("store: inserting raw payload: %w", err)
				}
			}
		}

		ver, verRep := snap.Version, snap.Reports[wallconnector.EndpointVersion]
		if !verRep.IsInvalid("firmware_version") && !verRep.IsMissing("firmware_version") {
			gp := ver.GridProfile()
			if _, err := tx.ExecContext(ctx, `INSERT INTO device_info (device_id, firmware_version, git_branch, part_number,
				serial_number, web_service, ieee1547_vf_trips_crc, ieee1547_ride_thru_crc, ieee1547_combined_crc,
				first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT (device_id) DO UPDATE SET firmware_version = excluded.firmware_version,
				git_branch = excluded.git_branch, part_number = excluded.part_number,
				serial_number = excluded.serial_number, web_service = excluded.web_service,
				ieee1547_vf_trips_crc = excluded.ieee1547_vf_trips_crc,
				ieee1547_ride_thru_crc = excluded.ieee1547_ride_thru_crc,
				ieee1547_combined_crc = excluded.ieee1547_combined_crc, last_seen_at = excluded.last_seen_at`,
				deviceID, ver.FirmwareVersion, ver.GitBranch, ver.PartNumber, ver.SerialNumber, ver.WebService,
				gp.VfTrips, gp.RideThru, gp.CombinedCompliance, ts, ts); err != nil {
				return fmt.Errorf("store: saving device info: %w", err)
			}
		}

		for _, ev := range events {
			if err := insertEvent(ctx, tx, deviceID, ev); err != nil {
				return err
			}
		}
		return insertPollLog(ctx, tx, deviceID, snap.FetchedAt, true, attempt, took, "")
	})
}

func insertEvent(ctx context.Context, tx *sql.Tx, deviceID int64, ev DeviceEvent) error {
	details := ev.Details
	if details == nil {
		details = map[string]string{}
	}
	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO device_events (device_id, ts, kind, details_json) VALUES (?, ?, ?, ?)",
		deviceID, ms(ev.TS), ev.Kind, string(b))
	if err != nil {
		return fmt.Errorf("store: inserting event: %w", err)
	}
	return nil
}

const maxPollErrorLen = 500

func insertPollLog(ctx context.Context, tx *sql.Tx, deviceID int64, at time.Time, ok bool, attempt int, took time.Duration, errText string) error {
	if r := []rune(errText); len(r) > maxPollErrorLen {
		errText = string(r[:maxPollErrorLen]) + "…"
	}
	_, err := tx.ExecContext(ctx, "INSERT INTO poll_log (device_id, ts, ok, attempt, duration_ms, error) VALUES (?, ?, ?, ?, ?, ?)",
		deviceID, ms(at), b2i(ok), attempt, took.Milliseconds(), errText)
	if err != nil {
		return fmt.Errorf("store: inserting poll log: %w", err)
	}
	return nil
}

// RecordPollFailure logs a failed poll attempt.
func (s *Store) RecordPollFailure(ctx context.Context, deviceID int64, at time.Time, attempt int, took time.Duration, pollErr error) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		return insertPollLog(ctx, tx, deviceID, at, false, attempt, took, pollErr.Error())
	})
}

// DeviceInfo returns the stored identity of a device.
func (s *Store) DeviceInfo(ctx context.Context, deviceID int64) (*DeviceInfo, error) {
	var di DeviceInfo
	var first, last int64
	err := s.db.QueryRowContext(ctx, `SELECT device_id, firmware_version, git_branch, part_number, serial_number,
		web_service, ieee1547_vf_trips_crc, ieee1547_ride_thru_crc, ieee1547_combined_crc, first_seen_at, last_seen_at
		FROM device_info WHERE device_id = ?`, deviceID).Scan(&di.DeviceID, &di.FirmwareVersion, &di.GitBranch,
		&di.PartNumber, &di.SerialNumber, &di.WebService, &di.GridProfile.VfTrips, &di.GridProfile.RideThru,
		&di.GridProfile.CombinedCompliance, &first, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	di.FirstSeen, di.LastSeen = fromMS(first), fromMS(last)
	return &di, nil
}

// LatestState loads what the poller remembers between restarts.
func (s *Store) LatestState(ctx context.Context, deviceID int64) (DeviceState, error) {
	var st DeviceState
	info, err := s.DeviceInfo(ctx, deviceID)
	switch {
	case err == nil:
		st.Info = info
	case !errors.Is(err, ErrNotFound):
		return st, err
	}
	var ts int64
	var uptime sql.NullInt64
	var plugged, contactor bool
	err = s.db.QueryRowContext(ctx, `SELECT ts, uptime_s, vehicle_connected, contactor_closed FROM readings_vitals
		WHERE device_id = ? ORDER BY ts DESC LIMIT 1`, deviceID).Scan(&ts, &uptime, &plugged, &contactor)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.LastSuccess = fromMS(ts)
	st.LastUptimeS, st.HasUptime = uptime.Int64, uptime.Valid
	st.LastPlugged = plugged || contactor
	return st, nil
}

// Events returns device events since a time, newest first.
func (s *Store) Events(ctx context.Context, deviceID int64, since time.Time, limit int) ([]DeviceEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, device_id, ts, kind, details_json FROM device_events
		WHERE device_id = ? AND ts >= ? ORDER BY ts DESC, id DESC LIMIT ?`, deviceID, ms(since), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []DeviceEvent
	for rows.Next() {
		var ev DeviceEvent
		var ts int64
		var details string
		if err := rows.Scan(&ev.ID, &ev.DeviceID, &ts, &ev.Kind, &details); err != nil {
			return nil, err
		}
		ev.TS = fromMS(ts)
		if err := json.Unmarshal([]byte(details), &ev.Details); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// PollLogEntry is one poll attempt.
type PollLogEntry struct {
	TS       time.Time
	OK       bool
	Attempt  int
	Duration time.Duration
	Error    string
}

// PollLog returns the most recent poll attempts for a device, newest first.
func (s *Store) PollLog(ctx context.Context, deviceID int64, limit int) ([]PollLogEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, ok, attempt, duration_ms, error FROM poll_log
		WHERE device_id = ? ORDER BY ts DESC, id DESC LIMIT ?`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []PollLogEntry
	for rows.Next() {
		var e PollLogEntry
		var ts, dur int64
		if err := rows.Scan(&ts, &e.OK, &e.Attempt, &dur, &e.Error); err != nil {
			return nil, err
		}
		e.TS, e.Duration = fromMS(ts), time.Duration(dur)*time.Millisecond
		out = append(out, e)
	}
	return out, rows.Err()
}
