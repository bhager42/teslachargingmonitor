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
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

// HistoryPoint is one stored poll, reconstructed for rule previews. Columns
// stored as NULL (decoder-flagged or absent) are reported as invalid.
type HistoryPoint struct {
	Snapshot *wallconnector.Snapshot
	Events   []DeviceEvent
}

// History returns stored polls for a device in [from, to), oldest first.
func (s *Store) History(ctx context.Context, deviceID int64, from, to time.Time) ([]HistoryPoint, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT v.ts, v.contactor_closed, v.vehicle_connected, v.session_s, v.grid_v,
		v.grid_hz, v.vehicle_current_a, v.current_a_a, v.current_b_a, v.current_c_a, v.current_n_a, v.voltage_a_v,
		v.voltage_b_v, v.voltage_c_v, v.relay_k1_v, v.relay_k2_v, v.relay_coil_v, v.pcba_temp_c, v.handle_temp_c,
		v.mcu_temp_c, v.uptime_s, v.session_energy_wh, v.config_status, v.evse_state, v.alerts_json, v.not_ready_json,
		l.thermal_foldbacks, l.alert_count, l.contactor_cycles_loaded, l.charge_starts, l.energy_wh,
		w.rssi, w.internet
		FROM readings_vitals v
		LEFT JOIN readings_lifetime l ON l.device_id = v.device_id AND l.ts = v.ts
		LEFT JOIN readings_wifi w ON w.device_id = v.device_id AND w.ts = v.ts
		WHERE v.device_id = ? AND v.ts >= ? AND v.ts < ? ORDER BY v.ts`, deviceID, ms(from), ms(to))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []HistoryPoint
	byTS := map[int64]int{}
	for rows.Next() {
		var ts int64
		var contactor, connected bool
		var f [17]sql.NullFloat64
		var cfg, evse, uptime sql.NullInt64
		var energy sql.NullFloat64
		var alerts, notReady string
		var tf, ac, ccl, cs, ewh, rssi sql.NullInt64
		var internet sql.NullBool
		if err := rows.Scan(&ts, &contactor, &connected, &f[0], &f[1], &f[2], &f[3], &f[4], &f[5], &f[6], &f[7],
			&f[8], &f[9], &f[10], &f[11], &f[12], &f[13], &f[14], &f[15], &f[16], &uptime, &energy, &cfg, &evse,
			&alerts, &notReady, &tf, &ac, &ccl, &cs, &ewh, &rssi, &internet); err != nil {
			return nil, err
		}
		snap := &wallconnector.Snapshot{FetchedAt: fromMS(ts), Reports: map[wallconnector.Endpoint]wallconnector.Report{}}
		var vr, lr, wr wallconnector.Report
		v := &snap.Vitals
		v.ContactorClosed, v.VehicleConnected = contactor, connected
		fl := func(rep *wallconnector.Report, name string, n sql.NullFloat64, dst *float64) {
			if n.Valid {
				*dst = n.Float64
			} else {
				rep.Invalid = append(rep.Invalid, wallconnector.FieldError{Field: name, Reason: "not stored"})
			}
		}
		fp := func(n sql.NullFloat64) *float64 {
			if !n.Valid {
				return nil
			}
			x := n.Float64
			return &x
		}
		var sess float64
		fl(&vr, "session_s", f[0], &sess)
		v.SessionS = int64(sess)
		fl(&vr, "grid_v", f[1], &v.GridV)
		fl(&vr, "grid_hz", f[2], &v.GridHz)
		fl(&vr, "vehicle_current_a", f[3], &v.VehicleCurrentA)
		fl(&vr, "currentA_a", f[4], &v.CurrentAA)
		fl(&vr, "currentB_a", f[5], &v.CurrentBA)
		fl(&vr, "currentC_a", f[6], &v.CurrentCA)
		fl(&vr, "currentN_a", f[7], &v.CurrentNA)
		fl(&vr, "voltageA_v", f[8], &v.VoltageAV)
		fl(&vr, "voltageB_v", f[9], &v.VoltageBV)
		fl(&vr, "voltageC_v", f[10], &v.VoltageCV)
		v.RelayK1V, v.RelayK2V, v.RelayCoilV = fp(f[11]), fp(f[12]), fp(f[13])
		fl(&vr, "pcba_temp_c", f[14], &v.PCBATempC)
		fl(&vr, "handle_temp_c", f[15], &v.HandleTempC)
		fl(&vr, "mcu_temp_c", f[16], &v.MCUTempC)
		fl(&vr, "session_energy_wh", energy, &v.SessionEnergyWh)
		if uptime.Valid {
			v.UptimeS = uptime.Int64
		} else {
			vr.Invalid = append(vr.Invalid, wallconnector.FieldError{Field: "uptime_s", Reason: "not stored"})
		}
		v.EVSEState, v.ConfigStatus = int(evse.Int64), int(cfg.Int64)
		_ = json.Unmarshal([]byte(alerts), &v.CurrentAlerts)
		_ = json.Unmarshal([]byte(notReady), &v.EVSENotReadyReasons)

		li := func(rep *wallconnector.Report, name string, n sql.NullInt64, dst *int64) {
			if n.Valid {
				*dst = n.Int64
			} else {
				rep.Invalid = append(rep.Invalid, wallconnector.FieldError{Field: name, Reason: "not stored"})
			}
		}
		l := &snap.Lifetime
		li(&lr, "thermal_foldbacks", tf, &l.ThermalFoldbacks)
		li(&lr, "alert_count", ac, &l.AlertCount)
		li(&lr, "contactor_cycles_loaded", ccl, &l.ContactorCyclesLoaded)
		li(&lr, "charge_starts", cs, &l.ChargeStarts)
		li(&lr, "energy_wh", ewh, &l.EnergyWh)
		var r64 int64
		li(&wr, "wifi_rssi", rssi, &r64)
		snap.WifiStatus.WifiRSSI = int(r64)
		if internet.Valid {
			snap.WifiStatus.Internet = internet.Bool
		} else {
			wr.Invalid = append(wr.Invalid, wallconnector.FieldError{Field: "internet", Reason: "not stored"})
		}
		snap.Reports[wallconnector.EndpointVitals] = vr
		snap.Reports[wallconnector.EndpointLifetime] = lr
		snap.Reports[wallconnector.EndpointWifiStatus] = wr
		byTS[ts] = len(out)
		out = append(out, HistoryPoint{Snapshot: snap})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	evs, err := s.db.QueryContext(ctx, `SELECT id, ts, kind, details_json FROM device_events
		WHERE device_id = ? AND ts >= ? AND ts < ? ORDER BY ts`, deviceID, ms(from), ms(to))
	if err != nil {
		return nil, err
	}
	defer func() { _ = evs.Close() }()
	for evs.Next() {
		ev := DeviceEvent{DeviceID: deviceID}
		var ts int64
		var details string
		if err := evs.Scan(&ev.ID, &ts, &ev.Kind, &details); err != nil {
			return nil, err
		}
		ev.TS = fromMS(ts)
		_ = json.Unmarshal([]byte(details), &ev.Details)
		if i, ok := byTS[ts]; ok {
			out[i].Events = append(out[i].Events, ev)
		}
	}
	return out, evs.Err()
}
