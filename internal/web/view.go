// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package web

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

// Display preferences (Settings → General).
type Display struct {
	TempUnit string `json:"temp_unit"` // "C" or "F"
}

const displayKey = "display"

func (s *Server) display(ctx context.Context) Display {
	d := Display{TempUnit: "C"}
	if err := s.st.GetSetting(ctx, displayKey, &d); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Warn("reading display settings", "err", err)
	}
	if d.TempUnit != "F" {
		d.TempUnit = "C"
	}
	return d
}

func fmtTemp(c float64, unit string) string {
	if unit == "F" {
		return fmt.Sprintf("%.1f °F", c*9/5+32)
	}
	return fmt.Sprintf("%.1f °C", c)
}

func fmtNum(v float64, unit string, digits int) string {
	return strconv.FormatFloat(v, 'f', digits, 64) + " " + unit
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h, m := int(d.Hours()), int(d.Minutes())%60
	if h > 0 {
		return fmt.Sprintf("%d h %02d min", h, m)
	}
	return fmt.Sprintf("%d min", m)
}

func fmtAgo(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

// DeviceCard is the dashboard view of one Wall Connector. All values are
// pre-formatted strings so the browser only sets textContent.
type DeviceCard struct {
	ID         int64             `json:"id"`
	Name       string            `json:"name"`
	State      string            `json:"state"`
	StateClass string            `json:"state_class"` // idle | plugged | charging | fault | offline | unknown
	Fields     map[string]string `json:"fields"`
	Updated    string            `json:"updated"`
	UpdatedAt  time.Time         `json:"updated_at"`
	Stale      bool              `json:"stale"`
	Alerts     []CardAlert       `json:"alerts"`
	CurrentPct int               `json:"current_pct"` // of the configured max current, for the meter
}

// CardAlert is an active alert on a card.
type CardAlert struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
}

// CardFields lists the field keys a card shows, in order, with labels.
var CardFields = []struct{ Key, Label string }{
	{"current", "Current"}, {"power", "Power"}, {"session_energy", "This session"}, {"session_time", "Session time"},
	{"grid", "Grid"}, {"handle_temp", "Handle"}, {"pcba_temp", "Circuit board"}, {"mcu_temp", "Controller"},
	{"wifi", "Wi-Fi"}, {"lifetime_energy", "Lifetime energy"},
}

func state(v wallconnector.Vitals, active []alerts.ActiveAlert) (string, string) {
	for _, a := range active {
		if a.Severity == alerts.Critical {
			return "Fault: " + a.Title, "fault"
		}
	}
	switch {
	case v.ContactorClosed && v.VehicleCurrentA >= 1:
		return "Charging", "charging"
	case v.VehicleConnected || v.ContactorClosed:
		return "Plugged in", "plugged"
	default:
		return "Idle", "idle"
	}
}

// buildCard assembles a card from the latest stored poll (pt may be nil).
func (s *Server) buildCard(d store.Device, pt *store.HistoryPoint, lastPoll *store.PollLogEntry, unit string, now time.Time) DeviceCard {
	c := DeviceCard{ID: d.ID, Name: d.Name, Fields: map[string]string{}, State: "Waiting for first poll", StateClass: "unknown"}
	for _, f := range CardFields {
		c.Fields[f.Key] = "–"
	}
	var active []alerts.ActiveAlert
	if s.alerts != nil {
		active = s.alerts.Active(d.ID)
	}
	for _, a := range active {
		c.Alerts = append(c.Alerts, CardAlert{Title: a.Title, Severity: a.Severity.String()})
	}
	if pt != nil {
		snap := pt.Snapshot
		v, vr := snap.Vitals, snap.Reports[wallconnector.EndpointVitals]
		ok := func(f string) bool { return !vr.IsInvalid(f) && !vr.IsMissing(f) }
		c.State, c.StateClass = state(v, active)
		if ok("vehicle_current_a") {
			c.Fields["current"] = fmtNum(v.VehicleCurrentA, "A", 1)
			if d.MaxCurrentA > 0 {
				c.CurrentPct = int(math.Round(math.Min(v.VehicleCurrentA/d.MaxCurrentA, 1.2) * 100))
				c.Fields["current"] += " of " + strconv.FormatFloat(d.MaxCurrentA, 'f', -1, 64) + " A"
			}
			if ok("grid_v") {
				c.Fields["power"] = fmtNum(v.VehicleCurrentA*v.GridV/1000, "kW", 2)
			}
		}
		if ok("session_energy_wh") {
			c.Fields["session_energy"] = fmtNum(v.SessionEnergyWh/1000, "kWh", 2)
		}
		if ok("session_s") && v.SessionS > 0 {
			c.Fields["session_time"] = fmtDuration(time.Duration(v.SessionS) * time.Second)
		}
		if ok("grid_v") && ok("grid_hz") {
			c.Fields["grid"] = fmt.Sprintf("%.1f V · %.2f Hz", v.GridV, v.GridHz)
		}
		for key, f := range map[string]struct {
			field string
			val   float64
		}{"handle_temp": {"handle_temp_c", v.HandleTempC}, "pcba_temp": {"pcba_temp_c", v.PCBATempC}, "mcu_temp": {"mcu_temp_c", v.MCUTempC}} {
			if ok(f.field) {
				c.Fields[key] = fmtTemp(f.val, unit)
			}
		}
		if wr := snap.Reports[wallconnector.EndpointWifiStatus]; !wr.IsInvalid("wifi_rssi") && !wr.IsMissing("wifi_rssi") {
			c.Fields["wifi"] = fmt.Sprintf("%d dBm", snap.WifiStatus.WifiRSSI)
		}
		if lr := snap.Reports[wallconnector.EndpointLifetime]; !lr.IsInvalid("energy_wh") && !lr.IsMissing("energy_wh") {
			c.Fields["lifetime_energy"] = fmtNum(float64(snap.Lifetime.EnergyWh)/1000, "kWh", 1)
		}
		c.UpdatedAt = snap.FetchedAt
	}
	if lastPoll != nil && !lastPoll.OK && (pt == nil || lastPoll.TS.After(pt.Snapshot.FetchedAt)) {
		c.State, c.StateClass = "Unreachable", "offline"
	}
	c.Updated = fmtAgo(c.UpdatedAt, now)
	interval := d.PollInterval
	if d.FastWhenPlugged && (c.StateClass == "charging" || c.StateClass == "plugged") {
		interval = d.PluggedInterval
	}
	c.Stale = !c.UpdatedAt.IsZero() && now.Sub(c.UpdatedAt) > interval*3/2
	return c
}

// cardFor loads everything a card needs from the store.
func (s *Server) cardFor(ctx context.Context, d store.Device, unit string) DeviceCard {
	pt, err := s.st.LatestPoint(ctx, d.ID)
	if err != nil {
		pt = nil
	}
	var last *store.PollLogEntry
	if log, err := s.st.PollLog(ctx, d.ID, 1); err == nil && len(log) == 1 {
		last = &log[0]
	}
	return s.buildCard(d, pt, last, unit, s.now())
}

func contextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}
