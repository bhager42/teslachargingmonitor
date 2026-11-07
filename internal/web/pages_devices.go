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
	"database/sql/driver"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/auth"
	"github.com/bhager42/teslachargingmonitor/internal/buildinfo"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

// PollControl is the poller API the web UI needs.
type PollControl interface {
	Reload(ctx context.Context) error
	PollNow(id int64) error
}

func (s *Server) deviceFromPath(w http.ResponseWriter, r *http.Request) (store.Device, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		var d store.Device
		if d, err = s.st.Device(r.Context(), id); err == nil {
			return d, true
		}
	}
	s.renderError(w, r, http.StatusNotFound, tr.T("error.not_found_title"), tr.T("error.no_device"))
	return store.Device{}, false
}

func (s *Server) home(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	cards := s.allCards(r)
	var recent []alertRow
	evs, _ := s.st.AlertEvents(r.Context(), store.AlertEventFilter{Limit: 8})
	for _, e := range evs {
		recent = append(recent, alertRow{ID: e.ID, Severity: e.Severity, Kind: e.Kind, When: fmtAgo(e.TS, s.now()),
			Message: e.Message, Acked: e.AckedAt != nil})
	}
	s.render(w, r, http.StatusOK, "home", s.base(page{"Title": tr.T("home.title"), "Cards": cards, "CardFields": CardFields,
		"Recent": recent}, sess, "home"))
}

var ranges = []struct {
	Key  string
	Span time.Duration
}{{"24h", 24 * time.Hour}, {"7d", 7 * 24 * time.Hour}, {"30d", 30 * 24 * time.Hour}, {"1y", 365 * 24 * time.Hour}}

func rangeSpan(key string) (time.Duration, bool) {
	for _, r := range ranges {
		if r.Key == key {
			return r.Span, true
		}
	}
	return 0, false
}

type kv struct{ K, V string }

func (s *Server) deviceDetail(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	d, ok := s.deviceFromPath(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	unit := s.display(ctx).TempUnit
	rng := r.URL.Query().Get("range")
	if _, ok := rangeSpan(rng); !ok {
		rng = "24h"
	}
	p := page{"Title": d.Name, "Device": d, "Card": s.cardFor(ctx, d, unit), "CardFields": CardFields, "Range": rng,
		"Ranges": ranges, "Unit": unit}
	var lifetime []kv
	if pt, err := s.st.LatestPoint(ctx, d.ID); err == nil {
		l := pt.Snapshot.Lifetime
		lifetime = []kv{
			{tr.T("device.energy"), fmtNum(float64(l.EnergyWh)/1000, "kWh", 1)},
			{tr.T("device.charging_time"), fmtDuration(time.Duration(l.ChargingTimeS) * time.Second)},
			{tr.T("device.sessions"), strconv.FormatInt(l.ChargeStarts, 10)},
			{tr.T("device.contactor_cycles"), fmt.Sprintf("%d (%d)", l.ContactorCycles, l.ContactorCyclesLoaded)},
			{tr.T("device.plug_ins"), strconv.FormatInt(l.ConnectorCycles, 10)},
			{tr.T("device.foldbacks"), strconv.FormatInt(l.ThermalFoldbacks, 10)},
			{tr.T("device.alerts"), strconv.FormatInt(l.AlertCount, 10)},
		}
		v := pt.Snapshot.Vitals
		p["Codes"] = []kv{
			{tr.T("device.evse_state"), wallconnector.EVSEStateInfo(v.EVSEState).Label},
			{tr.T("device.config_status"), wallconnector.ConfigStatusInfo(v.ConfigStatus).Label},
			{tr.T("device.not_ready"), codeList(v.EVSENotReadyReasons, wallconnector.NotReadyReasonInfo)},
			{tr.T("device.device_alerts"), codeList(v.CurrentAlerts, wallconnector.AlertInfo)},
		}
	}
	p["Lifetime"] = lifetime
	if info, err := s.st.DeviceInfo(ctx, d.ID); err == nil {
		p["Identity"] = []kv{
			{tr.T("device.firmware"), info.FirmwareVersion}, {tr.T("device.part"), info.PartNumber},
			{tr.T("device.serial"), wallconnector.MaskSerial(info.SerialNumber)},
			{tr.T("device.first_seen"), info.FirstSeen.Local().Format("2 Jan 2006")},
		}
	}
	raw, _, _ := s.st.LatestRaw(ctx, d.ID)
	var rawList []kv
	for _, ep := range wallconnector.Endpoints {
		if b, ok := raw[string(ep)]; ok {
			rawList = append(rawList, kv{ep.Path(), redactRaw(b)})
		}
	}
	p["Raw"] = rawList
	evs, _ := s.st.Events(ctx, d.ID, time.Time{}, 10)
	var events []kv
	for _, e := range evs {
		events = append(events, kv{e.TS.Local().Format("2 Jan 15:04"), eventLabel(e.Kind)})
	}
	p["Events"] = events
	var charts []page
	for _, m := range store.SeriesMetrics {
		switch m.Key {
		case "relay_k1_v", "relay_k2_v", "lifetime_energy_kwh":
			continue
		}
		u := m.Unit
		if u == "C" {
			u = "°" + unit
		}
		charts = append(charts, page{"Metric": m.Key, "Label": m.Label, "Unit": u})
	}
	p["Charts"] = charts
	s.render(w, r, http.StatusOK, "device", s.base(p, sess, "home"))
}

// eventLabel names a device event kind for the UI.
func eventLabel(kind string) string {
	switch kind {
	case store.EventReboot:
		return tr.T("event.reboot")
	case store.EventFirmwareChanged:
		return tr.T("event.firmware_changed")
	case store.EventGridProfileChanged:
		return tr.T("event.grid_profile_changed")
	case store.EventIdentityMismatch:
		return tr.T("event.identity_mismatch")
	}
	return strings.ReplaceAll(kind, "_", " ")
}

func codeList(codes []int, info func(int) wallconnector.CodeInfo) string {
	if len(codes) == 0 {
		return tr.T("device.codes_none")
	}
	parts := make([]string, 0, len(codes))
	for _, c := range codes {
		parts = append(parts, info(c).Label)
	}
	return strings.Join(parts, ", ")
}

// redactRaw masks identifiers in a raw payload shown in the UI.
func redactRaw(b []byte) string {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return tr.T("device.raw_invalid")
	}
	if s, ok := m["serial_number"].(string); ok {
		m["serial_number"] = wallconnector.MaskSerial(s)
	}
	for _, k := range []string{"wifi_mac", "wifi_ssid"} {
		if _, ok := m[k]; ok {
			m[k] = tr.T("device.raw_hidden")
		}
	}
	out, _ := json.MarshalIndent(m, "", "  ")
	return string(out)
}

// series returns chart data: GET /api/devices/{id}/series?metric=&range=
func (s *Server) series(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	d, ok := s.deviceFromPath(w, r)
	if !ok {
		return
	}
	span, ok := rangeSpan(r.URL.Query().Get("range"))
	if !ok {
		http.Error(w, "bad range", http.StatusBadRequest)
		return
	}
	metric := r.URL.Query().Get("metric")
	m, ok := store.LookupMetric(metric)
	if !ok {
		http.Error(w, "unknown metric", http.StatusBadRequest)
		return
	}
	now := s.now()
	pts, err := s.st.Series(r.Context(), d.ID, metric, now.Add(-span), now.Add(time.Minute), 400)
	if err != nil {
		s.log.Error("series", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	unit := m.Unit
	if unit == "C" {
		unit = "°" + s.display(r.Context()).TempUnit
		if unit == "°F" {
			for i := range pts {
				pts[i].Min, pts[i].Avg, pts[i].Max = pts[i].Min*9/5+32, pts[i].Avg*9/5+32, pts[i].Max*9/5+32
			}
		}
	}
	if pts == nil {
		pts = []store.SeriesPoint{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"metric": metric, "label": m.Label, "unit": unit, "points": pts})
}

// exportCSV streams readings for the selected range.
func (s *Server) exportCSV(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	d, ok := s.deviceFromPath(w, r)
	if !ok {
		return
	}
	span, ok := rangeSpan(r.URL.Query().Get("range"))
	if !ok {
		span = 30 * 24 * time.Hour
	}
	now := s.now()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="tcmon-device-%d-%s.csv"`, d.ID, now.Format("20060102")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time_utc", "vehicle_connected", "contactor_closed", "current_a", "grid_v", "grid_hz",
		"handle_temp_c", "pcba_temp_c", "mcu_temp_c", "session_energy_wh", "evse_state"})
	f := func(n driver.Valuer) string {
		v, _ := n.Value()
		if v == nil {
			return ""
		}
		return fmt.Sprint(v)
	}
	err := s.st.ExportVitals(r.Context(), d.ID, now.Add(-span), now.Add(time.Minute), func(e store.ExportRow) error {
		return cw.Write([]string{e.TS.Format(time.RFC3339), strconv.FormatBool(e.VehicleConnected),
			strconv.FormatBool(e.ContactorClosed), f(e.CurrentA), f(e.GridV), f(e.GridHz), f(e.HandleC), f(e.PCBAC),
			f(e.MCUC), f(e.SessionWh), f(e.EVSEState)})
	})
	cw.Flush()
	if err != nil {
		s.log.Error("csv export", "err", err)
	}
}

// pollNow asks the poller for an immediate poll.
func (s *Server) pollNow(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	d, ok := s.deviceFromPath(w, r)
	if !ok {
		return
	}
	back := "/devices/" + strconv.FormatInt(d.ID, 10)
	if r.PostFormValue("back") == "home" {
		back = "/"
	}
	if s.poll == nil {
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	if err := s.poll.PollNow(d.ID); err != nil {
		http.Redirect(w, r, back+"?ok=poll-limited", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, back+"?ok=polling", http.StatusSeeOther)
}

// ---- Settings → Devices (the Wall Connector address is set here, D2) ----

func (s *Server) devicesPage(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	devices, _ := s.st.Devices(r.Context())
	s.render(w, r, http.StatusOK, "devices", s.base(page{"Title": tr.T("devices.title"), "Devices": devices}, sess, "settings"))
}

type deviceForm struct {
	ID                                                    int64
	Name, Address, Breaker, MaxCurrent, Interval, Plugged string
	Voltage, Hz                                           string
	FastWhenPlugged, Enabled, AllowNonLAN                 bool
}

func formFromDevice(d store.Device) deviceForm {
	f := func(v float64) string {
		if v == 0 {
			return ""
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return deviceForm{ID: d.ID, Name: d.Name, Address: d.Address, Breaker: f(d.BreakerA), MaxCurrent: f(d.MaxCurrentA),
		Interval: strconv.Itoa(int(d.PollInterval.Minutes())), Plugged: strconv.Itoa(int(d.PluggedInterval.Minutes())),
		Voltage: f(d.NominalVoltageV), Hz: f(d.NominalHz), FastWhenPlugged: d.FastWhenPlugged, Enabled: d.Enabled,
		AllowNonLAN: d.AllowNonLAN}
}

func (f deviceForm) toDevice(base store.Device) (store.Device, error) {
	d := base
	d.Name, d.Address = strings.TrimSpace(f.Name), strings.TrimSpace(f.Address)
	num := func(s, label string) (float64, error) {
		if strings.TrimSpace(s) == "" {
			return 0, nil
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return 0, errors.New(tr.T("device_form.err_number", "field", label))
		}
		return v, nil
	}
	var err error
	if d.BreakerA, err = num(f.Breaker, tr.T("device_form.field_breaker")); err != nil {
		return d, err
	}
	if d.MaxCurrentA, err = num(f.MaxCurrent, tr.T("device_form.field_max_current")); err != nil {
		return d, err
	}
	if d.NominalVoltageV, err = num(f.Voltage, tr.T("device_form.field_voltage")); err != nil {
		return d, err
	}
	if d.NominalHz, err = num(f.Hz, tr.T("device_form.field_frequency")); err != nil {
		return d, err
	}
	iv, err1 := strconv.Atoi(strings.TrimSpace(f.Interval))
	pv, err2 := strconv.Atoi(strings.TrimSpace(f.Plugged))
	if err1 != nil || err2 != nil {
		return d, errors.New(tr.T("device_form.err_intervals"))
	}
	d.PollInterval, d.PluggedInterval = time.Duration(iv)*time.Minute, time.Duration(pv)*time.Minute
	d.FastWhenPlugged, d.Enabled, d.AllowNonLAN = f.FastWhenPlugged, f.Enabled, f.AllowNonLAN
	return d, d.Normalize()
}

func readDeviceForm(r *http.Request) deviceForm {
	return deviceForm{Name: r.PostFormValue("name"), Address: r.PostFormValue("address"),
		Breaker: r.PostFormValue("breaker"), MaxCurrent: r.PostFormValue("max_current"),
		Interval: r.PostFormValue("interval"), Plugged: r.PostFormValue("plugged_interval"),
		Voltage: r.PostFormValue("voltage"), Hz: r.PostFormValue("hz"),
		FastWhenPlugged: r.PostFormValue("fast_when_plugged") == "1", Enabled: r.PostFormValue("enabled") == "1",
		AllowNonLAN: r.PostFormValue("allow_non_lan") == "1"}
}

func (s *Server) renderDeviceForm(w http.ResponseWriter, r *http.Request, sess auth.Session, status int, f deviceForm, p page) {
	if p == nil {
		p = page{}
	}
	p["Form"], p["Title"] = f, tr.T("device_form.title_edit")
	if f.ID == 0 {
		p["Title"] = tr.T("common.add_wall_connector")
	}
	p["Voltages"] = []string{"120", "208", "220", "230", "240", "277", "400", "480"}
	s.render(w, r, status, "device_form", s.base(p, sess, "settings"))
}

func (s *Server) newDeviceForm(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	f := formFromDevice(store.NewDevice(tr.T("device_form.default_name"), ""))
	f.Breaker = ""
	s.renderDeviceForm(w, r, sess, http.StatusOK, f, nil)
}

func (s *Server) editDeviceForm(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	d, ok := s.deviceFromPath(w, r)
	if !ok {
		return
	}
	s.renderDeviceForm(w, r, sess, http.StatusOK, formFromDevice(d), nil)
}

// probeResult is shown after "Test connection".
type probeResult struct {
	OK                                     bool
	Message, Firmware, Part, Serial, State string
}

func (s *Server) probe(ctx context.Context, d store.Device) probeResult {
	addr, err := d.ParsedAddress()
	if err != nil {
		return probeResult{Message: err.Error()}
	}
	c := wallconnector.NewClient(addr, wallconnector.Options{AllowNonLAN: d.AllowNonLAN, UserAgent: "tcmon/" + buildinfo.Version})
	res, err := c.Probe(ctx)
	switch {
	case errors.Is(err, wallconnector.ErrNotWallConnector):
		return probeResult{Message: tr.T("device_form.probe_not_wc", "address", addr.String())}
	case errors.Is(err, wallconnector.ErrBlockedAddress):
		return probeResult{Message: tr.T("device_form.probe_blocked")}
	case err != nil:
		return probeResult{Message: tr.T("device_form.probe_none", "address", addr.String())}
	}
	st, _ := state(res.Vitals, nil)
	return probeResult{OK: true, Firmware: res.Firmware.Short(), Part: res.Version.PartNumber, Serial: res.MaskedSerial,
		State: st, Message: tr.T("device_form.probe_ok")}
}

func (s *Server) saveDevice(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ctx := r.Context()
	f := readDeviceForm(r)
	base := store.NewDevice("", "")
	var existing *store.Device
	if idStr := r.PathValue("id"); idStr != "" {
		d, ok := s.deviceFromPath(w, r)
		if !ok {
			return
		}
		existing, base, f.ID = &d, d, d.ID
	}
	d, err := f.toDevice(base)
	if err != nil {
		s.renderDeviceForm(w, r, sess, http.StatusBadRequest, f, page{"Error": err.Error()})
		return
	}
	addressChanged := existing == nil || existing.Address != d.Address
	if r.PostFormValue("action") == "test" || (addressChanged && r.PostFormValue("skip_test") != "1") {
		res := s.probe(ctx, d)
		if r.PostFormValue("action") == "test" || !res.OK {
			status := http.StatusOK
			if !res.OK {
				status = http.StatusBadRequest
			}
			s.renderDeviceForm(w, r, sess, status, f, page{"Probe": res})
			return
		}
	}
	now := s.now()
	if existing == nil {
		d, err = s.st.CreateDevice(ctx, d, now)
	} else {
		d, err = s.st.UpdateDevice(ctx, d, now)
	}
	if err != nil {
		s.renderDeviceForm(w, r, sess, http.StatusBadRequest, f, page{"Error": tr.T("device_form.err_save", "error", err.Error())})
		return
	}
	s.auditUI(r, "device_saved", map[string]string{"device_id": strconv.FormatInt(d.ID, 10), "address": d.Address})
	if s.poll != nil {
		if err := s.poll.Reload(ctx); err != nil {
			s.log.Error("reloading poller", "err", err)
		}
	}
	http.Redirect(w, r, "/settings/devices?ok=device-saved", http.StatusSeeOther)
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	d, ok := s.deviceFromPath(w, r)
	if !ok {
		return
	}
	if r.PostFormValue("confirm") != d.Name {
		s.renderDeviceForm(w, r, sess, http.StatusBadRequest, formFromDevice(d),
			page{"Error": tr.T("device_form.err_confirm")})
		return
	}
	if err := s.st.DeleteDevice(r.Context(), d.ID); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, tr.T("error.title"), tr.T("device_form.err_delete"))
		return
	}
	s.auditUI(r, "device_deleted", map[string]string{"device_id": strconv.FormatInt(d.ID, 10)})
	if s.poll != nil {
		_ = s.poll.Reload(r.Context())
	}
	http.Redirect(w, r, "/settings/devices?ok=device-deleted", http.StatusSeeOther)
}

func (s *Server) auditUI(r *http.Request, action string, details map[string]string) {
	if err := s.st.Audit(r.Context(), store.AuditEntry{TS: s.now(), IP: clientIP(r).String(), Action: action, Details: details}); err != nil {
		s.log.Error("audit", "err", err)
	}
}
