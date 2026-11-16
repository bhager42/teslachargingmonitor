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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bhager42/teslachargingmonitor/internal/energy"
	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

// Default Gateway polling cadence: §15.2 S5 (15 min) and the Wall
// Connector's plugged-in cadence while a car is connected (D10).
const (
	DefaultGatewayInterval         = 15 * time.Minute
	DefaultGatewayChargingInterval = 5 * time.Minute
)

// Gateway event kinds.
const (
	GatewayEventReboot          = "gateway_reboot"
	GatewayEventFirmwareChanged = "gateway_firmware_changed"
	GatewayEventGridChanged     = "grid_status_changed"
	GatewayEventCertChanged     = "gateway_cert_changed"
)

// gatewayAAD binds sealed Gateway passwords to their purpose.
var gatewayAAD = []byte("tcmon:gateway:customer_password:v1")

// Gateway is a configured Tesla Backup Gateway.
type Gateway struct {
	ID               int64
	Name             string
	Address          string // host[:port], e.g. "192.168.1.20"
	AllowNonLAN      bool
	Enabled          bool
	Pin              string // owner-confirmed certificate SHA-256 (hex)
	PendingPin       string // a different certificate seen since; polling stops
	PasswordEnc      []byte // sealed customer password; see SealGatewayPassword
	PollInterval     time.Duration
	ChargingInterval time.Duration
	Backoff          gateway.Backoff
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// NewGateway returns a Gateway with the default settings.
func NewGateway(name, address, pin string, passwordEnc []byte) Gateway {
	return Gateway{
		Name: name, Address: address, Enabled: true, Pin: pin, PasswordEnc: passwordEnc,
		PollInterval: DefaultGatewayInterval, ChargingInterval: DefaultGatewayChargingInterval,
	}
}

// SealGatewayPassword encrypts a customer password for Gateway.PasswordEnc.
func SealGatewayPassword(box *secrets.Box, pw secrets.Secret) ([]byte, error) {
	if !pw.IsSet() {
		return nil, tr.Err("gateway_check.err_password")
	}
	return box.Seal([]byte(pw.Reveal()), gatewayAAD)
}

// Password decrypts the customer password.
func (g Gateway) Password(box *secrets.Box) (secrets.Secret, error) {
	pt, err := box.Open(g.PasswordEnc, gatewayAAD)
	if err != nil {
		return "", fmt.Errorf("store: gateway %d password: %w", g.ID, err)
	}
	return secrets.Secret(pt), nil
}

// NormalizePin lower-cases a fingerprint and drops ':' separators.
func NormalizePin(p string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), ":", ""))
}

func validPin(p string) bool {
	b, err := hex.DecodeString(p)
	return err == nil && len(b) == 32
}

// Normalize validates g and rewrites Address and Pin into canonical form.
func (g *Gateway) Normalize() error {
	if n := utf8.RuneCountInString(g.Name); n < 1 || n > 64 {
		return tr.Err("device_check.err_name")
	}
	addr, err := wallconnector.ParseAddress(g.Address, wallconnector.AddressOptions{AllowNonLAN: g.AllowNonLAN})
	if err != nil {
		return err
	}
	g.Address = addr.HostPort()
	g.Pin = NormalizePin(g.Pin)
	if !validPin(g.Pin) {
		return tr.Err("gateway_check.err_pin")
	}
	if len(g.PasswordEnc) == 0 {
		return tr.Err("gateway_check.err_password")
	}
	for _, iv := range []struct {
		key string
		v   time.Duration
	}{{"device_check.err_poll_interval", g.PollInterval}, {"gateway_check.err_charging_interval", g.ChargingInterval}} {
		if iv.v < MinInterval || iv.v > MaxInterval || iv.v%time.Second != 0 {
			return tr.Err(iv.key, "min", MinInterval, "max", MaxInterval)
		}
	}
	return nil
}

const gatewayCols = `id, name, address, allow_non_lan, enabled, pin_sha256, pending_pin_sha256, password_enc,
	poll_interval_s, charging_interval_s, backoff_failures, backoff_until, backoff_cause, created_at, updated_at`

func scanGateway(sc interface{ Scan(...any) error }) (Gateway, error) {
	var g Gateway
	var poll, charging, until, created, updated int64
	err := sc.Scan(&g.ID, &g.Name, &g.Address, &g.AllowNonLAN, &g.Enabled, &g.Pin, &g.PendingPin, &g.PasswordEnc,
		&poll, &charging, &g.Backoff.Failures, &until, &g.Backoff.Cause, &created, &updated)
	g.PollInterval = time.Duration(poll) * time.Second
	g.ChargingInterval = time.Duration(charging) * time.Second
	if until > 0 {
		g.Backoff.Until = fromMS(until)
	}
	g.CreatedAt, g.UpdatedAt = fromMS(created), fromMS(updated)
	return g, err
}

// CreateGateway validates and inserts g.
func (s *Store) CreateGateway(ctx context.Context, g Gateway, now time.Time) (Gateway, error) {
	if err := g.Normalize(); err != nil {
		return Gateway{}, err
	}
	g.CreatedAt, g.UpdatedAt = now.UTC().Truncate(time.Millisecond), now.UTC().Truncate(time.Millisecond)
	res, err := s.db.ExecContext(ctx, `INSERT INTO gateways (name, address, allow_non_lan, enabled, pin_sha256,
		password_enc, poll_interval_s, charging_interval_s, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.Name, g.Address, b2i(g.AllowNonLAN), b2i(g.Enabled), g.Pin, g.PasswordEnc,
		int64(g.PollInterval/time.Second), int64(g.ChargingInterval/time.Second), ms(g.CreatedAt), ms(g.UpdatedAt))
	if err != nil {
		return Gateway{}, fmt.Errorf("store: creating gateway: %w", err)
	}
	g.ID, err = res.LastInsertId()
	return g, err
}

// UpdateGateway validates and saves g's settings (matched by ID). A new
// password or pin clears the login back-off and any pending certificate.
func (s *Store) UpdateGateway(ctx context.Context, g Gateway, now time.Time) (Gateway, error) {
	if err := g.Normalize(); err != nil {
		return Gateway{}, err
	}
	old, err := s.Gateway(ctx, g.ID)
	if err != nil {
		return Gateway{}, err
	}
	credsChanged := old.Pin != g.Pin || string(old.PasswordEnc) != string(g.PasswordEnc) || old.Address != g.Address
	_, err = s.db.ExecContext(ctx, `UPDATE gateways SET name = ?, address = ?, allow_non_lan = ?, enabled = ?,
		pin_sha256 = ?, password_enc = ?, poll_interval_s = ?, charging_interval_s = ?, updated_at = ?,
		pending_pin_sha256 = CASE WHEN ? THEN '' ELSE pending_pin_sha256 END,
		backoff_failures = CASE WHEN ? THEN 0 ELSE backoff_failures END,
		backoff_until = CASE WHEN ? THEN 0 ELSE backoff_until END,
		backoff_cause = CASE WHEN ? THEN '' ELSE backoff_cause END
		WHERE id = ?`,
		g.Name, g.Address, b2i(g.AllowNonLAN), b2i(g.Enabled), g.Pin, g.PasswordEnc,
		int64(g.PollInterval/time.Second), int64(g.ChargingInterval/time.Second), ms(now.UTC().Truncate(time.Millisecond)),
		credsChanged, credsChanged, credsChanged, credsChanged, g.ID)
	if err != nil {
		return Gateway{}, fmt.Errorf("store: updating gateway: %w", err)
	}
	return s.Gateway(ctx, g.ID)
}

// AcceptGatewayPin makes the pending certificate the pinned one, so polling
// resumes (the owner confirmed it after gateway_cert_changed).
func (s *Store) AcceptGatewayPin(ctx context.Context, id int64, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE gateways SET pin_sha256 = pending_pin_sha256, pending_pin_sha256 = '',
		updated_at = ? WHERE id = ? AND length(pending_pin_sha256) = 64`, ms(now), id)
	if err != nil {
		return fmt.Errorf("store: accepting gateway certificate: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetGatewayPendingPin records a certificate that differs from the pin.
// It does not change updated_at, so the poller's worker keeps its state.
func (s *Store) SetGatewayPendingPin(ctx context.Context, id int64, fp string) error {
	fp = NormalizePin(fp)
	if !validPin(fp) {
		return tr.Err("gateway_check.err_pin")
	}
	_, err := s.db.ExecContext(ctx, "UPDATE gateways SET pending_pin_sha256 = ? WHERE id = ?", fp, id)
	return err
}

// SetGatewayBackoff persists the login back-off. It does not change
// updated_at.
func (s *Store) SetGatewayBackoff(ctx context.Context, id int64, b gateway.Backoff) error {
	var until int64
	if !b.Until.IsZero() {
		until = ms(b.Until)
	}
	_, err := s.db.ExecContext(ctx, `UPDATE gateways SET backoff_failures = ?, backoff_until = ?, backoff_cause = ?
		WHERE id = ?`, b.Failures, until, b.Cause, id)
	return err
}

// DeleteGateway removes a Gateway and all of its data.
func (s *Store) DeleteGateway(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM gateways WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("store: deleting gateway: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Gateway returns one Gateway.
func (s *Store) Gateway(ctx context.Context, id int64) (Gateway, error) {
	g, err := scanGateway(s.db.QueryRowContext(ctx, "SELECT "+gatewayCols+" FROM gateways WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Gateway{}, ErrNotFound
	}
	return g, err
}

// Gateways returns all Gateways ordered by ID.
func (s *Store) Gateways(ctx context.Context) ([]Gateway, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+gatewayCols+" FROM gateways ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Gateway
	for rows.Next() {
		g, err := scanGateway(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GatewayInfo is what the Gateway reports about itself.
type GatewayInfo struct {
	GatewayID         int64
	FirmwareVersion   string
	GitHash           string
	FirmwareSince     time.Time
	UptimeS           int64
	HasUptime         bool
	BatteryCount      int
	FullPackWh        float64
	FirstFullPackWh   float64
	NominalEnergyKWh  float64
	SolarRatingW      float64
	Timezone          string
	RealMode          string
	BackupReservePct  float64 // raw scale; see gateway.AppPercent
	SitemasterRunning bool
	ConnectedToTesla  bool // unreliable; diagnostics only
	FirstSeen         time.Time
	LastSeen          time.Time
}

// GatewayEvent is a change detected by the poller.
type GatewayEvent struct {
	ID        int64
	GatewayID int64
	TS        time.Time
	Kind      string
	Details   map[string]string
}

func gwField(rep gateway.Report, name string, v any) any {
	if rep.Untrusted(name) {
		return nil
	}
	return v
}

func gwInvalid(reps ...gateway.Report) []string {
	var names []string
	for _, rep := range reps {
		for _, fe := range rep.Invalid {
			names = append(names, string(rep.Endpoint)+":"+fe.Field)
		}
		for _, m := range rep.Missing {
			names = append(names, string(rep.Endpoint)+":"+m)
		}
	}
	return names
}

// SaveGatewaySnapshot stores one successful Gateway poll atomically:
// readings, raw payloads, identity, detected events and a poll-log entry.
// info is optional (the slowly changing site description).
func (s *Store) SaveGatewaySnapshot(ctx context.Context, gatewayID int64, snap *gateway.Snapshot, info *gateway.Info,
	events []GatewayEvent, attempt int, took time.Duration,
) error {
	ts := ms(snap.FetchedAt)
	return s.withTx(ctx, func(tx *sql.Tx) error {
		a, ar := snap.Aggregates, snap.Reports[gateway.EndpointAggregates]
		soe, sr := snap.SOE, snap.Reports[gateway.EndpointSOE]
		sys, yr := snap.SystemStatus, snap.Reports[gateway.EndpointSystemStatus]
		gs, gr := snap.GridStatus, snap.Reports[gateway.EndpointGridStatus]
		grid := gs.GridStatus
		if gr.Untrusted("grid_status") {
			grid = ""
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO readings_site (gateway_id, ts, solar_w, load_w, site_w,
			battery_w, solar_exported_wh, load_imported_wh, site_imported_wh, site_exported_wh, battery_imported_wh,
			battery_exported_wh, soe_pct, remaining_wh, full_pack_wh, grid_status, invalid_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			gatewayID, ts,
			gwField(ar, "solar.instant_power", a.Solar.InstantPower), gwField(ar, "load.instant_power", a.Load.InstantPower),
			gwField(ar, "site.instant_power", a.Site.InstantPower), gwField(ar, "battery.instant_power", a.Battery.InstantPower),
			gwField(ar, "solar.energy_exported", a.Solar.EnergyExported), gwField(ar, "load.energy_imported", a.Load.EnergyImported),
			gwField(ar, "site.energy_imported", a.Site.EnergyImported), gwField(ar, "site.energy_exported", a.Site.EnergyExported),
			gwField(ar, "battery.energy_imported", a.Battery.EnergyImported),
			gwField(ar, "battery.energy_exported", a.Battery.EnergyExported),
			gwField(sr, "percentage", soe.Percentage),
			gwField(yr, "nominal_energy_remaining", sys.NominalEnergyRemaining),
			gwField(yr, "nominal_full_pack_energy", sys.NominalFullPackEnergy),
			grid, jsonList(gwInvalid(ar, sr, yr, gr))); err != nil {
			return fmt.Errorf("store: inserting site reading: %w", err)
		}

		for _, ep := range gateway.SnapshotEndpoints {
			if body, ok := snap.Raw[ep]; ok {
				if _, err := tx.ExecContext(ctx, `INSERT INTO gateway_raw_payloads (gateway_id, ts, endpoint, body)
					VALUES (?, ?, ?, ?)`, gatewayID, ts, string(ep), body); err != nil {
					return fmt.Errorf("store: inserting gateway raw payload: %w", err)
				}
			}
		}

		if err := upsertGatewayInfo(ctx, tx, gatewayID, ts, snap, info); err != nil {
			return err
		}
		for _, ev := range events {
			if err := insertGatewayEvent(ctx, tx, gatewayID, ev); err != nil {
				return err
			}
		}
		return insertGatewayPollLog(ctx, tx, gatewayID, snap.FetchedAt, true, attempt, took, "")
	})
}

func upsertGatewayInfo(ctx context.Context, tx *sql.Tx, gatewayID, ts int64, snap *gateway.Snapshot, info *gateway.Info) error {
	st, str := snap.Status, snap.Reports[gateway.EndpointStatus]
	fw := st.Firmware()
	if str.Untrusted("version") || fw == "" {
		return nil // without a trustworthy identity, keep what we had
	}
	var uptime any
	if d, err := st.Uptime(); err == nil && !str.Untrusted("up_time_seconds") {
		uptime = int64(d / time.Second)
	}
	sys, yr := snap.SystemStatus, snap.Reports[gateway.EndpointSystemStatus]
	fullPack := gwField(yr, "nominal_full_pack_energy", sys.NominalFullPackEnergy)
	op, opr := snap.Operation, snap.Reports[gateway.EndpointOperation]
	sm := snap.Sitemaster
	var nominal, rating any
	var tz string
	if info != nil {
		nominal = nullIfZero(info.SiteInfo.NominalSystemEnergyKWh)
		var w float64
		for _, s := range info.Solars {
			w += s.PowerRatingWatts
		}
		rating = nullIfZero(w)
		tz = info.SiteInfo.Timezone
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO gateway_info (gateway_id, firmware_version, git_hash, firmware_since_at,
		uptime_s, battery_count, full_pack_wh, first_full_pack_wh, nominal_energy_kwh, solar_rating_w, timezone,
		real_mode, backup_reserve_pct, sitemaster_running, connected_to_tesla, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (gateway_id) DO UPDATE SET
			firmware_since_at = CASE WHEN gateway_info.firmware_version = excluded.firmware_version
				THEN gateway_info.firmware_since_at ELSE excluded.firmware_since_at END,
			firmware_version = excluded.firmware_version, git_hash = excluded.git_hash,
			uptime_s = excluded.uptime_s, battery_count = excluded.battery_count,
			full_pack_wh = COALESCE(excluded.full_pack_wh, gateway_info.full_pack_wh),
			first_full_pack_wh = COALESCE(gateway_info.first_full_pack_wh, excluded.first_full_pack_wh),
			nominal_energy_kwh = COALESCE(excluded.nominal_energy_kwh, gateway_info.nominal_energy_kwh),
			solar_rating_w = COALESCE(excluded.solar_rating_w, gateway_info.solar_rating_w),
			timezone = CASE WHEN excluded.timezone != '' THEN excluded.timezone ELSE gateway_info.timezone END,
			real_mode = excluded.real_mode, backup_reserve_pct = excluded.backup_reserve_pct,
			sitemaster_running = excluded.sitemaster_running, connected_to_tesla = excluded.connected_to_tesla,
			last_seen_at = excluded.last_seen_at`,
		gatewayID, fw, st.GitHash, ts, uptime, len(sys.BatteryBlocks), fullPack, fullPack, nominal, rating, tz,
		op.RealMode, gwField(opr, "backup_reserve_percent", op.BackupReservePercent),
		b2i(sm.Running), b2i(sm.ConnectedToTesla), ts, ts)
	if err != nil {
		return fmt.Errorf("store: saving gateway info: %w", err)
	}
	return nil
}

func insertGatewayEvent(ctx context.Context, tx *sql.Tx, gatewayID int64, ev GatewayEvent) error {
	details := ev.Details
	if details == nil {
		details = map[string]string{}
	}
	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO gateway_events (gateway_id, ts, kind, details_json) VALUES (?, ?, ?, ?)",
		gatewayID, ms(ev.TS), ev.Kind, string(b)); err != nil {
		return fmt.Errorf("store: inserting gateway event: %w", err)
	}
	return nil
}

// RecordGatewayEvent stores an event outside a snapshot (e.g. a
// certificate change, which prevents the poll).
func (s *Store) RecordGatewayEvent(ctx context.Context, gatewayID int64, ev GatewayEvent) error {
	return s.withTx(ctx, func(tx *sql.Tx) error { return insertGatewayEvent(ctx, tx, gatewayID, ev) })
}

func insertGatewayPollLog(ctx context.Context, tx *sql.Tx, gatewayID int64, at time.Time, ok bool, attempt int, took time.Duration, errText string) error {
	if r := []rune(errText); len(r) > maxPollErrorLen {
		errText = string(r[:maxPollErrorLen]) + "…"
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO gateway_poll_log (gateway_id, ts, ok, attempt, duration_ms, error)
		VALUES (?, ?, ?, ?, ?, ?)`, gatewayID, ms(at), b2i(ok), attempt, took.Milliseconds(), errText); err != nil {
		return fmt.Errorf("store: inserting gateway poll log: %w", err)
	}
	return nil
}

// RecordGatewayPollFailure logs a failed Gateway poll attempt.
func (s *Store) RecordGatewayPollFailure(ctx context.Context, gatewayID int64, at time.Time, attempt int, took time.Duration, pollErr error) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		return insertGatewayPollLog(ctx, tx, gatewayID, at, false, attempt, took, pollErr.Error())
	})
}

// GatewayInfo returns the stored identity of a Gateway.
func (s *Store) GatewayInfo(ctx context.Context, gatewayID int64) (*GatewayInfo, error) {
	var gi GatewayInfo
	var since, first, last int64
	var uptime sql.NullInt64
	var fullPack, firstFull, nominal, rating, reserve sql.NullFloat64
	err := s.db.QueryRowContext(ctx, `SELECT gateway_id, firmware_version, git_hash, firmware_since_at, uptime_s,
		battery_count, full_pack_wh, first_full_pack_wh, nominal_energy_kwh, solar_rating_w, timezone, real_mode,
		backup_reserve_pct, sitemaster_running, connected_to_tesla, first_seen_at, last_seen_at
		FROM gateway_info WHERE gateway_id = ?`, gatewayID).Scan(&gi.GatewayID, &gi.FirmwareVersion, &gi.GitHash,
		&since, &uptime, &gi.BatteryCount, &fullPack, &firstFull, &nominal, &rating, &gi.Timezone, &gi.RealMode,
		&reserve, &gi.SitemasterRunning, &gi.ConnectedToTesla, &first, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	gi.FirmwareSince, gi.FirstSeen, gi.LastSeen = fromMS(since), fromMS(first), fromMS(last)
	gi.UptimeS, gi.HasUptime = uptime.Int64, uptime.Valid
	gi.FullPackWh, gi.FirstFullPackWh, gi.NominalEnergyKWh = fullPack.Float64, firstFull.Float64, nominal.Float64
	gi.SolarRatingW, gi.BackupReservePct = rating.Float64, reserve.Float64
	return &gi, nil
}

// GatewayState is what the poller remembers between restarts.
type GatewayState struct {
	Info        *GatewayInfo // nil until the first successful poll
	LastSuccess time.Time
	GridStatus  string
}

// LatestGatewayState loads the poller's memory for one Gateway.
func (s *Store) LatestGatewayState(ctx context.Context, gatewayID int64) (GatewayState, error) {
	var st GatewayState
	info, err := s.GatewayInfo(ctx, gatewayID)
	switch {
	case err == nil:
		st.Info = info
	case !errors.Is(err, ErrNotFound):
		return st, err
	}
	var ts int64
	err = s.db.QueryRowContext(ctx, `SELECT ts, grid_status FROM readings_site WHERE gateway_id = ?
		ORDER BY ts DESC LIMIT 1`, gatewayID).Scan(&ts, &st.GridStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.LastSuccess = fromMS(ts)
	return st, nil
}

// GatewayEvents returns Gateway events since a time, newest first.
func (s *Store) GatewayEvents(ctx context.Context, gatewayID int64, since time.Time, limit int) ([]GatewayEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, gateway_id, ts, kind, details_json FROM gateway_events
		WHERE gateway_id = ? AND ts >= ? ORDER BY ts DESC, id DESC LIMIT ?`, gatewayID, ms(since), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []GatewayEvent
	for rows.Next() {
		var ev GatewayEvent
		var ts int64
		var details string
		if err := rows.Scan(&ev.ID, &ev.GatewayID, &ts, &ev.Kind, &details); err != nil {
			return nil, err
		}
		ev.TS = fromMS(ts)
		_ = json.Unmarshal([]byte(details), &ev.Details)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// GatewayPollLog returns the most recent poll attempts, newest first.
func (s *Store) GatewayPollLog(ctx context.Context, gatewayID int64, limit int) ([]PollLogEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, ok, attempt, duration_ms, error FROM gateway_poll_log
		WHERE gateway_id = ? ORDER BY ts DESC, id DESC LIMIT ?`, gatewayID, limit)
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

// SiteReading is one stored Gateway poll. Pointer fields are nil when the
// decoder flagged the value.
type SiteReading struct {
	TS                                           time.Time
	SolarW, LoadW, SiteW, BatteryW               *float64
	SolarExportedWh, LoadImportedWh              *float64
	SiteImportedWh, SiteExportedWh               *float64
	BatteryImportedWh, BatteryExportedWh, SOEPct *float64
	GridStatus                                   string
}

// SiteReadings returns readings in [from, to), oldest first.
func (s *Store) SiteReadings(ctx context.Context, gatewayID int64, from, to time.Time) ([]SiteReading, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, solar_w, load_w, site_w, battery_w, solar_exported_wh,
		load_imported_wh, site_imported_wh, site_exported_wh, battery_imported_wh, battery_exported_wh, soe_pct,
		grid_status FROM readings_site WHERE gateway_id = ? AND ts >= ? AND ts < ? ORDER BY ts, id`,
		gatewayID, ms(from), ms(to))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SiteReading
	for rows.Next() {
		var r SiteReading
		var ts int64
		var v [11]sql.NullFloat64
		if err := rows.Scan(&ts, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9], &v[10],
			&r.GridStatus); err != nil {
			return nil, err
		}
		r.TS = fromMS(ts)
		p := func(n sql.NullFloat64) *float64 {
			if !n.Valid {
				return nil
			}
			return &n.Float64
		}
		r.SolarW, r.LoadW, r.SiteW, r.BatteryW = p(v[0]), p(v[1]), p(v[2]), p(v[3])
		r.SolarExportedWh, r.LoadImportedWh, r.SiteImportedWh, r.SiteExportedWh = p(v[4]), p(v[5]), p(v[6]), p(v[7])
		r.BatteryImportedWh, r.BatteryExportedWh, r.SOEPct = p(v[8]), p(v[9]), p(v[10])
		out = append(out, r)
	}
	return out, rows.Err()
}

// AnyVehiclePlugged reports whether the latest reading of any enabled Wall
// Connector shows a car plugged in or charging; the Gateway is then polled
// on its charging cadence so solar attribution stays accurate.
func (s *Store) AnyVehiclePlugged(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices d WHERE d.enabled = 1 AND EXISTS (
		SELECT 1 FROM readings_vitals v WHERE v.device_id = d.id
		AND v.ts = (SELECT MAX(ts) FROM readings_vitals WHERE device_id = d.id)
		AND (v.vehicle_connected = 1 OR v.contactor_closed = 1))`).Scan(&n)
	return n > 0, err
}

// SiteSamples returns the Gateway's lifetime counters in [from, to), plus
// the last reading before from, for solar attribution. With several
// Gateways it uses the first enabled one (the owner has one, D27). Rows with
// any counter the decoder flagged are skipped. It returns nil when no
// Gateway is configured.
func (s *Store) SiteSamples(ctx context.Context, from, to time.Time) ([]energy.SiteSample, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, "SELECT id FROM gateways WHERE enabled = 1 ORDER BY id LIMIT 1").Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	const cols = `ts, solar_exported_wh, site_imported_wh, site_exported_wh, battery_imported_wh, battery_exported_wh
		FROM readings_site WHERE gateway_id = ? AND solar_exported_wh IS NOT NULL AND site_imported_wh IS NOT NULL
		AND site_exported_wh IS NOT NULL AND battery_imported_wh IS NOT NULL AND battery_exported_wh IS NOT NULL`
	rows, err := s.db.QueryContext(ctx, `SELECT * FROM (SELECT `+cols+` AND ts < ? ORDER BY ts DESC LIMIT 1)
		UNION ALL SELECT `+cols+` AND ts >= ? AND ts < ? ORDER BY 1`, id, ms(from), id, ms(from), ms(to))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []energy.SiteSample
	for rows.Next() {
		var x energy.SiteSample
		var ts int64
		if err := rows.Scan(&ts, &x.SolarWh, &x.GridImportWh, &x.GridExportWh, &x.BatteryChargeWh, &x.BatteryDischargeWh); err != nil {
			return nil, err
		}
		x.TS = fromMS(ts)
		out = append(out, x)
	}
	return out, rows.Err()
}

// HasGateway reports whether an enabled Gateway is configured.
func (s *Store) HasGateway(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM gateways WHERE enabled = 1").Scan(&n)
	return n > 0, err
}

// GatewayHistoryEntry is one stored Gateway poll rebuilt for a rule preview.
type GatewayHistoryEntry struct {
	Snapshot *gateway.Snapshot
	Events   []GatewayEvent
}

// GatewayHistory rebuilds the stored Gateway polls in [from, to), oldest
// first, as partial snapshots: power, counters, battery level, energy
// remaining, full-pack energy and grid status, with the battery count from
// gateway_info. Values that were not stored (flagged by the decoder) are
// reported as missing, so rules skip them as they did live. Events are
// attached to the poll at which they were recorded.
func (s *Store) GatewayHistory(ctx context.Context, gatewayID int64, from, to time.Time) ([]GatewayHistoryEntry, error) {
	blocks := 0
	if info, err := s.GatewayInfo(ctx, gatewayID); err == nil {
		blocks = info.BatteryCount
	}
	evs, err := s.GatewayEvents(ctx, gatewayID, from, 10000)
	if err != nil {
		return nil, err
	}
	byTS := map[int64][]GatewayEvent{}
	for _, ev := range evs {
		byTS[ms(ev.TS)] = append([]GatewayEvent{ev}, byTS[ms(ev.TS)]...)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ts, solar_w, load_w, site_w, battery_w, solar_exported_wh,
		load_imported_wh, site_imported_wh, site_exported_wh, battery_imported_wh, battery_exported_wh, soe_pct,
		remaining_wh, full_pack_wh, grid_status FROM readings_site WHERE gateway_id = ? AND ts >= ? AND ts < ?
		ORDER BY ts, id`, gatewayID, ms(from), ms(to))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []GatewayHistoryEntry
	for rows.Next() {
		var ts int64
		var v [13]sql.NullFloat64
		var grid string
		if err := rows.Scan(&ts, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9], &v[10],
			&v[11], &v[12], &grid); err != nil {
			return nil, err
		}
		snap := &gateway.Snapshot{FetchedAt: fromMS(ts), Reports: map[gateway.Endpoint]gateway.Report{}}
		set := func(ep gateway.Endpoint, field string, n sql.NullFloat64, dst *float64) {
			if n.Valid {
				*dst = n.Float64
				return
			}
			r := snap.Reports[ep]
			r.Endpoint = ep
			r.Missing = append(r.Missing, field)
			snap.Reports[ep] = r
		}
		a := &snap.Aggregates
		set(gateway.EndpointAggregates, "solar.instant_power", v[0], &a.Solar.InstantPower)
		set(gateway.EndpointAggregates, "load.instant_power", v[1], &a.Load.InstantPower)
		set(gateway.EndpointAggregates, "site.instant_power", v[2], &a.Site.InstantPower)
		set(gateway.EndpointAggregates, "battery.instant_power", v[3], &a.Battery.InstantPower)
		set(gateway.EndpointAggregates, "solar.energy_exported", v[4], &a.Solar.EnergyExported)
		set(gateway.EndpointAggregates, "load.energy_imported", v[5], &a.Load.EnergyImported)
		set(gateway.EndpointAggregates, "site.energy_imported", v[6], &a.Site.EnergyImported)
		set(gateway.EndpointAggregates, "site.energy_exported", v[7], &a.Site.EnergyExported)
		set(gateway.EndpointAggregates, "battery.energy_imported", v[8], &a.Battery.EnergyImported)
		set(gateway.EndpointAggregates, "battery.energy_exported", v[9], &a.Battery.EnergyExported)
		set(gateway.EndpointSOE, "percentage", v[10], &snap.SOE.Percentage)
		set(gateway.EndpointSystemStatus, "nominal_energy_remaining", v[11], &snap.SystemStatus.NominalEnergyRemaining)
		set(gateway.EndpointSystemStatus, "nominal_full_pack_energy", v[12], &snap.SystemStatus.NominalFullPackEnergy)
		snap.SystemStatus.BatteryBlocks = make([]gateway.BatteryBlock, blocks)
		if grid == "" {
			snap.Reports[gateway.EndpointGridStatus] = gateway.Report{Endpoint: gateway.EndpointGridStatus,
				Missing: []string{"grid_status"}}
		}
		snap.GridStatus.GridStatus = grid
		out = append(out, GatewayHistoryEntry{Snapshot: snap, Events: byTS[ts]})
	}
	return out, rows.Err()
}
