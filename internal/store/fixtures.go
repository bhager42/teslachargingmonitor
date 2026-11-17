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
	"fmt"
	"math"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway"
)

// PollKind selects which stored poll "tcmon fixture export" picks. Every
// kind picks the newest matching poll that still has its raw payloads.
type PollKind string

// Poll kinds. Charging and Plugged apply to Wall Connectors; Night and
// OffGrid to Gateways; Charging also to a Gateway (a Gateway poll taken
// within 5 minutes of a Wall Connector poll with the contactor closed).
const (
	PollLatest   PollKind = "latest"
	PollCharging PollKind = "charging"
	PollPlugged  PollKind = "plugged"
	PollNight    PollKind = "night"
	PollOffGrid  PollKind = "off-grid"
)

// NightSolarW is the solar power below which a Gateway poll counts as night.
const NightSolarW = 20

// chargingNearMS is how close a Wall Connector poll must be to a Gateway
// poll for PollCharging.
const chargingNearMS = 5 * 60 * 1000

// DevicePollKinds and GatewayPollKinds list the valid kinds per source.
var (
	DevicePollKinds  = []PollKind{PollLatest, PollCharging, PollPlugged}
	GatewayPollKinds = []PollKind{PollLatest, PollCharging, PollNight, PollOffGrid}
)

// RawPollTime returns when the newest poll of a Wall Connector matching kind
// was taken, at or before before (zero means no bound). It returns
// ErrNotFound when no such poll has raw payloads left (they are pruned after
// the raw-payload retention period).
func (s *Store) RawPollTime(ctx context.Context, deviceID int64, kind PollKind, before time.Time) (time.Time, error) {
	var cond string
	switch kind {
	case PollLatest:
		cond = "1"
	case PollCharging:
		cond = `EXISTS (SELECT 1 FROM readings_vitals v WHERE v.device_id = r.device_id AND v.ts = r.ts
			AND v.contactor_closed = 1)`
	case PollPlugged:
		cond = `EXISTS (SELECT 1 FROM readings_vitals v WHERE v.device_id = r.device_id AND v.ts = r.ts
			AND v.vehicle_connected = 1 AND v.contactor_closed = 0)`
	default:
		return time.Time{}, fmt.Errorf("store: poll kind %q does not apply to a Wall Connector", kind)
	}
	return s.pollTime(ctx, `SELECT MAX(r.ts) FROM raw_payloads r WHERE r.device_id = ? AND r.ts <= ? AND `+cond,
		deviceID, before)
}

// GatewayRawPollTime is RawPollTime for a Backup Gateway.
func (s *Store) GatewayRawPollTime(ctx context.Context, gatewayID int64, kind PollKind, before time.Time) (time.Time, error) {
	var cond string
	var args []any
	switch kind {
	case PollLatest:
		cond = "1"
	case PollNight:
		cond = `EXISTS (SELECT 1 FROM readings_site s WHERE s.gateway_id = r.gateway_id AND s.ts = r.ts
			AND s.solar_w IS NOT NULL AND s.solar_w < ?)`
		args = append(args, NightSolarW)
	case PollOffGrid:
		cond = `EXISTS (SELECT 1 FROM readings_site s WHERE s.gateway_id = r.gateway_id AND s.ts = r.ts
			AND s.grid_status NOT IN ('', ?))`
		args = append(args, gateway.GridConnected)
	case PollCharging:
		cond = `EXISTS (SELECT 1 FROM readings_vitals v WHERE v.contactor_closed = 1
			AND v.ts BETWEEN r.ts - ? AND r.ts + ?)`
		args = append(args, chargingNearMS, chargingNearMS)
	default:
		return time.Time{}, fmt.Errorf("store: poll kind %q does not apply to a Gateway", kind)
	}
	return s.pollTime(ctx, `SELECT MAX(r.ts) FROM gateway_raw_payloads r WHERE r.gateway_id = ? AND r.ts <= ? AND `+cond,
		gatewayID, before, args...)
}

func (s *Store) pollTime(ctx context.Context, q string, id int64, before time.Time, extra ...any) (time.Time, error) {
	bound := int64(math.MaxInt64)
	if !before.IsZero() {
		bound = ms(before)
	}
	var ts sql.NullInt64
	if err := s.db.QueryRowContext(ctx, q, append([]any{id, bound}, extra...)...).Scan(&ts); err != nil {
		return time.Time{}, err
	}
	if !ts.Valid {
		return time.Time{}, ErrNotFound
	}
	return fromMS(ts.Int64), nil
}

// RawPoll returns the raw payloads of a Wall Connector's poll at ts, by
// endpoint name ("vitals", ...).
func (s *Store) RawPoll(ctx context.Context, deviceID int64, ts time.Time) (map[string][]byte, error) {
	return s.rawPoll(ctx, "SELECT endpoint, body FROM raw_payloads WHERE device_id = ? AND ts = ?", deviceID, ts)
}

// GatewayRawPoll returns the raw payloads of a Gateway's poll at ts, by
// endpoint path ("/api/status", ...).
func (s *Store) GatewayRawPoll(ctx context.Context, gatewayID int64, ts time.Time) (map[string][]byte, error) {
	return s.rawPoll(ctx, "SELECT endpoint, body FROM gateway_raw_payloads WHERE gateway_id = ? AND ts = ?", gatewayID, ts)
}

func (s *Store) rawPoll(ctx context.Context, q string, id int64, ts time.Time) (map[string][]byte, error) {
	rows, err := s.db.QueryContext(ctx, q, id, ms(ts))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]byte{}
	for rows.Next() {
		var ep string
		var body []byte
		if err := rows.Scan(&ep, &body); err != nil {
			return nil, err
		}
		out[ep] = body
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}
