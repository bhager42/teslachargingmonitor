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
	"errors"
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

// Interval limits shared by the GUI, the CLI and the database constraints.
const (
	MinInterval = time.Minute
	MaxInterval = 24 * time.Hour
)

// Default polling cadence (owner decisions D6, D10).
const (
	DefaultPollInterval    = 60 * time.Minute
	DefaultPluggedInterval = 5 * time.Minute
)

// ContinuousLoadFactor is the NEC 80 % rule: max charging current as a
// fraction of the breaker rating.
const ContinuousLoadFactor = 0.8

// MaxCurrentLimitA bounds the configured maximum charging current.
const MaxCurrentLimitA = 100.0

// Device is a configured Wall Connector.
type Device struct {
	ID              int64
	Name            string
	Address         string // normalized base URL, e.g. "http://192.168.1.17"
	AllowNonLAN     bool
	Enabled         bool
	PollInterval    time.Duration
	PluggedInterval time.Duration
	FastWhenPlugged bool
	NominalVoltageV float64
	NominalHz       float64
	BreakerA        float64 // 0 = not set
	MaxCurrentA     float64 // 0 = not set
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// NewDevice returns a Device with the default settings.
func NewDevice(name, address string) Device {
	return Device{
		Name:            name,
		Address:         address,
		Enabled:         true,
		PollInterval:    DefaultPollInterval,
		PluggedInterval: DefaultPluggedInterval,
		FastWhenPlugged: true,
		NominalVoltageV: 240,
		NominalHz:       60,
	}
}

// Normalize validates d and rewrites Address into canonical form. When
// BreakerA is set and MaxCurrentA is not, MaxCurrentA defaults to 80 % of it.
func (d *Device) Normalize() error {
	if n := utf8.RuneCountInString(d.Name); n < 1 || n > 64 {
		return tr.Err("device_check.err_name")
	}
	addr, err := wallconnector.ParseAddress(d.Address, wallconnector.AddressOptions{AllowNonLAN: d.AllowNonLAN})
	if err != nil {
		return err
	}
	d.Address = addr.BaseURL()
	for _, iv := range []struct {
		key string
		v   time.Duration
	}{{"device_check.err_poll_interval", d.PollInterval}, {"device_check.err_plugged_interval", d.PluggedInterval}} {
		if iv.v < MinInterval || iv.v > MaxInterval || iv.v%time.Second != 0 {
			return tr.Err(iv.key, "min", MinInterval, "max", MaxInterval)
		}
	}
	switch d.NominalVoltageV {
	case 120, 208, 220, 230, 240, 277, 400, 480:
	default:
		return tr.Err("device_check.err_voltage", "voltage", strconv.FormatFloat(d.NominalVoltageV, 'g', -1, 64))
	}
	if d.NominalHz != 50 && d.NominalHz != 60 {
		return tr.Err("device_check.err_frequency")
	}
	if d.BreakerA < 0 || d.BreakerA > 200 || d.MaxCurrentA < 0 || d.MaxCurrentA > MaxCurrentLimitA {
		return tr.Err("device_check.err_current_range")
	}
	if d.BreakerA > 0 && d.MaxCurrentA == 0 {
		// Capped so the default stays within the limit above (found by
		// FuzzDeviceNormalize: a 131 A breaker gave 104.8 A).
		d.MaxCurrentA = min(d.BreakerA*ContinuousLoadFactor, MaxCurrentLimitA)
	}
	if d.BreakerA > 0 && d.MaxCurrentA > d.BreakerA*ContinuousLoadFactor {
		return tr.Err("device_check.err_current_breaker", "max", strconv.FormatFloat(d.MaxCurrentA, 'g', -1, 64),
			"breaker", strconv.FormatFloat(d.BreakerA, 'g', -1, 64))
	}
	return nil
}

// ParsedAddress returns the device address as a wallconnector.Address.
func (d Device) ParsedAddress() (wallconnector.Address, error) {
	return wallconnector.ParseAddress(d.Address, wallconnector.AddressOptions{AllowNonLAN: d.AllowNonLAN})
}

const deviceCols = `id, name, address, allow_non_lan, enabled, poll_interval_s, plugged_interval_s,
	fast_when_plugged, nominal_voltage_v, nominal_hz, COALESCE(breaker_a, 0), COALESCE(max_current_a, 0),
	created_at, updated_at`

func scanDevice(sc interface{ Scan(...any) error }) (Device, error) {
	var d Device
	var poll, plugged, created, updated int64
	err := sc.Scan(&d.ID, &d.Name, &d.Address, &d.AllowNonLAN, &d.Enabled, &poll, &plugged,
		&d.FastWhenPlugged, &d.NominalVoltageV, &d.NominalHz, &d.BreakerA, &d.MaxCurrentA, &created, &updated)
	d.PollInterval = time.Duration(poll) * time.Second
	d.PluggedInterval = time.Duration(plugged) * time.Second
	d.CreatedAt, d.UpdatedAt = fromMS(created), fromMS(updated)
	return d, err
}

func nullIfZero(f float64) any {
	if f == 0 {
		return nil
	}
	return f
}

// CreateDevice validates and inserts d.
func (s *Store) CreateDevice(ctx context.Context, d Device, now time.Time) (Device, error) {
	if err := d.Normalize(); err != nil {
		return Device{}, err
	}
	d.CreatedAt, d.UpdatedAt = now.UTC().Truncate(time.Millisecond), now.UTC().Truncate(time.Millisecond)
	res, err := s.db.ExecContext(ctx, `INSERT INTO devices (name, address, allow_non_lan, enabled, poll_interval_s,
		plugged_interval_s, fast_when_plugged, nominal_voltage_v, nominal_hz, breaker_a, max_current_a, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.Name, d.Address, b2i(d.AllowNonLAN), b2i(d.Enabled), int64(d.PollInterval/time.Second),
		int64(d.PluggedInterval/time.Second), b2i(d.FastWhenPlugged), d.NominalVoltageV, d.NominalHz,
		nullIfZero(d.BreakerA), nullIfZero(d.MaxCurrentA), ms(d.CreatedAt), ms(d.UpdatedAt))
	if err != nil {
		return Device{}, fmt.Errorf("store: creating device: %w", err)
	}
	d.ID, err = res.LastInsertId()
	return d, err
}

// UpdateDevice validates and saves d (matched by ID).
func (s *Store) UpdateDevice(ctx context.Context, d Device, now time.Time) (Device, error) {
	if err := d.Normalize(); err != nil {
		return Device{}, err
	}
	d.UpdatedAt = now.UTC().Truncate(time.Millisecond)
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET name = ?, address = ?, allow_non_lan = ?, enabled = ?,
		poll_interval_s = ?, plugged_interval_s = ?, fast_when_plugged = ?, nominal_voltage_v = ?, nominal_hz = ?,
		breaker_a = ?, max_current_a = ?, updated_at = ? WHERE id = ?`,
		d.Name, d.Address, b2i(d.AllowNonLAN), b2i(d.Enabled), int64(d.PollInterval/time.Second),
		int64(d.PluggedInterval/time.Second), b2i(d.FastWhenPlugged), d.NominalVoltageV, d.NominalHz,
		nullIfZero(d.BreakerA), nullIfZero(d.MaxCurrentA), ms(d.UpdatedAt), d.ID)
	if err != nil {
		return Device{}, fmt.Errorf("store: updating device: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Device{}, ErrNotFound
	}
	return s.Device(ctx, d.ID)
}

// DeleteDevice removes a device and all of its data.
func (s *Store) DeleteDevice(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM devices WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("store: deleting device: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Device returns one device.
func (s *Store) Device(ctx context.Context, id int64) (Device, error) {
	d, err := scanDevice(s.db.QueryRowContext(ctx, "SELECT "+deviceCols+" FROM devices WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	return d, err
}

// Devices returns all devices ordered by ID.
func (s *Store) Devices(ctx context.Context) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+deviceCols+" FROM devices ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
