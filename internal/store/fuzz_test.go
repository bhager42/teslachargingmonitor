// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package store

import (
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

// FuzzDeviceNormalize checks the Wall Connector settings form validation:
// accepted settings are within the documented limits, and normalising
// twice changes nothing (what is stored is what is shown and polled).
func FuzzDeviceNormalize(f *testing.F) {
	f.Add("Garage", "192.168.1.17", int64(3600), int64(300), 240.0, 60.0, 60.0, 48.0, false)
	f.Add("x", "http://wc.lan:8080/", int64(60), int64(86400), 120.0, 50.0, 0.0, 0.0, true)
	f.Add("", "8.8.8.8", int64(59), int64(1), 230.0, 55.0, 201.0, 101.0, false)
	f.Add("Ünïcødé ✓", "[fd00::17]", int64(61), int64(0), 400.0, 50.0, 100.0, 80.0, false)
	f.Fuzz(func(t *testing.T, name, addr string, poll, plugged int64, volts, hz, breaker, maxA float64, allowNonLAN bool) {
		d := NewDevice(name, addr)
		d.PollInterval, d.PluggedInterval = time.Duration(poll)*time.Second, time.Duration(plugged)*time.Second
		d.NominalVoltageV, d.NominalHz, d.BreakerA, d.MaxCurrentA, d.AllowNonLAN = volts, hz, breaker, maxA, allowNonLAN
		if d.Normalize() != nil {
			return
		}
		if d.PollInterval < MinInterval || d.PollInterval > MaxInterval || d.MaxCurrentA < 0 || d.MaxCurrentA > 100 {
			t.Fatalf("accepted %+v", d)
		}
		if d.BreakerA > 0 && d.MaxCurrentA > d.BreakerA*ContinuousLoadFactor {
			t.Fatalf("max current %v above 80 %% of breaker %v", d.MaxCurrentA, d.BreakerA)
		}
		if _, err := wallconnector.ParseAddress(d.Address, wallconnector.AddressOptions{AllowNonLAN: d.AllowNonLAN}); err != nil {
			t.Fatalf("stored address %q does not parse: %v", d.Address, err)
		}
		again := d
		if err := again.Normalize(); err != nil || again != d {
			t.Fatalf("normalise not idempotent: %+v -> %+v (%v)", d, again, err)
		}
	})
}
