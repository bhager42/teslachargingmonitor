// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package store

import "testing"

func TestMaxCurrentDefault(t *testing.T) {
	for _, c := range []struct{ breaker, want float64 }{{60, 48}, {125, 100}, {131, 100}, {200, 100}, {0, 0}} {
		d := NewDevice("Garage", "192.168.1.17")
		d.BreakerA = c.breaker
		if err := d.Normalize(); err != nil || d.MaxCurrentA != c.want {
			t.Errorf("breaker %v A: max current %v A (%v), want %v A", c.breaker, d.MaxCurrentA, err, c.want)
		}
	}
}
