// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package gateway

import (
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

func FuzzDecode(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join(fixtures, "*", "*.json"))
	for _, p := range files {
		if b, err := os.ReadFile(p); err == nil { //nolint:gosec // test fixture path
			f.Add(b)
		}
	}
	f.Add([]byte(`{"battery_blocks":[null,1,{"p_out":1e309}]}`))
	f.Add([]byte(`{"site":{"num_meters_aggregated":"x"},"load":{"instant_power":-1e308}}`))
	f.Add([]byte(`[{"power_rating_watts":"7600"},[]]`))
	f.Add([]byte(`{"up_time_seconds":"9999999999h"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, dec := range decoders {
			rep, err := dec(data)
			if err != nil {
				continue
			}
			if len(rep.Unknown) > maxReportedUnknown+1 || len(rep.Invalid) > maxReportedUnknown || len(rep.Missing) > maxReportedUnknown {
				t.Fatalf("report too large: %d unknown, %d invalid, %d missing", len(rep.Unknown), len(rep.Invalid), len(rep.Missing))
			}
			for _, fe := range rep.Invalid {
				if utf8.RuneCountInString(fe.Reason) > maxReasonLen+1 {
					t.Fatalf("reason too long: %d", len(fe.Reason))
				}
			}
		}
		st, _, err := DecodeStatus(data)
		if err == nil {
			_, _ = st.Uptime()
			_ = st.Firmware()
		}
	})
}
