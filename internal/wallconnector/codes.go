// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package wallconnector

import "fmt"

// CodeInfo describes a numeric status code reported by the device.
// Known is false when the meaning has not been observed/confirmed; the UI
// shows the raw number in that case rather than guessing.
type CodeInfo struct {
	Code  int
	Label string
	Known bool
}

func (c CodeInfo) String() string { return c.Label }

// The tables below contain only meanings that have been OBSERVED on real
// hardware, with the context noted. Do not add guessed meanings; add a
// fixture and a note instead (see docs/DEVELOPMENT_PLAN.md §2).
var (
	evseStates = map[int]string{
		1: "Idle (no vehicle)", // UWC fw 26.26.10, unplugged
	}
	configStatuses = map[int]string{
		5: "Configured", // UWC fw 26.26.10, normal commissioned unit
	}
	notReadyReasons = map[int]string{
		// UWC fw 26.26.10 reports [2,4,8] while unplugged; individual
		// meanings are not yet known, so none are listed.
	}
	alertCodes = map[int]string{}
)

// UnpluggedNotReadyReasons is the set reported by an idle, unplugged UWC
// (fw 26.26.10). It is normal and must not raise alerts.
var UnpluggedNotReadyReasons = []int{2, 4, 8}

func lookup(table map[int]string, code int) CodeInfo {
	if l, ok := table[code]; ok {
		return CodeInfo{Code: code, Label: l, Known: true}
	}
	return CodeInfo{Code: code, Label: fmt.Sprintf("Unknown (code %d)", code)}
}

// EVSEStateInfo describes a vitals.evse_state value.
func EVSEStateInfo(code int) CodeInfo { return lookup(evseStates, code) }

// ConfigStatusInfo describes a vitals.config_status value.
func ConfigStatusInfo(code int) CodeInfo { return lookup(configStatuses, code) }

// NotReadyReasonInfo describes an entry of vitals.evse_not_ready_reasons.
func NotReadyReasonInfo(code int) CodeInfo { return lookup(notReadyReasons, code) }

// AlertInfo describes an entry of vitals.current_alerts.
func AlertInfo(code int) CodeInfo { return lookup(alertCodes, code) }
