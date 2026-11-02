// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package alerts evaluates alert rules against each poll and drives a
// per-(rule, device) state machine with debounce ("for"), minimum
// consecutive samples, hysteresis, cooldown, repeat-while-critical,
// resolved notices and snoozes. It produces notifications for Phase 4's
// channels and records an alert history.
package alerts

import (
	"encoding/json"
	"fmt"
	"time"
)

// Severity of an alert. The zero value means "not breaching".
type Severity int

// Severities, in increasing order.
const (
	None Severity = iota
	Info
	Warning
	Critical
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "info"
	case Warning:
		return "warning"
	case Critical:
		return "critical"
	default:
		return "none"
	}
}

// ParseSeverity parses the String form.
func ParseSeverity(s string) (Severity, error) {
	for _, v := range []Severity{None, Info, Warning, Critical} {
		if v.String() == s {
			return v, nil
		}
	}
	return None, fmt.Errorf("alerts: unknown severity %q", s)
}

// MarshalJSON encodes the severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON decodes a severity name.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	v, err := ParseSeverity(str)
	*s = v
	return err
}

// QuietHours mutes non-critical notifications during a daily window (e.g.
// 22:00–07:00) in the given location. Used by notification channels.
type QuietHours struct {
	Enabled bool
	Start   time.Duration // offset from local midnight
	End     time.Duration
}

// ParseQuietHours parses "HH:MM-HH:MM".
func ParseQuietHours(s string) (QuietHours, error) {
	var sh, sm, eh, em int
	if _, err := fmt.Sscanf(s, "%d:%d-%d:%d", &sh, &sm, &eh, &em); err != nil ||
		sh < 0 || sh > 23 || eh < 0 || eh > 23 || sm < 0 || sm > 59 || em < 0 || em > 59 {
		return QuietHours{}, fmt.Errorf("alerts: quiet hours must look like 22:00-07:00, got %q", s)
	}
	start := time.Duration(sh)*time.Hour + time.Duration(sm)*time.Minute
	end := time.Duration(eh)*time.Hour + time.Duration(em)*time.Minute
	if start == end {
		return QuietHours{}, fmt.Errorf("alerts: quiet hours start and end are equal")
	}
	return QuietHours{Enabled: true, Start: start, End: end}, nil
}

// Active reports whether t (in its own location) falls inside the window.
func (q QuietHours) Active(t time.Time) bool {
	if !q.Enabled {
		return false
	}
	y, m, d := t.Date()
	off := t.Sub(time.Date(y, m, d, 0, 0, 0, 0, t.Location()))
	if q.Start < q.End {
		return off >= q.Start && off < q.End
	}
	return off >= q.Start || off < q.End // window spans midnight
}

// Allows reports whether a notification of severity sev may be sent at t.
// Critical notifications always go through.
func (q QuietHours) Allows(sev Severity, t time.Time) bool {
	return sev >= Critical || !q.Active(t)
}
