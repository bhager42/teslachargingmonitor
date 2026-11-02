// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package auth

import (
	"sync"
	"time"
)

// Throttle limits failed login attempts per client IP (5 per 15 min) and
// globally (50 per 15 min). State is in memory: a restart clears it, which
// an attacker on the LAN cannot trigger.
type Throttle struct {
	mu     sync.Mutex
	now    func() time.Time
	window time.Duration
	perIP  int
	global int
	fails  map[string][]time.Time
	all    []time.Time
}

// NewThrottle returns a Throttle with the default limits.
func NewThrottle(now func() time.Time) *Throttle {
	return &Throttle{now: now, window: 15 * time.Minute, perIP: 5, global: 50, fails: map[string][]time.Time{}}
}

func (t *Throttle) prune(list []time.Time, now time.Time) []time.Time {
	i := 0
	for i < len(list) && now.Sub(list[i]) >= t.window {
		i++
	}
	return list[i:]
}

// Blocked returns how long ip must wait, or 0.
func (t *Throttle) Blocked(ip string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.all = t.prune(t.all, now)
	list := t.prune(t.fails[ip], now)
	if len(list) == 0 {
		delete(t.fails, ip)
	} else {
		t.fails[ip] = list
	}
	var wait time.Duration
	if len(list) >= t.perIP {
		wait = t.window - now.Sub(list[len(list)-t.perIP])
	}
	if len(t.all) >= t.global {
		wait = max(wait, t.window-now.Sub(t.all[len(t.all)-t.global]))
	}
	return wait
}

// Fail records a failed attempt.
func (t *Throttle) Fail(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.fails[ip] = append(t.fails[ip], now)
	t.all = append(t.all, now)
}

// Success clears an IP's failures.
func (t *Throttle) Success(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.fails, ip)
}
