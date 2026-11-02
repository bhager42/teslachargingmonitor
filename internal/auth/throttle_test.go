// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package auth

import (
	"testing"
	"time"
)

func TestThrottle(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	th := NewThrottle(func() time.Time { return now })
	for range 4 {
		th.Fail("a")
	}
	if th.Blocked("a") != 0 {
		t.Fatal("blocked after 4 failures")
	}
	th.Fail("a")
	if w := th.Blocked("a"); w != 15*time.Minute {
		t.Errorf("wait = %v", w)
	}
	th.Success("a")
	if th.Blocked("a") != 0 {
		t.Error("success did not clear the IP")
	}
	// Global limit: 50 failures from many IPs block everyone.
	for i := range 50 {
		th.Fail(string(rune('A' + i%26)))
	}
	if th.Blocked("fresh-ip") == 0 {
		t.Error("global limit not applied")
	}
	now = now.Add(15 * time.Minute)
	if th.Blocked("fresh-ip") != 0 {
		t.Error("global window did not expire")
	}
}

func TestUserMessage(t *testing.T) {
	if UserMessage(ErrBadPassword) == "" || UserMessage(CheckPolicy("x")) == "" || UserMessage(&ThrottledError{RetryAfter: time.Minute}) == "" {
		t.Error("safe errors hidden")
	}
	if UserMessage(errInternal) != "" {
		t.Error("internal error exposed")
	}
}

var errInternal = &struct{ error }{}
