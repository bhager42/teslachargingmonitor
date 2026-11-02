// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package poller

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// TestSoak polls the simulator thousands of times with no delay between
// polls and checks that goroutines and heap stay flat. Set TCMON_SOAK_POLLS
// (e.g. 3000) to run it; `make soak` does. It also reports database growth
// per poll, used for the storage estimate in docs/DEVELOPMENT_PLAN.md §5.
func TestSoak(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("TCMON_SOAK_POLLS"))
	if n <= 0 {
		t.Skip("set TCMON_SOAK_POLLS to run the soak test")
	}
	h := newHarnessSpeed(t, "charging", 300) // 1 real second = 5 simulated minutes
	h.addDevice(t)
	cfg := fastConfig()
	cfg.IntervalOverride = time.Millisecond
	m := New(h.st, cfg)
	ch, unsub := m.Subscribe(64)
	defer unsub()
	stop := run(t, m)

	scenarios := []string{"charging", "idle", "overheat", "reboot", "firmware-change", "wifi-weak"}
	sample := func() (int, uint64) {
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return runtime.NumGoroutine(), ms.HeapAlloc
	}
	var g0 int
	var h0 uint64
	warmup := n / 10
	for i := range n {
		if i%500 == 0 {
			_ = h.sim.SetScenario(scenarios[(i/500)%len(scenarios)])
		}
		u := next(t, ch)
		if u.Err != nil {
			t.Fatalf("poll %d failed: %v", i, u.Err)
		}
		if i == warmup {
			g0, h0 = sample()
		}
	}
	stop()
	g1, h1 := sample()

	stats, err := h.st.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	perPoll := float64(stats.SizeBytes) / float64(n)
	t.Logf("polls=%d goroutines %d→%d heap %.1f→%.1f MiB db=%.1f MiB (%.0f B/poll)",
		n, g0, g1, float64(h0)/(1<<20), float64(h1)/(1<<20), float64(stats.SizeBytes)/(1<<20), perPoll)
	t.Logf("estimate: hourly polling ≈ %.2f MiB/year; 2 h/day plugged in at 5 min ≈ %.2f MiB/year",
		perPoll*24*365/(1<<20), perPoll*(22+24)*365/(1<<20))

	if g1 > g0 {
		t.Errorf("goroutines grew from %d to %d", g0, g1)
	}
	if h1 > h0+8<<20 {
		t.Errorf("heap grew from %d to %d bytes", h0, h1)
	}
}
