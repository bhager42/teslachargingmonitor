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
	"errors"
	"testing"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

func TestRawPollSelection(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	d := addDevice(t, s)
	g := addGateway(t, s, testBox(t))
	base := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	at := func(m int) time.Time { return base.Add(time.Duration(m) * time.Minute) }

	// Wall Connector: charging at +0, plugged in at +30, idle at +60.
	saveWC := func(m int, scenario string, plugged bool) {
		t.Helper()
		snap := snapshotFrom(t, scenario, time.Minute, at(m))
		if plugged {
			snap.Vitals.VehicleConnected, snap.Vitals.ContactorClosed = true, false
		}
		snap.Raw[wallconnector.EndpointVersion] = []byte(`{"firmware_version":"26.34.0"}`)
		if err := s.SaveSnapshot(ctx, d.ID, snap, nil, 1, time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	saveWC(0, "charging", false)
	saveWC(30, "idle", true)
	saveWC(60, "idle", false)

	// Gateway: day near the charging poll, night at +40, off-grid at +50,
	// day again at +70.
	saveGW := func(m int, solarW float64, grid string) {
		t.Helper()
		snap := fixtureSnapshot(t, at(m))
		snap.Aggregates.Solar.InstantPower = solarW
		snap.GridStatus.GridStatus = grid
		if err := s.SaveGatewaySnapshot(ctx, g.ID, snap, nil, nil, 1, time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	saveGW(2, 3000, "SystemGridConnected")
	saveGW(40, 0, "SystemGridConnected")
	saveGW(50, 0, "SystemIslandedActive")
	saveGW(70, 2500, "SystemGridConnected")

	for _, tc := range []struct {
		kind    PollKind
		gateway bool
		before  time.Time
		want    time.Time
	}{
		{PollLatest, false, time.Time{}, at(60)},
		{PollLatest, false, at(59), at(30)},
		{PollCharging, false, time.Time{}, at(0)},
		{PollPlugged, false, time.Time{}, at(30)},
		{PollLatest, true, time.Time{}, at(70)},
		{PollNight, true, time.Time{}, at(50)},
		{PollNight, true, at(45), at(40)},
		{PollOffGrid, true, time.Time{}, at(50)},
		{PollCharging, true, time.Time{}, at(2)},
	} {
		var got time.Time
		var err error
		if tc.gateway {
			got, err = s.GatewayRawPollTime(ctx, g.ID, tc.kind, tc.before)
		} else {
			got, err = s.RawPollTime(ctx, d.ID, tc.kind, tc.before)
		}
		if err != nil || !got.Equal(tc.want) {
			t.Errorf("%s gateway=%v before=%v: got %v, %v; want %v", tc.kind, tc.gateway, tc.before, got, err, tc.want)
		}
	}

	if _, err := s.RawPollTime(ctx, d.ID, PollCharging, at(-1)); !errors.Is(err, ErrNotFound) {
		t.Errorf("no charging poll before the first one: %v", err)
	}
	if _, err := s.RawPollTime(ctx, d.ID, PollNight, time.Time{}); err == nil {
		t.Error("night accepted for a Wall Connector")
	}
	if _, err := s.GatewayRawPollTime(ctx, g.ID, PollPlugged, time.Time{}); err == nil {
		t.Error("plugged accepted for a Gateway")
	}

	raw, err := s.RawPoll(ctx, d.ID, at(0))
	if err != nil || string(raw["version"]) != `{"firmware_version":"26.34.0"}` || raw["vitals"] == nil {
		t.Errorf("RawPoll = %v, %v", raw, err)
	}
	graw, err := s.GatewayRawPoll(ctx, g.ID, at(50))
	if err != nil || graw["/api/status"] == nil {
		t.Errorf("GatewayRawPoll = %v, %v", graw, err)
	}
	if _, err := s.GatewayRawPoll(ctx, g.ID, at(1)); !errors.Is(err, ErrNotFound) {
		t.Errorf("GatewayRawPoll at a time without a poll: %v", err)
	}
}
