// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package poller

import (
	"strconv"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

// rebootSlack tolerates clock skew and poll duration when comparing the
// device uptime with the time elapsed since the previous poll.
const rebootSlack = 2 * time.Minute

// detectEvents compares a new snapshot with the previous state. On the first
// successful poll there is no baseline and nothing is reported.
func detectEvents(prev store.DeviceState, snap *wallconnector.Snapshot) []store.DeviceEvent {
	var out []store.DeviceEvent
	at := snap.FetchedAt
	vr := snap.Reports[wallconnector.EndpointVitals]
	verRep := snap.Reports[wallconnector.EndpointVersion]

	// Reboot: uptime is lower than "previous uptime + time since previous poll".
	if prev.HasUptime && !prev.LastSuccess.IsZero() && !vr.IsInvalid("uptime_s") && !vr.IsMissing("uptime_s") {
		elapsed := at.Sub(prev.LastSuccess)
		expected := time.Duration(prev.LastUptimeS)*time.Second + elapsed
		uptime := time.Duration(snap.Vitals.UptimeS) * time.Second
		if uptime+rebootSlack < expected {
			out = append(out, store.DeviceEvent{TS: at, Kind: store.EventReboot, Details: map[string]string{
				"uptime_s":          strconv.FormatInt(snap.Vitals.UptimeS, 10),
				"previous_uptime_s": strconv.FormatInt(prev.LastUptimeS, 10),
			}})
		}
	}

	if prev.Info == nil {
		return out
	}
	ok := func(f string) bool { return !verRep.IsInvalid(f) && !verRep.IsMissing(f) }
	ver := snap.Version

	if ok("serial_number") && prev.Info.SerialNumber != "" && ver.SerialNumber != prev.Info.SerialNumber {
		out = append(out, store.DeviceEvent{TS: at, Kind: store.EventIdentityMismatch, Details: map[string]string{
			"previous_serial": wallconnector.MaskSerial(prev.Info.SerialNumber),
			"serial":          wallconnector.MaskSerial(ver.SerialNumber),
		}})
	}
	if ok("firmware_version") && prev.Info.FirmwareVersion != "" && ver.FirmwareVersion != prev.Info.FirmwareVersion {
		out = append(out, store.DeviceEvent{TS: at, Kind: store.EventFirmwareChanged, Details: map[string]string{
			"from": prev.Info.FirmwareVersion, "to": ver.FirmwareVersion,
		}})
	}
	if gp := ver.GridProfile(); !gp.IsZero() && !prev.Info.GridProfile.IsZero() && gp != prev.Info.GridProfile {
		out = append(out, store.DeviceEvent{TS: at, Kind: store.EventGridProfileChanged, Details: map[string]string{
			"vf_trips_from": prev.Info.GridProfile.VfTrips, "vf_trips_to": gp.VfTrips,
			"ride_thru_from": prev.Info.GridProfile.RideThru, "ride_thru_to": gp.RideThru,
			"combined_from": prev.Info.GridProfile.CombinedCompliance, "combined_to": gp.CombinedCompliance,
		}})
	}
	return out
}

// nextState folds a successful snapshot into the poller's memory.
func nextState(prev store.DeviceState, snap *wallconnector.Snapshot) store.DeviceState {
	st := prev
	st.LastSuccess = snap.FetchedAt
	vr := snap.Reports[wallconnector.EndpointVitals]
	st.HasUptime = !vr.IsInvalid("uptime_s") && !vr.IsMissing("uptime_s")
	st.LastUptimeS = snap.Vitals.UptimeS
	st.LastPlugged = plugged(snap)
	verRep := snap.Reports[wallconnector.EndpointVersion]
	if !verRep.IsInvalid("firmware_version") && !verRep.IsMissing("firmware_version") {
		ver := snap.Version
		info := store.DeviceInfo{
			FirmwareVersion: ver.FirmwareVersion, GitBranch: ver.GitBranch, PartNumber: ver.PartNumber,
			SerialNumber: ver.SerialNumber, WebService: ver.WebService, GridProfile: ver.GridProfile(),
			LastSeen: snap.FetchedAt,
		}
		if prev.Info != nil {
			info.DeviceID, info.FirstSeen = prev.Info.DeviceID, prev.Info.FirstSeen
		} else {
			info.FirstSeen = snap.FetchedAt
		}
		st.Info = &info
	}
	return st
}

// plugged reports whether a car is connected or the contactor is closed,
// ignoring flags the decoder could not read.
func plugged(snap *wallconnector.Snapshot) bool {
	vr := snap.Reports[wallconnector.EndpointVitals]
	conn := snap.Vitals.VehicleConnected && !vr.IsInvalid("vehicle_connected")
	closed := snap.Vitals.ContactorClosed && !vr.IsInvalid("contactor_closed")
	return conn || closed
}
