// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package energy

// SavingsMethod selects which solar energy counts as money saved (owner
// decision D28). Either way, energy is priced at the electricity rate in
// effect when it was produced or used, time of use included.
type SavingsMethod string

const (
	// SavingsUsedAtHome counts solar the home used directly, plus the
	// share of Powerwall discharge estimated to have come from solar.
	// Exports earn nothing. Suits plans without export credits.
	SavingsUsedAtHome SavingsMethod = "used_at_home"
	// SavingsNetMetering counts every solar kWh produced, as if exports
	// were credited at the full retail rate (1:1 net metering).
	SavingsNetMetering SavingsMethod = "net_metering"
)

// SavingsMethods lists the methods in the order the settings page shows them.
var SavingsMethods = []SavingsMethod{SavingsUsedAtHome, SavingsNetMetering}

// Valid reports whether m is a known method.
func (m SavingsMethod) Valid() bool { return m == SavingsUsedAtHome || m == SavingsNetMetering }

// DefaultBatteryWh is the Powerwall capacity assumed when the Gateway has
// not reported one (one Powerwall 2).
const DefaultBatteryWh = 13500

// SolarSavings returns a copy of iv (oldest first, as SiteIntervals returns
// it) with SavedWh and Savings set for method m.
//
// For SavingsUsedAtHome, the Powerwalls' contents are tracked as two pools,
// energy charged from solar and from the grid (HomeSupply's rules decide
// which), and each discharge is assumed to draw from both in proportion.
// The pools start empty, so a discharge before any charge in iv counts as
// grid (pass a few days of history before the period of interest), and
// they are scaled down to batteryWh (≤ 0: DefaultBatteryWh) so that
// round-trip losses do not make the estimate drift. Within one interval a
// discharge is taken from the pools before that interval's charge is
// added.
func (p Plan) SolarSavings(iv []SiteInterval, m SavingsMethod, batteryWh float64) []SiteInterval {
	if batteryWh <= 0 {
		batteryWh = DefaultBatteryWh
	}
	out := make([]SiteInterval, len(iv))
	var fromSolar, fromGrid float64 // Wh in the Powerwalls
	for i, x := range iv {
		if m == SavingsNetMetering {
			x.SavedWh = max(x.SolarWh, 0)
		} else {
			f := splitFlows(x.SolarWh, x.ImportWh, x.ExportWh, x.ChargeWh, x.DischargeWh)
			stored := fromSolar + fromGrid
			share := 0.0
			if stored > 0 {
				share = fromSolar / stored
				keep := max(0, stored-max(x.DischargeWh, 0)) / stored
				fromSolar, fromGrid = fromSolar*keep, fromGrid*keep
			}
			x.SavedWh = f.home.Solar + f.home.Battery*share
			fromSolar += f.chargeFromSolar
			fromGrid += f.chargeOther
			if t := fromSolar + fromGrid; t > batteryWh {
				fromSolar, fromGrid = fromSolar*batteryWh/t, fromGrid*batteryWh/t
			}
		}
		x.Savings = p.Cost(x.From, x.To, x.SavedWh)
		out[i] = x
	}
	return out
}
