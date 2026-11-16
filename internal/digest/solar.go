// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package digest

import (
	"context"
	"fmt"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/energy"
	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// solarView is the summary's solar section (Phase 9 step 6), present only
// when a Backup Gateway is configured.
type solarView struct {
	Name, Production, Previous, Use, Grid, Car string
	Events                                     []string
}

func pctText(v float64, ok bool) string {
	if !ok {
		return "—"
	}
	return fmt.Sprintf("%.0f %%", 100*v)
}

// buildSolar fills the solar section for [from, to), compared with
// [prevFrom, from). charging holds every Wall Connector's priced intervals,
// which it attributes to solar, Powerwall and grid.
func buildSolar(ctx context.Context, st *store.Store, per Period, plan energy.Plan, charging []energy.Interval,
	prevFrom, from, to time.Time, cur string,
) (*solarView, error) {
	gws, err := st.Gateways(ctx)
	if err != nil || len(gws) == 0 {
		return nil, err
	}
	g := gws[0]
	samples, err := st.SiteSamples(ctx, prevFrom, to)
	if err != nil {
		return nil, err
	}
	iv := energy.SiteIntervals(samples)
	now, prev := energy.SiteTotal(iv, from, to), energy.SiteTotal(iv, prevFrom, from)
	sc, okSC := now.SelfConsumption()
	ss, okSS := now.SelfSufficiency()
	sv := &solarView{
		Name:       g.Name,
		Production: tr.T("digest.solar_production", "kwh", kwh(now.SolarKWh)),
		Use: tr.T("digest.solar_use", "home", kwh(now.HomeKWh), "self_use", pctText(sc, okSC),
			"self_sufficiency", pctText(ss, okSS)),
		Grid: tr.T("digest.solar_grid", "imported", kwh(now.ImportKWh), "exported", kwh(now.ExportKWh)),
	}
	sv.Previous = tr.T("digest.solar_previous", "kwh", kwh(prev.SolarKWh))
	if per == Monthly {
		sv.Previous = tr.T("digest.solar_monthly_previous", "kwh", kwh(prev.SolarKWh))
	}

	// The car's share, as on the Costs page (approximate).
	split := plan.Total(energy.Attribute(charging, energy.SupplyIntervals(samples)), from, to)
	if split.AttributedKWh > 0 {
		sv.Car = tr.T("digest.solar_car", "pct", fmt.Sprintf("%.0f", 100*split.SolarShare()), "kwh", kwh(split.SolarKWh),
			"savings", money(split.Savings, cur))
	}

	evs, err := st.GatewayEvents(ctx, g.ID, from, 10000)
	if err != nil {
		return nil, err
	}
	var outages, reboots, firmware int
	for _, e := range evs {
		if !e.TS.Before(to) {
			continue
		}
		switch e.Kind {
		case store.GatewayEventGridChanged:
			if e.Details["to"] != gateway.GridConnected {
				outages++
			}
		case store.GatewayEventReboot:
			reboots++
		case store.GatewayEventFirmwareChanged:
			firmware++
		}
	}
	if outages > 0 {
		sv.Events = append(sv.Events, tr.N("digest.event_grid_outage", outages))
	}
	if reboots > 0 {
		sv.Events = append(sv.Events, tr.N("digest.event_reboot", reboots))
	}
	if firmware > 0 {
		sv.Events = append(sv.Events, tr.N("digest.event_firmware_changed", firmware))
	}
	return sv, nil
}
