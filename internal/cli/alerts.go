// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package cli

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/alerts"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

func runAlerts(ctx context.Context, args []string, env Env) int {
	if len(args) == 0 || (args[0] != "rules" && args[0] != "history") {
		_, _ = fmt.Fprint(env.Stderr, "Usage:\n  tcmon alerts rules [-device ID]\n  tcmon alerts history [-limit 50]\n")
		return 2
	}
	fs, dir := newFlagSet("alerts "+args[0], env)
	deviceID := fs.Int64("device", 0, "device ID for device-specific settings (rules)")
	limit := fs.Int("limit", 50, "number of history entries (history)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	st, err := openStore(ctx, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
	defer func() { _ = tw.Flush() }()

	if args[0] == "rules" {
		cfgs, err := alerts.New(st, nil).Configs(ctx, *deviceID)
		if err != nil {
			return fail(env, "%v", err)
		}
		_, _ = fmt.Fprintln(tw, "RULE\tENABLED\tPARAMETERS\tFOR\tMIN SAMPLES\tCOOLDOWN\tREPEAT (critical)")
		for _, d := range alerts.Definitions() {
			c := cfgs[d.Key]
			var ps []string
			for _, k := range slices.Sorted(maps.Keys(c.Params)) {
				ps = append(ps, fmt.Sprintf("%s=%g", k, c.Params[k]))
			}
			enabled := fmt.Sprint(c.Enabled)
			if d.NeedsCalibration {
				enabled += " (needs calibration)"
			}
			repeat := "-"
			if c.Repeat > 0 {
				repeat = c.Repeat.String()
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", d.Key, enabled, strings.Join(ps, " "),
				c.For, c.MinSamples, c.Cooldown, repeat)
		}
		return 0
	}

	evs, err := st.AlertEvents(ctx, store.AlertEventFilter{Limit: *limit})
	if err != nil {
		return fail(env, "%v", err)
	}
	if len(evs) == 0 {
		_, _ = fmt.Fprintln(env.Stdout, "No alerts recorded.")
		return 0
	}
	_, _ = fmt.Fprintln(tw, "TIME\tDEVICE\tRULE\tKIND\tSEVERITY\tSENT\tMESSAGE")
	for _, e := range evs {
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%t\t%s\n", e.TS.Local().Format(time.DateTime), e.DeviceID,
			e.RuleKey, e.Kind, e.Severity, e.Notified, e.Message)
	}
	return 0
}
