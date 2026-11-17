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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/fixtureexport"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

var reFixtureLabel = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

func runFixture(ctx context.Context, args []string, env Env) int {
	if len(args) == 0 || args[0] != "export" {
		fixtureUsage(env)
		return 2
	}
	return fixtureExport(ctx, args[1:], env)
}

func fixtureUsage(env Env) {
	_, _ = fmt.Fprint(env.Stderr, `Usage:
  tcmon fixture export (-device ID | -gateway ID) [-when KIND] [-before TIME]
                       [-label LABEL] [-out DIR]

Writes a redacted copy of a poll tcmon already stored, as test fixtures for
the tcmon repository: no live capture and no Gateway login needed. Stored
payloads are kept for the raw-payload retention period (90 days by default).

  -when      which poll: the newest one that matches
               Wall Connector: latest, charging, plugged (plugged in, not charging)
               Gateway:        latest, charging, night, off-grid
  -before    only polls at or before this time (RFC 3339, e.g. 2026-11-20T03:00:00Z)
  -label     file name suffix (default: the -when kind; none for latest)
  -out       output directory (default <data-dir>/fixtures); files go in
             uwc/<firmware>/ or gateway/<firmware>/ beneath it, as in
             testdata/fixtures

Serial numbers, MAC addresses, SSIDs, IP addresses and other identifiers are
redacted and the result is checked; nothing is written if the check fails.
Review the files before committing them anyway.
`)
}

func fixtureExport(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("fixture export", env)
	fs.Usage = func() { fixtureUsage(env) }
	deviceID := fs.Int64("device", 0, "Wall Connector ID (tcmon device list)")
	gatewayID := fs.Int64("gateway", 0, "Gateway ID (tcmon gateway list)")
	when := fs.String("when", string(store.PollLatest), "which poll")
	beforeS := fs.String("before", "", "only polls at or before this RFC 3339 time")
	label := fs.String("label", "", "file name suffix")
	out := fs.String("out", "", "output directory (default <data-dir>/fixtures)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || (*deviceID > 0) == (*gatewayID > 0) {
		_, _ = fmt.Fprintln(env.Stderr, "tcmon fixture export: give exactly one of -device ID or -gateway ID")
		return 2
	}
	kind := store.PollKind(*when)
	kinds := store.DevicePollKinds
	if *gatewayID > 0 {
		kinds = store.GatewayPollKinds
	}
	if !slices.Contains(kinds, kind) {
		names := make([]string, len(kinds))
		for i, k := range kinds {
			names[i] = string(k)
		}
		_, _ = fmt.Fprintf(env.Stderr, "tcmon fixture export: -when must be one of %s\n", strings.Join(names, ", "))
		return 2
	}
	var before time.Time
	if *beforeS != "" {
		t, err := time.Parse(time.RFC3339, *beforeS)
		if err != nil {
			_, _ = fmt.Fprintln(env.Stderr, "tcmon fixture export: -before must be an RFC 3339 time, e.g. 2026-11-20T03:00:00Z")
			return 2
		}
		before = t
	}
	if *label == "" && kind != store.PollLatest {
		*label = string(kind)
	}
	if *label != "" && !reFixtureLabel.MatchString(*label) {
		_, _ = fmt.Fprintln(env.Stderr, "tcmon fixture export: -label may only contain a-z, 0-9 and '-'")
		return 2
	}
	if *out == "" {
		*out = filepath.Join(*dir, "fixtures")
	}

	st, err := openStore(ctx, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()

	var files fixtureexport.Files
	var at time.Time
	var sub string
	if *deviceID > 0 {
		sub = "uwc"
		at, err = st.RawPollTime(ctx, *deviceID, kind, before)
		if err == nil {
			var raw map[string][]byte
			if raw, err = st.RawPoll(ctx, *deviceID, at); err == nil {
				files, err = fixtureexport.WallConnector(raw, *label)
			}
		}
	} else {
		sub = "gateway"
		at, err = st.GatewayRawPollTime(ctx, *gatewayID, kind, before)
		if err == nil {
			var raw map[string][]byte
			if raw, err = st.GatewayRawPoll(ctx, *gatewayID, at); err == nil {
				files, err = fixtureexport.Gateway(raw, *label, at)
			}
		}
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		return fail(env, "no stored %s poll found for that ID (raw payloads are kept for the retention period only)", kind)
	case err != nil:
		return fail(env, "%v", err)
	}

	target := filepath.Join(*out, sub, files.Firmware)
	if err := os.MkdirAll(target, 0o750); err != nil {
		return fail(env, "%v", err)
	}
	for _, n := range files.Names() {
		if err := os.WriteFile(filepath.Join(target, n), files.Files[n], 0o600); err != nil {
			return fail(env, "%v", err)
		}
	}
	_, _ = fmt.Fprintf(env.Stdout, "Poll from %s (%s)\n", at.Format(time.RFC3339), kind)
	for _, n := range files.Names() {
		_, _ = fmt.Fprintf(env.Stdout, "  %s\n", filepath.Join(target, n))
	}
	_, _ = fmt.Fprintf(env.Stdout, "Wrote %d redacted files. Review them, then copy them into testdata/fixtures/%s/%s/ and run 'make test'.\n",
		len(files.Files), sub, files.Firmware)
	return 0
}
