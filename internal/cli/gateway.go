// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/gateway"
	"github.com/bhager42/teslachargingmonitor/internal/secrets"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

func runGateway(ctx context.Context, args []string, env Env) int {
	if len(args) == 0 {
		gatewayUsage(env)
		return 2
	}
	switch args[0] {
	case "fingerprint":
		return gatewayFingerprint(ctx, args[1:], env)
	case "add":
		return gatewayAdd(ctx, args[1:], env)
	case "list":
		return gatewayList(ctx, args[1:], env)
	case "accept-cert":
		return gatewayAcceptCert(ctx, args[1:], env)
	case "remove":
		return gatewayRemove(ctx, args[1:], env)
	default:
		gatewayUsage(env)
		return 2
	}
}

func gatewayUsage(env Env) {
	_, _ = fmt.Fprint(env.Stderr, `Usage:
  tcmon gateway fingerprint -address IP
  tcmon gateway add -address IP -pin SHA256 -password-stdin [-name NAME] [flags]
  tcmon gateway list
  tcmon gateway accept-cert ID
  tcmon gateway remove ID -yes

Reads a Tesla Backup Gateway 2 (Powerwall 2 / Powerwall+) on the LAN, read
only. Interim CLI until the web UI's Solar Gateway settings exist.

1. Run "fingerprint" and check the certificate it shows is your Gateway's.
2. Run "add" with that fingerprint as -pin. The customer password (usually
   the last 5 characters of the password on the label inside the Gateway
   door) is read from standard input or -password-file, never from an
   argument. "add" logs in once to test it; a rejected password is not
   retried, because the Gateway locks out repeated failures.
3. If the Gateway's certificate changes later, polling stops; check it and
   run "accept-cert".
`)
}

// readGatewayPassword reads the customer password exactly, without the
// trailing newline (unlike Gmail app passwords, spaces are kept).
func readGatewayPassword(env Env, fromStdin bool, file string) (secrets.Secret, error) {
	var raw []byte
	var err error
	switch {
	case fromStdin && file != "":
		return "", errors.New("use either -password-stdin or -password-file")
	case fromStdin:
		raw, err = io.ReadAll(io.LimitReader(bufio.NewReader(env.Stdin), 1024))
	case file != "":
		raw, err = os.ReadFile(file) //nolint:gosec // operator-provided secret file
	default:
		return "", errors.New("-password-stdin or -password-file is required")
	}
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	pw := strings.TrimRight(string(raw), "\r\n")
	if pw == "" {
		return "", errors.New("password is empty")
	}
	return secrets.Secret(pw), nil
}

func gatewayHostPort(address string, allowNonLAN bool) (string, error) {
	a, err := wallconnector.ParseAddress(address, wallconnector.AddressOptions{AllowNonLAN: allowNonLAN})
	if err != nil {
		return "", err
	}
	return a.HostPort(), nil
}

func gatewayFingerprint(ctx context.Context, args []string, env Env) int {
	fs, _ := newFlagSet("gateway fingerprint", env)
	address := fs.String("address", "", "IP address or hostname of the Backup Gateway")
	allowNonLAN := fs.Bool("allow-non-lan", false, "allow an address outside the local network")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	hp, err := gatewayHostPort(*address, *allowNonLAN)
	if err != nil {
		return fail(env, "%v", err)
	}
	fp, err := gateway.Fingerprint(ctx, hp, *allowNonLAN)
	if err != nil {
		return fail(env, "%v", err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "%s\n", fp)
	return 0
}

func gatewayAdd(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("gateway add", env)
	def := store.NewGateway("Powerwall", "", "", nil)
	name := fs.String("name", def.Name, "display name")
	address := fs.String("address", "", "IP address or hostname of the Backup Gateway")
	pin := fs.String("pin", "", `certificate SHA-256 fingerprint from "tcmon gateway fingerprint"`)
	interval := fs.Duration("interval", def.PollInterval, "polling interval")
	charging := fs.Duration("charging-interval", def.ChargingInterval, "polling interval while a car is plugged in")
	allowNonLAN := fs.Bool("allow-non-lan", false, "allow an address outside the local network")
	pwStdin := fs.Bool("password-stdin", false, "read the customer password from standard input")
	pwFile := fs.String("password-file", "", "read the customer password from a file (e.g. a Docker secret)")
	skipTest := fs.Bool("skip-test", false, "save without the test login")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *address == "" || *pin == "" {
		_, _ = fmt.Fprintln(env.Stderr, "tcmon gateway add: -address and -pin are required")
		return 2
	}
	pw, err := readGatewayPassword(env, *pwStdin, *pwFile)
	if err != nil {
		return fail(env, "%v", err)
	}
	st, box, err := openStoreAndBox(ctx, env, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	enc, err := store.SealGatewayPassword(box, pw)
	if err != nil {
		return fail(env, "%v", err)
	}
	g := store.NewGateway(*name, *address, *pin, enc)
	g.PollInterval, g.ChargingInterval, g.AllowNonLAN = *interval, *charging, *allowNonLAN
	if err := g.Normalize(); err != nil {
		return fail(env, "%v", err)
	}
	if !*skipTest {
		c, err := gateway.NewClient(g.Address, gateway.Options{Pin: g.Pin, Password: pw, AllowNonLAN: g.AllowNonLAN})
		if err != nil {
			return fail(env, "%v", err)
		}
		snap, err := c.Snapshot(ctx)
		c.Close()
		if err != nil {
			if errors.Is(err, gateway.ErrLoginRejected) {
				return fail(env, "the Gateway rejected the password; nothing saved. Check it before trying again: the Gateway locks out repeated failures")
			}
			return fail(env, "connection test failed: %v (nothing saved)", err)
		}
		_, _ = fmt.Fprintf(env.Stdout, "Connected: firmware %s, %d Powerwall(s), battery %.0f %%, solar %.0f W, grid %s\n",
			snap.Status.Firmware(), len(snap.SystemStatus.BatteryBlocks), snap.SOE.AppPercent(),
			snap.Aggregates.Solar.InstantPower, snap.GridStatus.GridStatus)
	}
	g, err = st.CreateGateway(ctx, g, time.Now())
	if err != nil {
		return fail(env, "%v", err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "Added gateway %d (%s at %s). A running server picks it up within a minute.\n", g.ID, g.Name, g.Address)
	return 0
}

func openStoreAndBox(ctx context.Context, env Env, dataDir string) (*store.Store, *secrets.Box, error) {
	st, err := openStore(ctx, dataDir)
	if err != nil {
		return nil, nil, err
	}
	key, err := secrets.LoadOrCreateKey(secretKeyPath(env, dataDir), func(m string) { _, _ = fmt.Fprintln(env.Stderr, "warning:", m) })
	if err != nil {
		_ = st.Close()
		return nil, nil, err
	}
	box, err := secrets.NewBox(key)
	if err != nil {
		_ = st.Close()
		return nil, nil, err
	}
	return st, box, nil
}

func gatewayList(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("gateway list", env)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := openStore(ctx, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	gws, err := st.Gateways(ctx)
	if err != nil {
		return fail(env, "%v", err)
	}
	if len(gws) == 0 {
		_, _ = fmt.Fprintln(env.Stdout, `No gateways. Add one with: tcmon gateway add (see "tcmon gateway")`)
		return 0
	}
	tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tADDRESS\tENABLED\tINTERVAL\tCHARGING\tFIRMWARE\tSTATUS")
	now := time.Now()
	for _, g := range gws {
		fw := "-"
		if info, err := st.GatewayInfo(ctx, g.ID); err == nil {
			fw = info.FirmwareVersion
		}
		status := "ok"
		switch {
		case g.PendingPin != "":
			status = "certificate changed: check it, then run accept-cert"
		case g.Backoff.Until.After(now):
			status = fmt.Sprintf("login suspended until %s (%s)", g.Backoff.Until.Local().Format(time.DateTime), g.Backoff.Cause)
		}
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%v\t%s\t%s\t%s\t%s\n", g.ID, g.Name, g.Address, g.Enabled,
			g.PollInterval, g.ChargingInterval, fw, status)
	}
	_ = tw.Flush()
	return 0
}

func gatewayAcceptCert(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("gateway accept-cert", env)
	if err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	id, err := parseID(fs)
	if err != nil {
		return fail(env, "%v", err)
	}
	st, err := openStore(ctx, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	g, err := st.Gateway(ctx, id)
	if err != nil {
		return fail(env, "gateway %d: %v", id, err)
	}
	if g.PendingPin == "" {
		return fail(env, "gateway %d has no changed certificate to accept", id)
	}
	if err := st.AcceptGatewayPin(ctx, id, time.Now()); err != nil {
		return fail(env, "gateway %d: %v", id, err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "Gateway %d now trusts certificate %s; polling resumes within a minute.\n", id, g.PendingPin)
	return 0
}

func gatewayRemove(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("gateway remove", env)
	yes := fs.Bool("yes", false, "confirm deletion of the gateway and ALL its history")
	if err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	id, err := parseID(fs)
	if err != nil {
		return fail(env, "%v", err)
	}
	if !*yes {
		return fail(env, "this deletes gateway %d and all of its readings; re-run with -yes to confirm", id)
	}
	st, err := openStore(ctx, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	if err := st.DeleteGateway(ctx, id); err != nil {
		return fail(env, "gateway %d: %v", id, err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "Removed gateway %d.\n", id)
	return 0
}
