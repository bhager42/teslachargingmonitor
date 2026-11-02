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
	"flag"
	"fmt"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/bhager42/teslachargingmonitor/internal/buildinfo"
	"github.com/bhager42/teslachargingmonitor/internal/store"
	"github.com/bhager42/teslachargingmonitor/internal/wallconnector"
)

func runDevice(ctx context.Context, args []string, env Env) int {
	if len(args) == 0 {
		deviceUsage(env)
		return 2
	}
	switch args[0] {
	case "add":
		return deviceAdd(ctx, args[1:], env)
	case "update":
		return deviceUpdate(ctx, args[1:], env)
	case "list":
		return deviceList(ctx, args[1:], env)
	case "remove":
		return deviceRemove(ctx, args[1:], env)
	case "test":
		return deviceTest(ctx, args[1:], env)
	default:
		deviceUsage(env)
		return 2
	}
}

func deviceUsage(env Env) {
	_, _ = fmt.Fprint(env.Stderr, `Usage:
  tcmon device add -address IP [-name NAME] [-breaker 60] [flags]
  tcmon device update ID [flags]
  tcmon device list
  tcmon device remove ID -yes
  tcmon device test IP

Run "tcmon device add -h" for all flags.
`)
}

type deviceFlags struct {
	name, address             string
	breaker, maxCurrent       float64
	voltage, hz               float64
	interval, pluggedInterval time.Duration
	fastWhenPlugged, enabled  bool
	allowNonLAN, skipTest     bool
}

func bindDeviceFlags(fs *flag.FlagSet, f *deviceFlags) {
	def := store.NewDevice("Wall Connector", "")
	fs.StringVar(&f.name, "name", def.Name, "display name")
	fs.StringVar(&f.address, "address", "", "IP address or hostname of the Wall Connector")
	fs.Float64Var(&f.breaker, "breaker", 0, "circuit breaker rating in amps (max current defaults to 80 %)")
	fs.Float64Var(&f.maxCurrent, "max-current", 0, "max charging current in amps set at commissioning")
	fs.Float64Var(&f.voltage, "voltage", def.NominalVoltageV, "nominal grid voltage")
	fs.Float64Var(&f.hz, "hz", def.NominalHz, "nominal grid frequency (50 or 60)")
	fs.DurationVar(&f.interval, "interval", def.PollInterval, "polling interval")
	fs.DurationVar(&f.pluggedInterval, "plugged-interval", def.PluggedInterval, "polling interval while a car is plugged in")
	fs.BoolVar(&f.fastWhenPlugged, "fast-when-plugged", def.FastWhenPlugged, "poll more often while a car is plugged in")
	fs.BoolVar(&f.enabled, "enabled", true, "poll this device")
	fs.BoolVar(&f.allowNonLAN, "allow-non-lan", false, "allow an address outside the local network")
	fs.BoolVar(&f.skipTest, "skip-test", false, "save without testing the connection first")
}

// apply copies the flags that were set (or all, for add) onto d.
func (f *deviceFlags) apply(fs *flag.FlagSet, d *store.Device, all bool) {
	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	use := func(name string) bool { return all || set[name] }
	if use("name") {
		d.Name = f.name
	}
	if use("address") {
		d.Address = f.address
	}
	if use("breaker") {
		d.BreakerA = f.breaker
		if !set["max-current"] {
			d.MaxCurrentA = 0 // recomputed from the breaker
		}
	}
	if use("max-current") {
		d.MaxCurrentA = f.maxCurrent
	}
	if use("voltage") {
		d.NominalVoltageV = f.voltage
	}
	if use("hz") {
		d.NominalHz = f.hz
	}
	if use("interval") {
		d.PollInterval = f.interval
	}
	if use("plugged-interval") {
		d.PluggedInterval = f.pluggedInterval
	}
	if use("fast-when-plugged") {
		d.FastWhenPlugged = f.fastWhenPlugged
	}
	if use("enabled") {
		d.Enabled = f.enabled
	}
	if use("allow-non-lan") {
		d.AllowNonLAN = f.allowNonLAN
	}
}

func probe(ctx context.Context, env Env, d store.Device) error {
	addr, err := d.ParsedAddress()
	if err != nil {
		return err
	}
	c := wallconnector.NewClient(addr, wallconnector.Options{
		AllowNonLAN: d.AllowNonLAN, UserAgent: "tcmon/" + buildinfo.Version,
	})
	_, _ = fmt.Fprintf(env.Stdout, "Testing connection to %s ...\n", addr)
	res, err := c.Probe(ctx)
	if err != nil {
		return err
	}
	v := res.Vitals
	_, _ = fmt.Fprintf(env.Stdout, "Found Wall Connector: part %s, firmware %s, serial %s\n",
		res.Version.PartNumber, res.Firmware.Short(), res.MaskedSerial)
	_, _ = fmt.Fprintf(env.Stdout, "  state: %s, grid %.1f V / %.2f Hz, handle %.1f °C\n",
		wallconnector.EVSEStateInfo(v.EVSEState), v.GridV, v.GridHz, v.HandleTempC)
	return nil
}

func deviceAdd(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("device add", env)
	var f deviceFlags
	bindDeviceFlags(fs, &f)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if f.address == "" {
		_, _ = fmt.Fprintln(env.Stderr, "tcmon device add: -address is required")
		return 2
	}
	d := store.NewDevice("", "")
	f.apply(fs, &d, true)
	if err := d.Normalize(); err != nil {
		return fail(env, "%v", err)
	}
	if !f.skipTest {
		if err := probe(ctx, env, d); err != nil {
			return fail(env, "connection test failed: %v (use -skip-test to save anyway)", err)
		}
	}
	st, err := openStore(ctx, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	d, err = st.CreateDevice(ctx, d, time.Now())
	if err != nil {
		return fail(env, "%v", err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "Added device %d (%s at %s). A running server picks it up within a minute.\n", d.ID, d.Name, d.Address)
	return 0
}

func parseID(fs *flag.FlagSet) (int64, error) {
	if fs.NArg() < 1 {
		return 0, errors.New("device ID required")
	}
	return strconv.ParseInt(fs.Arg(0), 10, 64)
}

// parseInterspersed lets the device ID come before or after the flags.
func parseInterspersed(fs *flag.FlagSet, args []string) error {
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return fs.Parse(append([]string{args[0]}, fs.Args()...))
	}
	return fs.Parse(args)
}

func deviceUpdate(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("device update", env)
	var f deviceFlags
	bindDeviceFlags(fs, &f)
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
	d, err := st.Device(ctx, id)
	if err != nil {
		return fail(env, "device %d: %v", id, err)
	}
	f.apply(fs, &d, false)
	if err := d.Normalize(); err != nil {
		return fail(env, "%v", err)
	}
	addressChanged := false
	fs.Visit(func(fl *flag.Flag) { addressChanged = addressChanged || fl.Name == "address" })
	if addressChanged && !f.skipTest {
		if err := probe(ctx, env, d); err != nil {
			return fail(env, "connection test failed: %v (use -skip-test to save anyway)", err)
		}
	}
	if _, err := st.UpdateDevice(ctx, d, time.Now()); err != nil {
		return fail(env, "%v", err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "Updated device %d.\n", id)
	return 0
}

func deviceList(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("device list", env)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := openStore(ctx, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	devices, err := st.Devices(ctx)
	if err != nil {
		return fail(env, "%v", err)
	}
	if len(devices) == 0 {
		_, _ = fmt.Fprintln(env.Stdout, "No devices. Add one with: tcmon device add -address <ip>")
		return 0
	}
	tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tADDRESS\tENABLED\tINTERVAL\tPLUGGED-IN\tMAX A\tLAST POLL\tFIRMWARE")
	for _, d := range devices {
		last, fw := "never", "-"
		if log, err := st.PollLog(ctx, d.ID, 1); err == nil && len(log) == 1 {
			status := "ok"
			if !log[0].OK {
				status = "failed"
			}
			last = log[0].TS.Local().Format(time.DateTime) + " (" + status + ")"
		}
		if info, err := st.DeviceInfo(ctx, d.ID); err == nil {
			fw = info.FirmwareVersion
		}
		plugged := d.PluggedInterval.String()
		if !d.FastWhenPlugged {
			plugged = "off"
		}
		maxA := "-"
		if d.MaxCurrentA > 0 {
			maxA = strconv.FormatFloat(d.MaxCurrentA, 'f', -1, 64)
		}
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%t\t%s\t%s\t%s\t%s\t%s\n",
			d.ID, d.Name, d.Address, d.Enabled, d.PollInterval, plugged, maxA, last, fw)
	}
	_ = tw.Flush()
	return 0
}

func deviceRemove(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("device remove", env)
	yes := fs.Bool("yes", false, "confirm deletion of the device and ALL its history")
	if err := parseInterspersed(fs, args); err != nil {
		return 2
	}
	id, err := parseID(fs)
	if err != nil {
		return fail(env, "%v", err)
	}
	if !*yes {
		return fail(env, "this deletes device %d and all of its readings; re-run with -yes to confirm", id)
	}
	st, err := openStore(ctx, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	if err := st.DeleteDevice(ctx, id); err != nil {
		return fail(env, "device %d: %v", id, err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "Removed device %d.\n", id)
	return 0
}

func deviceTest(ctx context.Context, args []string, env Env) int {
	fs := flag.NewFlagSet("tcmon device test", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	allow := fs.Bool("allow-non-lan", false, "allow an address outside the local network")
	if err := parseInterspersed(fs, args); err != nil || fs.NArg() != 1 {
		_, _ = fmt.Fprintln(env.Stderr, "Usage: tcmon device test IP")
		return 2
	}
	d := store.NewDevice("test", fs.Arg(0))
	d.AllowNonLAN = *allow
	if err := d.Normalize(); err != nil {
		return fail(env, "%v", err)
	}
	if err := probe(ctx, env, d); err != nil {
		return fail(env, "connection test failed: %v", err)
	}
	return 0
}
