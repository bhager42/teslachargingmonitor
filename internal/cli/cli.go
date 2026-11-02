// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package cli implements the tcmon command-line interface.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bhager42/teslachargingmonitor/internal/buildinfo"
	"github.com/bhager42/teslachargingmonitor/internal/store"
)

// Env is the process environment, injectable for tests.
type Env struct {
	Getenv func(string) string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// OSEnv returns the real process environment.
func OSEnv() Env {
	return Env{Getenv: os.Getenv, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
}

// DefaultDataDir is where the container stores its state.
const DefaultDataDir = "/data"

// Run executes the command line and returns the exit code.
func Run(ctx context.Context, args []string, env Env) int {
	if len(args) == 0 {
		usage(env.Stderr)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version", "--version", "-v":
		_, _ = fmt.Fprintln(env.Stdout, buildinfo.Get().String())
		return 0
	case "help", "--help", "-h":
		usage(env.Stdout)
		return 0
	case "serve":
		return runServe(ctx, rest, env)
	case "device":
		return runDevice(ctx, rest, env)
	case "alerts":
		return runAlerts(ctx, rest, env)
	case "notify":
		return runNotify(ctx, rest, env)
	case "backup":
		return runBackup(ctx, rest, env)
	case "migrate":
		return runMigrate(ctx, rest, env)
	default:
		_, _ = fmt.Fprintf(env.Stderr, "tcmon: unknown command %q\n\n", cmd)
		usage(env.Stderr)
		return 2
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: tcmon <command> [flags]

Commands:
  serve     Poll the configured Wall Connector(s) and run maintenance
  device    Manage Wall Connectors (add, list, update, remove, test)
            — interim CLI until the web UI exists; the web UI is the
              primary way to configure the device address
  alerts    Show alert rules and alert history (read-only)
  notify    Manage email notifications (add-email, update, list, test, remove, log)
  backup    Write a consistent copy of the database
  migrate   Apply database migrations and print the schema version
  version   Print version, license and source-code information
  help      Show this help

Every command that touches data accepts -data-dir (default $TCMON_DATA_DIR
or /data). Notification credentials are encrypted with the key in
$TCMON_SECRET_KEY_FILE (default <data-dir>/secret.key) — back it up together
with the database.
`)
}

// newFlagSet returns a FlagSet with the shared -data-dir flag.
func newFlagSet(name string, env Env) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("tcmon "+name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	def := env.Getenv("TCMON_DATA_DIR")
	if def == "" {
		def = DefaultDataDir
	}
	dir := fs.String("data-dir", def, "directory holding tcmon.db (env TCMON_DATA_DIR)")
	return fs, dir
}

func openStore(ctx context.Context, dataDir string) (*store.Store, error) {
	return store.Open(ctx, filepath.Join(dataDir, "tcmon.db"))
}

func fail(env Env, format string, a ...any) int {
	_, _ = fmt.Fprintf(env.Stderr, "tcmon: "+format+"\n", a...)
	return 1
}

func runBackup(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("backup", env)
	fs.Usage = func() { _, _ = fmt.Fprintln(env.Stderr, "Usage: tcmon backup [-data-dir DIR] DEST") }
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	st, err := openStore(ctx, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	if err := st.Backup(ctx, fs.Arg(0)); err != nil {
		return fail(env, "%v", err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "Backup written to %s\n", fs.Arg(0))
	return 0
}

func runMigrate(ctx context.Context, args []string, env Env) int {
	fs, dir := newFlagSet("migrate", env)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := openStore(ctx, *dir)
	if err != nil {
		return fail(env, "%v", err)
	}
	defer func() { _ = st.Close() }()
	v, err := st.SchemaVersion(ctx)
	if err != nil {
		return fail(env, "%v", err)
	}
	_, _ = fmt.Fprintf(env.Stdout, "Database schema version %d\n", v)
	return 0
}

// secretKeyPath returns the encryption key location.
func secretKeyPath(env Env, dataDir string) string {
	if p := env.Getenv("TCMON_SECRET_KEY_FILE"); p != "" {
		return p
	}
	return filepath.Join(dataDir, "secret.key")
}
