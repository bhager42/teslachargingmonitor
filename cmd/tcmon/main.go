// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Command tcmon is the Tesla Charger Monitoring server.
//
// Phase 0 only provides the "version" subcommand; "serve", "healthcheck",
// "reset-password", "hash-password" and "migrate" arrive in later phases
// (see docs/DEVELOPMENT_PLAN.md §3 and §14).
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/bhager42/teslachargingmonitor/internal/buildinfo"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "version", "--version", "-v":
		_, _ = fmt.Fprintln(stdout, buildinfo.Get().String())
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "tcmon: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: tcmon <command>

Commands:
  version   Print version, license and source-code information
  help      Show this help
`)
}
