// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package buildinfo exposes version metadata stamped in at build time and the
// source-code location that AGPL §13 requires the web UI to offer users.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// These are overridden at build time with -ldflags "-X ...". Forks must set
// SourceURL to the location of their own modified source code.
var (
	Version   = "dev"
	Commit    = ""
	Date      = ""
	SourceURL = "https://github.com/bhager42/teslachargingmonitor"
)

// Info is a snapshot of the build metadata.
type Info struct {
	Name      string
	Version   string
	Commit    string
	Date      string
	GoVersion string
	SourceURL string
}

// Get returns the build metadata, falling back to the VCS information that
// the Go toolchain embeds when the ldflags were not set.
func Get() Info {
	info := Info{
		Name:      "Tesla Charger Monitoring",
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		SourceURL: SourceURL,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.Date == "" {
					info.Date = s.Value
				}
			}
		}
	}
	return info
}

// SourceLink returns a link to the exact source of this build when the commit
// is known (GitHub-style tree URL), otherwise the repository URL.
func (i Info) SourceLink() string {
	base := strings.TrimSuffix(i.SourceURL, "/")
	if i.Commit == "" || !strings.HasPrefix(base, "https://github.com/") {
		return base
	}
	return base + "/tree/" + i.Commit
}

// String renders a one-line human readable summary.
func (i Info) String() string {
	commit := i.Commit
	if len(commit) > 12 {
		commit = commit[:12]
	}
	if commit == "" {
		commit = "unknown"
	}
	return fmt.Sprintf("%s %s (commit %s, built %s, %s)\nLicense: AGPL-3.0-or-later\nSource: %s",
		i.Name, i.Version, commit, orUnknown(i.Date), i.GoVersion, i.SourceLink())
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
