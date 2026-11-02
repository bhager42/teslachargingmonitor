// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

package wallconnector

import (
	"cmp"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// FirmwareVersion is a parsed firmware string such as
// "26.26.10+g42855ec9b9cd1" (major.minor.patch[-pre][+build]).
type FirmwareVersion struct {
	Major, Minor, Patch int
	Pre                 string // optional pre-release tag
	Build               string // build metadata, e.g. "g42855ec9b9cd1"
	Raw                 string
}

const maxFirmwareLen = 64

// ErrBadFirmware is returned for unparseable firmware version strings.
var ErrBadFirmware = errors.New("wallconnector: unrecognized firmware version")

// ParseFirmware parses a firmware version string.
func ParseFirmware(s string) (FirmwareVersion, error) {
	fv := FirmwareVersion{Raw: s}
	if s == "" || len(s) > maxFirmwareLen {
		return fv, fmt.Errorf("%w: length %d", ErrBadFirmware, len(s))
	}
	core, build, hasBuild := strings.Cut(s, "+")
	if hasBuild {
		if !validIdent(build) {
			return fv, fmt.Errorf("%w: build metadata", ErrBadFirmware)
		}
		fv.Build = build
	}
	core, pre, hasPre := strings.Cut(core, "-")
	if hasPre {
		if !validIdent(pre) {
			return fv, fmt.Errorf("%w: pre-release", ErrBadFirmware)
		}
		fv.Pre = pre
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return fv, fmt.Errorf("%w: want major.minor.patch", ErrBadFirmware)
	}
	nums := [3]*int{&fv.Major, &fv.Minor, &fv.Patch}
	for i, p := range parts {
		if p == "" || len(p) > 6 || strings.TrimLeft(p, "0123456789") != "" {
			return fv, fmt.Errorf("%w: component %q", ErrBadFirmware, p)
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return fv, fmt.Errorf("%w: component %q", ErrBadFirmware, p)
		}
		*nums[i] = n
	}
	return fv, nil
}

func validIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !isAlnum(r) && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

// isAlnum reports whether r is an ASCII letter or digit.
func isAlnum(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}

// Compare orders versions by major, minor, patch; a pre-release sorts before
// its release. Build metadata is ignored.
func (f FirmwareVersion) Compare(o FirmwareVersion) int {
	if c := cmp.Compare(f.Major, o.Major); c != 0 {
		return c
	}
	if c := cmp.Compare(f.Minor, o.Minor); c != 0 {
		return c
	}
	if c := cmp.Compare(f.Patch, o.Patch); c != 0 {
		return c
	}
	switch {
	case f.Pre == o.Pre:
		return 0
	case f.Pre == "":
		return 1
	case o.Pre == "":
		return -1
	default:
		return strings.Compare(f.Pre, o.Pre)
	}
}

// Short returns "major.minor.patch".
func (f FirmwareVersion) Short() string {
	return fmt.Sprintf("%d.%d.%d", f.Major, f.Minor, f.Patch)
}

func (f FirmwareVersion) String() string { return f.Raw }
