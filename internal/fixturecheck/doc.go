// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package fixturecheck holds repository hygiene tests for the captured Wall
// Connector fixtures under testdata/fixtures: they must be valid JSON and must
// not contain the owner's real identifiers (serial number, MAC, SSID, LAN IP).
package fixturecheck
