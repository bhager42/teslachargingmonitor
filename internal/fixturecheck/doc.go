// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package fixturecheck holds repository hygiene tests for the captured
// fixtures under testdata/fixtures: they must be valid JSON and must not
// contain the owner's real identifiers. Wall Connector fixtures are checked
// for their known fields (serial number, MAC, SSID, LAN IP); Backup Gateway
// fixtures (testdata/fixtures/gateway) get the recursive check from
// internal/gateway/redact (serials, DIN, names, email, tokens, addresses, IP
// and MAC addresses anywhere in the document).
package fixturecheck
