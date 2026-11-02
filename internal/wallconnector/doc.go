// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package wallconnector talks to the local, unauthenticated HTTP API of a
// Tesla Universal Wall Connector (and, best-effort, the Gen 3 Wall
// Connector): GET /api/1/{vitals,lifetime,wifi_status,version}.
//
// Everything the device returns is treated as untrusted input. Decoding is
// tolerant — unknown fields, missing fields, wrong types and physically
// implausible values are reported in a Report instead of failing the whole
// payload — so a firmware update that adds or renames a field degrades
// gracefully and shows up in the app's diagnostics.
//
// Field names were verified against UWC firmware 26.26.10 (fixtures in
// testdata/fixtures/uwc/). Charging-state values are not yet verified; see
// issue #1.
package wallconnector
