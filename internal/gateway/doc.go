// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package gateway reads a Tesla Backup Gateway 2 (Powerwall 2 / Powerwall+)
// over its local HTTPS API, read only (Phase 9, D27; ADR 0007).
//
// The API is undocumented. Payloads are untrusted: decode them with the
// Decode* functions and honor the Report (fields in Report.Invalid or
// Report.Missing must not drive alerts or costs). The Client pins the
// Gateway's self-signed certificate, reuses one login session, and backs
// off exponentially after a rejected login so it can never trigger the
// Gateway's lockout.
package gateway
