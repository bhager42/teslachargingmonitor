// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Brad Hager and contributors
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for details.

// Package webui embeds the web UI's HTML templates and static assets.
package webui

import "embed"

// Templates holds html/template files (templates/*.html).
//
//go:embed templates/*.html
var Templates embed.FS

// Static holds CSS, icons and (from Phase 6) JavaScript modules.
//
//go:embed static
var Static embed.FS
