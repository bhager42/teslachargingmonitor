#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Brad Hager and contributors
#
# Capture the local API of a Tesla Backup Gateway 2 (Powerwall 2 / Powerwall+)
# into redacted test fixtures (Phase 9 step 9.0).
#
# Usage: scripts/capture-gateway.sh <gateway-ip-or-host> [label] [-pin SHA256HEX]
#   label  suffix for the file names, e.g. day, night, charging, outage
#
# Output: testdata/fixtures/gateway/<firmware x.y.z>/<endpoint>[.label].json
#         plus index[.label].json with the HTTP status of every endpoint.
#
# It asks you to confirm the Gateway's certificate fingerprint, then prompts
# for the Gateway customer password (hidden; never an argument). It logs in
# ONCE and never retries, because the Gateway locks out repeated failures.
# Only GET requests follow the login; nothing on the Gateway changes.
# Run it in a real terminal. Review the files before committing.
set -eu

if [ $# -lt 1 ]; then
	sed -n '6,18p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
fi

host=$1
shift
label=
if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
	label=$1
	shift
fi

root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
cd "$root"
exec go run ./cmd/gwcapture -host "$host" -label "$label" "$@"
