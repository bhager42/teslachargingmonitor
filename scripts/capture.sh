#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Brad Hager and contributors
#
# Capture the local API of a Tesla (Universal) Wall Connector into redacted
# test fixtures.
#
# Usage: scripts/capture.sh <wall-connector-ip-or-host> [label]
#   label  optional suffix for the vitals file, e.g. "charging" ->
#          vitals.charging.json (default: vitals.json)
#
# Output: testdata/fixtures/uwc/<firmware x.y.z>/{version,lifetime,wifi_status,vitals[.label]}.json
#
# Redaction (always applied, never optional):
#   serial_number -> REDACTED00000
#   wifi_mac      -> 02:00:00:00:00:00
#   wifi_ssid     -> base64("REDACTED")
#   wifi_infra_ip -> 192.0.2.<last octet>   (RFC 5737 documentation range)
# Review the files before committing anyway.
set -eu

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
	sed -n '6,20p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
fi

host=$1
label=${2:-}

case "$host" in
	*[!A-Za-z0-9.:-]*|'') echo "invalid host: $host" >&2; exit 2 ;;
esac
case "$label" in
	*[!a-z0-9-]*) echo "label may only contain a-z, 0-9 and '-'" >&2; exit 2 ;;
esac

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }

fetch() {
	curl --fail --silent --show-error --max-time 5 --max-filesize 65536 \
		--proto '=http' --max-redirs 0 "http://$host/api/1/$1"
}

redact() {
	sed -E \
		-e 's/"serial_number" *: *"[^"]*"/"serial_number":"REDACTED00000"/' \
		-e 's/"wifi_mac" *: *"[^"]*"/"wifi_mac":"02:00:00:00:00:00"/' \
		-e 's/"wifi_ssid" *: *"[^"]*"/"wifi_ssid":"UkVEQUNURUQ="/' \
		-e 's/"wifi_infra_ip" *: *"[0-9]+\.[0-9]+\.[0-9]+\.([0-9]+)"/"wifi_infra_ip":"192.0.2.\1"/' \
		-e 's/"wifi_infra_ip" *: *"[^"]*:[^"]*"/"wifi_infra_ip":"192.0.2.1"/'
}

version_json=$(fetch version)
fw=$(printf '%s' "$version_json" | sed -nE 's/.*"firmware_version":"([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')
[ -n "$fw" ] || { echo "could not read firmware_version from /api/1/version" >&2; exit 1; }

root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
out="$root/testdata/fixtures/uwc/$fw"
mkdir -p "$out"

printf '%s\n' "$version_json" | redact > "$out/version.json"
fetch lifetime | redact > "$out/lifetime.json"
printf '\n' >> "$out/lifetime.json"
fetch wifi_status | redact > "$out/wifi_status.json"
printf '\n' >> "$out/wifi_status.json"
vitals_name=vitals.json
[ -n "$label" ] && vitals_name="vitals.$label.json"
fetch vitals | redact > "$out/$vitals_name"
printf '\n' >> "$out/$vitals_name"

echo "Wrote redacted fixtures to $out:"
ls -1 "$out"
echo "Review them, then run 'make test' (it verifies redaction) before committing."
