#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Brad Hager and contributors
#
# Fails if any tracked source file lacks the SPDX AGPL-3.0-or-later header
# within its first 5 lines. Run from the repository root.
set -eu

want='SPDX-License-Identifier: AGPL-3.0-or-later'
missing=0

files=$(mktemp)
trap 'rm -f "$files"' EXIT
git ls-files -- '*.go' '*.sh' '*.js' '*.mjs' '*.css' '*.html' '*.tmpl' '*.sql' \
	'*.yml' '*.yaml' 'Makefile' 'Dockerfile' '*.Dockerfile' > "$files"

while IFS= read -r f; do
	case "$f" in
		testdata/*|web/static/vendor/*) continue ;;
	esac
	if ! head -n 5 "$f" | grep -q "$want"; then
		echo "missing SPDX header: $f" >&2
		missing=1
	fi
done < "$files"

if [ "$missing" -ne 0 ]; then
	echo "Add '$want' (and the copyright line) to the files above." >&2
	exit 1
fi
echo "SPDX headers OK"
