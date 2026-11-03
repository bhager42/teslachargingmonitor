#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Brad Hager and contributors
#
# Structure and smoke tests for the tcmon container image (plan §11).
# Usage: scripts/image-test.sh IMAGE [MAX_MB]
set -eu

img=${1:?usage: image-test.sh IMAGE [MAX_MB]}
max_mb=${2:-25}
name=tcmon-imgtest-$$
dir=$(mktemp -d)
fails=0

cleanup() {
	docker rm -f "$name" "$name-uid" "$name-tz" >/dev/null 2>&1 || true
	docker volume rm "$name-data" >/dev/null 2>&1 || true
	rm -rf "$dir"
}
trap cleanup EXIT

pass() { echo "ok   $1"; }
fail() { echo "FAIL $1" >&2; fails=$((fails + 1)); }
check() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1: got '$2', want '$3'"; fi; }

inspect() { docker image inspect --format "$1" "$img"; }

# ---- image metadata --------------------------------------------------------
# Unpacked filesystem size (storage-driver independent; `docker image inspect`
# also counts the compressed blobs with the containerd image store).
docker create --name "$name-tz" "$img" >/dev/null
size=$(docker export "$name-tz" | wc -c)
mb=$((size / 1000 / 1000))
if [ "$mb" -lt "$max_mb" ]; then pass "size ${mb} MB < ${max_mb} MB"; else fail "size ${mb} MB >= ${max_mb} MB"; fi
check "runs as 568:568" "$(inspect '{{.Config.User}}')" "568:568"
check "entrypoint" "$(inspect '{{json .Config.Entrypoint}}')" '["/tcmon"]'
check "default command" "$(inspect '{{json .Config.Cmd}}')" '["serve"]'
check "healthcheck" "$(inspect '{{json .Config.Healthcheck.Test}}')" '["CMD","/tcmon","healthcheck"]'
# shellcheck disable=SC2016 # Go template, not shell
check "exposes 8443" "$(inspect '{{range $p, $v := .Config.ExposedPorts}}{{$p}} {{end}}')" "8443/tcp "
check "license label" "$(inspect '{{index .Config.Labels "org.opencontainers.image.licenses"}}')" "AGPL-3.0-or-later"
check "source label" "$(inspect '{{index .Config.Labels "org.opencontainers.image.source"}}')" "https://github.com/bhager42/teslachargingmonitor"
case " $(inspect '{{join .Config.Env " "}}') " in
	*" TCMON_DATA_DIR=/data "*) pass "TCMON_DATA_DIR=/data" ;;
	*) fail "TCMON_DATA_DIR not /data" ;;
esac

# ---- contents ----------------------------------------------------------------
if docker run --rm --entrypoint /bin/sh "$img" -c true >/dev/null 2>&1; then
	fail "image contains a shell"
else
	pass "no shell in the image"
fi
if docker cp "$name-tz:/usr/share/zoneinfo/America/Chicago" "$dir/tz" >/dev/null 2>&1; then
	pass "time zone database present"
else
	fail "time zone database missing (TZ would not work)"
fi
if docker cp "$name-tz:/etc/ssl/certs/ca-certificates.crt" "$dir/ca" >/dev/null 2>&1; then
	pass "CA certificates present (Gmail TLS)"
else
	fail "CA certificates missing"
fi
if docker run --rm "$img" version | grep -q "Tesla Charger Monitoring"; then
	pass "tcmon version runs"
else
	fail "tcmon version"
fi

# ---- hardened run, as in deploy/compose.yaml ----------------------------------
wait_healthy() {
	i=0
	while [ $i -lt 60 ]; do
		s=$(docker inspect --format '{{.State.Health.Status}}' "$1" 2>/dev/null || echo gone)
		[ "$s" = healthy ] && return 0
		[ "$s" = gone ] && return 1
		[ "$(docker inspect --format '{{.State.Running}}' "$1")" = true ] || return 1
		i=$((i + 1))
		sleep 1
	done
	return 1
}

docker volume create "$name-data" >/dev/null
docker run -d --name "$name" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
	--tmpfs /tmp:size=16m,mode=1777 --health-interval 2s --health-start-period 30s \
	-v "$name-data:/data" -p 127.0.0.1::8443 -e TZ=America/Chicago "$img" >/dev/null
if wait_healthy "$name"; then pass "hardened container becomes healthy"; else fail "hardened container not healthy"; docker logs "$name" >&2 || true; fi
port=$(docker port "$name" 8443/tcp | head -n 1 | sed 's/.*://')
# The self-signed certificate is pinned from the volume, never -k.
docker cp "$name:/data/tls/cert.pem" "$dir/cert.pem" >/dev/null 2>&1 || true
if [ -s "$dir/cert.pem" ] && [ "$(curl -sS --cacert "$dir/cert.pem" --resolve "localhost:$port:127.0.0.1" "https://localhost:$port/healthz")" = ok ]; then
	pass "GET /healthz over HTTPS (pinned self-signed certificate)"
else
	fail "GET /healthz over HTTPS"
fi
if docker logs "$name" 2>&1 | grep -q '"setup_token"'; then pass "first-run setup token is in the log"; else fail "no setup token in the log"; fi
if docker exec "$name" /tcmon healthcheck; then pass "tcmon healthcheck"; else fail "tcmon healthcheck"; fi

# ---- arbitrary UID owning a bind-mounted /data --------------------------------
mkdir -p "$dir/data"
chown 1234:1234 "$dir/data" 2>/dev/null || true
if [ "$(stat -c %u "$dir/data")" = 1234 ]; then
	docker run -d --name "$name-uid" --user 1234:1234 --read-only --cap-drop ALL \
		--health-interval 2s -v "$dir/data:/data" "$img" >/dev/null
	if wait_healthy "$name-uid"; then pass "runs as another UID that owns /data"; else fail "arbitrary UID"; docker logs "$name-uid" >&2 || true; fi
else
	echo "skip arbitrary UID (needs root to chown the test directory)"
fi

if [ "$fails" -ne 0 ]; then
	echo "$fails image check(s) failed" >&2
	exit 1
fi
echo "all image checks passed"
