# VulnCheck submission packet #7 — pricebuddy authenticated SSRF (redirect bypass)

Submit at **https://vulncheck.com/advisories/report** (or **disclosures@vulncheck.com**).

### Name to be credited
Abdulloh Nuriddinov (GitHub: 4bdull0hh)

### Contact email
abdullohnuriddinov677@gmail.com

### How you came across this
Independent source review + runtime PoC (AI-assisted).

### Supplier / maintainer
jez500 — https://github.com/jez500/pricebuddy (and the bundled dependency https://github.com/jez500/web-scraper-for-laravel)

### Affected product
**pricebuddy** — self-hosted price tracker (Laravel + Filament).

### Affected versions / environment confirmed
`main` @ `34f2b2f7ca3b9853d83ec686e46ad74fc0f21e12` (2026-10-05); app version string `development`. Uses `jez500/web-scraper-for-laravel ^1.0.9`. Maintainer to confirm earliest affected release.

### Vulnerability type
CWE-918 (Server-Side Request Forgery) — anti-SSRF guard bypassed by HTTP redirect following (validate-once / fetch-follows-redirects). Also exploitable via DNS-rebinding TOCTOU.

### Authentication
Authenticated — a Laravel Sanctum API token with the `meta-extraction:extract` ability (any panel user who can mint an API token).

### Suggested CVSS 3.1
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L` → ~**7.1 (High)**. Maintainer/VulnCheck to finalize.

### Description
`POST /api/meta-extraction` fetches a caller-supplied `url` server-side and returns
data extracted from the response. The `url` is validated by `App\Rules\PublicHttpUrl`,
which resolves the host and rejects loopback/RFC1918/link-local/cloud-metadata
ranges. The rule is thorough, but it validates **only the initial URL**: the
subsequent fetch, performed by the bundled `jez500/web-scraper-for-laravel` via
Laravel's `Http` client (`HttpDriver::fetch()` → `Http::...->get($url)` with no
`->withoutRedirecting()`), follows HTTP redirects (Guzzle default, up to 5 hops)
and never re-checks the redirect target.

An authenticated attacker submits `url = http://attacker-public-host/` (passes the
validator), and that host replies `302 Location: http://169.254.169.254/…` (or any
internal address). The scraper follows the redirect and fetches the internal
resource. Because the same request also accepts an extraction strategy
(`store.scrape_strategy.title.{type,value}`, with `type` in
selector/regex/xpath/json/schema_org), the attacker reads arbitrary slices of the
internal response in the returned `title`/`price`/`image` fields — a **readable**
SSRF (each field capped ~1000 chars, so large bodies are read in slices).

The guard is also defeatable by DNS rebinding (the rule resolves at validation
time; the fetch re-resolves at request time).

### Proof of concept (runtime-demonstrated)
Request (Sanctum token with `meta-extraction:extract`):
```json
{"url":"http://attacker.example/landing",
 "store":{"domains":[{"domain":"attacker.example"}],
          "scrape_strategy":{"title":{"type":"regex","value":"(?s)(.*)"}}}}
```
`attacker.example` is public → passes `PublicHttpUrl`; it 302s to
`http://169.254.169.254/latest/meta-data/…`; the scraper follows and the internal
body is returned in `title`.

Local demonstration, two parts:
- Part 1 — the real `PublicHttpUrl` rule: `http://8.8.8.8/...` PASSES;
  `127.0.0.1` / `localhost` / `169.254.169.254` / `[::1]` BLOCKED — and it inspects
  only the initial URL.
- Part 2 — the fetch (Laravel Http/Guzzle default, not disabled by the scraper)
  following a 302 from the submitted (public) host to an internal target returns the
  internal body; the same fetch without following redirects leaks nothing (HTTP 302).

PoC: `security-research/poc/pricebuddy-ssrf-redirect-poc.sh` (+
`pricebuddy-validator-test.php`, `pricebuddy-internal.php`, `pricebuddy-redirector.php`).

### Suggested fix
Disable redirect following on the scraper HTTP client, or re-run `PublicHttpUrl` on
every redirect `Location` (Guzzle `on_redirect`); defeat DNS rebinding by resolving
once and pinning the connection to the vetted public IP; apply the same to the
`scraper:3000` microservice path.

### Caveat (stated honestly)
Authenticated (needs an API token with the ability). Code path confirmed by reading
pricebuddy + the vendored scraper package; validator verdicts and redirect-follow
behavior demonstrated at runtime. A full end-to-end run against a live instance with
a real token + public redirector was not performed (needs a provisioned DB/token);
redirect-following is a well-established Laravel/Guzzle default and the scraper
package provably does not disable it. Sandbox has no outbound DNS / cannot bind a
public IP, so the "public" host is represented on loopback and public IPs given as
literals.

### References
- https://github.com/jez500/pricebuddy (`main` @ `34f2b2f`)
- https://github.com/jez500/web-scraper-for-laravel (`src/WebScraperHttp.php`, `src/Drivers/HttpDriver.php`)
- Full write-up: `security-research/pricebuddy-ssrf-redirect-bypass.md`
