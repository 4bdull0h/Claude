# Security research — vulnerability hunting in open-source GitHub projects

Open-ended audit of self-hosted open-source web apps, for **responsible
disclosure** to maintainers. Targets chosen by the auditor; everything here is
source review of public code (one finding also confirmed with a code-level PoC
against a throwaway sandbox), framed for coordinated disclosure (no attacks on
live systems, no weaponized exploits).

## Findings

| # | Project | Finding | Class | Severity | Status | Submission |
|---|---------|---------|-------|----------|--------|------------|
| 1 | [`lbr38/repomanager`](https://github.com/lbr38/repomanager) | `dist` parameter path traversal &rarr; arbitrary directory deletion/creation outside repo root | CWE-22 / CWE-23 | Medium–High (authenticated) | **Confirmed (code-level PoC)**, [details](./repomanager-dist-path-traversal.md) | [packet](./VULNCHECK-SUBMISSION.md) |
| 2 | [`lbr38/repomanager`](https://github.com/lbr38/repomanager) | Unsanitized `controller` POST param in `include_once` &rarr; authenticated PHP file inclusion (RCE if a `.php` plant exists) | CWE-98 / CWE-22 | High (authenticated; RCE contingent) | **Confirmed (PoC of include sink)**, [details](./repomanager-lfi-controller.md) | [packet](./VULNCHECK-SUBMISSION-2-lfi.md) |
| 3 | [`tuxxin/iNetPanel`](https://github.com/tuxxin/iNetPanel) | `get_user`/`list_domains` accounts-API actions skip the assigned-domain scope check their siblings enforce &rarr; `subadmin` reads any tenant's account/domain config (IDOR) | CWE-639 / CWE-285 | Medium (authenticated subadmin; cross-tenant info disclosure) | **Confirmed (code-level authorization asymmetry)**, [details](./inetpanel-accounts-idor.md) | [packet](./VULNCHECK-SUBMISSION-3-inetpanel-idor.md) |
| 4 | [`smskit/smskit`](https://github.com/smskit/smskit) | `poll.php` has no auth; attacker-chosen `device_id` self-registers and receives queued outbound SMS (OTP/2FA bodies + numbers) and diverts them from delivery | CWE-306 / CWE-200 | **High (unauthenticated SMS/OTP interception)** | **Confirmed (runtime PoC)**, [details](./smskit-poll-unauth-sms-interception.md) | [packet](./VULNCHECK-SUBMISSION-4-smskit.md) |
| 5 | [`dadaloop82/EverShelf`](https://github.com/dadaloop82/EverShelf) | `telegram_webhook` doesn't verify Telegram's secret token; with the default-empty chat allowlist, forged updates exfiltrate the shopping/inventory list to an attacker's chat | CWE-306 | **Low** (read-only, low-sensitivity, config-dependent; borderline-for-CVE) | Confirmed (code review), [details](./evershelf-telegram-webhook-unauth.md) | [packet](./VULNCHECK-SUBMISSION-5-evershelf.md) |

### Lower-severity observations (same audit)
- repomanager: single-level traversal via `name`/`section`; admin-only SSRF in GPG key import; `rm -rf "$path"` antipattern; no CSRF token check on the AJAX dispatcher. See the detailed reports.

- **[`imehdiha/cardpay`](https://github.com/imehdiha/cardpay)** — card-to-card payment gateway (PHP/MySQL, HMAC API, SMS matching, webhooks; ~27★, new). Audited the money paths:
  device API (HMAC-SHA256 + timestamp tolerance + nonce replay table + `hash_equals`; shortcut path uses a per-device bearer secret compared with `hash_equals`), merchant API (`ApiAuthService` canonical covers method/path/query/`sha256(body)`/ts/nonce, replay-protected), payment `status/verify/cancel` (scoped via `findForApplication(publicId, app.id)` — no IDOR), the unauthenticated buyer page (CSRF + rate-limited; `storeReceipt` validates MIME via `finfo`, random filename, fixed dir — no upload RCE/traversal), card numbers encrypted at rest. **No submittable vulnerability.**

- **[`1227cwx/HDupay`](https://github.com/1227cwx/HDupay)** — crypto (USDT/USDC) payment gateway, Epay-compatible (webman framework, ~14k LOC, ~40★). **Spot-checked** the money paths: the Epay signature service (standard `md5(ksort(k=v&…)+secret)` with `hash_equals` verify, no obvious param-injection bypass) and the HD-wallet handling (`hash_equals` mnemonic/seed fingerprints). Careful author; no finding on the audited surface (not an exhaustive review of 14k LOC).
- **[`kumatrk/initialrelease`](https://github.com/kumatrk/initialrelease)** ("Simple Kuma" affiliate tracker, ~108k LOC, ~44★). **Spot-checked** the public tracking path: the redirect destination is resolved from campaign/offer config (not an attacker-supplied `url=`), the inactive-redirect is allowlisted (`InactiveRedirectParser::isAllowedHttpUrl`), and schema introspection uses `real_escape_string`. No open-redirect/SQLi on the audited surface (mature codebase; not exhaustively reviewed).

- **[`mr-r0ot/NoRootVpn-Panel`](https://github.com/mr-r0ot/NoRootVpn-Panel)** — pure-PHP VLESS/XHTTP VPN panel for shared hosting (~3k LOC, ~14★, new). Auth is sound (`password_verify` + per-session CSRF `hash_equals`, install wizard guarded by `!$installed`); the data-plane `proxy.php` forwards to a **fixed** `127.0.0.1:$localPort` (config-set, not client-controlled — no SSRF/open-proxy); `exec()` uses `intval`/`escapeshellarg`. **Observation (not a distinct CVE):** unlike GumCP/iNetPanel, the first-run installer has no localhost/private-IP restriction, so a freshly-deployed, not-yet-configured instance can be taken over by whoever completes setup first (standard unprotected-installer race). No submittable finding.

- **[`mahirgul/AiPBX`](https://github.com/mahirgul/AiPBX)** — Asterisk PBX web portal / unified comms (~146k LOC, ~12★, new). Spot-checked the classic PBX sink — Asterisk `.call` spool-file injection in `FaxSendService` — and found it correctly mitigated (`dest_number`/`sender_did` forced to digits-only with an explicit security comment; admin sender validated against the DB); `asterisk -rx` calls wrap args in `escapeshellarg`. No finding on the audited surface.
- **[`nwnuyhs/flatbb`](https://github.com/nwnuyhs/flatbb)** — plain-PHP forum, SQLite/MySQL (~25k LOC, ~10★, new). SQL is parameterized; the link-preview fetcher (`core/links.php`) is a **textbook SSRF defense** — http/https + port 80/443 only, resolves the host and refuses if any resolved IP is private (DNS-rebinding aware), pins the cURL connection to the vetted IP, disables auto-redirect and re-validates each hop (max 3), TLS verify on. (Minor hardening note: the plugin **marketplace** client uses `CURLOPT_SSL_VERIFYPEER=>false` on an admin-only code-download path — worth fixing but admin-triggered, not a submittable finding.) No submittable vulnerability.

- **[`David-Crty/databasement`](https://github.com/David-Crty/databasement)** — self-hosted DB backup manager (Laravel, ~76k LOC, ~2.5k★, new, multi-tenant). Spot-checked command-building for `mysqldump`/`pg_dump`/`mongodump`/`redis-cli`/`ssh`: all user-supplied connection values go through `escapeshellarg`, and user-supplied extra dump flags are gated by a thorough bespoke `SafeDumpFlags` validator (per-engine denied file-write/code-load flags, getopt abbreviation + MySQL `_`/`-` and `--loose-/--skip-` prefix expansion, short-option clustering, sqlpackage `/opt:val`) plus a character allowlist. Exceptionally hardened; no finding on the audited surface.

- **[`Vateron-Media/XC_VM`](https://github.com/Vateron-Media/XC_VM)** — Xtream-Codes-derived IPTV panel (~364k LOC, ~95★/78 forks). Checked the classic unauth spot — `stream/auth.php` + `UserRepository::loadUserRow` credential/cache lookup. The `username`/`password`/token flow into `line_c_`/`line_t_` cache paths *looks* traversable but is not: the glued `line_c_`/`line_t_` prefix makes the first path component a literal (never a bare `..`), so `../` payloads ENOENT rather than resolving out; the DB fallback uses prepared `?` params, and cached results are re-verified against the row (`username==row && password==row`). No exploitable traversal/auth-bypass on the audited path.

### Leads investigated and ruled out (honest negatives)
- repomanager **command injection via malicious upstream mirror**: the Deb index path (`xz`/`bunzip2` on a remote-named file) is gated by an `in_array` allow-list built from the admin-validated `section`/`arch`, so remote metacharacters can't survive; the RPM `modifyrepo --mdtype=… <file>` path uses a hardcoded `additionalMetadataFiles` array. Both **not exploitable**.
- repomanager SQL injection: models use prepared statements (≈320 `prepare` vs the only interpolated queries using an internal `$tableName`). No user-driven SQLi found.

## Targets audited with no confirmed vulnerability

- **[`error311/FileRise`](https://github.com/error311/FileRise)** — PHP/JS self-hosted file manager (~1k★). Audited path sanitization, archive
  extraction (zip-slip), command exec, OnlyOffice callback SSRF, JWT/HMAC, share
  links, and the public portal flow. Core is well-hardened across every surface
  examined (dedicated path policies, `escapeshellarg` throughout, realpath
  containment, signed tokens + `hash_equals`, SSRF origin pinning, bcrypt +
  rate-limited share passwords). **No confirmable vulnerability found** in the
  code reachable in the repo; Pro features depend on a closed-source bundle not
  present. Recorded as a negative result rather than a manufactured finding.
- **[`m1k1o/blog`](https://github.com/m1k1o/blog)** — lightweight self-hosted PHP blog (~300★, ~4k LOC). Audited the AJAX dispatcher
  (`call_user_func(['Post', $action], $request)`), DB layer, auth/session, upload, and i18n. Reasonably hardened:
  all state-changing `Post` methods call `login_protected()`; queries use bound PDO params (the public `load()`
  feed binds its `loc`/`person`/`tag` filters); the AJAX dispatcher enforces a per-session CSRF token; `Lang::load`
  validates the `hl` language param with `^[a-z]+$` (no LFI); image upload is login-gated. Weaknesses are design-level
  only (plaintext password compared from config, `crc32` session value, admin-only SSRF via `parse_link`) — **no
  confirmable, submittable vulnerability**.
- **[`PhotoboothProject/photobooth`](https://github.com/PhotoboothProject/photobooth)** — Raspberry-Pi photo-booth web app (~680★, ~25k LOC, `dev`). Chosen as a
  shell-out-heavy target. Audited every web-reachable `exec`/`shell_exec` endpoint (`print`, `shellCommand`,
  `applyEffects`, `applyVideoEffects`, `previewCamera`, `liveChromaConfig`) and the file read/delete endpoints
  (`download`, `deletePhoto`). Consistently hardened: per-request CSRF tokens (`hash_equals`), filename
  allow-list `^[A-Za-z0-9._-]+$` + `basename()`, `escapeshellarg()` on all user-derived args, mode allow-lists via
  `switch`, and `(int)` casts; command templates come from admin config, not request input. One quirk —
  `download.php` uses the raw `image` param for the *thumbnail* path — is **not practically exploitable** (only
  reached when `IMAGES/basename(image)` is already an existing image with a valid extension, so the leaf filename
  can't be an arbitrary sensitive file). **No confirmable, submittable vulnerability** in the audited surface.
- **[`gumslone/GumCP`](https://github.com/gumslone/GumCP)** — Raspberry-Pi web control panel with command buttons, HTTP API and SSH execution (~170★).
  Despite being a low-star command-runner, it is **exceptionally hardened**: `include/auth.php` fails closed, uses CSRF
  tokens, `hash_equals`, per-IP login throttling, `session_regenerate_id`, and refuses to trust `X-Forwarded-For`;
  the unauthenticated `api.php` executes only pre-configured button commands gated by a 128-bit bearer hash
  (`^[a-f0-9]{32}$` + `hash_equals` + throttle + IP allow-list); `setup.php` restricts to private REMOTE_ADDR and
  self-disables after configuration. Command execution via `execute_command.php`/`ajax.php` is intended authenticated-
  admin functionality (no privilege boundary crossed). **No submittable vulnerability.**

## Method (reusable)

1. Map the input surface (HTTP entrypoints: ajax/API controllers reading `$_POST`/`$_GET`).
2. Enumerate dangerous sinks: `proc_open`/`exec`/`system`, SQL construction,
   `unlink`/`rm`/`mkdir`/`file_put_contents`, archive extraction, server-side HTTP fetchers.
3. Trace taint from each sink back to a source; at each hop check the validator's
   *actual* character class (not its name) and whether canonicalization/containment exists.
4. Confirm the end-to-end chain before claiming anything; record negative results honestly.

> Reports here are drafts for maintainers. No CVE is "published" by this repo;
> CVE IDs come from the maintainer's coordinated-disclosure process.
