# Submission tracker — VulnCheck

One place for everything you need to submit. Channel for all of these:

- **Web form:** https://vulncheck.com/advisories/report
- **Email:** disclosures@vulncheck.com
- VulnCheck is a CNA; they coordinate with the vendor and (per their program) publish within ~120 days whether or not it's fixed.
- Fill the two placeholders in each packet: **credit name** (or pseudonym/blank) and **your contact email**. I left them blank so your email isn't sent anywhere without you choosing to.

| Status key | meaning |
|---|---|
| ☐ not submitted | packet ready, you haven't sent it yet |
| ☑ submitted | you've sent it; awaiting VulnCheck ack |

---

## Submission 1 — repomanager `dist` path traversal  ☐ not submitted

- **Supplier / product:** lbr38 / **repomanager** (self-hosted deb/rpm repo manager)
- **Version:** 6.1.0, `devel` @ `a7bc264fa94b1cc325239d0c854569959ec83d68` (2026-10-09)
- **Type:** CWE-22 / CWE-23 path traversal (authenticated)
- **Impact:** arbitrary recursive directory **deletion** / creation outside `REPOS_DIR` (`/home/repo`), as the repomanager service account
- **Suggested CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` → 8.1 High (use `PR:H` if the required account is admin-only)
- **Full packet to paste:** [`VULNCHECK-SUBMISSION.md`](./VULNCHECK-SUBMISSION.md)
- **Technical write-up:** [`repomanager-dist-path-traversal.md`](./repomanager-dist-path-traversal.md)
- **PoC:** [`poc/verify.php`](./poc/verify.php) — confirmed (validator accepts `../`; `rm -rf` escapes `REPOS_DIR`)
- **One-line:** `Param\Dist::check()` allows `.` and `/`, so a `../`-laden distribution name flows unsanitized into `rm -rf`/`mkdir` with no containment.

## Submission 2 — repomanager `controller` PHP file inclusion  ☐ not submitted

- **Supplier / product:** lbr38 / **repomanager**
- **Version:** 6.1.0, `devel` @ `a7bc264` (2026-10-09)
- **Type:** CWE-98 / CWE-22 PHP local file inclusion (authenticated, any role)
- **Impact:** include+execute arbitrary local `.php`; **RCE if a `.php` file-plant primitive exists** (honest caveat in the packet)
- **Suggested CVSS 3.1:** `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` → ~7.5 High (RCE path), or ~7.1 for local-`.php` inclusion only
- **Full packet to paste:** [`VULNCHECK-SUBMISSION-2-lfi.md`](./VULNCHECK-SUBMISSION-2-lfi.md)
- **Technical write-up:** [`repomanager-lfi-controller.md`](./repomanager-lfi-controller.md)
- **PoC:** [`poc/lfi-controller-poc.php`](./poc/lfi-controller-poc.php) — confirmed include-sink executes a traversed `.php`
- **One-line:** `$_POST['controller']` is concatenated unsanitized into `include_once(ROOT.'/controllers/ajax/'.$controller.'.php')`.

## Submission 3 — iNetPanel accounts API IDOR  ☐ not submitted

- **Supplier / product:** tuxxin / **iNetPanel** (self-hosted hosting control panel)
- **Version:** 1.28.0, `main` @ `9b8c2e46afcef006c6f81871fb7857b4e9fd03c4` (2026-10-09)
- **Type:** CWE-639 / CWE-285 broken object-level authorization (authenticated `subadmin`)
- **Impact:** a limited `subadmin` reads any tenant's account + domain config (document roots, ports, PHP versions, WireGuard IPs) outside their assigned-domain scope
- **Suggested CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` → ~4.3 (use `C:H` → ~6.5 if topology is deemed sensitive)
- **Full packet to paste:** [`VULNCHECK-SUBMISSION-3-inetpanel-idor.md`](./VULNCHECK-SUBMISSION-3-inetpanel-idor.md)
- **Technical write-up:** [`inetpanel-accounts-idor.md`](./inetpanel-accounts-idor.md)
- **One-line:** `get_user`/`list_domains` in `api/accounts.php` omit the `canAccessDomain`/assigned-domain check that `detail`/`list`/`list_users` apply.

## Submission 4 — smskit unauthenticated SMS interception  ☐ not submitted

- **Supplier / product:** smskit / **smskit** (self-hosted SMS gateway)
- **Version:** 1.0.0, `main` @ `69e4ed82e62b5dde1647fc5e0187827a0e164284` (2026-10-09)
- **Type:** CWE-306 + CWE-200 missing authentication (unauthenticated)
- **Impact:** remote unauth attacker reads queued outbound SMS (OTP/2FA bodies + recipient numbers) via `poll.php?device_id=<any>` and diverts them from delivery; forged inbound/reports too
- **Suggested CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L` → ~8.2 High
- **Full packet to paste:** [`VULNCHECK-SUBMISSION-4-smskit.md`](./VULNCHECK-SUBMISSION-4-smskit.md)
- **Technical write-up:** [`smskit-poll-unauth-sms-interception.md`](./smskit-poll-unauth-sms-interception.md)
- **One-line:** `api/v1/poll.php` requires no auth, auto-registers any `device_id`, and returns queued SMS `to`/`message` to it (runtime-confirmed).

## Submission 5 — EverShelf unauthenticated Telegram webhook  ☐ not submitted  ⚠️ Low/borderline

- **Supplier / product:** dadaloop82 / **EverShelf** (self-hosted pantry manager)
- **Version:** 1.11.9, `main` @ `8923b468510be592f38eb678035e7e0b2519c2cc` (2026-10-09)
- **Type:** CWE-306 missing authentication (Telegram webhook secret not verified)
- **Impact:** with default-empty `TELEGRAM_ALLOWED_CHAT_IDS`, forged Telegram updates make the bot DM the victim's shopping/inventory list to the attacker's chat (read-only)
- **Suggested CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → ~5.3; practically Low
- **Full packet to paste:** [`VULNCHECK-SUBMISSION-5-evershelf.md`](./VULNCHECK-SUBMISSION-5-evershelf.md)
- **Technical write-up:** [`evershelf-telegram-webhook-unauth.md`](./evershelf-telegram-webhook-unauth.md)
- **Note:** EverShelf is otherwise well-hardened (fail-closed auth, pairing-based bootstrap, int-cast SQL, LAN-scoped scale SSRF). This is a marginal finding — maybe better as a maintainer hardening PR than a CVE.

## Submission 6 — kuwo-music-relay unauthenticated SSRF  ☐ not submitted

- **Supplier / product:** cdyUuu / **kuwo-music-relay** (single-file PHP audio-decrypt relay)
- **Version:** 1.0.0, `main` @ `90f76911dc977bf729a8b0bb18118d4ce4c5adb8` (2026-08-19; tested 2026-10-11)
- **Type:** CWE-918 server-side request forgery (unauthenticated, full-read)
- **Impact:** unauth attacker makes the server fetch arbitrary internal/cloud URLs via `url=`; responses are recoverable (decrypt is keystream XOR keyed by the attacker's `ekey`) → cloud-metadata credential theft / internal API disclosure. Guard off by default; redirect-follow + DNS-rebinding bypass it even when on.
- **Suggested CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L` → ~8.2 High
- **Full packet to paste:** [`VULNCHECK-SUBMISSION-6-kuwo-relay-ssrf.md`](./VULNCHECK-SUBMISSION-6-kuwo-relay-ssrf.md)
- **Technical write-up:** [`kuwo-music-relay-unauth-ssrf.md`](./kuwo-music-relay-unauth-ssrf.md)
- **PoC:** [`poc/kuwo-ssrf-request-poc.sh`](./poc/kuwo-ssrf-request-poc.sh) (+ `poc/kuwo-internal-server.php`) — relay fetches an attacker-chosen internal URL (runtime-confirmed); [`poc/kuwo-ssrf-readability.php`](./poc/kuwo-ssrf-readability.php) — recovers the fetched bytes from the relay's output.
- **One-line:** `decrypt.php?url=<any>` has no auth and no host allow-list, `RELAY_ALLOW_PRIVATE_IP` ships `true` (guard off), and the XOR decryption is keyed by the attacker's `ekey` → readable SSRF.

## Submission 7 — pricebuddy authenticated SSRF (redirect bypass)  ☐ not submitted

- **Supplier / product:** jez500 / **pricebuddy** (self-hosted price tracker, Laravel + Filament) — dep `jez500/web-scraper-for-laravel ^1.0.9`
- **Version:** `main` @ `34f2b2f7ca3b9853d83ec686e46ad74fc0f21e12` (2026-10-05); app version `development`
- **Type:** CWE-918 SSRF — careful `PublicHttpUrl` guard bypassed by redirect-follow (and DNS rebinding)
- **Auth:** authenticated (Sanctum token with `meta-extraction:extract` ability)
- **Impact:** `/api/meta-extraction` fetches an arbitrary `url`; the guard checks only the initial host, the scraper follows redirects without re-checking → reach 169.254.169.254 / 127.0.0.1 / internal APIs. Readable: attacker-supplied `store.scrape_strategy` returns chosen slices of the internal body.
- **Suggested CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L` → ~7.1 High
- **Full packet to paste:** [`VULNCHECK-SUBMISSION-7-pricebuddy-ssrf.md`](./VULNCHECK-SUBMISSION-7-pricebuddy-ssrf.md)
- **Technical write-up:** [`pricebuddy-ssrf-redirect-bypass.md`](./pricebuddy-ssrf-redirect-bypass.md)
- **PoC:** [`poc/pricebuddy-ssrf-redirect-poc.sh`](./poc/pricebuddy-ssrf-redirect-poc.sh) (+ `pricebuddy-validator-test.php`, `pricebuddy-internal.php`, `pricebuddy-redirector.php`)
- **One-line:** `PublicHttpUrl` validates only the submitted URL; `web-scraper-for-laravel`'s `Http::...->get()` follows redirects (never re-checked), so a public host that 302s to an internal address is fetched.

---

### Recommended order
Submit **both** (they're independent). If VulnCheck wants one report per issue, send #1 first (cleanest, fully confirmed), then #2 with its caveat.

### Optional: notify the maintainer directly
repomanager has no `SECURITY.md`. You can also open a **private** GitHub Security Advisory on `lbr38/repomanager` (Security → "Report a vulnerability"). VulnCheck will coordinate with the vendor regardless, so this is optional/parallel.

> Nothing here has been sent anywhere. No GitHub issues/PRs were opened on the target. These are drafts for you to submit.
