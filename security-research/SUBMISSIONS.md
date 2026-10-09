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

---

### Recommended order
Submit **both** (they're independent). If VulnCheck wants one report per issue, send #1 first (cleanest, fully confirmed), then #2 with its caveat.

### Optional: notify the maintainer directly
repomanager has no `SECURITY.md`. You can also open a **private** GitHub Security Advisory on `lbr38/repomanager` (Security → "Report a vulnerability"). VulnCheck will coordinate with the vendor regardless, so this is optional/parallel.

> Nothing here has been sent anywhere. No GitHub issues/PRs were opened on the target. These are drafts for you to submit.
