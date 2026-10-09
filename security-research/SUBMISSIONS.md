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

---

### Recommended order
Submit **both** (they're independent). If VulnCheck wants one report per issue, send #1 first (cleanest, fully confirmed), then #2 with its caveat.

### Optional: notify the maintainer directly
repomanager has no `SECURITY.md`. You can also open a **private** GitHub Security Advisory on `lbr38/repomanager` (Security → "Report a vulnerability"). VulnCheck will coordinate with the vendor regardless, so this is optional/parallel.

> Nothing here has been sent anywhere. No GitHub issues/PRs were opened on the target. These are drafts for you to submit.
