# VulnCheck submission packet #3 — iNetPanel accounts IDOR

Submit at **https://vulncheck.com/advisories/report** (or **disclosures@vulncheck.com**).
Fill the two `<...>` placeholders.

### Name to be credited
Abdulloh Nuriddinov (GitHub: 4bdull0hh)

### Contact email
abdullohnuriddinov677@gmail.com

### How you came across this
Independent source review (AI-assisted).

### Supplier / maintainer
tuxxin — https://github.com/tuxxin/iNetPanel

### Affected product
**iNetPanel** — self-hosted hosting control panel (PHP; Cloudflare-tunnel based cPanel alternative).

### Affected versions / environment confirmed
Version **1.28.0**, `main` @ `9b8c2e46afcef006c6f81871fb7857b4e9fd03c4` (reviewed 2026-10-09). Maintainer to confirm earliest affected release.

### Vulnerability type
CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-285 (Improper Authorization). Authenticated (delegated `subadmin` role).

### Suggested CVSS 3.1
`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` → ~4.3 (Medium-low). Use `C:H` (→ ~6.5) if the exposed hosting topology (document roots, ports, WireGuard peer IPs of other tenants) is treated as sensitive. Maintainer/VulnCheck to finalize.

### Description
iNetPanel supports delegated panel users with role `subadmin`, scoped to an
assigned set of domains (`panel_users.assigned_domains`). The accounts API
(`/api/accounts`, file `api/accounts.php`) is gated only by `Auth::check()`
(logged-in), with privileged actions self-gating via `Auth::requireAdmin()`.
Most read actions enforce the subadmin's scope — `list`/`list_users` filter to
assigned domains and `detail` calls `Auth::canAccessDomain()` — **but the
`get_user` and `list_domains` actions perform no scope check**. A `subadmin` can
therefore read any hosting account's record and full domain configuration
(document roots, ports, PHP versions, status, disk usage, WireGuard peer IP) for
accounts outside their delegated scope, breaking tenant/reseller isolation.

Usernames are predictable: the `create` action derives them from a domain's first
label (`preg_replace('/[^a-z0-9]/','',strtolower(explode('.',$domain)[0]))`), so a
subadmin who knows any hosted domain can resolve the target username.

No credentials are exposed (`hosting_users` has no secret columns); the impact is
cross-tenant disclosure of hosting configuration/topology.

### Proof of concept
As an authenticated `subadmin` (normal panel login cookie):

```
GET /api/accounts?action=get_user&username=<victim_account>
GET /api/accounts?action=list_domains&username=<victim_account>
```

Both return the victim account's data regardless of the caller's assigned domains.
Contrast with `action=detail&domain=<d>` (enforces `Auth::canAccessDomain`) and
`action=list_users` (filters to assigned domains) in the same file — the asymmetry
confirms the missing check is an oversight, not intent.

### Suggested fix
Apply the same assigned-domain / `canAccessDomain` check used by `detail`/`list`
to `get_user` and `list_domains`; ideally centralize as `Auth::canAccessUser()`
so new account-scoped actions can't ship without it.

### Caveat (state honestly)
Confirmed by code review of the authorization asymmetry between sibling actions in
`api/accounts.php` plus the login-only route gate in `public/index.php`; not
executed on a live install with two configured roles. Reproduction needs a panel
with at least one `subadmin` whose `assigned_domains` excludes the target account.

### References
- https://github.com/tuxxin/iNetPanel (`main` @ `9b8c2e4`)
- Full write-up: `security-research/inetpanel-accounts-idor.md`
