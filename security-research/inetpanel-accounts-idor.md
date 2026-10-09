# Security advisory (draft) — Broken object-level authorization (IDOR) in iNetPanel accounts API

**Project:** [`tuxxin/iNetPanel`](https://github.com/tuxxin/iNetPanel) — self-hosted hosting control panel (cPanel-like)
**Version audited:** 1.28.0, `main` @ `9b8c2e46afcef006c6f81871fb7857b4e9fd03c4` (2026-10-09)
**Class:** CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-285 (Improper Authorization)
**Impact:** A limited `subadmin` panel user can read **any** hosting account's details and domain configuration outside their delegated scope (cross-tenant/reseller information disclosure)
**Privilege required:** Authenticated `subadmin` (a delegated/reseller panel user, by design scoped to assigned domains)
**Status:** Confirmed by code review (clear authorization asymmetry vs. sibling actions); not run on a live multi-role install.

---

## Summary

iNetPanel supports delegated panel users with the `subadmin` role, whose access
is meant to be restricted to an assigned set of domains (`panel_users.assigned_domains`).
The accounts API enforces that scope on most read actions — `list` / `list_users`
filter results to the caller's assigned domains, and `detail` calls
`Auth::canAccessDomain()` — **but the `get_user` and `list_domains` actions perform
no authorization check at all** beyond being logged in. A `subadmin` can therefore
read any hosting account's record and full domain configuration (document roots,
ports, PHP versions, status, disk usage, WireGuard peer IP) for accounts they were
never granted, breaking the panel's tenant isolation.

## Where it lives

Routing (`public/index.php`): `/api/accounts` is guarded by `Auth::check()` only
(any logged-in panel user), not `requireAdmin`:

```php
foreach ([ '/api/accounts' => 'accounts.php', ... ] as $route => $file) {
    $router->add($route, function () use ($file) {
        Auth::check();                         // login only — subadmin passes
        require API_PATH . '/' . $file;
    });
}
```

`Auth::check()` requires only a valid session; `Auth::requireAdmin()` /
`hasFullAccess()` (role `admin`/`fulladmin`) is applied **per action** inside
`api/accounts.php`. The read actions split as follows:

| action        | authorization applied |
|---------------|-----------------------|
| `list_users`  | filters to `Auth::user()['domains']` when `!hasFullAccess()` ✔ |
| `list`        | assigned-domain filter ✔ |
| `detail`      | `Auth::canAccessDomain($domain)` ✔ |
| **`get_user`**    | **none** ✘ |
| **`list_domains`**| **none** ✘ |

`get_user` (`api/accounts.php`):

```php
case 'get_user':
    $username = trim($_GET['username'] ?? '');
    ...
    $user = DB::fetchOne('SELECT * FROM hosting_users WHERE username = ?', [$username]);
    $user['domains'] = DB::fetchAll('SELECT * FROM domains WHERE hosting_user_id = ? ...', [$user['id']]);
    foreach ($user['domains'] as &$d) {
        $d['disk'] = ... ; $d['ssl'] = ... ;            // document_root, port, php_version exposed
    }
    $user['wg_ip'] = ... ;                               // WireGuard peer IP exposed
    echo json_encode(['success' => true, 'data' => $user]);   // no scope check
```

`list_domains` is the same pattern: `username` → `SELECT * FROM domains` with no
`canAccessDomain`/assigned-domain filter.

## Exploitation

As any authenticated `subadmin` (session cookie from a normal panel login):

```
GET /api/accounts?action=get_user&username=<victim_account>      HTTP/1.1
Cookie: <subadmin panel session>

GET /api/accounts?action=list_domains&username=<victim_account>  HTTP/1.1
Cookie: <subadmin panel session>
```

Both return the victim account's data regardless of the subadmin's assigned
domains. Usernames are predictable — `create` derives them from the domain's
first label (`preg_replace('/[^a-z0-9]/', '', strtolower(explode('.', $domain)[0]))`),
so a subadmin who knows any hosted domain name can resolve the username and read
its configuration.

Disclosed per account: hosting username, shell, disk quota/usage, and for every
domain the `document_root`, `port`, `php_version`, `status`, SSL presence, and the
account's WireGuard peer IP — i.e. the internal hosting topology of other tenants/
resellers, useful for lateral targeting. (No password hashes: `hosting_users` holds
no secret columns, and `panel_users.password_hash` is not returned here.)

## Remediation

Apply the same scope check the sibling actions use. For `get_user` and
`list_domains`, after resolving the account, verify the caller may see it:

```php
if (!Auth::hasFullAccess()) {
    $allowed = Auth::user()['domains'] ?? [];
    $owns = DB::fetchAll('SELECT domain_name FROM domains WHERE hosting_user_id = ?', [$user['id']]);
    $visible = array_intersect(array_column($owns, 'domain_name'), $allowed);
    if (!$visible) { echo json_encode(['success'=>false,'error'=>'Access denied.']); break; }
}
```

Better: centralize it — route every account-scoped read through a single
`Auth::canAccessUser($username)` guard (mirroring `canAccessDomain`) so a new
action cannot silently ship without the check. Consider denying `subadmin`
accounts the ability to resolve arbitrary usernames at all.

## Notes on scope
The rest of iNetPanel's privileged surface is well-built: `TiCore/Shell.php`
whitelists `inetp` subcommands and `escapeshellarg`s every argument, stages files
in an owner-only dir (explicitly fixing a prior /tmp symlink class), and all
state-changing account/firewall actions call `requireAdmin`. This finding is an
authorization-coverage gap on two read actions, not a command-exec flaw.

## References
- Source: https://github.com/tuxxin/iNetPanel (`main` @ `9b8c2e4`)
- `public/index.php` (API route gating), `api/accounts.php` (`get_user`, `list_domains`, `detail`, `list_users`), `TiCore/Auth.php` (`check`, `requireAdmin`, `hasFullAccess`, `canAccessDomain`)
