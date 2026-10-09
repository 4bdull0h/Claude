# Security advisory (draft) — Authenticated PHP file inclusion via `controller` parameter in repomanager

**Project:** [`lbr38/repomanager`](https://github.com/lbr38/repomanager)
**Version audited:** 6.1.0, `devel` @ `a7bc264fa94b1cc325239d0c854569959ec83d68` (2026-10-09)
**Class:** CWE-98 (Improper Control of Filename for Include/Require) / CWE-22 (Path Traversal)
**Impact:** Inclusion+execution of arbitrary local `.php` files; **remote code execution if combined with any writable `.php` path** (upload / log poisoning)
**Privilege required:** Authenticated (any logged-in user — the dispatcher only checks that a session exists, not the role)
**Status:** Include-sink logic **confirmed** with a PoC; full RCE depends on a file-plant primitive not yet demonstrated.

---

## Summary

The AJAX dispatcher builds the path of a PHP file to `include_once()` by
concatenating the raw, unsanitized `controller` POST parameter:

`www/controllers/public/ajax/controller.php` (served as `/ajax/controller.php`):

```php
$controller = $_POST['controller'];               // raw, no sanitization
...
if (!file_exists(ROOT . '/controllers/ajax/' . $controller . '.php')) {
    response(HTTP_BAD_REQUEST, 'Bad controller.');
}
include_once(ROOT . '/controllers/ajax/' . $controller . '.php');   // path traversal -> include
```

`$controller` is never checked for `../`, absolute paths, or a basename
allow-list. A `.php` suffix is appended and a `file_exists()` gate is applied,
so the attacker can include **any existing `.php` file on the filesystem**
reachable by traversal. With a writable `.php` path (see *Impact*), this is
remote code execution.

Authentication: the dispatcher constructs `App\Main()` (level `all`), whose
`Session::load()` redirects unauthenticated requests to `/logout` and exits —
so this requires a valid session, but **no particular role/permission** (it runs
before any per-action permission check in the target controller). A read-only
user is sufficient.

## Proof of concept (include logic)

`security-research/poc/lfi-controller-poc.php` mirrors the dispatcher's include
line exactly:

```
$ php poc/lfi-controller-poc.php "repo/edit"
  resolved include target: .../controllers/ajax/repo/edit.php
  file_exists gate: FAIL (would say 'Bad controller')      # benign name, nonexistent here

$ php poc/lfi-controller-poc.php "../../../plant/pwn"
  resolved include target: .../controllers/ajax/../../../plant/pwn.php
  realpath: '.../plant/pwn.php'
  file_exists gate: PASS -> include_once fires
  LFI-EXECUTED: arbitrary PHP ran, id=0                     # planted pwn.php executed
```

Over HTTP the request is approximately:

```
POST /ajax/controller.php
X-Requested-With: XMLHttpRequest
Cookie: <any valid session>
Content-Type: application/x-www-form-urlencoded

controller=../../../../../../path/to/planted&action=x
```

## Impact / exploitability

- **Confirmed:** unsanitized attacker-controlled path reaches `include_once`;
  traversal includes & executes an arbitrary local `.php`.
- **RCE** follows if the attacker can write a `.php` file to any path on the
  host (or influence the content of an existing one): e.g. an upload feature
  that stores attacker-named/attacker-content files, or log/session files that
  can be made to contain PHP and happen to end in `.php`. This file-plant
  primitive is **not yet demonstrated** in repomanager and should be confirmed
  on a live install; the `.php` suffix is forced and PHP blocks NUL truncation,
  and `php://filter` is blocked here because `file_exists()` returns false for
  stream wrappers.
- Even without a plant, an authenticated user can force inclusion of arbitrary
  application `.php` files out of their intended control flow.

## Remediation

Do not derive an include path from user input. Map `controller` through a
strict allow-list, or at minimum reject traversal and pin to the directory:

```php
// allow only simple sub-paths like "repo/source/source"
if (!preg_match('#^[A-Za-z0-9_]+(/[A-Za-z0-9_]+)*$#', (string)$controller)) {
    response(HTTP_BAD_REQUEST, 'Bad controller.');
}
$base = realpath(ROOT . '/controllers/ajax');
$target = realpath($base . '/' . $controller . '.php');
if ($target === false || !str_starts_with($target, $base . '/')) {
    response(HTTP_BAD_REQUEST, 'Bad controller.');
}
include_once($target);
```

Also add a CSRF token check to the dispatcher (state-changing AJAX actions are
invoked here without one).

## References
- Source: https://github.com/lbr38/repomanager (`devel` @ `a7bc264`)
- PoC: `security-research/poc/lfi-controller-poc.php`
