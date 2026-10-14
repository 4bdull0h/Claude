# VulnCheck submission packet #2 — repomanager `controller` PHP file inclusion

Submit at **https://vulncheck.com/advisories/report** (or **disclosures@vulncheck.com**).
Fill the two `<...>` placeholders.

### Name to be credited
Abdulloh Nuriddinov (GitHub: 4bdull0hh)

### Contact email
abdullohnuriddinov677@gmail.com

### How you came across this
Independent source review + code-level PoC (AI-assisted).

### Supplier / maintainer
lbr38 — https://github.com/lbr38/repomanager

### Affected product
**repomanager** — self-hosted deb/rpm package repository manager (PHP).

### Affected versions / environment confirmed
Version **6.1.0**, `devel` @ `a7bc264fa94b1cc325239d0c854569959ec83d68` (reviewed 2026-10-09; PHP 8.3). Maintainer to confirm earliest affected release.

### Vulnerability type
CWE-98 (Improper Control of Filename for Include/Require Statement) / CWE-22 (Path Traversal). Authenticated.

### Suggested CVSS 3.1
- If a `.php` file-plant primitive exists (→ RCE): `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` → ~**7.5 High** (AC:H because it depends on a plantable path).
- Inclusion of arbitrary local `.php` only: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L` → ~**7.1 High**.
- Maintainer/VulnCheck to finalize once the plant primitive is assessed.

### Description
repomanager's AJAX dispatcher (`controllers/public/ajax/controller.php`, served
as `/ajax/controller.php`) builds the path of a PHP file to `include_once()` by
concatenating the **raw, unsanitized** `controller` POST parameter:

```php
$controller = $_POST['controller'];
if (!file_exists(ROOT . '/controllers/ajax/' . $controller . '.php')) { ... 'Bad controller'; }
include_once(ROOT . '/controllers/ajax/' . $controller . '.php');
```

No check for `../`, absolute paths, or a basename allow-list. An authenticated
user can traverse out of `controllers/ajax/` and include **any existing `.php`
file on the host** (a `.php` suffix is forced; a `file_exists()` gate applies).
This yields remote code execution when combined with any writable `.php` path
(e.g. an upload or log-poisoning primitive).

Authentication: `App\Main()` → `Session::load()` only requires a valid session
(redirects unauthenticated requests to `/logout`); it enforces **no role**, so
any logged-in user — including read-only — reaches the vulnerable `include`,
before any per-action permission check. The dispatcher also performs **no CSRF
check**.

### Proof of concept
`security-research/poc/lfi-controller-poc.php` reproduces the dispatcher's
include line exactly:

```
php poc/lfi-controller-poc.php "../../../plant/pwn"
  -> include target: .../controllers/ajax/../../../plant/pwn.php
  -> realpath: .../plant/pwn.php ; file_exists PASS ; include fires
  -> "LFI-EXECUTED: arbitrary PHP ran, id=0"   (planted pwn.php executed)
```

HTTP form:
```
POST /ajax/controller.php
X-Requested-With: XMLHttpRequest
Cookie: <any valid session>

controller=../../../../../../path/to/planted&action=x
```

### Suggested fix
Allow-list the controller name (`^[A-Za-z0-9_]+(/[A-Za-z0-9_]+)*$`) and
`realpath()`-contain the resolved path under `controllers/ajax/` before
including; add a CSRF token check to the dispatcher. (See the full write-up.)

### Caveat (state honestly)
The unsanitized include and traversal-to-execute are confirmed via PoC of the
dispatcher's exact logic. End-to-end RCE requires a `.php` file-plant primitive
on the host, which was not demonstrated; the maintainer/VulnCheck should assess
upload/log paths. Even absent that, arbitrary local `.php` inclusion by an
authenticated low-privilege user is the confirmed impact.

### References
- https://github.com/lbr38/repomanager (`devel` @ `a7bc264`)
- Full write-up: `security-research/repomanager-lfi-controller.md`
