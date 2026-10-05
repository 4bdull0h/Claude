# Security advisory (draft) — Path traversal via `dist` parameter in repomanager

**Project:** [`lbr38/repomanager`](https://github.com/lbr38/repomanager) — self-hosted deb/rpm package repository manager
**Branch/commit audited:** `devel` (shallow clone, 2026-10-05)
**Vulnerability class:** CWE-22 / CWE-23 — Improper limitation of a pathname to a restricted directory (path traversal)
**Impact:** Arbitrary recursive directory **deletion**, arbitrary directory **creation**, and controlled-filename file writes **outside the repository root**, executed as the repomanager service account
**Privilege required:** Authenticated user permitted to create / rebuild a Debian repository task
**Status:** Unconfirmed by maintainer — this is a draft for responsible disclosure, not a published CVE.

> ⚠️ This document is for responsible disclosure to the maintainer. It contains no
> ready-to-run exploit payload beyond what is necessary to demonstrate the flaw.
> Do not test against systems you do not own or are not authorized to assess.

---

## Summary

When a Debian repository task is created, the user-supplied **distribution name
(`dist`)** is validated by a rule that explicitly allows the characters `.` and
`/`. The value is then concatenated into multiple filesystem paths with **no
canonicalization and no base-path containment check**, and those paths are passed
to `rm -rf`, `mkdir(..., recursive)`, and `apt-ftparchive` output redirection.

Because `dist` may contain `../` sequences, an authenticated user can steer these
privileged filesystem operations outside the intended `REPOS_DIR` tree
(default `/home/repo`). The most severe concrete consequence is **arbitrary
recursive directory deletion** as the account running repomanager.

Shell *command* injection via `dist` is **not** possible here, because the same
validator rejects spaces, `;`, `` ` ``, `$`, `"`, `(`, `)` — only the path
traversal survives.

---

## Root cause

### 1. The validator permits `.` and `/`

`www/controllers/Task/Form/Param/Dist.php`

```php
public static function check(array $dists) : void
{
    if (empty($dists)) {
        throw new Exception('Distribution name must be specified');
    }
    foreach ($dists as $dist) {
        if (!Validate::alphaNumeric($dist, ['-', '_', '.', '/'])) {   // <-- '.' and '/' allowed
            throw new Exception('Distribution name cannot contain special characters except hyphen, underscore, dot, slash');
        }
    }
}
```

`Validate::alphaNumeric()` (`www/controllers/Utils/Validate.php`) strips the
"additional valid characters" and then runs `ctype_alnum()` on the remainder:

```php
public static function alphaNumeric(string $string, array $additionnalValidCharacters = []) : bool
{
    if (empty($string)) { return true; }
    if (!empty($additionnalValidCharacters)) {
        if (!ctype_alnum(str_replace($additionnalValidCharacters, '', $string))) { return false; }
    } else {
        if (!ctype_alnum($string)) { return false; }
    }
    return true;
}
```

Therefore a value such as `../../../../../../../../tmp/target` validates
successfully: after removing `.`, `/`, `-`, `_` the remainder (`tmptarget`) is
alphanumeric. Crucially there is **no check for the `..` path segment**.

For comparison, the sibling validators are stricter and are **not** affected the
same way:
- `Param\Name` / `Param\Section`: `alphaNumericHyphen(['.'])` — allow `.` but **not** `/` (only a single-segment `..` is possible).
- `Param\Arch`: `alphaNumericHyphen()` — no `.`, no `/`.
- `Param\Releasever` (rpm equivalent of dist): `is_numeric()` — safe.

`dist` is the only build parameter that allows both `.` and `/`, i.e. full
multi-level traversal.

### 2. No re-validation in the setter

`www/controllers/Repo/Repo.php`

```php
public function setDist(string $dist): void { $this->dist = $dist; }   // no validation
```

The task runner maps the raw param straight to this setter
(`www/controllers/Task/Execution.php`, `'dist' => 'setDist'`).

### 3. The value reaches filesystem sinks without containment

`www/controllers/Repo/Metadata/Create.php`

```php
if ($this->repoController->getPackageType() == 'deb') {
    $parentDir    = REPOS_DIR . '/deb/' . $this->repoController->getName()
                               . '/' . $this->repoController->getDist()      // <-- tainted
                               . '/' . $this->repoController->getSection();
    $snapshotPath = $parentDir . '/' . $this->repoController->getDate();
}
...
if (is_dir($snapshotPath)) {
    if (!Directory::deleteRecursive($snapshotPath)) { ... }                  // rm -rf on tainted path
}
if (!is_dir($parentDir)) { mkdir($parentDir, 0770, true); }                  // recursive mkdir on tainted path
```

`www/controllers/Repo/Metadata/Deb.php` (`create()`), the cleanest primitive —
the attacker-controlled `dist` is the **last** component of the deleted path:

```php
$dirs = ['dists', 'dists/' . $this->dist, 'dists/' . $this->dist . '/' . $this->section, 'pool', 'cache'];
foreach ($dirs as $dir) {
    if ($dir == 'pool') { continue; }
    if (is_dir($this->root . '/' . $dir)) {
        if (!Directory::deleteRecursive($this->root . '/' . $dir)) { ... }   // rm -rf ".../dists/<dist>"
    }
}
...
// Release file written via shell output redirection onto a tainted path:
$myprocess = new Process($this->aptftparchive . ' -c ' . $this->root . '/dist.conf release '
    . $this->root . '/dists/' . $this->dist
    . ' > ' . $this->root . '/dists/' . $this->dist . '/Release');
```

### 4. The deletion sink has no symlink/traversal guard

`www/controllers/Filesystem/Directory.php`

```php
public static function deleteRecursive(string $directoryPath) : bool
{
    if (!is_dir($directoryPath)) { return true; }
    $myprocess = new \Controllers\Process('/usr/bin/rm -rf "' . $directoryPath . '"');  // path only quoted, never canonicalized
    $myprocess->execute();
    $myprocess->close();
    ...
}
```

`Controllers\Process` runs the string through `proc_open()`, i.e. `/bin/sh -c`.
The path is wrapped in double quotes, which is why metacharacter injection is not
reachable *for this parameter* — but `../` inside the quotes is still honored by
`rm -rf` when it resolves the path.

---

## Attack path (end to end)

1. Authenticated user submits `POST /ajax/...` → `action=validate-execute` with
   `taskParams` JSON describing a new **deb** repository
   (`www/controllers/ajax/task.php`).
2. `Task\Form\Create::validate()` calls `Param\Dist::check($formParams['dist'])`,
   which accepts a `dist` containing `../` (see §1).
3. The task executes; `Repo\Metadata\Create` / `Repo\Metadata\Deb` build paths
   from `dist` and call `Directory::deleteRecursive()` / `mkdir()` /
   `apt-ftparchive > …` (§3).
4. With, e.g., `dist = ../../../../../../../../tmp/target`, the deletion in
   `Repo\Metadata\Deb::create()` resolves to `rm -rf "<root>/dists/../…/tmp/target"`
   → `/tmp/target` and everything under it is removed, as the repomanager service
   account. In the project's container image that account has broad filesystem
   access, so the blast radius includes repository data and other service-owned
   directories.

(Default `REPOS_DIR` is `/home/repo` — `www/controllers/App/Config/Settings.php`.)

### Impact ranking
- **Primary:** arbitrary recursive directory deletion → data destruction / DoS.
- **Secondary:** arbitrary directory creation; writing fixed-name metadata files
  (`Packages`, `Release`) into traversed locations.

---

## Remediation

Validate `dist` (and, defensively, `section`/`name`) as a **single safe path
segment** and enforce containment at every sink.

1. **Reject path separators and `..` in `Param\Dist::check`** — don't just
   allowlist `/` and `.`:

   ```php
   foreach ($dists as $dist) {
       // allow a normal distribution name only: letters, digits, '-', '_', '.'
       if (!preg_match('/^[A-Za-z0-9._-]+$/', $dist)
           || $dist === '.' || $dist === '..'
           || str_contains($dist, '..')) {
           throw new Exception('Invalid distribution name');
       }
   }
   ```

   If multi-segment dist names are a legitimate feature, split on `/`, validate
   each segment with the rule above, and forbid empty / `.` / `..` segments.

2. **Add a containment check before every filesystem operation.** After building
   a path, resolve it and verify it stays under the intended base:

   ```php
   $base = realpath(REPOS_DIR);
   $target = realpath(dirname($path)) ;              // parent must exist/resolve
   if ($base === false || $target === false || !str_starts_with($target . '/', $base . '/')) {
       throw new Exception('Path escapes repository root');
   }
   ```

3. **Harden `Directory::deleteRecursive()`** — canonicalize and containment-check
   the argument (and ideally use PHP's own recursive delete / `--one-file-system`)
   rather than shelling out to `rm -rf "$path"`.

4. `Validate::string()` is `htmlspecialchars(stripslashes(trim()))` — it is an
   HTML-output encoder, **not** a filesystem/shell sanitizer. Don't rely on it to
   make a value safe for `proc_open`/path use.

---

## Lower-severity observations (same audit)

- **Single-level traversal via `name` / `section`.** `Param\Name` and
  `Param\Section` allow `.` (not `/`), so a segment of `..` is accepted, giving a
  one-level traversal into the same sinks. Fix with the same per-segment rule.
- **Admin-only SSRF in GPG key import.** `Gpg::importFromUrl()` fetches an
  arbitrary user-supplied `http(s)` URL server-side via cURL
  (`www/controllers/Gpg.php`), gated only by `RepoPermission::allowedAction('edit-source')`.
  The host is not restricted, so an operator with that permission can make the
  server issue requests to internal `http(s)` endpoints. Lower severity (requires
  privileged account; response not directly reflected), but worth an allowlist /
  internal-IP block.
- **`rm -rf "$path"` antipattern.** Quoting the path blocks metacharacter
  injection *today* only because the current callers' validators forbid `"`, `$`
  and backtick. It is one loose validator away from command injection; prefer a
  non-shell delete or `escapeshellarg()` as defense in depth.

---

## Suggested disclosure process

The repository has **no `SECURITY.md`**. Recommended path:
1. Open a **private** GitHub Security Advisory via the repo's *Security →
   “Report a vulnerability”* tab (GitHub private vulnerability reporting), or
   email the maintainer directly. Do **not** open a public issue first.
2. Offer the maintainer a ~90-day coordinated-disclosure window and a patch
   (the §Remediation changes are small and self-contained).
3. Request a CVE via GitHub's advisory flow once a fix is scheduled.

---

### Audit scope note
This review was source-only (static) against a shallow `devel` clone; it was
**not** validated against a running instance. Before publishing, confirm the
end-to-end behavior on a disposable test deployment (create a deb repo task with a
traversing `dist` pointing at a throwaway directory and observe the resolved
`rm -rf` / `mkdir` target in the task log).
