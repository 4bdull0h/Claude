# VulnCheck submission packet — repomanager `dist` path traversal

**How to submit (you do this part — ~30 seconds):**
1. Go to **https://vulncheck.com/advisories/report** (or email **disclosures@vulncheck.com**).
2. Paste the fields below. VulnCheck doesn't require a specific template, but these map to their form.
3. VulnCheck takes over vendor coordination and (per their program) publishes within ~120 days whether or not it's fixed.

> Fill in the two `<...>` placeholders yourself — I deliberately didn't put your
> email/name into an external submission without you choosing to.

---

### Name to be credited
Abdulloh Nuriddinov (GitHub: 4bdull0hh)

### Contact email
abdullohnuriddinov677@gmail.com

### How you came across this
Independent security review of the public source (static audit + a code-level
proof-of-concept). AI-assisted analysis. *(Pick "discovered it yourself" if the
form asks; add "AI-assisted" in the description if you want to be precise.)*

### Supplier / maintainer
lbr38 (repomanager project maintainer) — https://github.com/lbr38/repomanager

### Affected product
**repomanager** — self-hosted deb/rpm package repository manager (PHP).

### Affected versions / environment confirmed
- Version **6.1.0**, `devel` branch, commit `a7bc264fa94b1cc325239d0c854569959ec83d68` (reviewed 2026-10-09).
- Likely affects all versions carrying the same `Param\Dist` validator + `Repo\Metadata` path handling; the maintainer should confirm the earliest affected release.
- Confirmed via code-level PoC on PHP 8.3 (validator + delete sink exercised with the project's own classes). Full live-deployment reproduction still recommended (see Caveat).

### Vulnerability type
CWE-22 / CWE-23 — Improper Limitation of a Pathname to a Restricted Directory (Path Traversal). Authenticated.

### Suggested CVSS 3.1
`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` → Base **8.1 (High)**
*(If the required account is admin-only, use `PR:H` → Base ~6.0 Medium. Maintainer/VulnCheck to confirm the exact privilege.)*

---

### Description (paste into the "describe the vulnerability" box)

repomanager validates the Debian **distribution name (`dist`)** supplied when
creating or rebuilding a repository with a rule that explicitly permits the
characters `.` and `/`, and never rejects the `..` path segment. The value is
then concatenated into filesystem paths with no canonicalization and no
base-directory containment check, and those paths are passed to `rm -rf`,
`mkdir(..., recursive)`, and `apt-ftparchive` output redirection. An
authenticated user who can create/rebuild a deb repository can therefore use
`../` sequences in `dist` to steer these privileged filesystem operations
outside the intended repository root (`REPOS_DIR`, default `/home/repo`). The
most severe consequence is **arbitrary recursive directory deletion** as the
account running repomanager (data destruction / denial of service); secondary
effects are arbitrary directory creation and writing fixed-name metadata files
into traversed locations.

**Root cause (code):**
- `www/controllers/Task/Form/Param/Dist.php` → `Validate::alphaNumeric($dist, ['-','_','.','/'])` — allows `.` and `/`; no `..` check.
- `www/controllers/Repo/Repo.php` → `setDist()` performs no validation.
- `www/controllers/Repo/Metadata/Create.php` → builds `REPOS_DIR/deb/<name>/<dist>/<section>/<date>` and calls `Directory::deleteRecursive()` / `mkdir(recursive)` on it.
- `www/controllers/Repo/Metadata/Deb.php::create()` → deletes `root/dists/<dist>` and runs `apt-ftparchive … > root/dists/<dist>/Release`.
- `www/controllers/Filesystem/Directory.php::deleteRecursive()` → `new Process('/usr/bin/rm -rf "' . $directoryPath . '"')` with no canonicalization/containment.

(Shell *command* injection via `dist` is not possible — the validator blocks spaces, `;`, `` ` ``, `$`, `"` — only the path traversal is reachable.)

### Proof of concept / reproduction

**Code-level PoC (confirmed):** load the project's own `Controllers\Utils\Validate`
and `Controllers\Task\Form\Param\Dist`, then reproduce the `Repo\Metadata\Create`
path build + the `deleteRecursive` `rm -rf "<path>"` form against a sandbox:

```
STEP 1 — real Param\Dist::check():
  ACCEPTED : bookworm
  ACCEPTED : ../../../../../../../../tmp      <- traversal accepted
  ACCEPTED : a/../../../b                      <- traversal accepted
STEP 2 — path build + rm -rf form (REPOS_DIR=<sandbox>/home/repo):
  dist         = ../../../../VICTIM
  snapshotPath = <sandbox>/home/repo/deb/myrepo/../../../../VICTIM/main/<date>
  realpath     = <sandbox>/VICTIM/main/<date>     <- OUTSIDE REPOS_DIR
  rm -rf "<snapshotPath>"  (exit 0)
  canary file  -> DELETED ;  inside REPOS_DIR? NO (escaped)
```

Harness: `security-research/poc/verify.php` (run `php poc/verify.php <repomanager_clone> <empty_sandbox>`).

**Live reproduction (recommended for the vendor):** on a disposable repomanager
install, as a user permitted to create deb repos, submit a repo/task with
`dist = ../../../../../../tmp/CANARY` (point at a throwaway directory you created),
run the build/rebuild, and observe `rm -rf`/`mkdir` hitting the path outside
`REPOS_DIR` in the task log.

### Suggested fix
Validate `dist` as safe path segment(s) — reject `/`, `..`, `.` segments
(`/^[A-Za-z0-9._-]+$/` per segment, no `..`) — and add a `realpath()`-based
containment check under `REPOS_DIR` before every `rm`/`mkdir`/write.
Also harden `Directory::deleteRecursive()` to canonicalize + contain (or stop
shelling out to `rm -rf "$path"`). Same loose validation note applies to
`name`/`section` (single-segment `..`).

### Caveat (state this honestly in the submission)
The validator gap and the traversal reaching the delete sink are confirmed at the
code level with the project's own classes. The live HTTP→sink wiring (that the
create/rebuild request reaches `Metadata\Deb::create()` with attacker `dist`, and
the exact permission required) was not reproduced on a running instance; VulnCheck
and/or the maintainer should confirm that step.

### References
- https://github.com/lbr38/repomanager (source; `devel` @ `a7bc264`)
- Full technical write-up: `security-research/repomanager-dist-path-traversal.md` (this repo/branch)
