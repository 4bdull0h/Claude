# Security research — vulnerability hunting in open-source GitHub projects

Open-ended audit of self-hosted open-source web apps, for **responsible
disclosure** to maintainers. Targets chosen by the auditor; everything here is
source review of public code (one finding also confirmed with a code-level PoC
against a throwaway sandbox), framed for coordinated disclosure (no attacks on
live systems, no weaponized exploits).

## Findings

| # | Project | Finding | Class | Severity | Status |
|---|---------|---------|-------|----------|--------|
| 1 | [`lbr38/repomanager`](https://github.com/lbr38/repomanager) | `dist` parameter path traversal &rarr; arbitrary directory deletion/creation outside repo root | CWE-22 / CWE-23 | Medium–High (authenticated) | **Confirmed (code-level PoC)**, [details](./repomanager-dist-path-traversal.md) |

### Lower-severity observations (same audit)
- repomanager: single-level traversal via `name`/`section`; admin-only SSRF in GPG key import; `rm -rf "$path"` antipattern. See the detailed report.

## Targets audited with no confirmed vulnerability

- **[`error311/FileRise`](https://github.com/error311/FileRise)** — PHP/JS self-hosted file manager (~1k★). Audited path sanitization, archive
  extraction (zip-slip), command exec, OnlyOffice callback SSRF, JWT/HMAC, share
  links, and the public portal flow. Core is well-hardened across every surface
  examined (dedicated path policies, `escapeshellarg` throughout, realpath
  containment, signed tokens + `hash_equals`, SSRF origin pinning, bcrypt +
  rate-limited share passwords). **No confirmable vulnerability found** in the
  code reachable in the repo; Pro features depend on a closed-source bundle not
  present. Recorded as a negative result rather than a manufactured finding.

## Method (reusable)

1. Map the input surface (HTTP entrypoints: ajax/API controllers reading `$_POST`/`$_GET`).
2. Enumerate dangerous sinks: `proc_open`/`exec`/`system`, SQL construction,
   `unlink`/`rm`/`mkdir`/`file_put_contents`, archive extraction, server-side HTTP fetchers.
3. Trace taint from each sink back to a source; at each hop check the validator's
   *actual* character class (not its name) and whether canonicalization/containment exists.
4. Confirm the end-to-end chain before claiming anything; record negative results honestly.

> Reports here are drafts for maintainers. No CVE is "published" by this repo;
> CVE IDs come from the maintainer's coordinated-disclosure process.
