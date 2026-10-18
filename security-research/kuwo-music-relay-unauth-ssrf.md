# kuwo-music-relay — unauthenticated, full-read Server-Side Request Forgery

- **Project:** [`cdyUuu/kuwo-music-relay`](https://github.com/cdyUuu/kuwo-music-relay) — single-file PHP "relay" that fetches an encrypted Kuwo Music file over HTTP, decrypts it, and streams it to a player.
- **File:** `decrypt.php` (entire app is one file).
- **Version / commit reviewed + tested:** `RELAY_VERSION = '1.0.0'`, `main` @ `90f76911dc977bf729a8b0bb18118d4ce4c5adb8` (committed 2026-08-19), PHP 8.3.
- **Class:** CWE-918 (Server-Side Request Forgery). Unauthenticated.
- **Severity:** High. Suggested CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L` → **8.2**.

## Summary

`decrypt.php` takes two **unauthenticated** query parameters — `url` and `ekey` —
and has the server issue HTTP(S) requests to `url` with cURL, then returns the
response body to the caller after a reversible transform. There is **no
authentication**, **no destination allow-list**, and the only SSRF guard in the
code is **disabled by the shipped default configuration**. An unauthenticated
remote attacker can therefore make the server request arbitrary internal/cloud
endpoints (e.g. `http://169.254.169.254/…`, `http://127.0.0.1:…`, internal admin
APIs) and — because the decryption is a keystream XOR keyed entirely by the
attacker-supplied `ekey` — **recover the fetched response bytes verbatim**. That
makes this a *readable* SSRF, not a blind one.

The README advertises **"SSRF protection — blocks requests to private/reserved IP
ranges"** as a feature, and instructs users to deploy the file as-is ("just
upload `decrypt.php` to any PHP server"). The default build does not have that
protection active.

## Root cause

### 1. The only SSRF guard is off by default

```php
// line 42
define('RELAY_ALLOW_PRIVATE_IP', true);   // Allow private/reserved IPs (set true for local/LAN use)
```

The host check is gated on this flag being **false**:

```php
// handle(), lines ~947-957
if (!RELAY_ALLOW_PRIVATE_IP) {
    $urlHost = parse_url($url, PHP_URL_HOST);
    if ($urlHost && !$this->isSafeRemoteHost($urlHost)) {
        http_response_code(403);
        echo 'Access denied: target host resolves to a private or reserved address.';
        return;
    }
}
```

Because the shipped default is `true`, the whole block is skipped. Every public
deployment of the unmodified file has **no** SSRF protection. The only other
input validation is a scheme check (`http`/`https` only) and an `ekey` length
check (50–4096 chars) — neither constrains the destination host.

There is **no allow-list** tying `url` to Kuwo's CDN domains anywhere in the
file; `url` is fully attacker-controlled.

### 2. Even with the guard enabled, it is bypassable

Should an operator set `RELAY_ALLOW_PRIVATE_IP = false`, two standard bypasses remain:

- **Redirect following.** Every cURL handle sets `CURLOPT_FOLLOWLOCATION => true`
  (in `probeRemoteFile`, `getRemoteFileSize`, `streamDownloadAndDecrypt`,
  `streamRangeFromCDN`) and the redirect target is **never re-validated**. The
  host check runs once against the *original* `url`. An attacker hosts a public
  URL that returns `302 Location: http://169.254.169.254/latest/meta-data/…`;
  cURL transparently follows it to the internal address.
- **DNS-rebinding TOCTOU.** `isSafeRemoteHost()` resolves the hostname with
  `gethostbynamel()` and checks the result, then cURL resolves the name again
  independently when it connects. An attacker-controlled name that returns a
  public IP to the check and a private IP to cURL (short-TTL rebinding) passes.
  Also note `isSafeRemoteHost()` returns **`true` (allow)** when the name fails
  to resolve at check time.

### 3. The response is readable (keystream XOR keyed by attacker input)

The fetched bytes are passed through `QmcCipherInterface::decrypt($data, $offset)`
and echoed to the caller. Both implementations are additive keystream ciphers:

- `MapCipher::decrypt()` → `return $data ^ $keystream;`
- `Rc4Cipher::decrypt()` → builds a keystream and XORs it into the data.

The keystream is derived **solely** from `ekey` (`QmcKeyDerivation::createCipherFromEkey($ekey)`),
which the attacker supplies. So the attacker knows the exact keystream and can
invert the transform:

```
server_output = fetched_bytes XOR keystream(ekey, offset)
fetched_bytes = server_output XOR keystream(ekey, offset)
```

i.e. the attacker recovers the internal response in cleartext. This elevates the
bug from a blind SSRF to a full-read SSRF (cloud-metadata credentials, internal
API JSON, etc.).

## Impact

- Unauthenticated SSRF against any host reachable from the server, including the
  loopback interface, RFC1918 ranges, link-local `169.254.169.254` cloud metadata,
  and internal-only services.
- **Readable**: the attacker recovers the fetched response body verbatim via the
  attacker-known keystream — so cloud IAM credentials, internal API responses,
  and other secrets are exfiltrable, not merely pingable.
- Works on the default build (guard off); on a hardened build it remains
  reachable via open-redirect and DNS-rebinding.
- Secondary: outbound request laundering / port-and-host probing (timing and
  error differences), and the server attaches a spoofable browser `User-Agent` +
  `Referer: https://www.kuwo.cn/` to the forged requests.

## Proof of concept

### Part A — the SSRF request fires (runtime-confirmed)

Unmodified `decrypt.php` served with `php -S`; a throwaway "internal" service on
`127.0.0.1:9999` logs inbound hits. No authentication, no cache primed.

```
GET /decrypt.php?url=http://127.0.0.1:9999/latest/meta-data/iam/&ekey=<120 chars>
Range: bytes=0-63
```

Observed on the internal service:

```
HIT from 127.0.0.1  UA=Mozilla/5.0 (Windows NT 10.0; Win64; x64) … Chrome/120 …  PATH=/latest/meta-data/iam/
```

The `User-Agent` is the relay's hard-coded `getCdnHeaders()` string — proving the
**relay** made the request, not the client. (The request path reaches the CDN
fetch via `streamRangeFromCDN → getRemoteFileSize($url)`, which runs before `ekey`
is even validated — so the forged request fires regardless of `ekey` validity.)

### Part B — the response is recoverable (cipher property)

Both QMC ciphers are keystream-XOR, and the keystream comes only from `ekey`
(attacker input). Harness using the project's own `MapCipher`/`Rc4Cipher`:

```
server_output = cipher->decrypt(fetched, offset)         // what the relay returns
keystream     = cipher->decrypt("\0" x len, offset)      // attacker reproduces it from ekey
recovered     = server_output XOR keystream
```

Result:

```
[MapCipher] recovered === fetched ? YES
        recovered plaintext: INTERNAL-SECRET: aws_key=AKIA_PRETEND_1234567890 (should never leak)
[Rc4Cipher] recovered === fetched ? YES
        recovered plaintext: INTERNAL-SECRET: aws_key=AKIA_PRETEND_1234567890 (should never leak)
```

PoC files in this repo: `poc/kuwo-ssrf-request-poc.sh` (Part A, with
`poc/kuwo-internal-server.php`) and `poc/kuwo-ssrf-readability.php` (Part B).

## Suggested fix

1. **Flip the insecure default:** ship `RELAY_ALLOW_PRIVATE_IP = false`.
2. **Allow-list destinations** to Kuwo CDN domains (the only legitimate targets),
   validated after each redirect hop — not just the initial URL.
3. **Re-validate on redirects:** disable `CURLOPT_FOLLOWLOCATION` (or set
   `CURLOPT_REDIR_PROTOCOLS` + a per-hop open-socket callback) and re-run the
   host check on every `Location`.
4. **Defeat DNS rebinding:** resolve once, reject if any resolved IP is
   private/reserved, and pin the connection to the vetted IP
   (`CURLOPT_RESOLVE` / `CURLOPT_OPENSOCKETFUNCTION`); treat unresolvable hosts
   as **deny**, not allow.
5. Consider requiring a shared secret, since a public, unauthenticated
   URL-fetcher is an open proxy by design.

(`flatbb`'s `core/links.php` in this same research set is a good reference
implementation of a rebinding-aware SSRF defense.)

## Caveat (stated honestly)

- Part A (the forged request reaching an attacker-chosen internal host) is
  confirmed at runtime on the unmodified file with default config.
- Part B (readability) is proven as a property of the project's own cipher
  classes; combined with attacker control of `ekey`, the fetched bytes are
  recoverable. A fully end-to-end "read AWS metadata through the relay with a
  real Kuwo `ekey`" chain was not run against a live cloud instance — but neither
  the SSRF nor the XOR-invertibility depends on a specific `ekey`.
- The redirect-follow and DNS-rebinding bypasses (for the non-default hardened
  config) are identified from the code; they are standard and were not separately
  scripted here.

## References

- Source: https://github.com/cdyUuu/kuwo-music-relay (`main` @ `90f7691`)
- `decrypt.php` lines: 42 (default flag), ~939-966 (scheme/guard/ekey checks),
  ~1232-1270 (`isSafeRemoteHost`/`isPublicIp`), 1373/1396/1428/1470/1489/1759/2085
  (`CURLOPT_FOLLOWLOCATION => true`), ~594-606 (`MapCipher::decrypt`), ~750-799
  (`Rc4Cipher::decrypt`), ~535-540 (`createCipherFromEkey`).
