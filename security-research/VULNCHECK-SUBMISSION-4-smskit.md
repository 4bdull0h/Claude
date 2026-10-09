# VulnCheck submission packet #4 — smskit unauthenticated SMS interception

Submit at **https://vulncheck.com/advisories/report** (or **disclosures@vulncheck.com**).
Fill the two `<...>` placeholders.

### Name to be credited
`<your name or pseudonym — or blank>`

### Contact email
`<your contact email>`

### How you came across this
Independent source review + runtime PoC (AI-assisted).

### Supplier / maintainer
smskit — https://github.com/smskit/smskit

### Affected product
**smskit** — self-hosted SMS gateway (PHP flat-file backend, Android relay app, REST API).

### Affected versions / environment confirmed
Version **1.0.0**, `main` @ `69e4ed82e62b5dde1647fc5e0187827a0e164284` (reviewed + runtime-tested 2026-10-09, PHP 8.3). Maintainer to confirm range.

### Vulnerability type
CWE-306 (Missing Authentication for Critical Function) + CWE-200 (Information Exposure). Unauthenticated.

### Suggested CVSS 3.1
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L` → ~**8.2 High** (unauth confidentiality breach of OTP/2FA traffic, plus message diversion/denial of delivery and forged inbound/reports). Maintainer/VulnCheck to finalize.

### Description
The Android-relay poll endpoint `api/v1/poll.php` requires **no authentication**.
A device is identified only by a caller-supplied `device_id` query parameter —
there is no device token or shared secret. On each poll the endpoint
auto-registers the supplied `device_id` as an `online` device in
`config/device_tokens.json`, assigns `queued` outbound messages to online devices
(round-robin sorted by `sms_sent_count` ascending, so a freshly registered device
sorts first), and returns the recipient number (`to`) and full body (`message`) of
queued items for that device, marking them `processing`.

Consequently an unauthenticated remote attacker can poll the endpoint with an
arbitrary `device_id` and receive the gateway's queued outbound SMS — typically
OTPs, 2FA codes and password-reset links — while simultaneously diverting them
from legitimate delivery (the messages are marked `processing` for the attacker's
fake device and never sent by the real relay). `api/v1/receive.php` and
`api/v1/report.php` are unauthenticated in the same way (forged inbound SMS /
forged delivery reports). The operator endpoints (`send`, `status`, `validate`,
`statistics`, `schedule`) do require an API key via `api/v1/_auth.php`; the device
channel has no equivalent.

### Proof of concept (runtime-confirmed)
Queued message in `config/sms_queue.json` (as `send.php` would create):
```json
{"queue":[{"id":"m1_1","message_id":"m1","to":"+15551234567",
 "message":"Your bank OTP is 918273. Do not share it.",
 "status":"queued","assigned_device":null,"source":"api"}]}
```
Attacker request (no API key):
```
GET /api/v1/poll.php?device_id=attacker-123&model=Evil&android=99
```
Response (HTTP 200):
```json
{"ok":true,"commands":[{"id":"m1_1","to":"+15551234567",
 "message":"Your bank OTP is 918273. Do not share it."}],"timestamp":"..."}
```
Reproduced locally with PHP's built-in server against a copy of `api/v1/` plus a
seeded `config/`.

### Suggested fix
Issue a per-device secret token at pairing (store hashed like the API keys), and
require it on `poll`/`receive`/`report` with a `hash_equals` check; stop
auto-registering unknown devices; or require the existing API key on the device
endpoints too.

### Caveat
Confirmed at runtime for the disclosure + queue-diversion behavior. Exact
real-world interception completeness depends on how many legitimate devices are
online (the attacker's zero-count device sorts first and can be registered many
times to dominate assignment); the unauthenticated disclosure itself is
unconditional.

### References
- https://github.com/smskit/smskit (`main` @ `69e4ed8`)
- Full write-up: `security-research/smskit-poll-unauth-sms-interception.md`
