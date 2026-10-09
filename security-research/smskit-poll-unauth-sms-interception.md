# Security advisory (draft) — Unauthenticated outbound-SMS interception in smskit

**Project:** [`smskit/smskit`](https://github.com/smskit/smskit) — self-hosted SMS gateway (PHP flat-file backend, Android relay, REST API)
**Version audited:** 1.0.0, `main` @ `69e4ed82e62b5dde1647fc5e0187827a0e164284` (2026-10-09)
**Class:** CWE-306 (Missing Authentication for Critical Function) + CWE-200 (Exposure of Sensitive Information)
**Impact:** A remote, unauthenticated attacker can read queued outbound SMS (recipient numbers + message bodies — commonly OTPs / 2FA codes / password-reset links) and divert them from legitimate delivery (interception + denial of delivery)
**Privilege required:** None (no API key, no device token)
**Status:** **Confirmed at runtime** against a seeded local instance.

---

## Summary

The Android-relay poll endpoint `api/v1/poll.php` performs **no authentication**.
A device is identified solely by a caller-supplied `device_id` query parameter;
there is no shared secret or device token anywhere in the flow. On each poll the
endpoint:

1. **Auto-registers** the supplied `device_id` into `config/device_tokens.json`
   as an `online` device — no pairing, no approval, no token.
2. Assigns `queued` outbound messages to the online devices (round-robin, sorted
   by `sms_sent_count` ascending — so a freshly registered device sorts **first**).
3. Returns, as `commands`, the `to` (recipient number) and `message` (full body)
   of every queued item assigned to (or still unassigned for) that `device_id`,
   and marks them `processing`.

Because a brand-new `device_id` is trusted immediately and sorts first for
assignment, any attacker who can reach the endpoint receives the gateway's queued
outbound SMS — and, by marking them `processing`/assigning them to the attacker's
fake device, prevents the real device(s) from ever sending them.

`api/v1/receive.php` and `api/v1/report.php` are likewise unauthenticated
(identified only by `device_id`), so an attacker can also inject forged inbound
SMS and forge delivery reports. By contrast, the operator-facing endpoints
(`send`, `status`, `validate`, `statistics`, `schedule`) do require an API key via
`api/v1/_auth.php` — the device channel simply has no equivalent.

## Proof of concept (runtime-confirmed)

Seed a gateway with one queued message (as `POST /api/v1/send.php` would create):

```json
// config/sms_queue.json
{"queue":[{"id":"m1_1","message_id":"m1","to":"+15551234567",
  "message":"Your bank OTP is 918273. Do not share it.",
  "status":"queued","assigned_device":null,"source":"api"}]}
```

Attacker request — **no API key**, arbitrary `device_id`:

```
GET /api/v1/poll.php?device_id=attacker-123&model=Evil&android=99
```

Response (HTTP 200):

```json
{
  "ok": true,
  "commands": [
    {"id":"m1_1","to":"+15551234567","message":"Your bank OTP is 918273. Do not share it."}
  ],
  "timestamp": "..."
}
```

The queued message (recipient + body) is disclosed to the unauthenticated caller
and marked `processing` (removed from legitimate delivery). Reproduced locally with
PHP's built-in server against a copy of `api/v1/` + a seeded `config/`.

### Impact
- **OTP / 2FA / password-reset interception:** SMS gateways predominantly carry
  one-time codes. An attacker polling the gateway harvests them in cleartext.
- **Denial of delivery:** diverted messages are marked `processing` for the
  attacker's fake device and never sent by the real relay.
- **Recipient/metadata disclosure:** destination numbers and message content of
  all queued traffic.
- Secondary (receive/report): forged inbound SMS and forged delivery status.

## Remediation

Authenticate the device channel with a per-device secret, not a guessable
identifier:

1. Issue a random **device token** at pairing (stored hashed, like the API keys in
   `_auth.php`), and require it on `poll`, `receive`, and `report` — compare with
   `hash_equals`. Reject unknown devices instead of auto-registering them.
2. Do not auto-create a device from an unauthenticated poll; require an operator
   to approve/pair a device first.
3. Consider requiring an API key (the existing `_auth.php`) on the device
   endpoints as well, or a separate device-token guard shared by all three.

Until fixed, operators must keep the gateway off any untrusted network — but the
endpoint offers no authentication option at all, so network isolation is the only
mitigation.

## References
- Source: https://github.com/smskit/smskit (`main` @ `69e4ed8`)
- `api/v1/poll.php` (no auth; auto-register; returns queued `to`/`message`), `api/v1/receive.php`, `api/v1/report.php`; contrast `api/v1/_auth.php` (API-key guard used by the operator endpoints).
