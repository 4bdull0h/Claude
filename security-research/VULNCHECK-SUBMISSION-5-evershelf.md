# VulnCheck submission packet #5 — EverShelf unauthenticated Telegram webhook

> ⚠️ **Borderline / Low severity.** Read-only, low-sensitivity data, config-dependent
> (default `TELEGRAM_ALLOWED_CHAT_IDS` empty). This may be better handled as a direct
> maintainer hardening fix than a CVE. Submit only if you want it on record; the
> repomanager (#1/#2), iNetPanel (#3) and smskit (#4) findings are the strong ones.

Submit at **https://vulncheck.com/advisories/report** (or **disclosures@vulncheck.com**). Fill the two `<...>` placeholders.

### Name to be credited
Abdulloh Nuriddinov (GitHub: 4bdull0hh)

### Contact email
abdullohnuriddinov677@gmail.com

### How you came across this
Independent source review (AI-assisted).

### Supplier / maintainer
dadaloop82 — https://github.com/dadaloop82/EverShelf

### Affected product
**EverShelf** — self-hosted smart pantry manager (PHP).

### Affected versions / environment confirmed
Version **1.11.9**, `main` @ `8923b468510be592f38eb678035e7e0b2519c2cc` (reviewed 2026-10-09).

### Vulnerability type
CWE-306 (Missing Authentication for Critical Function) → unauthenticated information disclosure.

### Suggested CVSS 3.1
`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → ~5.3 (Medium) in the worst default config; practically Low given data sensitivity. Maintainer/VulnCheck to finalize.

### Description
EverShelf's `telegram_webhook` action (public — listed in `evershelfPublicActions()`)
does not verify Telegram's `X-Telegram-Bot-Api-Secret-Token`. The only gate in
`telegramWebhookHandle()` is the optional `TELEGRAM_ALLOWED_CHAT_IDS` allowlist,
which is skipped when unset (the default). An unauthenticated attacker can POST a
forged Telegram update with an attacker-controlled `message.chat.id` and `text`;
the handler runs read-only bot commands (`/lista`, `/scadenze`) and calls
`telegramApiSend($token, $chatId, $reply)`, delivering the victim's shopping list
and expiring-inventory list to the attacker's Telegram chat.

### Proof of concept
With `TELEGRAM_ALLOWED_CHAT_IDS` unset and Telegram enabled, after starting the
bot to obtain `<ATTACKER_CHAT_ID>`:
```
POST /api/index.php?action=telegram_webhook
Content-Type: application/json

{"message":{"chat":{"id":<ATTACKER_CHAT_ID>},"text":"/lista"}}
```
The bot DMs the victim's shopping list to the attacker's chat.

### Limits
Requires the allowlist to be unset (default) or a known allowed chat id; Telegram
integration enabled; read-only (no modification); low-sensitivity data.

### Suggested fix
Verify a configured webhook `secret_token` via `X-Telegram-Bot-Api-Secret-Token`
(`hash_equals`) at the start of the handler; fail closed when the chat-id
allowlist is unset.

### Caveat
Confirmed by code review; not run live. Impact is modest and config-dependent — see the severity note at top.

### References
- https://github.com/dadaloop82/EverShelf (`main` @ `8923b46`)
- Full write-up: `security-research/evershelf-telegram-webhook-unauth.md`
