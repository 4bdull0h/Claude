# Security advisory (draft) — Unauthenticated Telegram webhook (missing secret-token verification) in EverShelf

**Project:** [`dadaloop82/EverShelf`](https://github.com/dadaloop82/EverShelf) — self-hosted smart pantry manager
**Version audited:** 1.11.9, `main` @ `8923b468510be592f38eb678035e7e0b2519c2cc` (2026-10-09)
**Class:** CWE-306 (Missing Authentication for Critical Function) → unauthenticated information disclosure
**Impact:** With the (default-empty) `TELEGRAM_ALLOWED_CHAT_IDS`, a remote unauthenticated attacker can POST a forged Telegram update to the public webhook and have the bot send the victim's shopping list / expiring-inventory to an attacker-controlled Telegram chat
**Privilege required:** None (public `telegram_webhook` action)
**Severity:** **Low** — read-only, low-sensitivity personal data; depends on the chat-id allowlist being unset (the default). Honestly flagged as **borderline for a CVE** (may fit better as a maintainer hardening fix). Included for completeness.
**Status:** Confirmed by code review.

---

## Summary

`telegram_webhook` is a public (no-API-token) action. Its handler
`telegramWebhookHandle()` does **not** verify Telegram's
`X-Telegram-Bot-Api-Secret-Token` header (the mechanism Telegram provides so a
server can prove a webhook call really came from Telegram). The only gate is an
**optional** chat-id allowlist, `TELEGRAM_ALLOWED_CHAT_IDS`, which is skipped
entirely when unset — the default:

```php
$allowed = array_filter(array_map('trim', explode(',', (string)env('TELEGRAM_ALLOWED_CHAT_IDS', ''))));
...
$chatId = (string)($msg['chat']['id'] ?? '');
if ($allowed !== [] && !in_array($chatId, $allowed, true)) { /* reject */ }
...
$cmd = strtolower(explode(' ', $text, 2)[0]);
if ($cmd === '/lista' || $cmd === '/list') { $reply = <shopping_list>; }
elseif ($cmd === '/scadenze' || $cmd === '/expiring') { $reply = <expiring inventory>; }
...
telegramApiSend($token, $chatId, $reply);   // sends to the chat_id from the forged update
```

Because the body is attacker-supplied and no Telegram secret is checked, an
attacker who can reach `/api/index.php?action=telegram_webhook` can submit a
crafted update with an arbitrary `message.chat.id` and `text`.

## Exploitation (when `TELEGRAM_ALLOWED_CHAT_IDS` is unset — default)

1. Attacker starts the target's bot in Telegram (public bots are reachable by
   username) to obtain their own `chat_id` and ensure the bot may message them.
2. Attacker POSTs a forged update to the victim's webhook:
   ```
   POST /api/index.php?action=telegram_webhook
   Content-Type: application/json

   {"message":{"chat":{"id":<ATTACKER_CHAT_ID>},"text":"/lista"}}
   ```
3. The server runs `/lista`, queries `shopping_list`, and calls
   `telegramApiSend($token, <ATTACKER_CHAT_ID>, <list>)` — delivering the
   victim's shopping list to the attacker's chat. `/scadenze` likewise leaks the
   expiring-inventory list.

No API token is involved; `telegram_webhook` is in `evershelfPublicActions()`.
The handler is read-only (no write/destructive bot commands), so impact is
confined to disclosure of shopping/inventory data.

## Conditions / limits
- Requires `TELEGRAM_ALLOWED_CHAT_IDS` to be unset (the default). If the operator
  sets it, an attacker must know/guess an allowed numeric chat id.
- Requires Telegram integration enabled (`TELEGRAM_BOT_TOKEN` set).
- Read-only: no data modification; data is low-sensitivity (groceries/expiry).

## Remediation
1. Set a webhook secret and verify it: configure the webhook with Telegram's
   `secret_token` and check `X-Telegram-Bot-Api-Secret-Token` with `hash_equals`
   at the top of `telegramWebhookHandle()`, rejecting mismatches.
2. Treat the chat-id allowlist as defense-in-depth, not the primary auth, and
   consider failing closed (reject) when it is unset rather than allowing all.

## References
- Source: https://github.com/dadaloop82/EverShelf (`main` @ `8923b46`)
- `api/lib/telegram.php` (`telegramWebhookHandle`, `telegramApiSend`), `api/lib/security.php` (`evershelfPublicActions` includes `telegram_webhook`).
