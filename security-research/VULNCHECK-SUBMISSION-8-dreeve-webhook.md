# VulnCheck submission packet #8 — dreeve unauthenticated Strava webhook forgery → activity deletion

Submit at **https://vulncheck.com/advisories/report** (or **disclosures@vulncheck.com**).

### Name to be credited
Abdulloh Nuriddinov (GitHub: 4bdull0hh)

### Contact email
abdullohnuriddinov677@gmail.com

### How you came across this
Independent source review (AI-assisted).

### Supplier / maintainer
Robin Ingelbrecht (robiningelbrecht) — https://github.com/dreeveapp/dreeve

### Affected product
**dreeve** (composer `robiningelbrecht/dreeve`) — self-hosted Strava statistics dashboard (Symfony, PHP 8.5).

### Affected versions / environment confirmed
`master` @ `745074da2ac4aa32d1a68571e90230ddcd82f0c6` (2026-10-13); latest release at review time **v5.5.0**. Maintainer to confirm earliest affected release.

### Vulnerability type
CWE-306 (Missing Authentication for Critical Function) + CWE-345 (Insufficient Verification of Data Authenticity) — spoofable webhook performing destructive actions.

### Authentication
Unauthenticated.

### Suggested CVSS 3.1
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` → ~**9.1** (contingent on webhooks being enabled; a conservative `…/I:H/A:L` ≈ 8.2). Maintainer/VulnCheck to finalize.

### Description
dreeve's Strava webhook endpoint `POST /strava/webhook` is public
(`AppAccessMap::PUBLIC_PATHS`) and its event handler performs **no origin
verification**: it does not check Strava's `verify_token` (that only guards the GET
`hub.challenge` subscription handshake), ignores the event's `owner_id`/
`subscription_id`, and Strava webhooks are unsigned. The only gate is a global
"webhooks enabled" flag. An unauthenticated attacker can POST forged events with an
attacker-chosen `object_id` and `aspect_type`.

A forged `{"object_type":"activity","aspect_type":"delete","object_id":<id>}` is
queued as a `WebhookEvent`, then the `app:strava:webhooks-process` cron routes the
`delete` aspect to `ActivityRepository::markActivitiesForDeletion()`
(`UPDATE Activity SET markedForDeletion=1 WHERE activityId IN (...)`), after which
`DeleteActivitiesMarkedForDeletionCommandHandler` hard-deletes them via
`DeleteActivity`. Result: **unauthenticated permanent deletion of arbitrary
activities**. Forged `create`/`update` events force Strava-API re-imports of
attacker-chosen IDs (API-quota/DoS abuse).

dreeve's dashboard is public by default, so the attacker can enumerate the victim's
real activity IDs from `/activities/{activityId}` and delete the entire history.

### Proof of concept
With webhooks enabled and Strava-API import mode (the live-sync setup), unauthenticated:
```
POST /strava/webhook
Content-Type: application/json

{"object_type":"activity","object_id":<victim_activity_id>,"aspect_type":"delete",
 "owner_id":1,"subscription_id":1,"event_time":1700000000}
```
On the next `app:strava:webhooks-process` run the activity is marked for deletion and
then permanently deleted. Repeat across IDs harvested from the public dashboard to
wipe the victim's history. (`create`/`update` instead force re-imports.)

### Suggested fix
Require a per-instance shared secret on the webhook URL (unguessable path segment or
header), validated on POST with `hash_equals`; verify `owner_id`/`subscription_id`
against the configured athlete/subscription; ignore `object_id`s never imported for
this athlete; rate-limit.

### Caveat (stated honestly)
Full chain confirmed by code review with exact file/line citations; not reproduced on
a live instance (needs PHP 8.5 + DB + the processing cron, not available here).
Requires webhooks enabled + Strava-API mode (opt-in but a documented first-class
feature); environmental score may vary. No confidentiality impact.

### References
- https://github.com/dreeveapp/dreeve (`master` @ `745074d`) — `StravaWebhookRequestHandler.php`, `AppAccessMap.php`, `ProcessWebhookEventCommandHandler.php`, `ProcessStravaWebhooksConsoleCommand.php`, `DbalActivityRepository.php`, `DeleteActivitiesMarkedForDeletionCommandHandler.php`
- Full write-up: `security-research/dreeve-unauth-webhook-activity-deletion.md`
