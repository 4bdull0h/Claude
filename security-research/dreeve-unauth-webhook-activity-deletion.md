# dreeve — unauthenticated Strava webhook forgery → arbitrary activity deletion / forced re-import

- **Project:** [`dreeveapp/dreeve`](https://github.com/dreeveapp/dreeve) (composer `robiningelbrecht/dreeve`) — self-hosted Strava statistics dashboard (Symfony, PHP 8.5), ~2.1k★. Formerly "Statistics for Strava".
- **Commit reviewed:** `master` @ `745074da2ac4aa32d1a68571e90230ddcd82f0c6` (2026-10-13); latest release at review time **v5.5.0**. Maintainer to confirm earliest affected release.
- **Class:** CWE-306 (Missing Authentication for Critical Function) + CWE-345 (Insufficient Verification of Data Authenticity) — a spoofable webhook that performs destructive actions.
- **Auth:** **Unauthenticated.**
- **Severity:** High/Critical. Suggested CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` → **9.1** (contingent on webhooks enabled — see Preconditions; a conservative `…/I:H/A:L` is ~8.2).

## Summary

dreeve exposes a public Strava webhook endpoint, `POST /strava/webhook`. The POST
(event) handler performs **no authentication and no origin verification whatsoever**:
it does not check Strava's `verify_token` (that only guards the GET subscription
handshake), nor the event's `owner_id`/`subscription_id`, and Strava webhooks carry
no signature. The only gate is a global "webhooks enabled" flag. Any unauthenticated
party who can reach the endpoint can therefore inject forged Strava events with
attacker-chosen `object_id` and `aspect_type`.

Forged `delete` events flow — via a queued `WebhookEvent` and the
`app:strava:webhooks-process` cron — into `markActivitiesForDeletion()` and then a
hard `DeleteActivity`. So an unauthenticated attacker can **permanently delete
arbitrary activities** from the victim's dreeve instance. Forged `create`/`update`
events force Strava-API re-imports of attacker-chosen IDs (resource/API-quota abuse).
Because the dashboard is public by default, the attacker can first **enumerate the
victim's real activity IDs** from `/activities/{activityId}` and then delete the
victim's entire activity history.

## The endpoint is public and unverified

`src/Infrastructure/Security/AppAccessMap.php` lists `/strava/webhook` in
`PUBLIC_PATHS`, so it bypasses the app's `requiresAuthentication` gate (correctly —
Strava's servers have no session). The POST handler,
`src/Controller/Strava/StravaWebhookRequestHandler.php::handleEvent()`:

```php
public function handleEvent(Request $request): Response
{
    if (!$this->settingsRepository->import()->getWebhookConfig()->isEnabled()) {
        return new JsonResponse('Webhooks are not enabled', Response::HTTP_NOT_FOUND);
    }
    $payload = Json::decode($request->getContent());
    $this->commandBus->dispatch(new ProcessWebhookEvent($payload));   // no verification
    return new Response('', Response::HTTP_OK);
}
```

- `verify_token` is checked **only** in `handleValidation()` (the GET `hub.challenge`
  handshake), never on POST.
- `owner_id` / `subscription_id` present in real Strava events are ignored.
- Strava webhook deliveries are **not signed**, so there is no HMAC to verify; a
  correct implementation must instead require a per-instance shared secret (e.g. a
  secret path segment or header) — dreeve requires nothing.

A `grep` across `src/Domain/Strava/Webhook` and `src/Controller/Strava` finds no
`owner_id`, `subscription_id`, `signature`, or `hmac` check anywhere.

## Destructive sink chain (forged `delete`)

1. `ProcessWebhookEventCommandHandler` stores the event verbatim:
   ```php
   $this->webhookEventRepository->add(WebhookEvent::create(
       objectId: (string) $payload['object_id'],      // attacker-controlled
       objectType: $payload['object_type'],           // 'activity'
       aspectType: $aspectType,                        // 'delete'
       payload: $payload,
   ));
   ```
2. Cron `app:strava:webhooks-process`
   (`src/Console/Strava/ProcessStravaWebhooksConsoleCommand.php`) grabs queued events:
   ```php
   if (WebhookAspectType::DELETE === $webhookEvent->getAspectType()) {
       $activityIdsToDelete->add(ActivityId::fromUnprefixed($webhookEvent->getObjectId()));
   }
   ...
   $this->activityRepository->markActivitiesForDeletion($activityIdsToDelete);
   ```
3. `DbalActivityRepository::markActivitiesForDeletion()`:
   `UPDATE Activity SET markedForDeletion = 1 WHERE activityId IN (:activityIds)`.
4. `DeleteActivitiesMarkedForDeletionCommandHandler` (part of the import run) reads
   `findMarkedForDeletion()` and dispatches `DeleteActivity($activityId)` for each →
   **permanent deletion**.

Forged `create`/`update` events take the other branch and are passed as
`--restrict-to-activity-ids` to `RunStravaImportConsoleCommand`, forcing Strava-API
fetches for attacker-chosen IDs (repeatable → API-quota exhaustion / DoS).

## Activity-ID enumeration (makes targeting trivial)

dreeve's dashboard is public by default (only `/admin` and `/api/v1` are
access-controlled; `requiresAuthentication` is opt-in). Activity detail pages live at
`/activities/{activityId}` and internal data at
`/api/internal/activities/{activityId}/…`, so an unauthenticated attacker can harvest
the victim's real activity IDs and then delete every one of them via forged `delete`
events. Even without the dashboard, Strava activity IDs are numeric and can be ranged.

## Preconditions (stated honestly)

- **Webhooks enabled** (`import.webhookConfig.enabled = true`). This is an opt-in but
  first-class, documented feature: users enable it for live Strava→dreeve sync, and
  the endpoint must be internet-reachable for Strava to call it.
- **Import mode = Strava API** (`ImportMode::isStravaApi()`), the default/primary mode
  (the alternative is file-import mode). The processing cron no-ops otherwise.
- The webhook URL path (`/strava/webhook`) is fixed and public; no secret segment.

## Impact

- Unauthenticated **permanent deletion** of arbitrary / all of the victim's imported
  activities (integrity + availability of the user's data history).
- Unauthenticated forced re-imports (`create`/`update`) → Strava API rate-limit
  consumption and unnecessary load (DoS-ish).

## Suggested fix

- Require a per-instance shared secret on the webhook URL (unguessable path segment or
  header), validated on **POST** with `hash_equals` — not just the GET handshake.
- Verify the event's `owner_id` matches the configured athlete and `subscription_id`
  matches the stored subscription; drop events that don't.
- Consider rate-limiting and never acting on `object_id`s that were not previously
  imported for this athlete.

## Caveat (stated honestly)

The full chain (unauth POST → queued event → `delete` branch →
`markActivitiesForDeletion` → `DeleteActivity`) is confirmed by reading the code with
exact file/line citations. It was **not** reproduced on a running instance: dreeve
requires PHP 8.5 + a provisioned DB + the processing cron, which this environment
can't stand up. Exploitation requires webhooks enabled + Strava-API mode (see
Preconditions); some may therefore score the environmental impact lower. No
confidentiality impact.

## References

- `dreeveapp/dreeve` @ `745074d` — `src/Controller/Strava/StravaWebhookRequestHandler.php`,
  `src/Infrastructure/Security/AppAccessMap.php`,
  `src/Domain/Strava/Webhook/ProcessWebhookEvent/ProcessWebhookEventCommandHandler.php`,
  `src/Console/Strava/ProcessStravaWebhooksConsoleCommand.php`,
  `src/Domain/Activity/DbalActivityRepository.php` (`markActivitiesForDeletion`),
  `src/Application/Import/StravaImport/DeleteActivitiesMarkedForDeletion/DeleteActivitiesMarkedForDeletionCommandHandler.php`.
