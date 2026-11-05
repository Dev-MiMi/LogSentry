# Web-to-Wazuh milestone 1: authenticated event inbox

This guide describes the event contract introduced in milestone 1. The current
implementation also includes [milestone 2](reliable_delivery.md): browser login,
multiple revocable collector identities, offline queues and HTTPS deployment.
No fictional data is loaded at startup. [Milestone 3](wazuh_integration.md) exports
these events for Wazuh; manager receipt is verified separately on the PC.

## Run it

From the project root:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python manage.py init_web --username admin
python manage.py init_receiver --collector-id logsentry-local
python manage.py runserver 127.0.0.1:8000
```

Run `init_receiver` once. It refuses to replace existing credentials. The token
is saved privately in `runtime/receiver/credentials.json`, not printed or
committed. The inbox is `runtime/receiver/events.sqlite3`. The directory is 0700
and files are 0600, owned by the OS user running Django. `init_web` runs the Django
account migrations. Read its private initial-login file to sign into the browser.
Existing milestone-1 credentials need `collector_access import` once after upgrade.

Open **http://127.0.0.1:8000/receiver/** or choose **Event inbox** in the navigation.
The page stays empty until events arrive. **Refresh inbox** loads the newest
records; this new page does not poll automatically yet.

In another terminal, send actual saved collector records:

```bash
source .venv/bin/activate
python -m logsentry.collector --list
python manage.py send_collected_events --source ubuntu-dpkg --limit 5
```

Choose a source actually listed on your installation. The sender reads the
collector database without changing evidence or collection positions. If there
are no saved records, first follow [local collection](local_collection.md).

Successful delivery prints counts and the `--after-record` value to use with
the same source for the next batch. On failure, repeat the same command and
cursor: stable event IDs prevent duplicate storage. This command sends manually;
use milestone 2's `forward_events --watch` for persistent queued delivery.

## API contract

`POST /api/v1/events/` requires `Content-Type: application/json` and an
`Authorization: Bearer ...` header. The collector identity comes from its private
credential, not request JSON. Cookies, query parameters and bodies cannot supply
authentication. The envelope has `schema_version: 1` and an `events` list with
1–100 objects.

| Event field | Meaning |
| --- | --- |
| `event_id` | UUID that stays the same on retries |
| `platform` | `linux`, `termux`, or `android` |
| `source` | Source identifier: up to 128 letters/digits/dots/underscores/hyphens |
| `event_type` | Collector-reported type, using the same identifier format |
| `observed_at` | Collector observation time, with explicit timezone |
| `occurred_at` | Original source timestamp; null/omitted if unknown |
| `message` | Evidence text, at most 8,192 characters within the request-size limit |

Times use ISO 8601 with `T` and an offset, are normalized to UTC, and displayed in
WAT. The server adds its own `received_at`. Collector timestamps depend on its
clock. An app entering the foreground does not establish that a login succeeded.
Direct SSH capture has observation time only; the sender leaves occurrence time
unknown for those records.

Unknown fields, malformed JSON, invalid times and duplicate IDs inside a batch
are rejected. Requests are limited to 256 KiB. Whole batches commit together:
a conflict or full inbox rolls back all new records in the request. An existing
ID with identical normalized contents counts as a duplicate; changed contents
are rejected rather than overwriting evidence.

| HTTP status | Meaning |
| --- | --- |
| `201` | New events stored, possibly alongside duplicates |
| `200` | All events were already present |
| `400` / `413` / `415` | Invalid data, oversized request, or wrong content type |
| `401` | Missing/invalid collector authentication |
| `403` | Unencrypted request from outside loopback |
| `409` | An existing ID has different contents; whole batch rejected |
| `503` | Configuration/storage unavailable; retain events and retry unchanged IDs |
| `507` | Inbox full; retain unsent events at the collector |

Receipts contain `schema_version`, `accepted`, `duplicates`, and `status: stored`.
This confirms only LogSentry receipt, not Wazuh delivery. The inbox holds 10,000
records and refuses new ones when full; it never silently discards unforwarded
evidence. Only the latest 100 appear in the browser.

## Deployment boundary

Keep the development server on loopback. Browser pages require a Django login.
Use an SSH tunnel as described in the [dashboard guide](django_dashboard.md) for
remote viewing; do not expose the development server on a public/LAN interface.

The API uses bearer authentication without browser sessions, so it does not need
a CSRF cookie. Browser page routes retain Django's CSRF middleware. The API
requires HTTPS for direct non-loopback requests; the sender allows HTTP only
to literal loopback IPs. HTTPS uses normal certificate verification, and
redirects are refused to avoid disclosing collector credentials.

For remote deployment use the HTTPS/proxy configuration, service units and
per-collector enrollment described in [milestone 2](reliable_delivery.md). By
default forwarded HTTPS headers are not trusted; only the supplied loopback
proxy deployment enables this. A future mobile collector must filter sensitive
notification fields and redact secrets before submission.

## Files to learn first

1. `receiver/serializers.py` defines and validates event fields.
2. `receiver/views.py` receives requests and displays the inbox.
3. `receiver/storage.py` saves records and prevents duplicates.

`authentication.py` checks collector tokens. `sending.py` sends real saved
records. Management commands expose setup/sending without putting tokens on the
command line. Tests use isolated stores with test-only records.

## Roadmap after this milestone

- Deploy the milestone-2 HTTPS receiver and queued delivery on your Linux PC.
- Apply the [Wazuh file handoff](wazuh_integration.md) and verify manager arrival.
- Configure Wazuh decoders, detection rules and investigation views.
- Verify recovery, retention and complete delivery/alert workflows.
- Add the Android collector, with actual collection coverage tested on the phone.

A browser cannot read other Android apps' private logs. Later, the Android
collector can send accessible observations through this API. Authentication
monitoring still requires reliable authentication events from each app.

## Verification

```bash
python manage.py check
python manage.py test receiver dashboard -v 2
python -m unittest discover -s tests -v
node --test tests/collected_live.test.cjs
```

Automated tests use temporary stores. The sender command above verifies delivery
with actual records collected from your system.
