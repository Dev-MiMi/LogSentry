# Django dashboard: collected system logs

The homepage at `/` lists sources registered with the local collector and the
number of retained records in each. Select a source to see its records, collection
state, parsing issues and supported SSH findings. `/collected/` remains an alias
for the same source list. The former sample dashboard and `/alerts/<number>/`
sample evidence pages have been removed.

The dashboard reads only `runtime/collection.sqlite3`. If there is no collection
database, it displays **No collected sources yet**. It never fills missing data
with fictional examples. The original authentication sample is now a fixture
under `tests/fixtures/`, used only by explicitly run automated tests.

## Run the collector and dashboard

From the project root, register accessible log files using their actual starting
year and source timezone, then keep collection running:

```bash
python3 -m logsentry.collector --discover --year 2026 --timezone UTC
python3 -m logsentry.collector --watch
```

In another terminal:

```bash
cd /root/LogSentry
source .venv/bin/activate
python manage.py init_web --username admin  # First run only.
python manage.py runserver 127.0.0.1:8000
```

Open **http://127.0.0.1:8000/**. Watch mode checks log files every second, and the
visible page checks saved results every two seconds. Both processes must stay
running. Use **Pause updates** to read records. Times are displayed in Nigeria
time, **WAT (UTC+1)**. See [collection setup](local_collection.md) for source
formats, permissions, retention and error handling.

## How the files work together

1. `logsentry/collector.py` reads new complete lines from registered system files.
2. `logsentry/collection_store.py` saves records and reading positions in SQLite.
3. `dashboard/urls.py` routes `/` and `/collected/` to `collected_logs()`.
4. `dashboard/collected.py` opens the store read-only, lists sources and analyzes
   retained records when a source is selected.
5. `dashboard/templates/dashboard/collected.html` renders the page;
   `collected_content.html` provides the records and source table.
6. `dashboard/static/dashboard/collected.js` checks for changes and updates the
   page without a full reload. Unchanged records do not rerun detection.

Evidence links use `/collected/<source_id>/alerts/<finding_id>/`. Each finding ID
identifies its supporting records. An expired or changed finding returns 404
instead of opening unrelated evidence. Findings are computed from retained
records, not saved incident tickets.

## Local access and verification

The dashboard requires a Django login. `init_web` creates the account and a
private `runtime/web/initial-login.json` handoff file. Keep
it bound to `127.0.0.1`; the collector and browser view run locally. If Ubuntu is
on another computer, an SSH tunnel can provide local browser access:

```bash
ssh -L 8000:127.0.0.1:8000 your-user@your-server
```

Templates escape log content. Browser URLs cannot choose filesystem paths.
These collection pages use GET/HEAD and read-only evidence access; storage
failures show an explicit error rather than fallback data. Django accounts and
sessions use `runtime/web/site.sqlite3`; the collector evidence store is separate.

The [event inbox](web_receiver.md) at `/receiver/` displays authenticated
submissions to `/api/v1/events/` in a separate private store. The POST API
requires a collector token; browser login cannot authorize event submissions.
[Milestone 2](reliable_delivery.md) adds queued delivery, revocation, status and
HTTPS deployment files. Forwarding to Wazuh is not connected yet.

To install dependencies on another machine:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Run verification from the project root:

```bash
.venv/bin/python manage.py check
.venv/bin/python manage.py test receiver dashboard -v 2
python3 -m unittest discover -s tests -v
node --test tests/collected_live.test.cjs
```
