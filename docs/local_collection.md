# Collect Ubuntu and Termux logs

The local collector reads configured log files and saves their records in
`runtime/collection.sqlite3`. The Django **Collected logs** page reads that store.
The homepage at `/` displays the collected sources; `/collected/` opens the same
view. No sample records are displayed when the database is empty or unavailable.
The pages run on the local device. This batch has no remote receiving API.

## First run

From the project root, using the actual starting year and timezone of your logs:

```bash
python3 -m logsentry.collector --discover --year 2026 --timezone UTC
python3 -m logsentry.collector --list
```

Discovery registers existing paths for Ubuntu `auth.log`, `dpkg.log`, and APT
history, plus Termux dpkg, APT history and alternatives logs. It never creates
missing source files or recursively searches private directories. Missing SSH
logs are normal if no SSH server or logging service is running. Unreadable
existing sources produce a visible error; run the collector as a user with
legitimate read access rather than making authentication logs world-readable.

The first pass imports existing complete lines. Each pass reads up to 2,000
lines or approximately 1 MiB per source. Repeat the command or use watch mode
to catch up with larger files. It remembers the byte position across restarts:

```bash
python3 -m logsentry.collector --watch
```

Watch mode checks each source every **one second** by default. The collected-log
pages check saved results every **two seconds**, updating records, findings and
source state without a full-page reload. At light load, a complete line written
to disk usually appears within about **1–3 seconds**, plus processing time.
Applications can buffer output before writing it; LogSentry cannot read records
until they reach the file and end with a newline. Large backlogs or Android
suspending Termux can add delay. This is near-real-time polling.

Dashboard dates use a named month and a 12-hour clock with seconds, for example
`2 Nov 2026, 1:08:02 AM WAT`. **Event time** is when the log says the event
happened; **Collected at** is when LogSentry read it. **Last check** is when the
collector last checked that source. Pages and live updates use Nigeria time:
**Africa/Lagos**, displayed as **WAT (UTC+1)**. Source timestamps are interpreted
using their configured log timezone, then converted for display. Missing event
times display **Not available**.

Use **Pause updates** while investigating a record; collection continues saving
in the separate process. **Resume updates** catches up. Selecting text or
focusing a link also defers replacement. Hidden browser tabs stop requesting
updates until visible. The page shows connection failures and retries; a source
not checked for 15 seconds is marked as delayed. A deliberately slower custom
`--interval` can also trigger that label. Evidence detail pages stay static.

Keep that terminal open. Ctrl+C stops it without deleting collected records.
In another terminal:

```bash
source .venv/bin/activate
python manage.py runserver 127.0.0.1:8000
```

Open **http://127.0.0.1:8000/collected/** and select a source. New records appear
automatically with JavaScript enabled; otherwise use **Refresh now**. The
last-check timestamp shows when polling last happened; it is not
a guarantee that the collector is still running. Android may suspend or stop
Termux in the background. No background service is installed by these commands.
Keep the dashboard bound to loopback; user accounts and remote access protection
have not yet been added.

## Register a specific file

For an existing Ubuntu authentication log:

```bash
python3 -m logsentry.collector --file /var/log/auth.log --name ubuntu-auth --format syslog --year 2026 --timezone UTC
```

For a program's plain text output, replace `/absolute/path/to/app.log` with the
real accessible filename:

```bash
python3 -m logsentry.collector --file /absolute/path/to/app.log --name my-app --format text --year 2026 --timezone UTC
```

Formats:

- `syslog`: traditional or ISO timestamps, host and process prefix, e.g.
  `Nov  2 12:00:00 ubuntu sshd[123]: Failed password ...`. The existing SSH
  detection rules apply. Other correctly prefixed events are retained too.
- `dpkg`: `YYYY-MM-DD HH:MM:SS message`. Package activity gets an event timestamp
  and is available as investigation context. Package-specific rules are not
  implemented yet.
- `sshd_capture`: actual OpenSSH messages captured by LogSentry's local endpoint.
  Timestamps are explicitly labelled observation times; existing SSH rules apply.
  See [SSH collection](ssh_collection.md).
- `text`: arbitrary UTF-8 lines. Preserves content and collection time without
  inventing an event time. Use this for APT history and raw application output.

Termux OpenSSH output written directly with `sshd -E` often has no syslog
timestamp/hostname prefix. Collect such a file as `text`; the current SSH rules
cannot evaluate it. To use those rules, the source must supply timestamped
syslog-format SSH records. Alternatively, the separate `ssh_capture` command
runs a dedicated localhost endpoint and captures its messages with observation
times. The file collector itself does not start SSH or assume `/var/log/auth.log`
exists in a proot Ubuntu.

For real logs, the current SSH policy still uses the engine defaults (3 repeated
failures, 5 in 5 minutes, normal hours 06:00–22:00, trusted `192.168.1.0/24`). The
source page displays these values. Adjust the policy in `logsentry/config.py`
for your environment before interpreting unusual-source or time alerts.

## Termux versus Ubuntu

An Ubuntu collector can read Termux paths only when those paths are exposed to
that Ubuntu environment. Here the Termux prefix is accessible at
`/data/data/com.termux/files/usr`. On another installation, run a collector from
a project checkout inside Termux if necessary; it needs Python but not Django.
Its default store belongs to that checkout. To share a store with the dashboard,
both must be able to access the same private database path (the dashboard path
is `LOGSENTRY_COLLECTION_DATABASE` in settings).

Use `--database /path/to/private-directory/collection.sqlite3` for a separate
collector store. The immediate directory must be owned by the running user and
mode 0700; the database must be mode 0600. Avoid Android shared storage, which
may not support these permissions. These commands cannot read other Android
apps' private logs or Android screen-unlock records.

## How the three collector modules cooperate

1. **`collection_sources.py`** describes each source and interprets its format.
2. **`collection_store.py`** opens private SQLite storage for records and progress.
3. **`collector.py`** polls files and saves new records with their byte offsets.

The source files are opened read-only. Records and progress are committed in
the same database transaction. If saving fails, both roll back. This prevents
normal restart/retry duplication. A partial final line waits for its newline.
An invalid UTF-8 or malformed record stays visible with a parsing issue.

The dashboard uses `dashboard/collected.py`. It opens the store read-only,
analyzes each source separately using the existing engine, and renders records
with HTML escaping. It never treats a browser query as a filesystem path.
`dashboard/static/dashboard/collected.js` requests updates from the same page.
The response includes an escaped HTML fragment only when the saved data or
policy changes; unchanged heartbeats return small status updates without
rerunning detection. The collector still needs to be running independently.
Findings link to specific evidence IDs; if the evidence changes or expires,
an old link returns 404 instead of opening an unrelated finding.

## Limits of this first collector

- Retains the latest **10,000 records per source**. Older records are removed
  from the store, with a visible count. Original logs are untouched. The page
  displays the latest 200 records, while detection uses the retained history.
- Rotation or truncation starts a new file generation; old stored records
  remain until retention removes them. The collector checks inode, size and
  a fingerprint before the saved offset. It cannot guarantee lossless capture
  during rapid rotations, writes to renamed files, or identical rewrites.
- A structured record exceeding 8 KiB, or a plain text record exceeding 64 KiB,
  pauses that source with an error, rolling back the current batch rather than
  silently losing or truncating evidence. The larger text limit accommodates
  long APT package lists.
- Only newline-terminated records are collected. Sources must be regular files;
  symbolic links, FIFOs and binary journal files are not supported.
- Rules operate per source, not across different devices or duplicate feeds.
  Collected alerts are computed on page load, not stored incident tickets.
- SQLite storage uses Unix permissions, not encryption. This is local file
  collection, not Android-wide access, a systemd journal reader, or a network agent.

## Verify

```bash
python3 -m unittest discover -s tests -v
.venv/bin/python manage.py test dashboard -v 2
node --test tests/collected_live.test.cjs
```

Collector tests use temporary files for append/restart, rotation, truncation,
transaction rollback, partial writes, parsing failures, permissions, retention
and command behavior. Dashboard tests check real saved evidence, source
isolation, escaping, error visibility, bounded display and stable evidence links.
The Node checks exercise browser scheduling, pause/resume, hidden tabs,
connection recovery and deferral while reading, using a simulated browser DOM.
