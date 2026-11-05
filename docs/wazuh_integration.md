# Milestone 3: Wazuh file integration

LogSentry can now export real received events as single-line JSON for Wazuh's
built-in JSON decoder. The exporter runs on the **LogSentry receiver host**, after
events have arrived through the authenticated web API.

The flow is:

`collector → LogSentry receiver → events.jsonl → Wazuh logcollector → manager`

If the receiver and manager share a PC, configure the manager's localfile reader.
If the receiver is on another computer, install/enroll a Wazuh agent there and
configure that agent's localfile reader instead. Do not install an agent on the
manager host just for this handoff, and do not monitor the same file twice.
The manager does not read files directly from a different machine's Termux storage.

## What is implemented and what remains

- Real-event JSON export with saved offsets and interruption recovery.
- A Wazuh `<localfile>` configuration and Linux service for continuous export.
- Dashboard/CLI export counts, errors and pending records.
- A command to match one exported event against a supplied Wazuh manager archive.

Exporting locally is **not a manager acknowledgement**. This project has no live
connection to your installed manager until you apply the configuration on the PC.
Manager arrival must still be checked there. Custom threat-detection rules and
alert dashboards are milestone 4; Android app collection remains milestone 6.

## First configure Wazuh on the receiver host

Use the paths for the installation on that computer. Our PC deployment uses
`/opt/logsentry` for code and `/var/lib/logsentry` for runtime data. From that
checkout, the following prints a configuration fragment; it does not edit Wazuh:

```bash
sudo -u logsentry env LOGSENTRY_RUNTIME_DIR=/var/lib/logsentry .venv/bin/python manage.py wazuh_status --localfile
```

The same fragment is in `deploy/wazuh/localfile.xml`:

```xml
<localfile>
  <location>/var/lib/logsentry/wazuh/events.jsonl</location>
  <log_format>json</log_format>
  <only-future-events max-size="128MB">no</only-future-events>
</localfile>
```

Back up `/var/ossec/etc/ossec.conf`, then insert this fragment **inside an existing
`<ossec_config>` element**, preserving the rest of the configuration. Apply it on
the receiver's Wazuh manager or enrolled agent, according to the layout above.
Do not replace the whole configuration with the fragment.

`only-future-events=no` lets Wazuh read events written while its logcollector was
stopped. `max-size=128MB` matches our export cap rather than Wazuh's smaller
default backlog setting. Wazuh restart/first-discovery behavior must be tested
with your installed version: configure and start its reader before starting the
exporter whenever possible. Never assume a preexisting file was ingested just
because it exists.

## File access and startup

The exporter creates `wazuh/` as mode 0700 and `events.jsonl` as mode 0600, owned
by the LogSentry service account. Wazuh's standard Linux logcollector runs with
privileges that can read this file. Verify your actual service's access if it is
custom-hardened. Keep the file private; do not make raw evidence world-readable
or grant Wazuh access to collector credentials through a broad permission change.

For an initial setup, create the directory and an empty file as the LogSentry
user before restarting the Wazuh reader. Only do this if the file does not exist:

```bash
sudo install -d -o logsentry -g logsentry -m 0700 /var/lib/logsentry/wazuh
```

Then, in a shell as `logsentry`, use no-clobber creation:

```bash
umask 077
(set -C; : > /var/lib/logsentry/wazuh/events.jsonl)
```

An “already exists” error means leave that file intact. Never truncate it. The
exporter can adopt an empty file, but refuses a nonempty file without its matching
checkpoint. Run the applicable Wazuh service restart on the reader host after
editing its configuration:

```bash
sudo systemctl restart wazuh-manager
# Or, on a separate receiver host with an agent:
sudo systemctl restart wazuh-agent
```

Use only the applicable service. Check `/var/ossec/logs/ossec.log` for file-reader
or configuration errors. A stopped remote manager/agent needs to be restored
before receipt can be established.

## Start exporting

For the existing local development checkout:

```bash
source .venv/bin/activate
python manage.py export_wazuh --watch
```

Without `--watch`, the command exports at most 100 records and exits. Watch mode
checks every two seconds, including when paused after an error. Stop with Ctrl+C.
It exports **all events already stored in the receiver**, not raw files directly.
Keep the collector/forwarder running separately to receive new events.

On the Ubuntu PC, install `deploy/logsentry-wazuh-export.service` in
`/etc/systemd/system/` after completing the [receiver deployment](reliable_delivery.md):

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now logsentry-wazuh-export
sudo journalctl -u logsentry-wazuh-export -n 30 --no-pager
```

This service uses `/var/lib/logsentry`, while a development command defaults to
the checkout's ignored `runtime/`. The exporter does not install Wazuh, enroll an
agent, change Wazuh configuration, or alter the original collector/inbox evidence.

## Check export status and JSON decoding

Sign into LogSentry and open `/receiver/`, or run:

```bash
python manage.py wazuh_status
```

The Wazuh panel shows exported/pending counts, the last check and errors. A check
older than 15 seconds is labelled stale. “Exported” means written and flushed to
the local file, not received, indexed, or alerted by Wazuh.

On the Wazuh manager, use `/var/ossec/bin/wazuh-logtest` and paste one **actual**
JSON line from the export (securely copied there if the receiver is separate).
Phase 2 should report the `json` decoder and fields such as:

- `integration: logsentry`
- `logsentry.collector_id`, `logsentry.event_id`, `logsentry.record_id`
- `logsentry.source`, `logsentry.platform`, `logsentry.event_type`
- `logsentry.message`, `logsentry.payload_sha256`
- `logsentry.observed_at`, `logsentry.received_at`, and an optional/null occurrence time

The top-level envelope and collector identity are assigned by LogSentry. Message
content remains collector-supplied evidence. Newlines/control characters are JSON
escaped, not new records. Each line has a 60 KiB limit to leave room in Wazuh
4.14's 64 KiB log buffer. Event times remain distinct from collection/receipt
times; this export never invents an authentication event or assigns a severity.

`wazuh-logtest` validates decoding only. Pasting a record into it does not prove
the real file reader delivered that record. JSON wrapping also means stock SSH
rules do not automatically analyse the inner message; milestone 4 adds rules for
the exported fields. A lack of alerts is not evidence of delivery failure or safety.

## Verify actual manager arrival

To inspect events that do not yet match an alert rule, Wazuh can write a JSON
archive. On the **manager**, set `<logall_json>yes</logall_json>` inside the existing
`<global>` element of `/var/ossec/etc/ossec.conf`, preserving other settings, and
restart the manager. This enables archiving for all received sources and increases
disk usage; use it for the verification window and restore the previous setting
afterwards unless you intend to maintain full archiving with retention.

Then allow an actual new event through the collector → receiver → exporter →
Wazuh path. The manager should write it to `/var/ossec/logs/archives/archives.json`.
Use the numeric receiver record ID shown by `wazuh_status`:

```bash
python manage.py wazuh_status --archive /path/to/manager-archives.json --record-id RECORD_ID
```

Run this command as the owner of LogSentry's export state. If the Wazuh archive
is not readable by that user, make a private copy of the relevant current archive
owned by that user; do not change ownership of Wazuh's live logs or run LogSentry
as root to bypass its own state ownership checks. For a separate manager, copy
the archive securely from that manager first.

The command scans at most the last 64 MiB, requiring the JSON decoder name,
manager metadata, and an exact `full_log` match against the receiver record,
including its IDs and payload hash. It records when that **one record** matched
the supplied archive. No match leaves receipt unverified; search the appropriate
archived day if the event has rotated out. The input archive is operator-provided
evidence, not cryptographic remote attestation. It is not an automatic acknowledgement
for other events, and a successful check does not prove dashboard indexing.

Archives are not automatically visible in the default alerts index. Archive
indexing/Filebeat settings and investigation views depend on your Wazuh setup;
milestone 4 addresses the alert/rule workflow. Do not enable a blanket high-severity
rule just to make routine transport records appear as threats.

## Recovery, retention and capacity

The exporter saves a pending byte journal before writing. It flushes the file
before advancing its checkpoint. After an interrupted append it compares the
existing bytes with the journal and completes the remaining bytes. A crash after
a complete write but before checkpointing does not produce another local line.
Only one exporter can use a directory at a time. Unchanged files are checked
against their inode, size and saved trailing hash; this is accidental-change
detection, not full tamper-proof storage.

Do **not** configure logrotate, copytruncate, or another writer for this file.
Replacement/truncation/untracked appended bytes pause the exporter. Restore the
original export plus its checkpoint from a consistent backup to resume. A new
export directory replays retained inbox events, which can duplicate Wazuh records.
Wazuh itself may replay records after a restart/state reset. Stable collector/event
IDs help identify replays; Wazuh does not automatically deduplicate these IDs.

This milestone deliberately keeps receiver evidence and every exported byte:

- The export stops at 128 MiB without deleting data or advancing past unexported events.
- The receiver still caps stored records at 10,000. Exporting does not free that
  capacity, because file output provides no manager acknowledgement.
- Oversized export records stop the batch without truncation. Inspect their
  receiver evidence; do not change evidence to bypass the limit.
- Restoring disk capacity/permissions lets an interrupted append resume. At a
  configured capacity limit, plan verified archival and retention before continuing.
- There is no automatic retention or deletion based solely on “exported” status.
  Capacity is visible; ongoing high-volume operation needs the verified archival
  and retention workflow in later system-verification work.

## Verification and sources

```bash
python manage.py test receiver.test_wazuh -v 2
python manage.py test receiver dashboard -v 1
```

Tests exercise exact evidence, bounded batches, restart recovery at several write
stages, file replacement/truncation, capacity failures, archive matching and the
authenticated dashboard. They use temporary evidence only. Applying Wazuh's
configuration and validating manager arrival on your PC remain deployment checks.

Official references used for this integration:

- [Wazuh localfile configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)
- [Built-in JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html)
- [Decoder/rule testing](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [Manager event archives](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html)
- [Wazuh 4.14 JSON reader limits](https://github.com/wazuh/wazuh/blob/v4.14.0/src/logcollector/read_json.c)
