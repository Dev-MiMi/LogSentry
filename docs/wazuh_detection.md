# Milestone 4: Wazuh rules and investigations

**Complete for the local Ubuntu lab on 6 November 2026.** Nine custom rules,
severity mapping, authenticated investigation pages and exact alert verification
are active. Individual events are searchable in Wazuh's alerts index.

## Verified on the PC

- Wazuh 4.14.10 configuration validation passed. All 20 isolated scenarios passed
  in both standalone logtest and the active manager's logtest sessions, including
  three/five-failure boundaries, replay, identity separation and root success
  after failures.
- Fixed correlation to use the final failure **group**, since an event promoted
  to rule 110020 no longer has final rule ID 110010. Without this fix, the fifth
  failure and success-after-three-failures alerts were missed. Both elevated
  failure rules retain `logsentry_ssh_failure`; successes and invalid-user
  messages do not enter that history.
- Exact real package record **319** matched rule **110001**, level **3**. Exact
  real localhost SSH login record **325** matched rule **110012**, level **3**.
  Both were checked against `alerts.json`, the original event contents and
  `wazuh-alerts-4.x-2026.11.06`, with one indexed match per collector/event pair.
  Queries through the authenticated dashboard API returned those same records.
- Three Discover searches were saved: **LogSentry — All events**,
  **LogSentry — Routine activity**, and **LogSentry — Security findings**.
  Dashboard timezone is `Africa/Lagos`. Browser rendering was not inspected;
  saved objects and dashboard search responses were verified through its API.
- The original 286 export records, inode and byte prefix were preserved.
  At acceptance there were 330 unique exports, 44 indexed new LogSentry events,
  no pending deliveries and no exporter errors. The indexer cluster was green.
  Full archive output and archive indexing remain off.
- All 78 receiver/dashboard tests passed. The engine/collector suite ran 148
  tests with its optional SSH test skipped; that test was then run separately
  with the real OpenSSH dependency (11/11 SSH tests passed). All seven dashboard
  JavaScript cases also passed.
- After starting the lab again on 7 November, dashboard and indexer health were
  green, all nine services were active, and the saved searches persisted.
  Authenticated package/SSH investigation pages and the rule catalogue returned
  the expected evidence with `no-store`; login and API access checks passed.

Private evidence is in `runtime/milestone4/acceptance.json`, the two exact alert
copies, logtest results and `dashboard-views.json`. No test-only attack records
were inserted into the live pipeline. Security correlation behavior was checked
in isolated logtest; live acceptance used actual package work and a successful
key login, not a simulated compromise.

The forwarder now selects `ubuntu-dpkg` and `local-ssh`. OpenSSH was installed
for the existing capture feature; the system SSH service and socket are disabled.
The dedicated capture listens only on `127.0.0.1:2222`, allows the existing `user`
account's dedicated key, and exits each login through `/usr/bin/true`. It was
stopped after verification and runs **on demand**, separately from the nine lab
services. Start it with `python3 -m logsentry.ssh_capture serve` and use the login
command it prints. See [SSH collection](ssh_collection.md). The forwarding source
remains registered; starting capture produces new real events automatically.

## What changes

The exporter adds `logsentry.enrichment_version: 1` and, for recognized Linux or
Termux SSH records, `logsentry.ssh` fields. The built-in Wazuh JSON decoder reads
them, so **no extra decoder is required**. The original message, payload hash,
collector identity and timestamps remain unchanged. Existing export lines are
not rewritten. Their original milestone 3 receipt verification still works.

SSH enrichment requires a matching event type, a real-looking `sshd` or
`sshd-session` prefix and valid IP/port. Direct messages are supported for the
existing `local-ssh` capture with observation time only. An Android notification,
an unparsed record, or another application's message cannot become a parsed SSH
login just by containing the words “Failed password”. These are authenticated
collector reports, not proof that a collector or endpoint is uncompromised.

| Rule | Wazuh level | LogSentry priority | Meaning |
| --- | --- | --- | --- |
| 110000 | 3 | Informational | Other collected activity |
| 110001 | 3 | Informational | Package activity |
| 110010 | 5 | Low | Single SSH authentication failure |
| 110011 | 5 | Low | Unknown SSH account |
| 110012 | 3 | Informational | Successful SSH login |
| 110013 | 7 | Medium | Root SSH login; check authorization |
| 110020 | 8 | Medium | 3 matching failed deliveries in 300 seconds |
| 110021 | 10 | High | 5 matching failed deliveries in 300 seconds; possible brute force |
| 110022 | 12 | High | Success following at least 3 failed deliveries for the same account within 600 seconds |

Priority labels are our mapping for these rules, not replacements for Wazuh's
numeric levels. None of these observations alone justifies “Critical”.
Level 3 activity is deliberately indexed through Wazuh's normal alerts pipeline
so routine package records can be searched without full archive indexing. It is
informational, not an attack. Use `logsentry_security` to focus on findings.

Correlation stays within one collector, source, hostname and normalized IP.
Success-after-failures also matches username. Only failed-login messages count
toward failure thresholds; a separate “Invalid user” message is not another
password failure. Mapped IPv6 and equivalent IPv4 are grouped together.

**Wazuh uses processing time for these windows.** Offline batches, historical
logs and replay may create apparent bursts or success/failure ordering that did
not happen on the endpoint. Check `occurred_at`, `observed_at`, `received_at` and
distinct event IDs before escalating. `different_field` avoids counting copies
of the current failure event against itself; it is not a persistent deduplication
store and cannot eliminate all replay combinations. Wazuh correlation history
can reset on restart and is not shared across independent managers.

These rules do not implement learned behavior or a default unusual-hours policy.
They do not assume that private IPs are trusted. Agree a per-device policy before
adding time/network alerts. Android app collection remains milestone 6.

## Install on the existing Ubuntu lab

Run from the updated checkout on the **Wazuh manager PC**, with the lab running.
The commands below are for `/home/user/LogSentry`; use your actual checkout path.

1. Check for rule ID conflicts and any existing local rules:

   ```bash
   sudo rg 'id="1100[0-9]{2}"' /var/ossec/etc/rules /var/ossec/ruleset/rules
   ```

   No output means no conflicts were found. If these IDs already belong to other
   rules, stop and resolve the collision. Do not overwrite another integration.
   Also review existing `<active-response>` entries in `ossec.conf`: this package
   does not install automatic blocking, but an existing broad level-based response
   could react to the new findings.

2. Install this separate rules file. If it already exists, back it up first;
   replace it only after confirming it is your earlier LogSentry rules file:

   ```bash
   sudo install -o root -g wazuh -m 0640 deploy/wazuh/logsentry_rules.xml /var/ossec/etc/rules/logsentry_rules.xml
   sudo /var/ossec/bin/wazuh-analysisd -t
   ```

   Wazuh's existing `<ruleset>` must include `<rule_dir>etc/rules</rule_dir>`.
   Keep all existing rule directories and decoder settings. Confirm
   `<jsonout_output>yes</jsonout_output>` and `<log_alert_level>3</log_alert_level>`
   (or a lower threshold), so informational records are written to `alerts.json`.
   If your deployment intentionally uses a higher threshold, level 3 activity
   will not appear until that policy is changed. No archive setting is needed.
   Do not restart the manager if validation fails; restore the backed-up rule file.

3. Run the isolated rule scenarios before activating the change:

   ```bash
   sudo .venv/bin/python deploy/wazuh/test_rules.py --logtest /var/ossec/bin/wazuh-logtest-legacy
   ```

   The standalone binary reads the candidate configuration from disk without
   requiring a live manager restart. Its artificial cases never enter the
   receiver, the export file, or the real alerts dashboard. It checks final IDs
   and levels, threshold boundaries, separated identities, replay, root success
   precedence and unrelated-app text. All scenarios must pass on your Wazuh
   version; a successful XML parse alone is insufficient.

4. Restart the manager and affected LogSentry services:

   ```bash
   sudo systemctl restart wazuh-manager
   sudo systemctl start logsentry-lab.target
   sudo systemctl restart logsentry-web logsentry-wazuh-export
   sudo .venv/bin/python deploy/wazuh/test_rules.py
   bash deploy/lab/lab.sh status
   ```

   The exporter has `Requires=wazuh-manager`; restarting Wazuh may stop it, which
   is why it is started again here. There are no new Python dependencies, database
   migrations or static assets for this milestone. Do not start a second exporter.

## Verify a real event and dashboard visibility

The PC currently forwards `ubuntu-dpkg` and the on-demand `local-ssh` source.
Allow the next actual package operation
you intended to perform to generate a new record. A normal package record is
enough to verify activity indexing. SSH findings require a real registered SSH
source to be selected by the forwarder; a package log cannot produce SSH alerts.
Do not invent attack records or replay the export to make the dashboard busy.

Find the new record in LogSentry's inbox and open **Investigate record**. The
page gives its original evidence and a Wazuh query using collector/event IDs.

On the PC, get a private copy of the relevant `alerts.json` as the LogSentry
runtime owner. Wazuh's live file is normally
`/var/ossec/logs/alerts/alerts.json`. Keep its permissions and ownership intact.
Run as the owner of the LogSentry runtime:

```bash
.venv/bin/python manage.py verify_wazuh_alert --alerts /path/to/private/alerts.json --record-id RECORD_ID
```

The command checks the last 64 MiB, JSON decoder, manager metadata, exact original
event content and known rule ID/level. It is read-only and does not print raw
messages. Success verifies the supplied file's evidence for that one record,
not every exported event or the dashboard index. Like milestone 3 archive
verification, a supplied file is operator evidence rather than remote attestation.

Open Wazuh at the lab's `https://127.0.0.1:8443`, then **Threat hunting** (or
Discover with `wazuh-alerts-*`, depending on version). Set a range containing
the new event's **Wazuh processing time**, refresh, and search:

```text
rule.groups: logsentry
```

Use the exact collector/event query from LogSentry to locate the verified record.
Expand it and confirm `rule.id`, `rule.level`, `data.logsentry.event_id`,
`data.logsentry.record_id` and the original message. Save two searches if useful:

```text
rule.groups: logsentry AND rule.level: 3
rule.groups: logsentry_security
```

The first is routine activity; the second is findings needing review. Add columns
for `rule.description`, `rule.level`, `data.logsentry.collector_id`,
`data.logsentry.source`, `data.logsentry.ssh.source_ip` and
`data.logsentry.ssh.username`. Set the dashboard's `dateFormat:tz` setting to
`Africa/Lagos` for Nigeria time. LogSentry already uses WAT.

On this PC the three searches are already available in **Discover → Open**.
The reusable saved objects are in `deploy/wazuh/logsentry-searches.ndjson` for
import through **Dashboard management → Saved objects → Import** on another lab
with the existing `wazuh-alerts-*` index pattern. Use a time range containing the
events (for example **Today** on the acceptance date). The security search can
be empty when there are no security findings; ordinary activity is level 3.

If a verified manager alert is missing from the dashboard, inspect Filebeat and
the indexer, the alerts module, index permissions and the time range. Do not
interpret it as an exporter failure or regenerate duplicate evidence. Old events
processed before these rules were installed do not automatically become alerts.

## Completion evidence and rollback

Milestone 4 is fully complete on the PC after rule validation and all logtest
scenarios pass, a real newly delivered record matches `alerts.json`, and the same
collector/event ID is visible in `wazuh-alerts-*`. Record counts, rule IDs and test
results in a private `runtime/milestone4/` acceptance note; keep raw logs and login
files out of Git. Record whether SSH sources are actually connected separately.

To roll back rules, restore the previous file, or move this newly added file out
of `etc/rules`, validate with `wazuh-analysisd -t`, and restart the manager and
exporter as above. Keep the export and checkpoint together and unchanged.
LogSentry's new SSH fields do not require the custom rules to remain readable.
Activity indexing adds storage use; sustained load and retention remain milestone 5.

References:

- https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
- https://documentation.wazuh.com/current/user-manual/ruleset/testing.html
- https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html
