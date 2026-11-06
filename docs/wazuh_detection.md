# Milestone 4: Wazuh rules and investigations

Implemented in this checkout: searchable activity, SSH rule fields, nine Wazuh
rules, severity mapping, authenticated evidence pages and exact alert verification.
The Ubuntu PC still needs the installation and live dashboard checks below.
Do not mark this milestone fully complete on code tests alone.

## PC handoff status

The phone session completed these checks before handoff:

- 78 receiver/dashboard tests passed, including 9 new milestone 4 tests.
- 148 engine/collector tests ran successfully, with 1 optional SSH test skipped.
- All 7 dashboard JavaScript tests passed.
- `git diff --check` passed.

**Actual Wazuh engine validation has not completed.** An isolated offline test
setup on the phone was interrupted; no passing Wazuh result is claimed. Start
with the configuration check and `deploy/wazuh/test_rules.py` on the Ubuntu PC.
In particular, confirm correlation threshold counts and precedence for a root
success after failures. Fix any discrepancies before activating the rules.
The Python tests validate enrichment, evidence boundaries and test-runner parsing;
they do not replace running Wazuh's rule engine.

No PC configuration, service or dashboard setting was changed by this phone
implementation. The next session should read this guide and `docs/local_wazuh_lab.md`,
inspect the running PC lab, perform the remaining checks, then update the roadmap
with actual results. Preserve the existing export file and checkpoint. Synthetic
scenarios belong only in Wazuh logtest; use real new events for live acceptance.

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
   sudo .venv/bin/python deploy/wazuh/test_rules.py
   ```

   This uses Wazuh's ruleset test sessions. Its artificial cases never enter the
   receiver, the export file, or the real alerts dashboard. It checks final IDs
   and levels, threshold boundaries, separated identities, replay, root success
   precedence and unrelated-app text. All scenarios must pass on your Wazuh
   version; a successful XML parse alone is insufficient.

4. Restart the manager and affected LogSentry services:

   ```bash
   sudo systemctl restart wazuh-manager
   sudo systemctl start logsentry-lab.target
   sudo systemctl restart logsentry-web logsentry-wazuh-export
   bash deploy/lab/lab.sh status
   ```

   The exporter has `Requires=wazuh-manager`; restarting Wazuh may stop it, which
   is why it is started again here. There are no new Python dependencies, database
   migrations or static assets for this milestone. Do not start a second exporter.

## Verify a real event and dashboard visibility

The PC currently forwards `ubuntu-dpkg`. Allow the next actual package operation
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
