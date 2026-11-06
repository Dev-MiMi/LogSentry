# Local LogSentry/Wazuh lab

Milestone 3 was deployed and verified on the Ubuntu PC on **6 November 2026**.
This profile keeps the existing checkout at `/home/user/LogSentry` and its private
`runtime/` data, owned by the existing `user` account. It uses system services
with restricted write access and automatic process recovery. The separate
`/opt/logsentry` / dedicated-account production templates remain available.

## Start, stop and open the lab

From `/home/user/LogSentry`:

```bash
bash deploy/lab/lab.sh start
bash deploy/lab/lab.sh status
bash deploy/lab/lab.sh stop
```

`restart` is also supported. These commands control `logsentry-lab.target`, which
groups all nine services below. They are not enabled at boot. Start the lab when
testing and stop it afterward to release memory.

| Component | Local address / private login file |
| --- | --- |
| LogSentry receiver and dashboard | `https://127.0.0.1:8444/receiver/`; `runtime/web/initial-login.json` |
| Wazuh dashboard | `https://127.0.0.1:8443`; `runtime/wazuh-dashboard-login.json` |
| Collector submission endpoint | `https://127.0.0.1:8444/api/v1/events/` |

The LogSentry HTTPS certificate uses a local CA. Import the **public** certificate
`runtime/milestone3/tls/ca.pem` into your browser's certificate-authority store to
trust this lab. Do not import or share a `*-key.pem` file. The forwarder already
uses this CA and validates the certificate and hostname. Keep login/token files
private. All listeners are bound to loopback, so remote devices cannot yet submit.

Gunicorn's internal HTTP port 8000 is for the local HTTPS proxy. Use port 8444 in
the browser. `DEBUG=0`, explicit hosts, authenticated browser pages, secure cookies,
request limits and collector authentication are active. Domain-wide HSTS preload
and subdomain flags are intentionally unset for this local IP deployment.

## Running pipeline

```text
/var/log/dpkg.log
  → logsentry-collector → runtime/collection.sqlite3
  → logsentry-forwarder → authenticated HTTPS API
  → logsentry-web → runtime/receiver/events.sqlite3
  → logsentry-wazuh-export → runtime/wazuh/events.jsonl
  → wazuh-manager
  → matching alerts → filebeat → wazuh-indexer → wazuh-dashboard
```

The ninth service, `logsentry-proxy`, provides local HTTPS and static files.
The collector reads registered sources; the current forwarder selects
`ubuntu-dpkg`. No Android collector or SSH threat rule was created by deployment.
Package events are context, not invented attacks.

The deployment templates are in `deploy/lab/`. `.service.in` files use `@ROOT@`,
`@USER@` and `@GROUP@` placeholders; the installed copies have those substituted.
Configuration is in `/etc/logsentry-lab/`; static assets are copied to
`/var/lib/logsentry-lab-static/`. The default Nginx service is disabled; the lab
uses a separate Nginx configuration through `logsentry-proxy.service`.

The receiver has one Gunicorn worker with two threads. Collection and forwarding
run continuously while the lab is active. The exporter polls every two seconds.
The five LogSentry services use `Restart=always` with a five-second delay;
deliberate `systemctl stop` still leaves them stopped. Wazuh's scans remain in the
previously selected lightweight profile, with a 1 GiB indexer heap.

Do not run a second exporter or forwarder against the same state. Do not replace,
rotate, truncate or manually append to `runtime/wazuh/events.jsonl`. The exporter
tracks its inode and checkpoint. Code edits require restarting affected services;
the running deployment does not automatically reload application changes.

## Verification performed

- The managed forwarder delivered 229 retained real package records over HTTPS.
  The already received record was deduplicated. Exact receiver record **229** was
  matched in the Wazuh manager archive, including JSON decoder, event identifiers
  and payload hash.
- With the receiver stopped, the collector picked up **57 additional actual
  package records**, including the deployment's Nginx installation. They stayed
  queued across a forwarder restart and drained after the receiver returned.
- Exact receiver record **286** then matched the Wazuh manager archive. All
  **286** receiver events were exported with no duplicate collector/event pairs,
  no pending records and no export errors. Exact receipt checks apply to the
  selected records, not an automatic acknowledgement for every exported record.
- The receiver and exporter were deliberately terminated. Systemd started new
  processes automatically, and delivery resumed without duplicate local exports.
- The grouped stop/start command was checked with all nine services. After a
  fresh start all services were active and the Wazuh cluster was green.
- Browser login, secure session cookies and static assets were checked over
  HTTPS. Anonymous evidence access redirected to login; the API rejected requests
  without a collector credential.
- All **69 receiver/dashboard regression tests passed**, including real HTTPS
  certificate validation. A pre-existing test fixture now explicitly registers
  `localhost`, matching its captured hostname, so it works on this named PC.

Private evidence: `runtime/milestone3/acceptance.json`,
`initial-managed-delivery-receipt.jsonl` and
`after-receiver-recovery-receipt.jsonl`. Raw logs, certificates, tokens and runtime
databases remain Git-ignored. The Wazuh configuration backup for this stage is
`/var/backups/logsentry-milestone3-20261106-153704/ossec.conf`.

Full JSON archiving was enabled only for the receipt verification window and
restored to **off** afterward. Archive indexing remains disabled. The normal
Wazuh alerts dashboard does not display every exported package event; milestone 4
adds appropriate rules and investigation views.

## Inspect operation

```bash
.venv/bin/python manage.py delivery_status
.venv/bin/python manage.py wazuh_status
sudo journalctl -u logsentry-web -u logsentry-proxy -u logsentry-collector \
  -u logsentry-forwarder -u logsentry-wazuh-export -n 60 --no-pager
```

The export's `verified_at` is a historical match for `verified_record`, not live
proof for later events. Repeat the bounded archive verification in
[Wazuh integration](wazuh_integration.md) when fresh receipt evidence is needed.

The receiver cap is 10,000 events; the export cap is 128 MiB. There is no automatic
deletion/retention policy. Stop and inspect reported capacity errors; do not clear
checkpoints or delete evidence to silence them. Broader rotation, retention,
resource sizing and production reliability remain milestone 5. Ubuntu 26.04 is
not in Wazuh's currently listed supported OS versions; these checks establish
that this specific local installation works, not vendor support or load capacity.
At the final check the five LogSentry processes used about 142 MiB combined.
The host had approximately 1.3 GiB available RAM and nearly full swap, so continue
using this as a small lab and stop it when it is not needed.
