# Phone collector to the Ubuntu/Wazuh PC

The existing file collector can run inside the phone's Debian/proot environment.
Its forwarder sends authenticated HTTPS requests to the PC, where the receiver
stores events and the exporter hands them to Wazuh. This uses the existing
pipeline. The dedicated mobile app is reserved for the final milestone and
begins only on explicit user instruction. Collection currently covers files
accessible to Termux/proot.

The project's intended sources are security-related events and crash logs from
various installed mobile apps. The package and SSH records verified below are
test sources for delivery and investigation; app-specific security/crash
collection and Wazuh detection still need integration and verification. The
web-app interface remains the current product.

## Current deployment

The PC's collector API is available at:

```text
https://192.168.139.101:8444/api/v1/events/
```

A separate Nginx server binds to that LAN address, allows `192.168.139.0/24`,
and exposes only POST requests to the events and heartbeat endpoints.
The existing browser interface remains at `https://127.0.0.1:8444/receiver/`.
Wazuh, the indexer and Gunicorn remain bound to loopback.

The LAN certificate covers the exact IP address and is signed by the existing
LogSentry lab CA. Distribute **only the public CA certificate** to the phone and
configure its forwarder with `--ca-file`. Keep the CA key and server key on the
PC. Certificate and IP checks must remain enabled.

The receiver has enrolled a separate `termux-phone` collector. Its private
credential is stored in ignored `runtime/phone-lan/termux-phone.json`. Transfer
it through authenticated SSH or USB to an owner-only phone directory; do not
put it in Git, screenshots, chat, URLs or shell arguments. A verified LAN
heartbeat using the existing PC credential confirms the listener's certificate
and authentication behavior. This does **not** establish phone delivery.

**Phone-to-PC deployment was completed on 7 November 2026.** The phone checkout
is `/root/LogSentry` inside Debian/proot. Its verified Termux SSH address is
`192.168.139.191:8022`, using account `u0_a128` and a dedicated PC setup key.
The host fingerprint was compared with the fingerprint supplied from the phone
before any credential was transferred.

The phone's new destination is under `runtime/pc-forwarder/`, containing its
private credential, public CA, destination configuration, separate SQLite
outbox, settings module and command wrapper. Its previous localhost forwarding
configuration and outbox, including one queued record, were preserved.
The new forwarder selects `termux-apt`, `termux-alternatives` and `local-ssh`.
Debian's larger `ubuntu-dpkg`/`ubuntu-apt` backlog was not selected for this
destination. These source names identify logs available on the phone; they do
not grant access to protected Android-wide events.

### Verified delivery

- 36 real retained phone records reached the PC through trusted HTTPS. The
  corresponding Wazuh alerts were queried through the authenticated dashboard.
- A new key-authenticated localhost SSH login was performed inside the phone's
  Debian environment with its existing capture. The server ran `/usr/bin/true`
  and exited; it did not provide an interactive session. This produced another
  11 real records, giving **47 indexed phone records** at acceptance.
- Exact fresh receiver record **372** matched rule **110013**, level **7**,
  including original exported contents, JSON decoder, collector/event IDs and
  the dashboard's indexed copy. The root username is the account in the phone's
  Debian/proot environment; it does not establish Android root access or an
  attack. This was an authorized test login.
- The new queue drained to zero, reported no errors/quarantined records, and
  continued sending heartbeats after the configuring SSH session closed. The
  indexer cluster was green. The PC export/checkpoint was not reset or replayed.
- **LogSentry — Phone events** was saved in Wazuh Discover and verified through
  the dashboard's saved-object API. Reusable export:
  `deploy/wazuh/logsentry-phone-search.ndjson`.

Private evidence is in `runtime/phone-lan/acceptance.json` and
`runtime/phone-lan/fresh-phone-alert.json`. Phone credentials remain in ignored,
owner-only runtime storage on both devices.

### Start and inspect the phone forwarder

The ordinary collector was already running and remains active. The PC forwarder
runs in a detached proot session. Proot's ordinary session exit kills children,
so a plain `nohup` inside a short SSH session does not keep this process alive.

From **plain Termux**, list sessions:

```sh
proot-distro ps
```

After the PC-forwarder session has stopped, start it with:

```sh
proot-distro login --detach --work-dir /root/LogSentry debian -- sh -c 'exec sh runtime/pc-forwarder/pc-forwarder.sh start >> runtime/pc-forwarder/forwarder.log 2>&1'
```

Record the returned session PID. Stop only that session with
`proot-distro kill PID`. Do not stop other Debian sessions or start competing
workers. To inspect its private queue from inside Debian:

```sh
cd /root/LogSentry
sh runtime/pc-forwarder/pc-forwarder.sh status
```

Both collection and forwarding must run for newly written source activity.
The SSH capture was stopped after the login test; it is on demand. Termux APT
and alternatives files will produce further records during actual package work.
Phone restart or Android stopping Termux requires starting the processes again;
this setup is not an Android boot service.

## Phone setup requirements

- Keep the phone and PC on the same Wi-Fi/hotspot network. The PC address is
  DHCP-assigned; a network or address change requires updating the LAN listener,
  allowed host, certificate SAN and phone endpoint. Use a router DHCP reservation
  when available. Do not open router port forwarding for this LAN lab.
- Inspect the phone's existing registered sources and collection database before
  selecting files. Preserve original records and any existing forwarding queue.
- Create a **separate destination configuration and outbox** for this PC URL and
  the `termux-phone` identity. An existing queue is bound to its original URL,
  collector and collection database; changing that binding is rejected.
- Run the collector and PC forwarder while testing. Debian/proot normally has no
  systemd; phone process management and Android background suspension must be
  accounted for. Do not run duplicate workers against one outbox.
- Check the phone's local delivery status, then the PC receiver's collector
  contact and received event IDs. Confirm the exact real event in Wazuh's
  `alerts.json` and `wazuh-alerts-*` before claiming end-to-end completion.

Open **Discover → Open → LogSentry — Phone events**, use **Last 24 hours** on the
acceptance date, and remove unrelated level filters. Or filter with:

```text
rule.groups: logsentry AND data.logsentry.collector_id: "termux-phone"
```

The `manager.name` and agent `000` fields identify the PC manager reading the
export file. `data.logsentry.collector_id` identifies the authenticated event
origin, so it is the appropriate field for selecting phone events.

## PC configuration and rollback

The installed LAN server is `/etc/logsentry-lab/nginx-lan.conf`, included by the
existing proxy configuration. Its template is
[`deploy/lab/nginx-lan.conf.example`](../deploy/lab/nginx-lan.conf.example).
The explicit LAN host is added in `/etc/logsentry-lab/web.env`.
Public/private certificate files are under `/etc/logsentry-lab/tls/`.
Private deployment details and the configuration backup location are in
`runtime/phone-lan/pc-deployment.json`.

Before changing or removing the LAN listener, back up its configuration and
validate with `nginx -t -c /etc/logsentry-lab/nginx.conf`. To undo this deployment,
restore the saved `nginx.conf` and `web.env`, restart `logsentry-web`, start and
reload `logsentry-proxy`, then confirm the local interface works. Receiver
evidence, export checkpoints and forwarding queues must remain intact.
Revoke the separate phone credential only if it should lose access.
