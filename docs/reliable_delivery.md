# Milestone 2: accounts, durable delivery and Linux deployment

The browser now requires a Django login. Collectors use separate bearer tokens
registered by hash; revoking one token leaves other collectors and stored evidence
intact. The sender copies evidence into a private persistent outbox and removes
it only after receiving an acknowledgement from LogSentry.

Wazuh forwarding is still milestone 3. This delivery receipt means the LogSentry
receiver saved the records, not that Wazuh analysed them.

## Upgrade the existing local installation

From the project root:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python manage.py init_web --username admin
python manage.py collector_access import
python manage.py runserver 127.0.0.1:8000
```

`init_web` creates the account/session database, a persistent signing key and a
random administrator password. Read `runtime/web/initial-login.json` locally to
sign in; the command does not print its contents. Keep this file private and
remove it after saving the password securely. `python manage.py changepassword
admin` changes the password interactively. Restart Django after initialization.

The `collector_access import` command registers the milestone-1 credential. It
migrates the inbox schema without removing received records. Run it once; a
repeated import fails instead of re-enabling a revoked identity. A fresh receiver
can use `init_receiver --collector-id NAME` instead.

Configure automatic sending once:

```bash
python manage.py configure_forwarder --endpoint http://127.0.0.1:8000/api/v1/events/
python manage.py forward_events --watch
```

The default selects all registered local sources. Add repeated `--source NAME`
arguments to restrict it. In another terminal keep the original collector running:

```bash
python -m logsentry.collector --watch
```

The collector reads files; the forwarder copies saved records and delivers them.
Both must run to deliver new file activity. The forwarder continues queuing while
the receiver is offline, retries with backoff up to five minutes, and resumes
after restart. `forward_events` without `--watch` performs one cycle and respects
any stored retry deadline. Ctrl+C preserves all unacknowledged records.

Open `/receiver/` after signing in. It shows each collector's last contact,
reported queue count/errors, and this host's local queue when one exists. These
are snapshots; refresh the page to update them. Contact older than 30 seconds is
marked stale. A disconnected collector cannot update its remote status; inspect
its local queue/terminal for the current error.

## Individual collector credentials

On the receiver, create a credential for each machine:

```bash
python manage.py collector_access enroll --collector-id termux-phone --output runtime/enrollment/termux-phone.json
python manage.py collector_access revoke --collector-id termux-phone
```

Enrollment writes a private credential file and stores only its SHA-256 token
hash in the receiver. Copy the file to the collector through a secure channel,
with mode 0600 inside an owner-only 0700 directory. Do not put token values into
URLs, Git, screenshots, or shell arguments. Identity reuse is rejected, including
after revocation. A replacement credential should have a new identity and a
separate outbox. Old pending evidence is not automatically reassigned; retain and
review it rather than deleting it.

On the collector, configure its destination with the received credential:

```bash
python manage.py configure_forwarder --endpoint https://logsentry.example.com/api/v1/events/ --credentials runtime/enrollment/termux-phone.json
```

For private TLS certificates, append `--ca-file /path/to/trusted-ca.pem`. This
enables certificate and hostname validation using your trusted CA; it never
disables verification. Credentials/configuration and the queue remain local.
The manual sender is still available for inspection and small deliveries.

## Queue guarantees and limits

- Cursor advancement and copying evidence into the outbox commit together. The
  collector evidence store remains unchanged. Retrying a lost acknowledgement
  reuses event IDs, so receiver deduplication prevents duplicate stored records.
- Each outbox is bound to one receiver URL, collector identity and source database
  file identity. Changing them requires a separate outbox, not silent reuse.
  A process lock prevents competing workers using the same queue.
- The outbox holds at most 20,000 records/128 MiB of serialized payload. At capacity
  it stops advancing cursors; delivery of existing records continues. Disk-full
  errors also preserve uncommitted cursors and pending records.
- Unrepresentable records (for example messages longer than the API allows) are
  retained locally with an issue, counted as needing review, and skipped for
  delivery so valid evidence can proceed. They consume queue capacity; no automatic
  truncation or deletion is performed. Run `python manage.py delivery_status`
  locally, or append `--review` to inspect up to 50 problem records. The latter
  prints evidence that may be sensitive, so use a private terminal.
- Existing collection retention is 10,000 records per source. Records can be lost
  **before** they reach the queue if the forwarder is stopped or full while the
  collector continues. Retention changes raise a persistent coverage warning;
  it is conservative and does not prove every removed record was missed. Keep
  source logs/archives and size retention for your workload. This is not an
  unlimited or lossless logging system.
- The receiver's current 10,000-event capacity still applies. HTTP 507 keeps
  evidence queued. Forwarding/retention in milestone 3 will address ongoing volume.
- The forwarder sends a credential-authenticated heartbeat after delivery (or
  when idle). Reported pending counts/errors are collector claims and become stale
  while disconnected. They are never interpreted as proof of a security incident.

## Deploy on the Ubuntu 26.04 PC

The PC was off during implementation; these deployment steps have not been run
on it. First start it and choose a hostname/IP for the receiver. SSH is convenient
for remote administration but local terminal setup works too.

Install `python3-venv`, `nginx`, `openssl`, and Git using Ubuntu's package manager.
Copy/clone the project to `/opt/logsentry` and create a dedicated unprivileged
`logsentry` service account. Keep application code administrator-owned and readable
by that account. Create `/var/lib/logsentry` owned by `logsentry` with mode 0700.
Create the virtual environment in `/opt/logsentry/.venv` and install requirements.

For initialization run commands from `/opt/logsentry`, as the service user:

```bash
sudo -u logsentry env LOGSENTRY_RUNTIME_DIR=/var/lib/logsentry .venv/bin/python manage.py init_web --username admin
sudo -u logsentry env LOGSENTRY_RUNTIME_DIR=/var/lib/logsentry .venv/bin/python manage.py init_receiver --collector-id linux-pc
.venv/bin/python manage.py collectstatic --noinput
```

Serve `staticfiles/` read-only to Nginx. Copy `deploy/web.env.example` to
`/etc/logsentry/web.env`, change the hostname to your chosen DNS name/IP, and
protect this file as root-owned mode 0600. The persistent Django key comes from
`/var/lib/logsentry/web/secret.key`. Never use development settings remotely.

Provide a TLS certificate covering that exact DNS name/IP at:

- `/etc/logsentry/tls/fullchain.pem`
- `/etc/logsentry/tls/privkey.pem` (root-owned mode 0600)

A publicly trusted certificate works if you control a domain. For a private LAN,
use your own CA or a locally generated certificate with the correct Subject
Alternative Name and distribute its trust securely to the browser and sender.
Do not click through certificate errors or disable sender verification. The
`--ca-file` option supports this setup without needing a public domain.

Copy `deploy/nginx.conf.example` into Nginx's `conf.d`, replacing its hostname.
It terminates TLS, rate-limits login/API requests, bounds bodies, and overwrites
forwarding headers. Nginx is the only network-facing service; Gunicorn binds to
127.0.0.1:8000. Do not expose port 8000 or configure another untrusted proxy in
front of it. A firewall should allow HTTPS only from the intended networks.

Copy `deploy/logsentry-web.service` into `/etc/systemd/system/`, then validate and
start only after configuration/certificates are in place:

```bash
sudo nginx -t
sudo systemctl daemon-reload
sudo systemctl enable --now logsentry-web
sudo systemctl reload nginx
```

Open `https://YOUR-HOST/`, sign in with the generated account, and enroll each
collector. Configure their HTTPS endpoint and start their forwarders. On Linux
collectors with the same `/opt/logsentry` and `/var/lib/logsentry` layout, the
supplied `logsentry-forwarder.service` can manage the worker. Termux/proot normally
does not run systemd; use its terminal/process management instead.

The web receiver host does not need a local collector unless you want its own
logs too. On a collector host, register/read only accessible sources and run the
collector separately; the delivery service does not grant extra file permissions.

`manage.py check --deploy` leaves two optional HSTS settings unset: include all
subdomains and preload. They require control of a domain and a long-term HTTPS
commitment and are not appropriate to enable automatically for a private LAN/IP.
The supplied proxy sends no HTTP application traffic; HTTPS uses secure cookies.

## Acceptance check

1. Sign in and send actual collected records to the receiver over HTTPS.
2. Stop the receiver and generate more observable source activity. Verify local
   pending count grows and a delivery error appears.
3. Restart the forwarder while still offline; its records must remain queued.
4. Restore the receiver, allow the retry deadline to pass, and confirm the queue
   drains and records appear once. Revocation must stop only that collector.
5. Confirm unauthenticated browsers cannot view evidence and HTTP cannot expose
   the deployed application. Keep HTTPS certificates valid.

Automated checks: `python manage.py test receiver dashboard` and
`python -m unittest discover -s tests`. See [milestone 1](web_receiver.md) for the
event contract. Android app collection and Wazuh forwarding remain later work.

## Verification performed during implementation

The implementation was exercised in the existing Debian/Termux environment,
not on the powered-off Ubuntu PC. Automated tests covered offline buffering,
restarts, lost acknowledgements, revoked credentials, browser login/CSRF, and
TLS certificate/hostname rejection. A temporary Nginx 1.26.3 + Gunicorn 26.2.0
deployment also verified HTTPS login, secure cookies and actual-record delivery
with the supplied proxy configuration. The systemd units passed validation
after substituting this workspace's executable paths. The PC's own certificates,
service installation and networking must still be verified during deployment.
