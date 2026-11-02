# Real SSH authentication logs

LogSentry can analyze actual SSH server records in two ways:

- **Existing Ubuntu auth.log:** register the file as `syslog`; the server and
  system logger supply timestamps. This is the usual choice for an existing
  Ubuntu SSH installation.
- **Direct OpenSSH capture:** run a separate local endpoint with
  `python3 -m logsentry.ssh_capture serve`. LogSentry records the actual messages
  emitted by OpenSSH, including public-key authentication successes and failures.
  This works without systemd or rsyslog in a Termux/proot environment.

## Existing system authentication log

If SSH and its system logger already write `/var/log/auth.log`, register it with
its actual starting year and source timezone:

```bash
python3 -m logsentry.collector --file /var/log/auth.log --name ubuntu-auth --format syslog --year 2026 --timezone UTC
python3 -m logsentry.collector --watch
```

Use a user with read permission for that file. Do not change the log's timezone
just because the dashboard displays Nigeria time. No daemon restart or server
configuration change is needed for this file-based integration.

## Local endpoint in Termux/Ubuntu/Debian

This workspace is Debian in a Termux/proot container. It initially had an SSH
client but no server, auth.log or running system journal. OpenSSH server was
installed for this integration; the container's service policy blocked automatic
startup. The separate LogSentry endpoint listens only on **127.0.0.1:2222**.

On another Ubuntu/Debian machine, the dependency is `openssh-server`. Installing
it can start the machine's system SSH service depending on its service policy;
the setup below configures only LogSentry's separate endpoint. In native Termux,
install its `openssh` package and run the commands from the project checkout
inside Termux. The agent must be able to read its keys and write private storage.

Generate dedicated keys and configuration **once**:

```bash
python3 -m logsentry.ssh_capture setup
```

The current workspace already has this setup. It creates files under ignored
`runtime/ssh/` with private permissions. Repeating setup refuses to overwrite
keys/configuration. Options `--port`, `--user` and `--directory` select another
unprivileged port, existing account or new directory. Custom directories must
also be passed to `serve`.

Start capture in a terminal:

```bash
python3 -m logsentry.ssh_capture serve
```

OpenSSH runs in the foreground. The command registers **local-ssh** as a source,
then saves its output in `runtime/ssh/observed.jsonl`. It requires an installed
`sshd`. If a Linux OpenSSH build reports a missing `/run/sshd`, its administrator
must create the standard directory (`install -d -m 0755 /run/sshd`); it can be
lost across reboots in containers. The server validates its configuration first
and prints any startup errors.

Keep the collector and dashboard running in separate terminals:

```bash
python3 -m logsentry.collector --watch
```

```bash
.venv/bin/python manage.py runserver 127.0.0.1:8000
```

If the collector was already running before the SSH format was added, restart
it once to load the new Python code. Open the homepage and select **local-ssh**.
Messages come from a real OpenSSH process; the collector does not seed examples.

## Generate a real successful login

`serve` prints the exact client command for your account and chosen directory.
For this workspace, from the project root:

```bash
ssh -T -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none -o StrictHostKeyChecking=yes -o UserKnownHostsFile=runtime/ssh/known_hosts -i runtime/ssh/client_ed25519 -p 2222 root@127.0.0.1
```

This uses the endpoint's dedicated client key. OpenSSH authenticates the account,
runs `/usr/bin/true` (or the native environment's `true`) and exits immediately.
It intentionally provides no interactive shell, forwarding, terminal or password
authentication. The server reports **Accepted publickey**, and LogSentry displays
it as a successful login. No password or private key contents appear in logs.

To make one actual invalid-account attempt, use the same command with an account
that does not exist on your machine, for example `logsentry_missing@127.0.0.1`.
OpenSSH rejects it; inspect the resulting invalid-user records. Modern OpenSSH
may temporarily throttle a client after multiple failed attempts. A rejected
connection alone does not always represent a failed authentication record.

The existing SSH rules work for any parsed authentication method, including
public-key failures. Tests verify repeated failures, brute-force windows,
invalid accounts, and success following failures. Default trusted networks are
still `192.168.1.0/24`, so a successful localhost login can trigger an unusual-IP
finding. This is a policy match, not evidence of an attack. Review the displayed
policy before interpreting alerts.

## Time and evidence

OpenSSH's direct `-e` output has no timestamp. The capture process wraps each
message with an **observed_at** time and local hostname. The UI explicitly shows
**Observed at**, converted to WAT, and explains that detection windows use that
time. **Collected at** is when the file collector saved it to SQLite. Process
scheduling, buffering or suspension can delay observations; these timestamps
must not be described as precise times supplied by the server.

The raw evidence shown in SQLite and the dashboard is the original SSH message.
The JSON envelope remains in the capture file. Invalid envelopes retain a visible
parsing issue. Ordinary SSH diagnostics remain `other` events. In particular,
**Accepted key ... found at ...** only describes finding a key; only the later
**Accepted publickey for ...** counts as successful authentication.

Capture rotates at 10 MiB and keeps one backup. The existing collector detects
replacement and retains up to 10,000 records for this source. It can miss unread
data during rapid rotation; this is not a lossless production logging pipeline.
An overlong server message stops capture explicitly. Ctrl+C or SIGTERM stops the
capture command and its own SSH process group. Stopping capture does not erase
saved records. The dashboard's last-check status describes the file collector,
not whether this separate SSH process is still listening.

## Code and verification

- `logsentry/ssh_capture.py`: prepares the endpoint, starts OpenSSH, records its
  actual output, rotates the private log and handles shutdown.
- `logsentry/collection_sources.py`: validates `sshd_capture` envelopes and reuses
  the existing SSH parser, retaining each original message as evidence.
- `logsentry/collector.py`: imports the new format into the same collection store.
- `dashboard/templates/dashboard/`: displays observation-time labels and findings.

Run normal tests, plus an opt-in real OpenSSH integration test:

```bash
python3 -m unittest discover -s tests -v
.venv/bin/python manage.py test dashboard -v 2
LOGSENTRY_TEST_OPENSSH=1 python3 -m unittest discover -s tests -p test_ssh_capture.py -v
```

The opt-in test starts its own localhost server with temporary keys and storage,
makes real failed/successful login attempts, then stops it. It disables recent
OpenSSH's per-source connection penalty only in that temporary test configuration
so the complete detection sequence can be verified. Test records never enter
your regular collection database.
