# LogSentry

A Python security log analyzer focused on Ubuntu SSH authentication. The engine
reads log files, detects suspicious patterns, assigns priorities, and generates
investigation reports. It includes a CLI, a local Django dashboard, and an
incremental collector for accessible Ubuntu/Termux log files.
An authenticated web inbox starts the next phase toward Wazuh integration.

Requires Python 3.10+ and system timezone data. No third-party Python packages
are needed for the engine. The dashboard uses Django 5.2 LTS, installed in
`.venv`. Run commands from the **project root**, not inside `tests/` or
`logsentry/`.

## Open the web dashboard

On the configured Ubuntu/Wazuh PC, use the [managed local lab](docs/local_wazuh_lab.md)
at `https://127.0.0.1:8444/receiver/`. The development-server instructions below
apply when the managed lab is stopped or on another installation.

```bash
cd /root/LogSentry
source .venv/bin/activate
python manage.py init_web --username admin  # Once, to create the private login.
python manage.py runserver 127.0.0.1:8000
```

Open **http://127.0.0.1:8000/** on the device running the server. The homepage
lists sources and counts from the local collection database. Select a source
to inspect its records and supported SSH findings. Without collected data, it
shows an empty state. All displayed events come from explicitly collected files;
there is no sample dashboard or demo-data fallback. Times use Nigeria time,
**WAT (UTC+1)**. Sign in using the private `runtime/web/initial-login.json` file
created by `init_web`. Browser file uploads are not implemented. See
[the Django walkthrough](docs/django_dashboard.md) for setup and the request flow.

To install the web dependencies on another machine:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Web-to-Wazuh milestone 1: event inbox

With `.venv` active, provision the receiver once:

```bash
python manage.py init_receiver --collector-id logsentry-local
```

Run Django on loopback as above, then open **http://127.0.0.1:8000/receiver/**.
In another terminal, submit real saved records from an existing source:

```bash
python manage.py send_collected_events --source ubuntu-dpkg --limit 5
```

Choose a source actually registered on your installation. The API authenticates
the collector, validates records and deduplicates retries. Evidence and tokens
stay in private, ignored `runtime/receiver/` files. This confirms LogSentry
receipt; manager arrival requires the Wazuh integration below. See the
[receiver walkthrough](docs/web_receiver.md).

## Milestone 2: reliable delivery and protected access

Browser pages now require a login. Existing milestone-1 installations should
run `python manage.py collector_access import` once to register their credential
in the new revocable registry. Fresh `init_receiver` setups do this automatically.

```bash
python manage.py configure_forwarder --endpoint http://127.0.0.1:8000/api/v1/events/
python manage.py forward_events --watch
```

Keep the local collector running separately. The forwarder copies real saved
events into a persistent queue, retries outages, and deduplicates redelivery.
The inbox shows collector contact and pending/error reports. Individual tokens
can be enrolled or revoked. See [reliable delivery and Ubuntu deployment](docs/reliable_delivery.md)
for account setup, HTTPS, service files and queue/retention limits. Deployment to
your PC still requires running those steps on that machine.

## Milestone 3: Wazuh integration

```bash
python manage.py wazuh_status --localfile
python manage.py export_wazuh --watch
```

The first command prints Wazuh's file-reader configuration for this installation.
Apply it on the receiver host's Wazuh manager (same PC) or enrolled Wazuh agent
(separate receiver), then start exporting. The exporter writes received events
as JSON lines to `runtime/wazuh/events.jsonl`, with a recoverable checkpoint.
The inbox shows export progress separately from manager verification. Run
`python manage.py wazuh_status` for command-line status.

Milestone 3 is complete for the Ubuntu PC's local testing lab: managed HTTPS
receipt, continuous export, exact manager receipt and process recovery were
verified on 6 November 2026. Use [the local lab guide](docs/local_wazuh_lab.md)
for start/stop commands, access and verification evidence. The commands above
are for manual deployments; do not start a second exporter while its lab service runs.
See [Wazuh setup and verification](docs/wazuh_integration.md) for other hosts and
storage/replay limits. [Roadmap](docs/roadmap.md): milestones 1–4 complete for the
local lab; hardening is milestone 5 and Android collection is milestone 6.

Milestone 4 now includes [Wazuh rules and investigation tools](docs/wazuh_detection.md).
It indexes routine activity at informational level and detects recognized SSH
failures, repeated failures, possible brute force and successes after failures.
The rules are active on the Ubuntu lab: all 20 Wazuh scenarios passed, and exact
real package and SSH login events were verified in the manager and dashboard's
index. Open an inbox record to inspect its evidence and copy its Wazuh search,
or use **Discover → Open → LogSentry — All events** in Wazuh with the appropriate
time range. The guide includes installation steps for other hosts, isolated
Wazuh scenarios and the exact `verify_wazuh_alert` command.

## Collect local Ubuntu/Termux logs

```bash
python3 -m logsentry.collector --discover --year 2026 --timezone UTC
python3 -m logsentry.collector --watch
```

Use the actual source year/timezone. In another terminal start Django as above,
then open **http://127.0.0.1:8000/** (`/collected/` also works). Select a source to inspect saved
records and supported SSH findings. Collection checks every second; the page
updates automatically every two seconds. Use **Pause updates** while reading.
Keep both the collector and Django running. Ctrl+C stops the
collector; its saved positions let it resume without re-importing unchanged logs.

Discovery checks existing Ubuntu/Termux authentication and package log paths.
It does not create missing SSH logs. Package and plain text logs provide context;
only supported SSH records receive the existing authentication detections.
Records are stored privately under ignored `runtime/`, with 10,000 retained
per source. The collector runs locally and needs read access to each source.
See [local collection setup and limits](docs/local_collection.md).

## Collect real SSH authentication

For systems without `auth.log` or a running journal, LogSentry can capture actual
OpenSSH output from a separate localhost endpoint. With OpenSSH installed, run
`python3 -m logsentry.ssh_capture setup` once, then
`python3 -m logsentry.ssh_capture serve`. Keep the collector running and select
**local-ssh** in the dashboard. The command prints a key-based login check.
See [SSH collection](docs/ssh_collection.md) for setup and the observation-time
limitations of direct SSH output. Existing `/var/log/auth.log` files can instead
be registered directly as `syslog` sources.

## Save an incident report

For an existing Ubuntu SSH authentication log, supply its path, starting year
and source timezone. For example, if `/var/log/auth.log` exists and its dates
start in 2026 using UTC:

```bash
python3 -m logsentry /var/log/auth.log --year 2026 --timezone UTC --output reports/auth_incident.txt
```

The command displays the report and saves a new UTF-8 file. Existing output
paths are refused. Use a new filename for another run. New files are private
to their owner on POSIX systems. Reports are ignored by Git.

Traditional timestamps omit the year and timezone, so supply the actual
starting year and configure the source system's timezone. UTC is the default.
Historic logs should not automatically use today's year. The CLI analyzes
supported SSH log files; it does not invent authentication data when a source
is missing. The current Termux/Ubuntu environment needs an SSH log source
configured before this command can analyze actual login activity.

## Customize the rules

```bash
python3 -m logsentry --help
```

Options control thresholds, time windows, trusted networks, normal hours, year,
and timezone. For example:

```bash
python3 -m logsentry /var/log/auth.log --year 2026 --trusted-network 192.168.1.0/24 --trusted-network 10.0.0.0/8
```

Supplying trusted networks replaces the default `192.168.1.0/24`. Use
`--no-trusted-networks` to flag all successful sources as unexpected.

## Verify the code

```bash
python3 -m unittest discover -s tests -v
```

For the Django pages, with `.venv` active:

```bash
python manage.py check
python manage.py test receiver dashboard -v 2
node --test tests/collected_live.test.cjs
```

Fictional records live only in the test fixtures and temporary test stores.
They are never loaded by the dashboard or auto-discovered by the collector.
The older `log_reader.py` and `logsentry_reference.py` teaching scripts require
an explicit input path; use `python3 -m logsentry` for the maintained CLI.

Read [the command/report walkthrough](docs/command_and_reports.md) for the
complete flow and links to explanations of the individual modules.
