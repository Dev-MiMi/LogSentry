# LogSentry

A Python security log analyzer focused on Ubuntu SSH authentication. The engine
reads log files, detects suspicious patterns, assigns priorities, and generates
investigation reports. It includes a CLI, a local Django dashboard, and an
incremental collector for accessible Ubuntu/Termux log files.

Requires Python 3.10+ and system timezone data. No third-party Python packages
are needed for the engine. The dashboard uses Django 5.2 LTS, installed in
`.venv`. Run commands from the **project root**, not inside `tests/` or
`logsentry/`.

## Open the web dashboard

```bash
cd /root/LogSentry
source .venv/bin/activate
python manage.py runserver 127.0.0.1:8000
```

Open **http://127.0.0.1:8000/** on the device running the server. The homepage
lists sources and counts from the local collection database. Select a source
to inspect its records and supported SSH findings. Without collected data, it
shows an empty state. All displayed events come from explicitly collected files;
there is no sample dashboard or demo-data fallback. Times use Nigeria time,
**WAT (UTC+1)**. User accounts and log uploads are not implemented yet. See
[the Django walkthrough](docs/django_dashboard.md) for setup and the request flow.

To install the web dependencies on another machine:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

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
python manage.py test dashboard -v 2
node --test tests/collected_live.test.cjs
```

Fictional records live only in the test fixtures and temporary test stores.
They are never loaded by the dashboard or auto-discovered by the collector.
The older `log_reader.py` and `logsentry_reference.py` teaching scripts require
an explicit input path; use `python3 -m logsentry` for the maintained CLI.

Read [the command/report walkthrough](docs/command_and_reports.md) for the
complete flow and links to explanations of the individual modules.
