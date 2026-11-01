# LogSentry

A Python security log analyzer focused on Ubuntu SSH authentication. The engine
reads log files, detects suspicious patterns, assigns priorities, and generates
investigation reports. A Django dashboard is planned; this version is a CLI.

Requires Python 3.10+ and system timezone data. No third-party Python packages
are needed. Run commands from the **project root**, not inside `tests/` or
`logsentry/`.

## Run the sample

```bash
cd /root/LogSentry
python3 -m logsentry samples/auth.log --year 2026 --timezone UTC
```

The fictional sample has 12 parsed events, six failed logins, three successful
logins, and six alerts: three High and three Medium. Alerts may overlap; they
are not six independent incidents or confirmation of an attack.

## Save an incident report

```bash
python3 -m logsentry samples/auth.log --year 2026 --timezone UTC --output reports/sample_incident.txt
```

The command displays the report and saves a new UTF-8 file. Existing output
paths are refused. Use a new filename for another run. New files are private
to their owner on POSIX systems. Reports are ignored by Git.

Traditional timestamps omit the year and timezone, so supply the actual
starting year and configure the source system's timezone. UTC is the default.
The sample year is 2026; historic logs should not automatically use today's year.

## Customize the rules

```bash
python3 -m logsentry --help
```

Options control thresholds, time windows, trusted networks, normal hours, year,
and timezone. For example:

```bash
python3 -m logsentry samples/auth.log --year 2026 --trusted-network 192.168.1.0/24 --trusted-network 203.0.113.0/24
```

Supplying trusted networks replaces the default `192.168.1.0/24`. Use
`--no-trusted-networks` to flag all successful sources as unexpected.

## Verify the code

```bash
python3 -m unittest discover -s tests -v
```

Read [the command/report walkthrough](docs/command_and_reports.md) for the
complete flow and links to explanations of the individual modules.
