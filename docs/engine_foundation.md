# Reading the three foundation modules

These modules implement the log-reading foundation. They do not yet run
detection rules, generate reports, or serve a Django dashboard. Your existing
`log_reader.py` and `logsentry_reference.py` remain separate learning examples.

## 1. `logsentry/config.py`: What policy do we want?

`DetectionSettings` groups our decisions in one record. For example:

```python
settings = DetectionSettings(year=2026, timezone_name="Africa/Lagos")
```

The starting year is explicit because traditional Ubuntu logs omit it. The
timezone describes the machine that produced the log, not necessarily the
machine running LogSentry. Other fields hold our planned failure thresholds,
time windows, trusted networks, and normal login hours.

`__post_init__` runs automatically when settings are created. It rejects values
such as negative time windows, fractional thresholds, and invalid networks.
`frozen=True` prevents changing the policy accidentally after construction.
The example trusted network is a lab setting, not a claim that private IPs
are automatically trustworthy. The thresholds are policy choices to tune.

## 2. `logsentry/data.py`: What information are we keeping?

`LogEvent` represents an observed log entry. A failed-login event contains its
timestamp, hostname, username, source IP, authentication method, original line,
and line number. Times are stored in UTC so later calculations compare the same
clock. The original line remains available as evidence.

`ParsedLog` groups the results into `events` and `issues`. An issue means a line
could not be interpreted; it does not mean the activity was safe. It also counts
total and blank lines. `field(default_factory=list)` gives each result its own
list instead of accidentally sharing one list between separate imports.

`Alert` and `Analysis` are records for the next stage. They do not perform
detection. An alert must have a recognized severity and evidence. Its timestamp
is the latest time in that evidence. An analysis will bundle the input, policy,
findings, and generation time for reports or a dashboard.

## 3. `logsentry/parser.py`: How do we extract the facts?

The public entry point is `read_system_logs(path, settings)`:

1. Read bounded lines from a UTF-8 file.
2. Check the timestamp, hostname, process, and message format.
3. Recognize SSH successes, failures, and invalid-user attempts.
4. Validate the IP and source port; normalize equivalent IP spellings.
5. Return events plus a visible list of rejected lines.

A message from another application is kept as `other`, even if it contains
“Failed password.” Supported SSH process names are `sshd` and `sshd-session`.
These format checks are not proof that the input file itself is authentic.

The parser accepts traditional timestamps and ISO timestamps with a year.
Offsets in ISO timestamps take precedence over the configured timezone.
Legacy December-to-January rollover assumes the file's months are in order;
yearless logs cannot resolve arbitrary ordering or multiple years reliably.
Ambiguous/nonexistent local times around daylight-saving changes are reported
as issues unless the log gives an explicit offset. The parser supports this
Ubuntu syslog format, not every journal export, Windows log, or application log.

The batch limits are 10 MiB, 100,000 lines, and 8 KiB per line. Oversized input
raises `InputLimitError`; invalid UTF-8 raises `ValueError`. Missing files and
permission failures reach the caller so the future UI can display them.
The reader bounds each raw line before decoding it to avoid loading a giant
single-line file into memory. Results still use memory within those limits.

## See one input become a structured event

Run Python from the project directory:

```bash
python3
```

Then type:

```python
from logsentry.config import DetectionSettings
from logsentry.parser import read_system_logs

settings = DetectionSettings(year=2026)
result = read_system_logs("samples/auth.log", settings)

print(len(result.events))             # 12 parsed events
print(len(result.issues))             # 0 rejected lines
event = result.events[3]              # The fourth sample entry
print(event.username)                 # bob
print(event.source_ip)                # 203.0.113.42
print(event.timestamp.isoformat())    # 2026-10-29T10:15:01+00:00
print(event.line_number)              # 4
```

The next module will examine these facts and decide which ones warrant alerts.
For now, no alert is generated merely by reading a log.

## Verify the behavior

```bash
python3 -m unittest discover -s tests -v
```

The checks cover real sample counts, invalid inputs, settings validation,
timezone conversion, New Year rollover, bounded reading, and evidence records.
They run with Python's standard library; no Django installation is needed yet.
