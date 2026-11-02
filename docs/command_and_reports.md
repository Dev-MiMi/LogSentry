# Features 3 and 8: a runnable command and investigation report

The sample calculations in this learning walkthrough use the fictional test
fixture in `tests/fixtures/ssh_auth.log`. The dashboard displays collected system
logs only; see [local collection](local_collection.md) for operational use.

The package now has an entry point that calls the existing functions. You do
not need to run `parser.py` or `detection.py` directly.

## Try it

Run from the project root:

```bash
cd /root/LogSentry
python3 -m logsentry tests/fixtures/ssh_auth.log --year 2026 --timezone UTC
```

The report describes all six sample findings, their priorities, reasons, and
supporting source lines. There are three High and three Medium alerts. The
same evidence can support more than one rule, so these are not six distinct
incidents. The reference script's older severity assumptions are independent
of the current engine's policy.

To save a new report as well:

```bash
python3 -m logsentry tests/fixtures/ssh_auth.log --year 2026 --timezone UTC --output reports/sample_incident.txt
```

Existing paths are refused. Choose another filename on subsequent runs. Reports
are UTF-8 text, owner-only on POSIX systems, and excluded from Git. You can
read them in your editor. The function does not overwrite existing symlinks,
hardlinks, log files, or reports. Output parent directories are created as
needed. If a write fails after creation, a partial new file may remain;
the command returns an error and a retry requires a different filename.

## The three new files

### `logsentry/__main__.py`: start the package

When you run `python3 -m logsentry`, Python starts this file in package context.
It imports `main` from `cli.py`, calls it, and converts its return value into
the process exit code:

```python
raise SystemExit(main())
```

This is the difference between a module defining functions and a runnable
program calling them.

### `logsentry/cli.py`: coordinate the work

`argparse` reads the filename and flags. For example, `--year 2026` becomes an
integer setting, and `--output reports/sample_incident.txt` becomes an output
path. Settings validation runs before reading any log.

`analyze_log(log_path, settings)` follows this order:

1. `read_system_logs` returns parsed events and issues (Feature 1).
2. Detection functions examine those events (Features 2, 4, 5, and 6).
3. Their Alert records carry severity and evidence (Feature 7).
4. The function returns an Analysis holding the input, policy, alerts, and time.

`analyze_log` does not print or save. A future Django view can use the same result
to build dashboard pages. The `main` function builds the report, optionally
saves it, and displays it. Errors and saved-file messages go to stderr, while
the report goes to stdout.

The flow is:

```text
__main__.py starts cli.main()
    → validate settings
    → read_system_logs()
    → detection rules
    → Analysis record
    → build_investigation_report()
    → display report / optionally generate_incident_report()
```

### `logsentry/reporting.py`: explain and preserve findings

`build_investigation_report(analysis)` returns text (Feature 3). It includes:

- Source, generated time, event counts, blank lines, and rejected-line counts.
- First/last event times and the policy used for interpretation.
- Findings ordered by severity and time, with reasons and original source lines.
- Parsing issues and limitations that affect the findings.
- Suggested investigation steps; it does not carry out those actions.

`generate_incident_report(report, path)` creates the text file (Feature 8).
Generating text and writing it are separate so a Django page can eventually
offer a download without writing arbitrary paths on the web server.

Text from logs and filenames is escaped for terminal display: newline,
terminal-control, and invisible formatting characters cannot inject fake
headings or terminal commands into the displayed report. The original evidence
in each event remains unchanged. A future HTML view still needs normal Django
HTML escaping; this terminal escaping is not an HTML sanitizer.

## Settings and exit codes

Run `python3 -m logsentry --help` to see all options. The starting year is
required so historic yearless logs do not accidentally use the current year.
UTC is the default timezone; configure the actual source timezone as needed.
Thresholds, windows in minutes, hours, and trusted networks are configurable.

`--trusted-network` can be repeated and replaces the default subnet. The flag
`--no-trusted-networks` means every source is unexpected; it does not disable
network checks and cannot be combined with `--trusted-network`.

| Exit code | Meaning |
| --- | --- |
| 0 | Completed, including runs that produced alerts |
| 1 | Input/output failure, including missing files or existing output paths |
| 2 | Invalid/missing arguments or invalid settings |
| 3 | Completed with rejected log lines; report has partial coverage |

No alerts does not mean the machine is safe. Empty inputs and files with no
supported SSH events are explicitly identified in the report. Partial parses
still produce a report with rejected lines listed and exit code 3.

## Run verification

From the project root:

```bash
python3 -m unittest discover -s tests -v
```

The new checks run the actual module command, verify sample findings and policy
changes, inspect saved-file contents/permissions, and test rejected input,
existing outputs, link preservation, error handling, and display escaping.

For earlier module explanations, see [the foundation](engine_foundation.md),
[repeated failures](repeated_failures.md), [brute force](brute_force.md),
[suspicious logins](suspicious_logins.md), and [suspicious events](suspicious_events.md).

This is a batch CLI, not a continuous log collector or Django application yet.
