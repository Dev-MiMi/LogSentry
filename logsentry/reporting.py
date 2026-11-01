"""FEATURES 3 AND 8: Explain findings and optionally save an incident report."""

from collections import Counter
from pathlib import Path
import os
import unicodedata

from .data import Analysis


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _safe_text(value: object) -> str:
    """Display untrusted text without letting it inject terminal control codes.

    Escaping also prevents a filename or raw log from inserting fake report
    headings. The original evidence in LogEvent remains unchanged.
    """
    text = str(value)
    return "".join(
        character.encode("unicode_escape").decode("ascii")
        if unicodedata.category(character).startswith("C") else character
        for character in text
    )


def build_investigation_report(analysis: Analysis) -> str:
    """FEATURE 3: Return readable text without printing or writing any files."""
    parsed = analysis.parsed
    settings = analysis.settings
    event_counts = Counter(event.event_type for event in parsed.events)
    severity_counts = Counter(alert.severity for alert in analysis.alerts)
    alerts = sorted(analysis.alerts, key=lambda alert: (
        SEVERITY_ORDER[alert.severity], alert.timestamp, alert.hostname,
        alert.source_ip, alert.rule, alert.usernames, alert.evidence[-1].line_number,
    ))
    lines = [
        "LOGSENTRY INVESTIGATION / INCIDENT REPORT",
        "=" * 40,
        f"Generated (UTC): {analysis.generated_at.isoformat()}",
        f"Log source: {_safe_text(analysis.source_name)}",
        "",
        "INPUT AND COVERAGE",
        f"Total input lines: {parsed.total_lines}",
        f"Parsed events: {len(parsed.events)}",
        f"Blank lines: {parsed.blank_lines}",
        f"Rejected lines: {len(parsed.issues)}",
        f"Failed logins: {event_counts['failed_login']}",
        f"Successful logins: {event_counts['successful_login']}",
        f"Invalid-user notices: {event_counts['invalid_user']}",
        f"Other events: {event_counts['other']}",
    ]
    if parsed.events:
        lines.extend([
            f"First event (UTC): {min(event.timestamp for event in parsed.events).isoformat()}",
            f"Last event (UTC): {max(event.timestamp for event in parsed.events).isoformat()}",
        ])
    if parsed.issues:
        lines.append("Coverage: PARTIAL. Rejected lines were not analyzed; review the issues below.")
    if not any(event_counts[kind] for kind in ("failed_login", "successful_login", "invalid_user")):
        lines.append("Coverage: No supported SSH authentication events were available to assess.")

    # Display the policy actually used, including assumptions for yearless logs.
    lines.extend([
        "", "POLICY USED",
        f"Legacy timestamp starting year: {settings.year}",
        f"Local timezone for timestamps and login hours: {_safe_text(settings.timezone_name)}",
        f"Normal login hours: {settings.normal_start_hour:02d}:00-{settings.normal_end_hour:02d}:00 (end exclusive)",
        "Trusted networks: " + (", ".join(settings.trusted_networks) or "None (all sources are unexpected)"),
        f"Repeated failures: {settings.repeated_threshold} across the imported log",
        f"Brute-force rule: {settings.brute_force_threshold} failures within {settings.brute_force_window}",
        f"Success after failures: {settings.repeated_threshold} failures within {settings.success_after_failures_window}, same account/host/IP",
        "", "SEVERITY SUMMARY",
        f"Total alerts: {len(alerts)}",
    ])
    for severity in SEVERITY_ORDER:
        lines.append(f"{severity}: {severity_counts[severity]}")

    lines.extend(["", "INVESTIGATION FINDINGS"])
    if not alerts:
        lines.append("No alerts were produced from the parsed events under this policy.")

    for number, alert in enumerate(alerts, start=1):
        lines.extend([
            "", f"Finding {number}: {_safe_text(alert.rule)}",
            f"Severity: {alert.severity}",
            f"Time (UTC): {alert.timestamp.isoformat()}",
            f"Host: {_safe_text(alert.hostname)}",
            f"Source IP: {_safe_text(alert.source_ip)}",
            "Usernames: " + (", ".join(_safe_text(name) for name in alert.usernames) or "Unknown"),
            f"Reason: {_safe_text(alert.description)}",
            "Supporting log records (not necessarily distinct login attempts):",
        ])
        for event in sorted(alert.evidence, key=lambda item: (item.timestamp, item.line_number)):
            lines.append(f"  Line {event.line_number}: {_safe_text(event.raw_line)}")

    lines.extend(["", "PARSING ISSUES"])
    if not parsed.issues:
        lines.append("None.")
    for issue in parsed.issues:
        lines.append(f"Line {issue.line_number}: {_safe_text(issue.reason)}")

    lines.extend([
        "", "INTERPRETATION AND LIMITS",
        "Alerts are investigation leads, not proof of an attack or confirmed compromise.",
        "Related rules can reuse evidence; alert totals are not unique incident counts.",
        "Yearless timestamps use the chosen starting year and month-order rollover assumption.",
        "Rules assess this batch only; duplicate records are not deduplicated.",
        "Brute-force findings report the first qualifying burst per host/IP in this import.",
        "Network matching is an explicit policy, not an IP reputation lookup.",
        "", "SUGGESTED NEXT STEPS",
        "Review evidence and parsing issues, and confirm the log year, timezone, and policy.",
    ])
    if alerts:
        lines.extend([
            "Confirm whether the affected accounts, source IPs, and login times are expected.",
            "Review activity following any successful login after failures.",
            "If compromise is confirmed, follow your incident-response process for containment and recovery.",
        ])
    return "\n".join(lines) + "\n"


def generate_incident_report(report: str, report_path: str | Path) -> Path:
    """FEATURE 8: Create a new UTF-8 report, refusing to overwrite any path.

    The new file is readable/writable by its owner on POSIX systems (0600).
    O_EXCL also refuses existing symlinks and hard-linked files. Parent folders
    are created if needed. A write failure is propagated to the caller.
    """
    path = Path(report_path)
    # Encode before file creation so bad input cannot create an empty artifact.
    contents = report.encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as report_file:
        report_file.write(contents)
    return path
