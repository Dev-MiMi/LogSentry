"""A complete, beginner-friendly reference version of the LogSentry engine.

This file demonstrates the eight planned LogSentry features in one place.
It reads the fictional Ubuntu authentication log in samples/auth.log.

Run it from the project directory with:
    python3 logsentry_reference.py
"""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
import ipaddress
import re
from typing import Optional


# ---------------------------------------------------------------------------
# SETTINGS: These values make the detection rules easy to change later.
# ---------------------------------------------------------------------------

LOG_PATH = Path("samples/auth.log")
REPORT_PATH = Path("reports/latest_incident_report.txt")

# Three failures from one IP are treated as repeated failed login attempts.
REPEATED_FAILURE_THRESHOLD = 3

# Five failures within five minutes are treated as a possible brute-force attack.
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=5)

# A successful login after repeated failures within ten minutes may mean that
# an attacker eventually guessed the password.
COMPROMISE_WINDOW = timedelta(minutes=10)

# Successful logins before 06:00 or from 22:00 onward are considered unusual.
NORMAL_LOGIN_START_HOUR = 6
NORMAL_LOGIN_END_HOUR = 22

# These are the networks that this example treats as trusted office networks.
# A real installation would load this list from a configuration file.
TRUSTED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


# ---------------------------------------------------------------------------
# DATA CLASSES: These give each parsed event and alert a clear structure.
# ---------------------------------------------------------------------------


@dataclass
class LogEvent:
    """One useful event extracted from a raw system-log line."""

    timestamp: datetime
    event_type: str
    outcome: str
    username: Optional[str]
    source_ip: Optional[str]
    raw_line: str


@dataclass
class Alert:
    """One suspicious finding produced by a LogSentry detection rule."""

    alert_type: str
    severity: str
    timestamp: datetime
    description: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    evidence: list[str] = field(default_factory=list)


# These regular expressions extract usernames and IP addresses from SSH logs.
FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<ip>\S+)"
)
SUCCESS_LOGIN_PATTERN = re.compile(
    r"Accepted \S+ for (?P<username>\S+) from (?P<ip>\S+)"
)
INVALID_USER_PATTERN = re.compile(
    r"Invalid user (?P<username>\S+) from (?P<ip>\S+)"
)
LOG_PREFIX_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<message>.*)$"
)


# ---------------------------------------------------------------------------
# FEATURE 1: READ SYSTEM LOGS
# Read the file line by line, parse useful SSH events, and safely skip lines
# that LogSentry does not yet understand.
# ---------------------------------------------------------------------------


def parse_log_line(line: str, year: int) -> Optional[LogEvent]:
    """Convert one Ubuntu auth-log line into a LogEvent object."""

    prefix_match = LOG_PREFIX_PATTERN.match(line)
    if not prefix_match:
        return None

    # Ubuntu's traditional auth.log timestamp has no year, so this learning
    # version supplies the current year when converting it to datetime.
    timestamp_text = (
        f"{year} {prefix_match.group('month')} "
        f"{prefix_match.group('day')} {prefix_match.group('clock')}"
    )
    try:
        timestamp = datetime.strptime(timestamp_text, "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    message = prefix_match.group("message")

    # Check a failed login before checking "Invalid user", because some failed
    # login lines contain both phrases.
    failed_match = FAILED_LOGIN_PATTERN.search(message)
    if failed_match:
        return LogEvent(
            timestamp=timestamp,
            event_type="failed_login",
            outcome="failure",
            username=failed_match.group("username"),
            source_ip=failed_match.group("ip"),
            raw_line=line,
        )

    success_match = SUCCESS_LOGIN_PATTERN.search(message)
    if success_match:
        return LogEvent(
            timestamp=timestamp,
            event_type="successful_login",
            outcome="success",
            username=success_match.group("username"),
            source_ip=success_match.group("ip"),
            raw_line=line,
        )

    invalid_match = INVALID_USER_PATTERN.search(message)
    if invalid_match:
        return LogEvent(
            timestamp=timestamp,
            event_type="invalid_user",
            outcome="failure",
            username=invalid_match.group("username"),
            source_ip=invalid_match.group("ip"),
            raw_line=line,
        )

    # Other log lines are still kept for the investigation summary, although
    # this version does not run detection rules against them.
    return LogEvent(
        timestamp=timestamp,
        event_type="other",
        outcome="informational",
        username=None,
        source_ip=None,
        raw_line=line,
    )


def read_system_logs(log_path: Path) -> list[LogEvent]:
    """Read a log file and return all events that could be parsed."""

    events = []
    current_year = datetime.now().year

    with log_path.open(encoding="utf-8") as log_file:
        for line in log_file:
            event = parse_log_line(line.strip(), current_year)
            if event is not None:
                events.append(event)

    return events


# ---------------------------------------------------------------------------
# FEATURE 7: ASSIGN SEVERITY LEVELS TO ALERTS
# All detection functions use this one severity function, so the policy is
# consistent and can be changed in one place.
# ---------------------------------------------------------------------------


def assign_severity(
    alert_type: str,
    failed_count: int = 0,
    reason_count: int = 1,
) -> str:
    """Return Critical, High, Medium, or Low for an alert."""

    if alert_type == "possible_account_compromise":
        return "Critical"
    if alert_type == "brute_force":
        return "High"
    if alert_type == "suspicious_login" and reason_count >= 2:
        return "High"
    if alert_type in {"suspicious_login", "invalid_user"}:
        return "Medium"
    if alert_type == "repeated_failed_logins" and failed_count >= 5:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# FEATURE 2: DETECT SUSPICIOUS EVENTS
# This general detector finds invalid usernames and a successful login that
# happens soon after several failures from the same IP address.
# ---------------------------------------------------------------------------


def detect_suspicious_events(events: list[LogEvent]) -> list[Alert]:
    """Detect invalid users and possible successful account compromise."""

    alerts = []
    failures_by_ip: dict[str, list[LogEvent]] = defaultdict(list)

    for event in sorted(events, key=lambda item: item.timestamp):
        if event.event_type == "failed_login" and event.source_ip:
            failures_by_ip[event.source_ip].append(event)

        if event.event_type == "invalid_user":
            alerts.append(
                Alert(
                    alert_type="invalid_user",
                    severity=assign_severity("invalid_user"),
                    timestamp=event.timestamp,
                    description=f"Login attempt used unknown account '{event.username}'.",
                    source_ip=event.source_ip,
                    username=event.username,
                    evidence=[event.raw_line],
                )
            )

        if event.event_type == "successful_login" and event.source_ip:
            recent_failures = [
                failure
                for failure in failures_by_ip[event.source_ip]
                if timedelta(0)
                <= event.timestamp - failure.timestamp
                <= COMPROMISE_WINDOW
            ]

            if len(recent_failures) >= REPEATED_FAILURE_THRESHOLD:
                evidence = [failure.raw_line for failure in recent_failures]
                evidence.append(event.raw_line)
                alerts.append(
                    Alert(
                        alert_type="possible_account_compromise",
                        severity=assign_severity("possible_account_compromise"),
                        timestamp=event.timestamp,
                        description=(
                            f"Successful login followed {len(recent_failures)} "
                            "recent failures from the same IP."
                        ),
                        source_ip=event.source_ip,
                        username=event.username,
                        evidence=evidence,
                    )
                )

    return alerts


# ---------------------------------------------------------------------------
# FEATURE 4: DETECT REPEATED FAILED LOGIN ATTEMPTS
# Count failed logins for each source IP and alert when the count reaches the
# configured repeated-failure threshold.
# ---------------------------------------------------------------------------


def detect_repeated_failed_logins(events: list[LogEvent]) -> list[Alert]:
    """Find IP addresses responsible for repeated failed logins."""

    failures_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "failed_login" and event.source_ip:
            failures_by_ip[event.source_ip].append(event)

    alerts = []
    for source_ip, failures in failures_by_ip.items():
        if len(failures) >= REPEATED_FAILURE_THRESHOLD:
            ordered_failures = sorted(failures, key=lambda item: item.timestamp)
            alerts.append(
                Alert(
                    alert_type="repeated_failed_logins",
                    severity=assign_severity(
                        "repeated_failed_logins",
                        failed_count=len(failures),
                    ),
                    timestamp=ordered_failures[-1].timestamp,
                    description=(
                        f"Detected {len(failures)} failed logins from one IP."
                    ),
                    source_ip=source_ip,
                    username=ordered_failures[-1].username,
                    evidence=[event.raw_line for event in ordered_failures],
                )
            )

    return alerts


# ---------------------------------------------------------------------------
# FEATURE 5: FLAG POSSIBLE BRUTE-FORCE ATTACKS
# Use a sliding time window so five failures trigger an alert only when they
# occur within five minutes, rather than anywhere in the whole log file.
# ---------------------------------------------------------------------------


def detect_brute_force_attacks(events: list[LogEvent]) -> list[Alert]:
    """Find at least five failures from one IP within five minutes."""

    failures_by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.event_type == "failed_login" and event.source_ip:
            failures_by_ip[event.source_ip].append(event)

    alerts = []
    for source_ip, failures in failures_by_ip.items():
        ordered_failures = sorted(failures, key=lambda item: item.timestamp)

        # Each starting position is tested with the fifth event after it.
        # Stop after the first matching window to avoid duplicate alerts.
        for start_index in range(
            len(ordered_failures) - BRUTE_FORCE_THRESHOLD + 1
        ):
            window = ordered_failures[
                start_index : start_index + BRUTE_FORCE_THRESHOLD
            ]
            duration = window[-1].timestamp - window[0].timestamp

            if duration <= BRUTE_FORCE_WINDOW:
                alerts.append(
                    Alert(
                        alert_type="brute_force",
                        severity=assign_severity("brute_force"),
                        timestamp=window[-1].timestamp,
                        description=(
                            f"Detected {BRUTE_FORCE_THRESHOLD} failed logins "
                            f"within {duration}."
                        ),
                        source_ip=source_ip,
                        username=window[-1].username,
                        evidence=[event.raw_line for event in window],
                    )
                )
                break

    return alerts


# ---------------------------------------------------------------------------
# FEATURE 6: IDENTIFY SUSPICIOUS LOGIN TIMES AND SOURCE IPS
# Check successful logins against normal working hours and trusted networks.
# ---------------------------------------------------------------------------


def is_trusted_ip(source_ip: str) -> bool:
    """Return True when an IP belongs to one of the configured networks."""

    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return False

    return any(address in network for network in TRUSTED_NETWORKS)


def detect_suspicious_logins(events: list[LogEvent]) -> list[Alert]:
    """Find successful logins at unusual times or from untrusted IPs."""

    alerts = []
    for event in events:
        if event.event_type != "successful_login" or not event.source_ip:
            continue

        reasons = []
        if not (
            NORMAL_LOGIN_START_HOUR
            <= event.timestamp.hour
            < NORMAL_LOGIN_END_HOUR
        ):
            reasons.append("login occurred outside normal hours")

        if not is_trusted_ip(event.source_ip):
            reasons.append("source IP is outside the trusted networks")

        if reasons:
            alerts.append(
                Alert(
                    alert_type="suspicious_login",
                    severity=assign_severity(
                        "suspicious_login",
                        reason_count=len(reasons),
                    ),
                    timestamp=event.timestamp,
                    description="; ".join(reasons).capitalize() + ".",
                    source_ip=event.source_ip,
                    username=event.username,
                    evidence=[event.raw_line],
                )
            )

    return alerts


# ---------------------------------------------------------------------------
# FEATURE 3: PRODUCE AN INVESTIGATION REPORT
# Turn the parsed evidence and alerts into a readable report for an analyst.
# ---------------------------------------------------------------------------


def build_investigation_report(
    log_path: Path,
    events: list[LogEvent],
    alerts: list[Alert],
) -> str:
    """Build a plain-text security investigation report."""

    event_counts = Counter(event.event_type for event in events)
    severity_counts = Counter(alert.severity for alert in alerts)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    ordered_alerts = sorted(
        alerts,
        key=lambda alert: (
            severity_order.get(alert.severity, 99),
            alert.timestamp,
        ),
    )

    lines = [
        "LOGSENTRY SECURITY INVESTIGATION REPORT",
        "=" * 41,
        f"Generated (UTC): {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S}",
        f"Log source: {log_path}",
        f"Total parsed events: {len(events)}",
        f"Failed logins: {event_counts['failed_login']}",
        f"Successful logins: {event_counts['successful_login']}",
        f"Total alerts: {len(alerts)}",
        "",
        "ALERT SEVERITY SUMMARY",
        "-" * 22,
    ]

    for severity in ("Critical", "High", "Medium", "Low"):
        lines.append(f"{severity}: {severity_counts[severity]}")

    lines.extend(["", "INVESTIGATION FINDINGS", "-" * 22])

    if not ordered_alerts:
        lines.append("No suspicious events were detected.")

    for number, alert in enumerate(ordered_alerts, start=1):
        lines.extend(
            [
                "",
                f"Finding {number}: {alert.alert_type.replace('_', ' ').title()}",
                f"Severity: {alert.severity}",
                f"Time: {alert.timestamp}",
                f"Source IP: {alert.source_ip or 'Unknown'}",
                f"Username: {alert.username or 'Unknown'}",
                f"Reason: {alert.description}",
                "Evidence:",
            ]
        )
        for evidence_line in alert.evidence:
            lines.append(f"  - {evidence_line}")

    lines.extend(
        [
            "",
            "RECOMMENDED INVESTIGATION ACTIONS",
            "-" * 33,
            "1. Confirm whether the source IP and login time are expected.",
            "2. Review the affected account's recent authentication activity.",
            "3. Reset credentials if account compromise is suspected.",
            "4. Block or monitor hostile source IPs according to local policy.",
        ]
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# FEATURE 8: GENERATE AN INCIDENT REPORT FILE
# Save the complete investigation report so it can later be downloaded from
# the Django dashboard or attached to an incident record.
# ---------------------------------------------------------------------------


def generate_incident_report(report: str, report_path: Path) -> None:
    """Create the report directory and write the report to disk."""

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# PROGRAM FLOW: Run all eight features in order.
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the LogSentry reference engine from log input to report output."""

    try:
        events = read_system_logs(LOG_PATH)
    except FileNotFoundError:
        print(f"Log file was not found: {LOG_PATH}")
        return
    except PermissionError:
        print(f"Permission denied while reading: {LOG_PATH}")
        return

    # Each detector returns Alert objects. Combining them gives the report one
    # list of findings, regardless of which rule found each problem.
    alerts = []
    alerts.extend(detect_suspicious_events(events))
    alerts.extend(detect_repeated_failed_logins(events))
    alerts.extend(detect_brute_force_attacks(events))
    alerts.extend(detect_suspicious_logins(events))

    report = build_investigation_report(LOG_PATH, events, alerts)
    generate_incident_report(report, REPORT_PATH)

    # Print the same report in the terminal for immediate review.
    print(report)
    print(f"\nIncident report saved to: {REPORT_PATH}")


if __name__ == "__main__":
    main()
