"""Detection rules examine parsed facts and return alerts for investigation.

This module currently implements Feature 4. Other rules will be added one at
a time. Importing it does not read files or run the detectors automatically.
"""

from collections import defaultdict
from typing import Iterable

from .config import DetectionSettings
from .data import Alert, LogEvent


# FEATURE 4: Detect repeated failed logins per host and source IP.
def detect_repeated_failed_logins(
    events: Iterable[LogEvent], settings: DetectionSettings
) -> list[Alert]:
    """Return one alert per host/IP with enough failures in this input.

    This rule counts the entire imported log, regardless of elapsed time.
    It does not establish a brute-force attack; Feature 5 will apply a window.
    Different usernames on the same host/IP are counted together and listed
    in the alert, because one source may try several accounts.
    """
    # Each key identifies BOTH the target machine and the login source.
    # defaultdict(list) creates an empty list when we first encounter a key.
    failures_by_source: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)

    for event in events:
        # Ignore successful logins, session messages, and invalid-user notices.
        # A failed login for an invalid user is counted once as failed_login.
        if event.event_type != "failed_login" or not event.source_ip:
            continue
        key = (event.hostname, event.source_ip)
        failures_by_source[key].append(event)

    alerts = []
    for (hostname, source_ip), failures in failures_by_source.items():
        if len(failures) < settings.repeated_threshold:
            continue

        # Sorting preserves a readable evidence timeline even if input records
        # arrive out of order. The caller's event list is not modified.
        evidence = tuple(sorted(
            failures, key=lambda event: (event.timestamp, event.line_number)
        ))
        usernames = tuple(sorted({
            event.username for event in evidence if event.username is not None
        }))

        alerts.append(Alert(
            rule="repeated_failed_logins",
            # FEATURE 7: Medium is this rule's initial investigation priority.
            # The evidence shows repetition; it does not confirm compromise.
            severity="Medium",
            hostname=hostname,
            source_ip=source_ip,
            usernames=usernames,
            description=(
                f"Observed {len(evidence)} failed logins from {source_ip} "
                f"on {hostname} across the imported log "
                f"(threshold: {settings.repeated_threshold})."
            ),
            evidence=evidence,
        ))

    # Return a predictable order for tests and the eventual dashboard.
    return sorted(alerts, key=lambda alert: (
        alert.timestamp, alert.hostname, alert.source_ip
    ))
