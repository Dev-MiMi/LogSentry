"""Detection rules examine parsed facts and return alerts for investigation.

This module currently implements Features 4 and 5. Other rules will be added one at
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
    It does not establish a brute-force attack; Feature 5 separately applies a window.
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


# FEATURE 5: Flag possible brute-force attacks within a configured time window.
def detect_brute_force_attacks(
    events: Iterable[LogEvent], settings: DetectionSettings
) -> list[Alert]:
    """Return the first qualifying burst per host/IP in this imported log.

    With the default settings, any five consecutive failures within five
    minutes qualify. Every starting position is checked, so earlier slow
    attempts cannot hide a later burst. A success does not erase failures;
    this rule identifies the attempt pattern, not whether a login succeeded.
    """
    failures_by_source: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.event_type != "failed_login" or not event.source_ip:
            continue
        failures_by_source[(event.hostname, event.source_ip)].append(event)

    alerts = []
    threshold = settings.brute_force_threshold
    for (hostname, source_ip), failures in failures_by_source.items():
        ordered = sorted(failures, key=lambda event: (event.timestamp, event.line_number))

        # For five failures, the last index is four positions after the first.
        # Stop before starting positions that have fewer than five events left.
        for start in range(len(ordered) - threshold + 1):
            end = start + threshold - 1
            duration = ordered[end].timestamp - ordered[start].timestamp
            if duration > settings.brute_force_window:
                continue

            # Copy only the matching failures into the evidence. Slicing uses
            # an exclusive end, so end + 1 includes the fifth matching event.
            evidence = tuple(ordered[start:end + 1])
            usernames = tuple(sorted({
                event.username for event in evidence if event.username is not None
            }))
            alerts.append(Alert(
                rule="brute_force",
                # FEATURE 7: This rapid pattern has higher priority than a
                # whole-file repetition count, but compromise is not confirmed.
                severity="High",
                hostname=hostname,
                source_ip=source_ip,
                usernames=usernames,
                description=(
                    f"Possible brute-force attack: observed {threshold} failed logins "
                    f"from {source_ip} on {hostname} within {duration} "
                    f"(configured window: {settings.brute_force_window})."
                ),
                evidence=evidence,
            ))
            # Report one qualifying burst per source in this batch. Otherwise
            # overlapping windows would repeatedly alert on the same failures.
            break

    return sorted(alerts, key=lambda alert: (
        alert.timestamp, alert.hostname, alert.source_ip
    ))
