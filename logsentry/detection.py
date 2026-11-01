"""Detection rules examine parsed facts and return alerts for investigation.

This module currently implements Features 4, 5, and 6. Other rules will be added one at
a time. Importing it does not read files or run the detectors automatically.
"""

from collections import defaultdict
from ipaddress import ip_address, ip_network
from typing import Iterable
from zoneinfo import ZoneInfo

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


# FEATURE 6: Identify successful logins at unusual times or from untrusted IPs.
def detect_suspicious_logins(
    events: Iterable[LogEvent], settings: DetectionSettings
) -> list[Alert]:
    """Return one alert for each successful login outside the configured policy.

    Hours are checked in the configured local timezone. Networks are an explicit
    allowlist, not a reputation database: an address outside them is unexpected
    under this policy, not necessarily malicious. The caller supplies parsed
    events with validated IPs. Missing source IPs cannot be assessed by this rule.
    """
    # Parse the policy once per call, rather than once per event.
    local_zone = ZoneInfo(settings.timezone_name)
    trusted_networks = tuple(ip_network(network) for network in settings.trusted_networks)
    alerts = []

    for event in events:
        if event.event_type != "successful_login" or not event.source_ip:
            continue

        # FEATURE 1 stores UTC; FEATURE 6 evaluates the machine's local hours.
        # astimezone handles changes in UTC offset, including daylight saving.
        local_time = event.timestamp.astimezone(local_zone)
        reasons = []
        if not settings.is_normal_login_hour(local_time.hour):
            reasons.append(
                f"login at {local_time.isoformat()} ({settings.timezone_name}) "
                f"was outside configured hours "
                f"{settings.normal_start_hour:02d}:00-{settings.normal_end_hour:02d}:00"
            )

        # Use real network membership, not a string-prefix check. A mapped IPv6
        # source represents its IPv4 address, just as in our parser.
        address = ip_address(event.source_ip)
        address = getattr(address, "ipv4_mapped", None) or address
        trusted = any(
            address.version == network.version and address in network
            for network in trusted_networks
        )
        if not trusted:
            reasons.append(f"source IP {address} was outside configured trusted networks")

        if not reasons:
            continue

        alerts.append(Alert(
            rule="suspicious_login",
            # FEATURE 7: Both reasons together receive a higher priority.
            severity="High" if len(reasons) == 2 else "Medium",
            hostname=event.hostname,
            source_ip=str(address),
            usernames=(event.username,) if event.username is not None else (),
            description="Successful login flagged: " + "; ".join(reasons) + ".",
            evidence=(event,),
        ))

    return sorted(alerts, key=lambda alert: (
        alert.timestamp, alert.hostname, alert.source_ip, alert.evidence[0].line_number
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
