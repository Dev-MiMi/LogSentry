"""Detection rules examine parsed facts and return alerts for investigation.

This module implements Features 2, 4, 5, and 6, with initial severity choices
for Feature 7. Importing it does not read files or run detectors automatically.
"""

from collections import defaultdict, deque
from ipaddress import ip_address, ip_network
from typing import Iterable
from zoneinfo import ZoneInfo

from .config import DetectionSettings
from .data import Alert, LogEvent


# FEATURE 2: Group records targeting invalid account names.
def detect_invalid_user_attempts(events: Iterable[LogEvent]) -> list[Alert]:
    """Return one finding per host/IP/invalid username in this imported log.

    SSH may emit an invalid-user notice AND a failed-password record for one
    attempt. Both are evidence for one finding; their count is not an attempt
    count. Failed-login records can also reveal an invalid user on their own.
    """
    records_by_account: dict[tuple[str, str, str], list[LogEvent]] = defaultdict(list)
    for event in events:
        targets_invalid_user = (
            event.event_type == "invalid_user"
            or (event.event_type == "failed_login" and event.invalid_user)
        )
        if not targets_invalid_user or not event.source_ip or not event.username:
            continue
        key = (event.hostname, event.source_ip, event.username)
        records_by_account[key].append(event)

    alerts = []
    for (hostname, source_ip, username), records in records_by_account.items():
        evidence = tuple(sorted(records, key=lambda event: (event.timestamp, event.line_number)))
        alerts.append(Alert(
            rule="invalid_user",
            # FEATURE 7: Invalid accounts warrant review, but may be typos.
            severity="Medium",
            hostname=hostname,
            source_ip=source_ip,
            usernames=(username,),
            description=(
                f"Authentication records from {source_ip} on {hostname} "
                f"targeted invalid username '{username}'. "
                "The records may describe more than one stage of the same attempt."
            ),
            evidence=evidence,
        ))

    return sorted(alerts, key=lambda alert: (
        alert.timestamp, alert.hostname, alert.source_ip, alert.usernames
    ))


# FEATURE 2: Correlate a successful login with that account's recent failures.
def detect_success_after_failures(
    events: Iterable[LogEvent], settings: DetectionSettings
) -> list[Alert]:
    """Find successes after repeated failures of the same host/IP/account.

    The default requires three valid-account failures in the preceding ten
    minutes, including exactly ten minutes. Every success resets that key's
    history, even if it did not reach the threshold. Invalid-user failures
    cannot establish that an existing account's credentials were guessed.
    """
    # A deque is a queue: append adds the latest failure; popleft removes the
    # oldest one efficiently when it falls outside our time window.
    failures_by_account: dict[tuple[str, str, str], deque[LogEvent]] = defaultdict(deque)
    ordered = sorted(events, key=lambda event: (
        event.timestamp, event.line_number, event.hostname, event.source_ip or "",
        event.username or "", event.event_type,
    ))
    alerts = []
    for event in ordered:
        if event.event_type not in {"failed_login", "successful_login"}:
            continue
        if not event.source_ip or not event.username or event.invalid_user:
            continue

        # Matching all three values avoids combining unrelated accounts,
        # source addresses, or target machines into a compromise suspicion.
        key = (event.hostname, event.source_ip, event.username)
        recent = failures_by_account[key]
        while recent and event.timestamp - recent[0].timestamp > settings.success_after_failures_window:
            recent.popleft()

        if event.event_type == "failed_login":
            recent.append(event)
            continue

        if len(recent) >= settings.repeated_threshold:
            alerts.append(Alert(
                rule="success_after_failures",
                # FEATURE 7: High signals a need to investigate. These logs
                # alone do not confirm that an attacker gained access.
                severity="High",
                hostname=event.hostname,
                source_ip=event.source_ip,
                usernames=(event.username,),
                description=(
                    f"Successful login for '{event.username}' on {event.hostname} "
                    f"from {event.source_ip} followed {len(recent)} failed logins "
                    f"for the same account, host, and IP within the preceding "
                    f"{settings.success_after_failures_window} "
                    f"(threshold: {settings.repeated_threshold}). "
                    "Possible account compromise requires investigation."
                ),
                evidence=tuple(recent) + (event,),
            ))

        # The previous failures must not be reused for every later success.
        recent.clear()

    return sorted(alerts, key=lambda alert: (
        alert.timestamp, alert.hostname, alert.source_ip, alert.usernames,
        alert.evidence[-1].line_number,
    ))


def detect_suspicious_events(
    events: Iterable[LogEvent], settings: DetectionSettings
) -> list[Alert]:
    """FEATURE 2: Run both rules on the same input, including a one-use iterator."""
    # Materializing once ensures a generator is not exhausted by the first rule.
    records = tuple(events)
    alerts = detect_invalid_user_attempts(records)
    alerts.extend(detect_success_after_failures(records, settings))
    return sorted(alerts, key=lambda alert: (
        alert.timestamp, alert.hostname, alert.source_ip, alert.usernames, alert.rule
    ))


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
