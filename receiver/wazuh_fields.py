"""Derive searchable SSH facts without changing collector evidence.

The authenticated collector is still the source of these claims. Parsing proves
that a message fits OpenSSH syntax, not that a device is uncompromised.
"""

from datetime import datetime
import hashlib
import json

from logsentry.config import DetectionSettings
from logsentry.parser import PREFIX, TimestampReader, parse_log_line


def ssh_fields(event):
    """Return bounded, deterministic enrichment; unrelated observations stay raw."""
    if event["platform"] not in {"linux", "termux"} or event["event_type"] not in {
        "failed_login", "successful_login", "invalid_user",
    }:
        return None
    message = event["message"]
    if len(message.encode("utf-8")) > 8192:
        return None
    try:
        stamp = datetime.fromisoformat((event["occurred_at"] or event["observed_at"]).replace("Z", "+00:00"))
        if stamp.utcoffset() is None:
            return None
        prefix = PREFIX.fullmatch(message)
        if prefix:
            # The collector has already resolved a legacy year/timezone. Reuse
            # that time while the parser validates the process and SSH message.
            line = stamp.isoformat() + message[len(prefix["time"]):]
        elif event["source"] == "local-ssh" and event["occurred_at"] is None:
            # Our direct sshd capture has observation time, not an event clock.
            line = f"{stamp.isoformat()} {event['collector_id']} sshd: {message}"
        else:
            return None
        parsed = parse_log_line(line, 1, TimestampReader(DetectionSettings(year=stamp.year)))
    except (ValueError, OverflowError):
        return None
    if parsed.event_type != event["event_type"] or not parsed.source_ip:
        return None
    identity = [event["collector_id"], event["source"], parsed.hostname, parsed.source_ip]
    def key(parts):
        return hashlib.sha256(json.dumps(parts, ensure_ascii=True).encode()).hexdigest()
    return {
        "kind": parsed.event_type,
        "hostname": parsed.hostname,
        "source_ip": parsed.source_ip,
        "username": parsed.username,
        "method": parsed.authentication_method or "unknown",
        "invalid_user": "yes" if parsed.invalid_user else "no",
        "time_basis": "occurred_at" if event["occurred_at"] else "observed_at",
        "source_key": key(identity),
        "account_key": key([*identity, parsed.username]),
    }
