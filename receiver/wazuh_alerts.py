"""Bounded verification of one exact event in operator-supplied alerts.json.

An alert file confirms manager alerting only. Dashboard indexing is a separate
check. No Wazuh credentials or raw alert files are exposed through the web app.
"""

import json
import os
from pathlib import Path
import stat

from .storage import open_inbox
from .wazuh_export import ARCHIVE_SCAN_BYTES, ExportError, event_document, open_state
from .wazuh_rules import RULES


def verified_alert(directory, inbox, alerts, record_id):
    with open_state(directory, readonly=True) as db:
        state = db.execute("SELECT binding, last_record FROM state WHERE id=1").fetchone()
    with open_inbox(inbox, readonly=True) as db:
        info = Path(inbox).stat()
        binding = json.dumps([str(Path(inbox).absolute()), info.st_dev, info.st_ino])
        if binding != state["binding"] or not 0 < record_id <= state["last_record"]:
            raise ExportError("Choose a checkpointed record from this export's original inbox.")
        row = db.execute("SELECT * FROM events WHERE id=?", (record_id,)).fetchone()
    if row is None:
        raise ExportError("Receiver evidence is missing.")
    expected = (event_document(row), event_document(row, enriched=False))
    fd = os.open(alerts, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ExportError("Alerts must be a regular local file.")
        if info.st_size > ARCHIVE_SCAN_BYTES:
            stream.seek(info.st_size - ARCHIVE_SCAN_BYTES)
            stream.readline(1024 * 1024)
        remaining = ARCHIVE_SCAN_BYTES
        while remaining > 0:
            line = stream.readline(min(remaining, 1024 * 1024))
            if not line:
                break
            remaining -= len(line)
            try:
                alert = json.loads(line)
                if alert.get("decoder", {}).get("name") != "json" or not alert.get("manager", {}).get("name"):
                    continue
                if json.loads(alert.get("full_log", "")) not in expected:
                    continue
                rule = alert.get("rule", {})
                rule_id = str(rule.get("id"))
                if rule_id not in RULES or rule.get("level") != RULES[rule_id][0]:
                    continue
                return {"record_id": record_id, "collector_id": row["collector_id"],
                        "event_id": row["event_id"], "rule_id": rule_id,
                        "level": RULES[rule_id][0], "severity": RULES[rule_id][1],
                        "manager_alert_verified": True, "dashboard_indexing_verified": False}
            except (ValueError, AttributeError, TypeError, RecursionError):
                continue
    raise ExportError("No exact LogSentry alert found in the last 64 MiB. Alerting remains unverified for this record.")
