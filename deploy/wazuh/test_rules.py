#!/usr/bin/env python3
"""Run isolated scenarios in Wazuh logtest, never the collector or live log file.

Run on the Wazuh manager after installing logsentry_rules.xml:
    sudo .venv/bin/python deploy/wazuh/test_rules.py
Each scenario has a fresh logtest session; events within it share history.
Before restarting the live manager, use --logtest with wazuh-logtest-legacy
to test the candidate configuration directly from disk.
"""

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from receiver.wazuh_export import event_document
from receiver.wazuh_rules import RULES


def document(kind="failed_login", *, user="alice", ip="192.0.2.10", collector="test-pc",
             host="test-host", source="ubuntu-auth", platform="linux", message=None):
    messages = {
        "failed_login": f"Failed password for {user} from {ip} port 44000 ssh2",
        "successful_login": f"Accepted publickey for {user} from {ip} port 44000 ssh2",
        "invalid_user": f"Invalid user {user} from {ip} port 44000",
        "package_activity": "2026-11-06 14:00:00 status installed test-package:all 1.0",
        "notification": "Test-only notification",
    }
    text = message if message is not None else messages[kind]
    if message is None and kind in {"failed_login", "successful_login", "invalid_user"}:
        text = f"Nov  6 14:00:00 {host} sshd[10]: {text}"
    event = {"event_id": str(uuid.uuid4()), "platform": platform, "source": source,
             "event_type": kind, "observed_at": "2026-11-06T14:00:00+00:00",
             "occurred_at": "2026-11-06T14:00:00+00:00", "message": text}
    payload = json.dumps(event)
    return event_document({"id": 1, "collector_id": collector, "payload": payload,
                           "payload_hash": hashlib.sha256(payload.encode()).hexdigest(),
                           "received_at": event["observed_at"]})


def scenarios():
    yield "routine package activity", [document("package_activity")], ["110001"]
    yield "notification is not authentication", [document("notification", platform="android")], ["110000"]
    yield "single SSH failure", [document()], ["110010"]
    yield "unknown account", [document("invalid_user")], ["110011"]
    yield "normal success", [document("successful_login")], ["110012"]
    yield "privileged success", [document("successful_login", user="root")], ["110013"]
    yield "three then five failures", [document() for _ in range(5)], ["110010", "110010", "110020", "110010", "110021"]
    for key in ("collector", "source", "host", "ip"):
        other = "192.0.2.11" if key == "ip" else "other-test-value"
        yield f"different {key} does not merge", [document(), document(), document(**{key: other})], ["110010"] * 3
    repeated = document()
    yield "same event replay is not five failures", [repeated] * 5, ["110010"] * 5
    yield "IPv4-mapped IPv6 is same IP", [document(), document(ip="::ffff:192.0.2.10"), document()], ["110010", "110010", "110020"]
    yield "success after three failures", [document() for _ in range(3)] + [document("successful_login")], ["110010", "110010", "110020", "110022"]
    yield "success after two failures", [document(), document(), document("successful_login")], ["110010", "110010", "110012"]
    yield "another account success", [document() for _ in range(3)] + [document("successful_login", user="bob")], ["110010", "110010", "110020", "110012"]
    yield "root success after failures", [document(user="root") for _ in range(3)] + [document("successful_login", user="root")], ["110010", "110010", "110020", "110022"]
    forged = document(message="Nov  6 14:00:00 test-host otherapp: Failed password for alice from 192.0.2.10 port 44000 ssh2")
    yield "other process is not sshd", [forged], ["110000"]
    android = document(platform="android")
    yield "Android text is not SSH evidence", [android], ["110000"]
    old = deepcopy(document())
    old["logsentry"].pop("ssh")
    old["logsentry"].pop("enrichment_version")
    yield "legacy export remains activity", [old], ["110000"]


def run_scenario(binary, documents, expected):
    result = subprocess.run([str(binary)], input="".join(json.dumps(d) + "\n" for d in documents),
                            text=True, capture_output=True, timeout=45, check=False)
    output = result.stdout + result.stderr
    phases = re.split(r"\*\*Phase 3: Completed filtering \(rules\)\.", output)[1:]
    found = []
    for phase in phases:
        rule = re.search(r"^\s*(?:Rule )?id:\s*'?(\d+)'?", phase, re.I | re.M)
        level = re.search(r"^\s*level:\s*'?(\d+)'?", phase, re.I | re.M)
        found.append((rule[1] if rule else None, int(level[1]) if level else None))
    wanted = [(key, RULES[key][0]) for key in expected]
    # Match diagnostics, not the INFO setting "rule_tree_memory_warning".
    diagnostic = re.search(
        r"^(?:\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} [\w.-]+:\s*)?"
        r"(?:ERROR|WARNING)\b|^Wazuh-logtest error", output, re.I | re.M)
    if result.returncode or found != wanted or diagnostic:
        raise RuntimeError(f"Expected {wanted}, got {found}.\n{output[-8000:]}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logtest", type=Path, default=Path("/var/ossec/bin/wazuh-logtest"))
    args = parser.parse_args()
    if not args.logtest.is_file():
        parser.exit(2, "Wazuh logtest is unavailable. Run this command on the configured Wazuh manager.\n")
    failures = 0
    count = 0
    for name, documents, expected in scenarios():
        count += 1
        try:
            run_scenario(args.logtest, documents, expected)
            print(f"PASS: {name}")
        except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
            failures += 1
            print(f"FAIL: {name}: {error}", file=sys.stderr)
    print(f"{count - failures}/{count} Wazuh scenarios passed. This does not verify live ingestion or indexing.")
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
