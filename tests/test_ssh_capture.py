"""Capture/parser tests; a real OpenSSH check is opt-in, using temporary storage."""

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from logsentry.cli import analyze_parsed
from logsentry.collection_sources import Source, interpret
from logsentry.collection_store import open_store, retained_records, source_rows
from logsentry.collector import collect_source, register_source
from logsentry.config import DetectionSettings
from logsentry.data import ParsedLog
from logsentry.parser import TimestampReader
from logsentry.ssh_capture import CaptureWriter, client_command, main, setup


NOW = datetime(2026, 11, 2, 19, 30, tzinfo=timezone.utc)
FAILED = "Failed publickey for user from 127.0.0.1 port 40123 ssh2: ED25519 SHA256:example"
ACCEPTED = "Accepted publickey for user from 127.0.0.1 port 40123 ssh2: ED25519 SHA256:example"


class SSHCaptureTests(unittest.TestCase):
    def setUp(self):
        self.folder = TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.path = self.root / "observed.jsonl"
        self.database = self.root / "store" / "collection.sqlite3"
        self.source = Source("ssh", self.path, "sshd_capture", 2026, "Africa/Lagos", "phone")

    def envelope(self, message=FAILED, **changes):
        record = {"version": 1, "hostname": "phone", "observed_at": NOW.isoformat(), "message": message}
        record.update(changes)
        return json.dumps(record)

    def parse(self, text):
        return interpret(text, 1, TimestampReader(DetectionSettings(year=2026)), self.source)

    def test_real_output_shapes_are_parsed_without_counting_key_lookup_as_login(self):
        cases = [(FAILED, "failed_login"), (ACCEPTED, "successful_login"),
                 ("Invalid user nobody from 127.0.0.1 port 40444", "invalid_user"),
                 ("Accepted key ED25519 SHA256:example found at /private/authorized_keys:1", "other"),
                 ("Server listening on 127.0.0.1 port 2222.", "other")]
        for message, kind in cases:
            with self.subTest(kind=kind):
                event = self.parse(self.envelope(message))
                self.assertEqual(event.event_type, kind)
                self.assertEqual(event.raw_line, message)
                self.assertEqual(event.timestamp, NOW)

    def test_invalid_envelopes_cannot_spoof_hosts_timestamps_or_multiple_events(self):
        values = ["not json", "[]", self.envelope(version=2), self.envelope(version=True),
                  self.envelope(hostname="another-host"), self.envelope(message=123),
                  self.envelope(observed_at="2026-11-02T12:00:00"),
                  self.envelope(observed_at="invalid"), self.envelope(FAILED + "\n" + ACCEPTED),
                  self.envelope("x" * 8193), self.envelope(message="Failed publickey malformed")]
        for value in values:
            with self.subTest(value=value[:80]), self.assertRaises(ValueError):
                self.parse(value)

    def test_writer_and_collector_keep_observed_time_and_original_message(self):
        writer = CaptureWriter(self.path)
        try:
            writer.write(FAILED, "phone", NOW)
            writer.write(ACCEPTED, "phone", NOW)
        finally:
            writer.close()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(json.loads(self.path.read_text().splitlines()[0])["message"], FAILED)
        with open_store(self.database) as db:
            source_id = register_source(db, self.source)
            self.assertEqual(collect_source(db, source_id), 2)
            self.assertEqual(collect_source(db, source_id), 0)
            records = retained_records(db, source_id)
            self.assertEqual(records[0]["raw_line"], FAILED)
            self.assertEqual(records[0]["timestamp"], NOW.isoformat())
            self.assertEqual(records[1]["event_type"], "successful_login")
            self.assertEqual(source_rows(db)[0]["issue_count"], 0)

    def test_capture_uses_existing_detectors(self):
        settings = DetectionSettings(year=2026)
        events = [interpret(self.envelope(), i, TimestampReader(settings), self.source) for i in range(1, 6)]
        analysis = analyze_parsed(ParsedLog(events=events, total_lines=5), "ssh", settings)
        self.assertEqual({alert.rule for alert in analysis.alerts}, {"brute_force", "repeated_failed_logins"})
        self.assertTrue(all(event.raw_line == FAILED for alert in analysis.alerts for event in alert.evidence))

    def test_capture_rotation_keeps_previous_file_and_collector_reads_new_generation(self):
        writer = CaptureWriter(self.path)
        try:
            writer.write(FAILED, "phone", NOW)
            with open_store(self.database) as db:
                source_id = register_source(db, self.source)
                collect_source(db, source_id)
                with patch("logsentry.ssh_capture.MAX_CAPTURE_BYTES", self.path.stat().st_size + 1):
                    writer.write(ACCEPTED, "phone", NOW)
                collect_source(db, source_id)
                self.assertEqual([r["generation"] for r in retained_records(db, source_id)], [0, 1])
                self.assertEqual(json.loads(self.path.with_name("observed.jsonl.1").read_text())["message"], FAILED)
        finally:
            writer.close()

    def test_writer_rejects_symlink_shared_file_and_hardlink(self):
        target = self.root / "target"
        target.write_text("preserve")
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            CaptureWriter(self.path).write(FAILED, "phone", NOW)
        self.path.unlink()
        os.link(target, self.path)
        with self.assertRaises(ValueError):
            CaptureWriter(self.path).write(FAILED, "phone", NOW)
        self.path.unlink()
        self.path.write_text("existing")
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            CaptureWriter(self.path).write(FAILED, "phone", NOW)
        self.assertEqual(target.read_text(), "preserve")

    def test_invalid_capture_stays_visible_without_destroying_valid_records(self):
        self.path.write_text(self.envelope() + "\n" + self.envelope(hostname="wrong") + "\n")
        with open_store(self.database) as db:
            source_id = register_source(db, self.source)
            collect_source(db, source_id)
            records = retained_records(db, source_id)
            self.assertEqual(records[0]["event_type"], "failed_login")
            self.assertIn("hostname", records[1]["issue"])
            self.assertEqual(records[1]["raw_line"], self.envelope(hostname="wrong"))

    def test_setup_restricts_endpoint_and_refuses_overwrite(self):
        if not shutil.which("ssh-keygen"):
            self.skipTest("ssh-keygen not installed")
        directory = self.root / "endpoint"
        setup(directory, 22222, pwd.getpwuid(os.getuid()).pw_name)
        config = (directory / "sshd_config").read_text()
        for setting in ("ListenAddress 127.0.0.1", "PasswordAuthentication no", "StrictModes yes",
                        "DisableForwarding yes", "PermitTTY no", "ForceCommand"):
            self.assertIn(setting, config)
        self.assertEqual(stat.S_IMODE((directory / "client_ed25519").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertIn("StrictHostKeyChecking=yes", client_command(directory))
        original = (directory / "host_ed25519").read_bytes()
        with self.assertRaises(FileExistsError):
            setup(directory, 22222, pwd.getpwuid(os.getuid()).pw_name)
        self.assertEqual((directory / "host_ed25519").read_bytes(), original)

    def test_setup_rejects_invalid_port_or_account_patterns(self):
        for port, user in ((22, "root"), (70000, "root"), (2222, "*"), (2222, "root\nPasswordAuthentication yes")):
            with self.assertRaises(ValueError):
                setup(self.root / "endpoint", port, user)

    def test_serve_preflight_failure_does_not_register_a_source(self):
        endpoint = self.root / "endpoint"
        endpoint.mkdir(mode=0o700)
        config = endpoint / "sshd_config"
        config.write_text("broken configuration")
        config.chmod(0o600)
        (endpoint / "endpoint.json").write_text('{"port": 2222, "username": "root"}')
        with patch("logsentry.ssh_capture._binary", return_value="/usr/sbin/sshd"), patch(
            "logsentry.ssh_capture.subprocess.run", return_value=subprocess.CompletedProcess([], 1, b"", b"bad config")
        ), redirect_stderr(StringIO()), redirect_stdout(StringIO()):
            self.assertEqual(main(["serve", "--directory", str(endpoint), "--database", str(self.database)]), 1)
        self.assertFalse(self.database.exists())


@unittest.skipUnless(os.environ.get("LOGSENTRY_TEST_OPENSSH") == "1", "Set LOGSENTRY_TEST_OPENSSH=1 for a real local OpenSSH test")
class RealOpenSSHTests(unittest.TestCase):
    def test_real_key_authentication_failures_success_and_invalid_user_reach_engine(self):
        # StrictModes checks every parent of AuthorizedKeysFile. /tmp is shared,
        # so keep this temporary endpoint under the private project runtime dir.
        runtime = Path(__file__).resolve().parents[1] / "runtime"
        runtime.mkdir(mode=0o700, exist_ok=True)
        with TemporaryDirectory(prefix="ssh-test-", dir=runtime) as temp:
            root = Path(temp)
            endpoint = root / "endpoint"
            database = root / "store" / "collection.sqlite3"
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
            setup(endpoint, port, pwd.getpwuid(os.getuid()).pw_name)
            # Recent OpenSSH penalizes a source after several rejected logins.
            # Disable that throttle ONLY in this temporary test endpoint so we
            # can verify the full burst-and-success sequence deterministically.
            effective = subprocess.run([shutil.which("sshd") or "/usr/sbin/sshd", "-T", "-f",
                                        str(endpoint / "sshd_config")], capture_output=True, text=True, check=True)
            if "persourcepenalties " in effective.stdout:
                with (endpoint / "sshd_config").open("a") as config:
                    config.write("PerSourcePenalties no\n")
            with (root / "capture-output.txt").open("w+") as output:
                process = subprocess.Popen([sys.executable, "-m", "logsentry.ssh_capture", "serve",
                    "--directory", str(endpoint), "--database", str(database)], stdout=output, stderr=output)
                try:
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        if process.poll() is not None:
                            output.seek(0)
                            self.fail(output.read())
                        if (endpoint / "observed.jsonl").exists() and "Server listening" in (endpoint / "observed.jsonl").read_text():
                            break
                        time.sleep(0.1)
                    else:
                        self.fail("OpenSSH did not start")
                    command = client_command(endpoint)
                    # The host key is a valid private key that is not authorized
                    # as a client key. This creates actual failed publickey logs.
                    bad = [str(endpoint / "host_ed25519") if arg == str(endpoint / "client_ed25519") else arg for arg in command]
                    for _ in range(5):
                        failed = subprocess.run(bad, capture_output=True, timeout=15)
                        self.assertEqual(failed.returncode, 255)
                    accepted = subprocess.run(command, capture_output=True, timeout=15)
                    output.flush()
                    self.assertEqual(accepted.returncode, 0, accepted.stderr.decode() + (endpoint / "observed.jsonl").read_text())
                    invalid = subprocess.run(command[:-1] + ["logsentry_nonexistent_account@127.0.0.1"], capture_output=True, timeout=15)
                    self.assertEqual(invalid.returncode, 255)
                finally:
                    process.send_signal(signal.SIGTERM)
                    process.wait(timeout=10)
                with open_store(database) as db:
                    source_row = source_rows(db)[0]
                    collect_source(db, source_row["id"])
                    records = retained_records(db, source_row["id"])
                    self.assertTrue(any(row["event_type"] == "successful_login" for row in records))
                    self.assertTrue(any(row["event_type"] == "invalid_user" for row in records))
                    self.assertFalse([row["issue"] for row in records if row["issue"]])
                source = Source("local-ssh", endpoint / "observed.jsonl", "sshd_capture", 2026,
                                "Africa/Lagos", socket.gethostname())
                policy = DetectionSettings(year=2026, timezone_name="Africa/Lagos")
                dates = TimestampReader(policy)
                events = [interpret(line, number, dates, source) for number, line in enumerate(source.path.read_text().splitlines(), 1)]
                analysis = analyze_parsed(ParsedLog(events=events, total_lines=len(events)), "local-ssh", policy)
                self.assertTrue({"brute_force", "repeated_failed_logins", "success_after_failures", "invalid_user"}
                                <= {alert.rule for alert in analysis.alerts})


if __name__ == "__main__":
    unittest.main()
