"""Wazuh handoff tests: isolated synthetic records never enter the real inbox."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from io import StringIO
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from unittest.mock import patch
import uuid
from xml.etree import ElementTree

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from .storage import open_inbox, save_batch
from .wazuh_export import (ExportError, encode_record, event_document, export_lock,
                          export_once, export_status, localfile_xml, open_state, verify_archive)


@override_settings(ALLOWED_HOSTS=["testserver", "127.0.0.1"])
class WazuhExportTests(TestCase):
    def setUp(self):
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.inbox = self.root / "receiver" / "events.sqlite3"
        self.directory = self.root / "wazuh"
        self.log = self.directory / "events.jsonl"
        self.event = {
            "event_id": str(uuid.uuid4()), "platform": "android", "source": "chosen-app",
            "event_type": "notification", "observed_at": "2026-11-05T08:00:00+00:00",
            "occurred_at": None, "message": 'Alert text\n{"integration":"forged"}\t<script>\x1b[31m naïve 🔒',
        }
        settings = override_settings(LOGSENTRY_RECEIVER_DATABASE=self.inbox,
                                     LOGSENTRY_WAZUH_DIRECTORY=self.directory,
                                     LOGSENTRY_OUTBOX_DATABASE=self.root / "outbox" / "unused.sqlite3")
        settings.enable()
        self.addCleanup(settings.disable)
        self.client.force_login(get_user_model().objects.create_user("export-reviewer"))

    def add_events(self, count=1):
        events = [{**self.event, "event_id": str(uuid.uuid4())} for _ in range(count)]
        save_batch(self.inbox, "phone-one", events)
        with open_inbox(self.inbox, readonly=True) as db:
            return db.execute("SELECT * FROM events ORDER BY id").fetchall()

    def run_export(self, **kwargs):
        with export_lock(self.directory), open_state(self.directory) as db:
            return export_once(db, self.directory, self.inbox, **kwargs)

    def test_json_evidence_and_provenance_roundtrip_and_restarts(self):
        rows = self.add_events(2)
        self.assertEqual(self.run_export(), 2)
        self.assertEqual(self.run_export(), 0)
        lines = self.log.read_bytes().splitlines()
        self.assertEqual(len(lines), 2)
        for line, row in zip(lines, rows):
            decoded = json.loads(line)
            self.assertEqual(decoded, event_document(row))
            self.assertEqual(decoded["integration"], "logsentry")
            self.assertEqual(decoded["logsentry"]["message"], self.event["message"])
            self.assertIsNone(decoded["logsentry"]["occurred_at"])
            self.assertNotIn("severity", decoded)
        status = export_status(self.directory, self.inbox)
        self.assertEqual((status["exported"], status["pending"]), (2, 0))
        self.assertIsNone(status["verified_record"])
        self.assertNotIn("journal", status)
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        with open_inbox(self.inbox, readonly=True) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 2)

    def test_new_records_bounded_batches_and_concurrent_ingestion(self):
        self.add_events(3)
        self.assertEqual(self.run_export(batch_size=1), 1)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(save_batch, self.inbox, "another-phone", [self.event]).result()
        self.assertEqual(self.run_export(), 3)
        self.assertEqual(len(self.log.read_bytes().splitlines()), 4)

    def test_partial_write_is_completed_without_duplicate_or_lost_lines(self):
        rows = self.add_events(3)
        def broken_append(stream, data):
            stream.write(data[:len(data) // 2])
            os.fsync(stream.fileno())
            raise OSError("disk disconnected")
        with patch("receiver.wazuh_export._append_remaining", side_effect=broken_append):
            with self.assertRaises(ExportError):
                self.run_export()
        failed = export_status(self.directory, self.inbox)
        self.assertEqual((failed["exported"], failed["pending"]), (0, 3))
        self.assertTrue(failed["error"])
        self.assertEqual(self.run_export(), 3)
        self.assertEqual(self.log.read_bytes(), b"".join(encode_record(row) for row in rows))
        self.assertEqual(export_status(self.directory, self.inbox)["error"], "")

    def test_crash_after_fsync_before_checkpoint_does_not_duplicate(self):
        self.add_events(2)
        with patch("receiver.wazuh_export._tail", wraps=__import__("receiver.wazuh_export", fromlist=["_tail"])._tail) as tail:
            original = tail._mock_wraps
            def after_append(stream, offset):
                if offset > 0:
                    raise OSError("checkpoint interruption")
                return original(stream, offset)
            tail.side_effect = after_append
            with self.assertRaises(ExportError):
                self.run_export()
        original_bytes = self.log.read_bytes()
        self.assertEqual(len(original_bytes.splitlines()), 2)
        self.assertEqual(self.run_export(), 2)
        self.assertEqual(self.log.read_bytes(), original_bytes)

    def test_write_failure_before_append_keeps_journal_for_restart(self):
        self.add_events()
        with patch("receiver.wazuh_export._append_remaining", side_effect=OSError("full")):
            with self.assertRaises(ExportError):
                self.run_export()
        self.assertEqual(self.log.stat().st_size, 0)
        self.assertEqual(self.run_export(), 1)

    def test_refuses_replaced_truncated_or_externally_appended_exports(self):
        self.add_events()
        self.run_export()
        data = self.log.read_bytes()
        with self.log.open("ab") as stream:
            stream.write(b"untracked\n")
        with self.assertRaises(ExportError):
            self.run_export()
        self.assertTrue(self.log.read_bytes().endswith(b"untracked\n"))
        self.log.write_bytes(b"")
        with self.assertRaises(ExportError):
            self.run_export()
        self.log.write_bytes(data)
        self.assertEqual(self.run_export(), 0)
        moved = self.directory / "moved"
        self.log.rename(moved)
        self.log.write_bytes(data)
        self.log.chmod(0o600)
        with self.assertRaises(ExportError):
            self.run_export()

    def test_untracked_existing_file_symlink_and_fifo_are_refused(self):
        self.add_events()
        self.directory.mkdir(mode=0o700)
        self.log.write_bytes(b"other evidence\n")
        self.log.chmod(0o600)
        with self.assertRaises(ExportError):
            self.run_export()
        self.assertEqual(self.log.read_bytes(), b"other evidence\n")
        self.log.unlink()
        target = self.root / "target"
        target.write_text("untouched")
        self.log.symlink_to(target)
        with self.assertRaises(ExportError):
            self.run_export()
        self.assertEqual(target.read_text(), "untouched")
        self.log.unlink()
        os.mkfifo(self.log, 0o600)
        with self.assertRaises(ExportError):
            self.run_export()

    def test_inbox_replacement_and_parallel_exporter_refused(self):
        self.add_events()
        self.run_export()
        self.inbox.rename(self.inbox.with_suffix(".original"))
        self.add_events()
        with self.assertRaises(ExportError):
            self.run_export()
        with self.assertRaises(ExportError):
            export_status(self.directory, self.inbox)
        with export_lock(self.directory):
            with self.assertRaises(ExportError):
                with export_lock(self.directory):
                    pass

    def test_capacity_and_line_limits_preserve_inbox_and_checkpoint(self):
        self.add_events(2)
        with patch("receiver.wazuh_export.MAX_EXPORT_BYTES", 10):
            with self.assertRaises(ExportError):
                self.run_export()
        self.assertEqual(export_status(self.directory, self.inbox)["exported"], 0)
        with patch("receiver.wazuh_export.MAX_LINE_BYTES", 10):
            with self.assertRaises(ExportError):
                self.run_export()
        self.assertEqual(self.log.stat().st_size, 0)
        self.assertEqual(self.run_export(), 2)

    def test_corrupt_journal_tail_never_overwritten(self):
        self.add_events()
        with patch("receiver.wazuh_export._append_remaining", side_effect=OSError("offline")):
            with self.assertRaises(ExportError):
                self.run_export()
        self.log.write_bytes(b"wrong bytes")
        with self.assertRaises(ExportError):
            self.run_export()
        self.assertEqual(self.log.read_bytes(), b"wrong bytes")

    def test_localfile_configuration_is_valid_and_does_not_execute_paths(self):
        tree = ElementTree.fromstring(localfile_xml(self.directory))
        self.assertEqual(tree.findtext("location"), str(self.log))
        self.assertEqual(tree.findtext("log_format"), "json")
        self.assertEqual(tree.findtext("only-future-events"), "no")
        self.assertEqual(tree.find("only-future-events").attrib["max-size"], "128MB")
        escaped = ElementTree.fromstring(localfile_xml(self.root / "name&value"))
        self.assertIn("name&value", escaped.findtext("location"))
        for value in ("*.json", "file%Y", "line\nbreak"):
            with self.assertRaises(ExportError):
                localfile_xml(self.root / value)
        static = ElementTree.parse(Path(__file__).resolve().parents[1] / "deploy/wazuh/localfile.xml")
        self.assertEqual(static.findtext("log_format"), "json")

    def test_archive_verification_requires_exact_evidence_not_just_uuid(self):
        rows = self.add_events()
        self.run_export()
        archive = self.root / "archives.json"
        document = event_document(rows[0])
        entry = {"decoder": {"name": "json"}, "manager": {"name": "test-manager"}, "full_log": json.dumps(document)}
        altered = {**document, "logsentry": {**document["logsentry"], "message": "changed"}}
        archive.write_text(json.dumps({**entry, "full_log": json.dumps(altered)}) + "\n")
        with self.assertRaises(ExportError):
            verify_archive(self.directory, self.inbox, archive, rows[0]["id"])
        self.assertIsNone(export_status(self.directory, self.inbox)["verified_record"])
        archive.write_text('not JSON\n{}\n' + json.dumps(entry) + '\n')
        # Watch holds this lock for its lifetime. Verify an already checkpointed
        # record without having to stop continuous export.
        with export_lock(self.directory):
            call_command("wazuh_status", archive=archive, record_id=rows[0]["id"], stdout=StringIO())
        state = export_status(self.directory, self.inbox)
        self.assertEqual(state["verified_record"], rows[0]["id"])
        self.assertIsNotNone(state["verified_at"])
        with self.assertRaises(ExportError):
            verify_archive(self.directory, self.inbox, archive, 99999)

    def test_ui_no_mutation_authentication_stale_error_and_verification(self):
        self.add_events()
        response = self.client.get("/receiver/")
        self.assertContains(response, "Wazuh export")
        self.assertContains(response, "Not started")
        self.assertFalse(self.directory.exists())
        self.run_export()
        response = self.client.get("/receiver/")
        self.assertContains(response, "1 exported")
        self.assertContains(response, "Manager receipt has not been verified")
        with open_state(self.directory) as db, db:
            db.execute("UPDATE state SET verified_record=1, verified_at='2026-11-05T08:00:00+00:00'")
        response = self.client.get("/receiver/")
        self.assertContains(response, "Record 1 matched a supplied Wazuh archive")
        self.assertContains(response, "5 Nov 2026, 9:00:00 AM WAT")
        with open_state(self.directory) as db, db:
            db.execute("UPDATE state SET last_checked=?, error=?", ("2000-01-01T00:00:00+00:00", "<script>error</script>"))
        response = self.client.get("/receiver/")
        self.assertContains(response, "Check is stale")
        self.assertContains(response, "&lt;script&gt;error&lt;/script&gt;")
        self.client.logout()
        self.assertEqual(self.client.get("/receiver/").status_code, 302)

    def test_commands_export_config_and_status_without_fake_data(self):
        output = StringIO()
        call_command("wazuh_status", localfile=True, stdout=output)
        self.assertIn("<log_format>json</log_format>", output.getvalue())
        self.assertFalse(self.directory.exists())
        with self.assertRaises(CommandError):
            call_command("export_wazuh", stdout=StringIO())
        self.add_events()
        call_command("export_wazuh", stdout=StringIO())
        call_command("wazuh_status", stdout=StringIO())
        self.assertEqual(len(self.log.read_bytes().splitlines()), 1)
