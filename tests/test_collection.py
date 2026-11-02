"""Collector integration checks using temporary log files, never system writes."""

from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import time
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from logsentry.collection_sources import Source, discover_sources
from logsentry.collection_store import open_store, retained_records, source_rows
from logsentry.collector import collect_source, main, register_source


FAILURE = "2026-11-01T12:00:00+00:00 ubuntu sshd[12]: Failed password for alice from 203.0.113.8 port 2222 ssh2\n"


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.folder = TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.database = self.root / "private" / "collection.sqlite3"
        self.log = self.root / "auth.log"
        self.log.write_text(FAILURE)

    def source(self, name="ubuntu-auth", format_name="syslog", timezone="UTC"):
        return Source(name, self.log, format_name, 2026, timezone, "test-host")

    def test_first_import_restart_append_and_original_file_preserved(self):
        original = self.log.read_bytes()
        with open_store(self.database) as db:
            source_id = register_source(db, self.source())
            self.assertEqual(collect_source(db, source_id), 1)
            self.assertEqual(collect_source(db, source_id), 0)
        self.assertEqual(self.log.read_bytes(), original)
        with self.log.open("a") as stream:
            stream.write(FAILURE)
        with open_store(self.database) as db:
            self.assertEqual(register_source(db, self.source()), source_id)
            self.assertEqual(collect_source(db, source_id), 1)
            rows = retained_records(db, source_id)
            self.assertEqual([row["line_number"] for row in rows], [1, 2])
            self.assertTrue(all(row["event_type"] == "failed_login" for row in rows))
            self.assertEqual(rows[0]["raw_line"] + "\n", FAILURE)

    def test_partial_line_waits_for_newline_without_advancing(self):
        self.log.write_text(FAILURE.rstrip("\n"))
        with open_store(self.database) as db:
            source_id = register_source(db, self.source())
            self.assertEqual(collect_source(db, source_id), 0)
            self.assertEqual(source_rows(db)[0]["offset"], 0)
            with self.log.open("a") as stream:
                stream.write("\n")
            self.assertEqual(collect_source(db, source_id), 1)

    def test_rename_rotation_retains_old_evidence_with_distinct_generation(self):
        with open_store(self.database) as db:
            source_id = register_source(db, self.source())
            collect_source(db, source_id)
            self.log.rename(self.root / "auth.log.1")
            self.log.write_text(FAILURE.replace("alice", "bob"))
            self.assertEqual(collect_source(db, source_id), 1)
            rows = retained_records(db, source_id)
            self.assertEqual([row["generation"] for row in rows], [0, 1])
            self.assertEqual([row["username"] for row in rows], ["alice", "bob"])
            self.assertEqual(source_rows(db)[0]["rotations"], 1)

    def test_copytruncate_with_refill_larger_than_offset_is_detected(self):
        with open_store(self.database) as db:
            source_id = register_source(db, self.source())
            collect_source(db, source_id)
            self.log.write_text(FAILURE.replace("alice", "mallory") * 2)
            self.assertEqual(collect_source(db, source_id), 2)
            self.assertEqual(source_rows(db)[0]["rotations"], 1)

    def test_truncate_to_empty_resets_offset(self):
        with open_store(self.database) as db:
            source_id = register_source(db, self.source())
            collect_source(db, source_id)
            self.log.write_text("")
            self.assertEqual(collect_source(db, source_id), 0)
            self.assertEqual(source_rows(db)[0]["offset"], 0)
            self.log.write_text(FAILURE)
            self.assertEqual(collect_source(db, source_id), 1)

    def test_transaction_failure_rolls_back_records_and_offset(self):
        with open_store(self.database) as db:
            source_id = register_source(db, self.source())
            db.execute("""CREATE TRIGGER reject_checkpoint BEFORE UPDATE OF offset ON sources
                          BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END""")
            with self.assertRaises(sqlite3.IntegrityError):
                collect_source(db, source_id)
            self.assertEqual(retained_records(db, source_id), [])
            self.assertEqual(source_rows(db)[0]["offset"], 0)
            db.execute("DROP TRIGGER reject_checkpoint")
            self.assertEqual(collect_source(db, source_id), 1)

    def test_invalid_utf8_and_malformed_records_remain_visible(self):
        self.log.write_bytes(FAILURE.encode() + b"\xff\nnot syslog\n")
        with open_store(self.database) as db:
            source_id = register_source(db, self.source())
            self.assertEqual(collect_source(db, source_id), 3)
            rows = retained_records(db, source_id)
            self.assertIn("\\xff", rows[1]["raw_line"])
            self.assertIn("UTF-8", rows[1]["issue"])
            self.assertIn("prefix", rows[2]["issue"])
            self.assertEqual(source_rows(db)[0]["issue_count"], 2)

    def test_oversized_line_pauses_without_silently_skipping_evidence(self):
        self.log.write_text("x" * 8193 + "\n")
        with open_store(self.database) as db:
            source_id = register_source(db, self.source())
            with self.assertRaisesRegex(ValueError, "8 KiB"):
                collect_source(db, source_id)
            self.assertEqual(source_rows(db)[0]["offset"], 0)
            self.assertIn("paused", source_rows(db)[0]["last_error"])

    def test_text_logs_accept_long_package_lists_but_remain_bounded(self):
        self.log.write_text("Install: " + "package " * 4000 + "\n")
        with open_store(self.database) as db:
            source_id = register_source(db, self.source(format_name="text"))
            self.assertEqual(collect_source(db, source_id), 1)
            self.assertEqual(retained_records(db, source_id)[0]["raw_line"] + "\n", self.log.read_text())
            with self.log.open("a") as stream:
                stream.write("x" * (64 * 1024) + "\n")
            with self.assertRaisesRegex(ValueError, "64 KiB"):
                collect_source(db, source_id)
            self.assertEqual(len(retained_records(db, source_id)), 1)

    def test_missing_source_and_permission_error_are_visible_then_recover(self):
        with open_store(self.database) as db:
            source_id = register_source(db, self.source())
            self.log.unlink()
            with self.assertRaises(FileNotFoundError):
                collect_source(db, source_id)
            self.assertTrue(source_rows(db)[0]["last_error"])
            self.log.write_text(FAILURE)
            with patch("logsentry.collector.os.open", side_effect=PermissionError("denied")):
                with self.assertRaises(PermissionError):
                    collect_source(db, source_id)
            self.assertIn("denied", source_rows(db)[0]["last_error"])
            self.assertEqual(collect_source(db, source_id), 1)
            self.assertEqual(source_rows(db)[0]["last_error"], "")

    def test_symlink_fifo_and_database_cannot_be_sources(self):
        with open_store(self.database) as db:
            self.log.unlink()
            self.log.symlink_to(self.database)
            source_id = register_source(db, self.source())
            with self.assertRaises(OSError):
                collect_source(db, source_id)
            self.log.unlink()
            os.mkfifo(self.log)
            with self.assertRaisesRegex(ValueError, "regular file"):
                collect_source(db, source_id)
            database_id = register_source(db, Source("database", self.database, "text", 2026))
            with self.assertRaisesRegex(ValueError, "database cannot"):
                collect_source(db, database_id)

    def test_storage_private_and_readonly_never_creates(self):
        with self.assertRaises(FileNotFoundError):
            with open_store(self.database, readonly=True):
                pass
        self.assertFalse(self.database.parent.exists())
        with open_store(self.database):
            pass
        self.assertEqual(stat.S_IMODE(self.database.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.database.parent.stat().st_mode), 0o700)
        with open_store(self.database, readonly=True) as db:
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("DELETE FROM sources")
        self.database.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private"):
            with open_store(self.database):
                pass

    def test_database_symlink_and_shared_directory_are_rejected(self):
        self.database.parent.mkdir(mode=0o700)
        self.database.symlink_to(self.log)
        with self.assertRaises(ValueError):
            with open_store(self.database):
                pass
        self.database.unlink()
        self.database.parent.chmod(0o755)
        with self.assertRaises(ValueError):
            with open_store(self.database):
                pass
        self.assertEqual(self.log.read_text(), FAILURE)

    def test_package_time_uses_source_timezone_and_text_has_no_invented_time(self):
        self.log.write_text("2026-11-01 12:00:00 install python:all <none> 3.13\n")
        with open_store(self.database) as db:
            source_id = register_source(db, self.source(format_name="dpkg", timezone="Africa/Lagos"))
            collect_source(db, source_id)
            event = retained_records(db, source_id)[0]
            self.assertEqual(event["timestamp"], "2026-11-01T11:00:00+00:00")
            self.assertEqual(event["event_type"], "package_activity")
            other = self.root / "app.log"
            other.write_text("Application started\n")
            text_id = register_source(db, Source("app", other, "text", 2026))
            collect_source(db, text_id)
            record = retained_records(db, text_id)[0]
            self.assertIsNone(record["timestamp"])
            self.assertTrue(record["received_at"])
            self.assertEqual(record["issue"], "")

    def test_year_rollover_survives_restart_and_rotation(self):
        self.log.write_text("Dec 31 23:59:00 host sshd[1]: " + FAILURE.split(": ", 1)[1])
        with open_store(self.database) as db:
            source_id = register_source(db, self.source())
            collect_source(db, source_id)
        self.log.rename(self.root / "old.log")
        self.log.write_text("Jan  1 00:00:00 host sshd[1]: " + FAILURE.split(": ", 1)[1])
        with open_store(self.database) as db:
            collect_source(db, source_id)
            self.assertTrue(retained_records(db, source_id)[1]["timestamp"].startswith("2027-01-01"))

    def test_bounded_batches_and_retention_keep_checkpoint(self):
        self.log.write_text(FAILURE * 5)
        with open_store(self.database) as db:
            source_id = register_source(db, self.source())
            with patch("logsentry.collector.BATCH_LINES", 2), patch("logsentry.collector.RECORDS_PER_SOURCE", 3):
                self.assertEqual(collect_source(db, source_id), 2)
                self.assertEqual(collect_source(db, source_id), 2)
                self.assertEqual(collect_source(db, source_id), 1)
                self.assertEqual(collect_source(db, source_id), 0)
            self.assertEqual([row["line_number"] for row in retained_records(db, source_id)], [3, 4, 5])
            self.assertEqual(source_rows(db)[0]["dropped"], 2)

    def test_duplicate_path_or_changed_configuration_is_rejected(self):
        with open_store(self.database) as db:
            register_source(db, self.source())
            for source in (self.source(name="alias"), self.source(timezone="Africa/Lagos")):
                with self.assertRaisesRegex(ValueError, "different settings"):
                    register_source(db, source)

    def test_discovery_checks_only_existing_known_paths(self):
        ubuntu = self.root / "ubuntu"
        prefix = self.root / "termux"
        for path in (ubuntu / "var/log/auth.log", prefix / "var/log/apt/history.log"):
            path.parent.mkdir(parents=True)
            path.write_text("")
        sources = discover_sources(2026, "UTC", ubuntu_root=ubuntu, termux_prefix=prefix)
        self.assertEqual([source.name for source in sources], ["ubuntu-auth", "termux-apt"])

    def test_cli_register_collect_list_and_resume(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["--database", str(self.database), "--file", str(self.log),
                                   "--name", "test", "--year", "2026"]), 0)
            self.assertEqual(main(["--database", str(self.database)]), 0)
            self.assertEqual(main(["--database", str(self.database), "--list"]), 0)
        self.assertIn("collected 1 new records", output.getvalue())
        self.assertIn("collected 0 new records", output.getvalue())
        self.assertIn("1 retained records", output.getvalue())

    def test_cli_watch_stops_cleanly_and_retries(self):
        with redirect_stdout(StringIO()), patch("logsentry.collector.time.sleep", side_effect=KeyboardInterrupt) as sleep:
            code = main(["--database", str(self.database), "--file", str(self.log),
                         "--name", "test", "--year", "2026", "--watch"])
        self.assertEqual(code, 0)
        sleep.assert_called_once_with(1)
        with open_store(self.database) as db:
            self.assertEqual(source_rows(db)[0]["record_count"], 1)

    def test_running_watch_collects_new_append_without_restart_or_duplicates(self):
        # Exercise the real long-running process, not just calls to collect_source.
        self.log.write_text("")
        with open_store(self.database) as db:
            source_id = register_source(db, self.source())
        process = subprocess.Popen([
            sys.executable, "-m", "logsentry.collector", "--database", str(self.database),
            "--watch", "--interval", "0.2",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with open_store(self.database, readonly=True) as db:
                    if source_rows(db)[0]["last_checked"]:
                        break
                time.sleep(0.05)
            else:
                self.fail("Watch process did not start polling")
            with self.log.open("a") as stream:
                stream.write(FAILURE)
            while time.monotonic() < deadline:
                with open_store(self.database, readonly=True) as db:
                    records = retained_records(db, source_id)
                if records:
                    break
                time.sleep(0.05)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["event_type"], "failed_login")
            time.sleep(0.3)  # Another poll must not duplicate the same entry.
            with open_store(self.database, readonly=True) as db:
                self.assertEqual(len(retained_records(db, source_id)), 1)
            self.assertIsNone(process.poll())
        finally:
            process.terminate()
            process.communicate(timeout=5)

    def test_cli_invalid_arguments_and_missing_files_return_nonzero(self):
        for args in (["--discover"], ["--file", str(self.log)], ["--interval", "nan"], ["--interval", "0"]):
            with self.subTest(args=args), redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit) as error:
                    main(args)
                self.assertEqual(error.exception.code, 2)
        self.log.unlink()
        with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
            self.assertEqual(main(["--database", str(self.database), "--file", str(self.log),
                                   "--name", "test", "--year", "2026"]), 1)


if __name__ == "__main__":
    unittest.main()
