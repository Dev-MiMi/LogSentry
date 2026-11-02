"""Behavior checks for settings, data records, and log reading; no dependencies."""

from collections import Counter
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from logsentry.config import DetectionSettings
from logsentry.data import Alert, Analysis, LogEvent, ParsedLog
from logsentry.parser import InputLimitError, parse_lines, read_system_logs


ROOT = Path(__file__).resolve().parents[1]


def login_line(time="Oct 29 10:15:01", message=None, process="sshd[2201]"):
    if message is None:
        message = "Failed password for bob from 203.0.113.42 port 60101 ssh2"
    return f"{time} ubuntu-lab {process}: {message}\n"


class SettingsTests(unittest.TestCase):
    def test_example_settings_and_hours(self):
        settings = DetectionSettings(year=2026)
        self.assertEqual(settings.brute_force_window, timedelta(minutes=5))
        self.assertFalse(settings.is_normal_login_hour(5))
        self.assertTrue(settings.is_normal_login_hour(6))
        self.assertTrue(settings.is_normal_login_hour(21))
        self.assertFalse(settings.is_normal_login_hour(22))

    def test_night_shift_hours(self):
        settings = DetectionSettings(year=2026, normal_start_hour=22, normal_end_hour=6)
        self.assertTrue(settings.is_normal_login_hour(23))
        self.assertTrue(settings.is_normal_login_hour(5))
        self.assertFalse(settings.is_normal_login_hour(6))
        self.assertFalse(settings.is_normal_login_hour(12))

    def test_invalid_policy_is_rejected_early(self):
        examples = (
            {"year": 0}, {"year": 10000}, {"year": True},
            {"brute_force_threshold": 1}, {"repeated_threshold": 1},
            {"brute_force_threshold": 2.5}, {"normal_start_hour": 1.5},
            {"normal_start_hour": -1}, {"normal_end_hour": 25},
            {"normal_start_hour": 6, "normal_end_hour": 6},
            {"brute_force_window": timedelta(0)},
            {"success_after_failures_window": timedelta(seconds=-1)},
            {"brute_force_window": 5}, {"timezone_name": "Unknown/Zone"},
            {"timezone_name": "/etc/passwd"}, {"timezone_name": ""},
            {"trusted_networks": ("192.168.1.20/24",)},
            {"trusted_networks": ("not-a-network",)},
            {"trusted_networks": (123,)}, {"trusted_networks": ["10.0.0.0/8"]},
        )
        for changes in examples:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                DetectionSettings(**({"year": 2026} | changes))

    def test_settings_are_immutable(self):
        settings = DetectionSettings(year=2026)
        with self.assertRaises(FrozenInstanceError):
            settings.year = 2027


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.settings = DetectionSettings(year=2026)

    def parse(self, *lines, **settings):
        return parse_lines(lines, DetectionSettings(year=2026, **settings))

    def test_sample_counts_and_evidence(self):
        result = read_system_logs(ROOT / "tests/fixtures/ssh_auth.log", self.settings)
        self.assertEqual(result.total_lines, 12)
        self.assertFalse(result.issues)
        self.assertEqual(Counter(event.event_type for event in result.events), {
            "failed_login": 6, "successful_login": 3, "invalid_user": 1, "other": 2,
        })
        failed = result.events[3]
        self.assertEqual(failed.source_ip, "203.0.113.42")
        self.assertEqual(failed.username, "bob")
        self.assertEqual(failed.hostname, "ubuntu-lab")
        self.assertEqual(failed.line_number, 4)
        self.assertIn("Failed password for bob", failed.raw_line)

    def test_invalid_user_failure_is_not_double_counted(self):
        result = self.parse(login_line(message=(
            "Failed password for invalid user admin from 198.51.100.23 port 61000 ssh2"
        )))
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].event_type, "failed_login")
        self.assertEqual(result.events[0].username, "admin")
        self.assertTrue(result.events[0].invalid_user)

    def test_public_key_and_modern_sshd_process(self):
        result = self.parse(login_line(process="sshd-session[100]", message=(
            "Accepted publickey for alice from 192.168.1.20 port 52010 ssh2"
        )))
        self.assertEqual(result.events[0].event_type, "successful_login")
        self.assertEqual(result.events[0].authentication_method, "publickey")

    def test_ipv6_is_normalized_including_ipv4_mapped_addresses(self):
        examples = (
            ("2001:0db8:0:0:0:0:0:1", "2001:db8::1"),
            ("::ffff:203.0.113.42", "203.0.113.42"),
        )
        for source, expected in examples:
            with self.subTest(source=source):
                result = self.parse(login_line(message=(
                    f"Failed password for bob from {source} port 60101 ssh2"
                )))
                self.assertEqual(result.events[0].source_ip, expected)

    def test_other_app_message_does_not_become_a_login(self):
        result = self.parse(login_line(process="webapp[22]"))
        self.assertEqual(result.events[0].event_type, "other")
        self.assertIsNone(result.events[0].source_ip)

    def test_bad_lines_are_reported_and_reading_continues(self):
        result = self.parse("not a log entry\n", login_line(), "\n")
        self.assertEqual(result.total_lines, 3)
        self.assertEqual(result.blank_lines, 1)
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].line_number, 2)
        self.assertEqual(result.issues[0].line_number, 1)

    def test_invalid_authentication_records_are_issues(self):
        messages = (
            "Failed password for bob from not-an-ip port 60101 ssh2",
            "Failed password for bob from fe80::1%eth0 port 60101 ssh2",
            "Failed password for bob from 203.0.113.42 port 65536 ssh2",
            "Failed password for bob from 203.0.113.42 port 0 ssh2",
            "Accepted password for invalid user bob from 203.0.113.42 port 22 ssh2",
            "Failed password for bob",
            "Invalid user admin",
        )
        for message in messages:
            with self.subTest(message=message):
                result = self.parse(login_line(message=message))
                self.assertFalse(result.events)
                self.assertEqual(len(result.issues), 1)

    def test_control_characters_and_embedded_newlines_are_issues(self):
        for suffix in ("\x1b[31m", "\x00", "\x7f", "\nextra", "\n"):
            with self.subTest(suffix=suffix):
                result = self.parse(login_line().rstrip("\n") + suffix + "\n")
                self.assertFalse(result.events)
                self.assertEqual(len(result.issues), 1)

    def test_crlf_line_endings_are_supported(self):
        result = self.parse(login_line().replace("\n", "\r\n"))
        self.assertEqual(len(result.events), 1)
        self.assertFalse(result.issues)

    def test_log_timezone_is_converted_to_utc(self):
        result = self.parse(login_line(), timezone_name="Africa/Lagos")
        self.assertEqual(result.events[0].timestamp, datetime(2026, 10, 29, 9, 15, 1, tzinfo=timezone.utc))

    def test_iso_offset_overrides_configured_year_and_timezone(self):
        result = self.parse(login_line(time="2024-02-29T10:15:01+02:00"))
        self.assertEqual(result.events[0].timestamp, datetime(2024, 2, 29, 8, 15, 1, tzinfo=timezone.utc))

    def test_new_year_rollover_is_preserved(self):
        result = self.parse(
            login_line(time="Dec 31 23:59:59"),
            login_line(time="Jan  1 00:00:01"),
        )
        self.assertEqual(result.events[1].timestamp.year, 2027)
        self.assertEqual(result.events[1].timestamp - result.events[0].timestamp, timedelta(seconds=2))

    def test_bad_record_does_not_change_the_year(self):
        result = self.parse(
            login_line(time="Nov 30 23:59:59"),
            login_line(time="Dec 31 23:59:59", message="Failed password for bob"),
            login_line(time="Jan 1 00:00:01"),
        )
        self.assertEqual(len(result.issues), 1)
        self.assertEqual(result.events[-1].timestamp.year, 2026)

    def test_bad_dates_are_reported(self):
        for date in ("Feb 30 10:00:00", "Foo 29 10:00:00", "Oct 29 25:00:00"):
            with self.subTest(date=date):
                result = self.parse(login_line(time=date))
                self.assertEqual(len(result.issues), 1)
                self.assertFalse(result.events)

    def test_ambiguous_and_nonexistent_dst_times_require_offset(self):
        for date in ("Mar 8 02:30:00", "Nov 1 01:30:00"):
            with self.subTest(date=date):
                result = self.parse(login_line(time=date), timezone_name="America/New_York")
                self.assertEqual(len(result.issues), 1)
                self.assertFalse(result.events)
        explicit = self.parse(login_line(time="2026-11-01T01:30:00-04:00"), timezone_name="America/New_York")
        self.assertEqual(explicit.events[0].timestamp.hour, 5)

    def test_file_reading_propagates_missing_file(self):
        with TemporaryDirectory() as folder:
            with self.assertRaises(FileNotFoundError):
                read_system_logs(Path(folder) / "missing.log", self.settings)

    def test_file_reader_rejects_invalid_utf8_and_oversized_line(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "auth.log"
            path.write_bytes(b"\xff\n")
            with self.assertRaisesRegex(ValueError, "UTF-8"):
                read_system_logs(path, self.settings)
            path.write_bytes(b"x" * 8193)
            with self.assertRaises(InputLimitError):
                read_system_logs(path, self.settings)

    def test_input_byte_and_line_budgets(self):
        with patch("logsentry.parser.MAX_INPUT_BYTES", 10):
            with self.assertRaises(InputLimitError):
                self.parse(login_line())
        with patch("logsentry.parser.MAX_INPUT_LINES", 1):
            with self.assertRaises(InputLimitError):
                self.parse(login_line(), login_line())


class DataTests(unittest.TestCase):
    def event(self, hour=10):
        return LogEvent(
            timestamp=datetime(2026, 10, 29, hour, tzinfo=timezone.utc),
            hostname="ubuntu-lab", event_type="failed_login",
            line_number=1, raw_line="evidence", username="bob", source_ip="203.0.113.42",
        )

    def test_events_reject_missing_timezone_and_cannot_be_changed(self):
        with self.assertRaises(ValueError):
            LogEvent(datetime(2026, 10, 29), "lab", "other", 1, "evidence")
        event = self.event()
        with self.assertRaises(FrozenInstanceError):
            event.username = "alice"

    def test_events_normalize_offsets(self):
        event = LogEvent(datetime(2026, 10, 29, 10, tzinfo=timezone(timedelta(hours=2))), "lab", "other", 1, "evidence")
        self.assertEqual(event.timestamp.hour, 8)
        self.assertEqual(event.timestamp.tzinfo, timezone.utc)

    def test_parse_results_have_independent_lists(self):
        first, second = ParsedLog(), ParsedLog()
        first.events.append(self.event())
        self.assertFalse(second.events)

    def test_alert_evidence_is_required_and_uses_latest_time(self):
        fields = dict(rule="brute_force", severity="High", hostname="lab",
                      source_ip="203.0.113.42", usernames=("bob",), description="Finding")
        with self.assertRaises(ValueError):
            Alert(**fields, evidence=())
        with self.assertRaises(ValueError):
            Alert(**(fields | {"severity": "Unknown"}), evidence=(self.event(),))
        evidence = [self.event(12), self.event(10)]
        alert = Alert(**fields, evidence=evidence)
        evidence.clear()
        self.assertEqual(len(alert.evidence), 2)
        self.assertEqual(alert.timestamp.hour, 12)

    def test_analysis_normalizes_its_generation_time(self):
        analysis = Analysis("sample", DetectionSettings(year=2026), ParsedLog(), (),
                            datetime(2026, 10, 29, 10, tzinfo=timezone(timedelta(hours=2))))
        self.assertEqual(analysis.generated_at.hour, 8)


if __name__ == "__main__":
    unittest.main()
