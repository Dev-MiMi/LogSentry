"""Verify the repeated-failure rule with activity that should and should not alert."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

from logsentry.config import DetectionSettings
from logsentry.data import LogEvent
from logsentry.detection import detect_repeated_failed_logins
from logsentry.parser import parse_lines, read_system_logs


ROOT = Path(__file__).resolve().parents[1]


class RepeatedFailureTests(unittest.TestCase):
    def setUp(self):
        self.settings = DetectionSettings(year=2026)

    def failure(self, number, **changes):
        event = LogEvent(
            timestamp=datetime(2026, 10, 29, 10, tzinfo=timezone.utc)
            + timedelta(minutes=number),
            hostname="ubuntu-lab",
            event_type="failed_login",
            line_number=number + 1,
            raw_line=f"sample failure {number}",
            username="bob",
            source_ip="203.0.113.42",
            authentication_method="password",
        )
        return replace(event, **changes)

    def test_sample_produces_one_alert_with_original_evidence(self):
        parsed = read_system_logs(ROOT / "samples/auth.log", self.settings)
        alerts = detect_repeated_failed_logins(parsed.events, self.settings)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule, "repeated_failed_logins")
        self.assertEqual(alert.severity, "Medium")
        self.assertEqual(alert.hostname, "ubuntu-lab")
        self.assertEqual(alert.source_ip, "203.0.113.42")
        self.assertEqual(alert.usernames, ("bob",))
        self.assertEqual([event.line_number for event in alert.evidence], [4, 5, 6, 7, 8])
        self.assertIs(alert.evidence[0], parsed.events[3])
        self.assertEqual(alert.timestamp, parsed.events[7].timestamp)

    def test_empty_and_below_threshold_inputs_do_not_alert(self):
        for count in (0, 1, 2):
            with self.subTest(count=count):
                events = [self.failure(number) for number in range(count)]
                self.assertEqual(detect_repeated_failed_logins(events, self.settings), [])

    def test_exact_threshold_alerts_and_custom_threshold_is_respected(self):
        events = [self.failure(number) for number in range(3)]
        self.assertEqual(len(detect_repeated_failed_logins(events, self.settings)), 1)
        settings = replace(self.settings, repeated_threshold=4)
        self.assertEqual(detect_repeated_failed_logins(events, settings), [])

    def test_different_hosts_are_not_combined(self):
        events = [self.failure(0), self.failure(1), self.failure(2, hostname="other-host")]
        self.assertEqual(detect_repeated_failed_logins(events, self.settings), [])

    def test_different_source_ips_are_not_combined(self):
        events = [self.failure(0), self.failure(1), self.failure(2, source_ip="198.51.100.23")]
        self.assertEqual(detect_repeated_failed_logins(events, self.settings), [])

    def test_multiple_accounts_are_reported_without_double_counting(self):
        events = [
            self.failure(0), self.failure(1, username="alice"),
            self.failure(2, username="admin", invalid_user=True),
            self.failure(3, event_type="invalid_user", username="admin", invalid_user=True),
        ]
        alert = detect_repeated_failed_logins(events, self.settings)[0]
        self.assertEqual(len(alert.evidence), 3)
        self.assertEqual(alert.usernames, ("admin", "alice", "bob"))

    def test_successes_other_events_and_missing_ips_do_not_count(self):
        events = [
            self.failure(0), self.failure(1),
            self.failure(2, event_type="successful_login"),
            self.failure(3, event_type="other"),
            self.failure(4, source_ip=None),
        ]
        self.assertEqual(detect_repeated_failed_logins(events, self.settings), [])

    def test_entire_file_is_counted_even_when_failures_are_days_apart(self):
        start = datetime(2026, 10, 29, tzinfo=timezone.utc)
        events = [self.failure(number, timestamp=start + timedelta(days=number)) for number in range(3)]
        alert = detect_repeated_failed_logins(events, self.settings)[0]
        self.assertEqual(len(alert.evidence), 3)
        self.assertIn("across the imported log", alert.description)

    def test_out_of_order_evidence_is_sorted_without_changing_input(self):
        events = [self.failure(2), self.failure(0), self.failure(1)]
        original = list(events)
        alert = detect_repeated_failed_logins(events, self.settings)[0]
        self.assertEqual([event.line_number for event in alert.evidence], [1, 2, 3])
        self.assertEqual(events, original)

    def test_multiple_sources_each_produce_one_alert_in_stable_order(self):
        first = [self.failure(number) for number in range(3)]
        second = [self.failure(number, hostname="second-host") for number in range(3)]
        alerts = detect_repeated_failed_logins(second + first, self.settings)
        reversed_alerts = detect_repeated_failed_logins(reversed(second + first), self.settings)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts, reversed_alerts)
        self.assertEqual({alert.hostname for alert in alerts}, {"ubuntu-lab", "second-host"})

    def test_malformed_and_non_ssh_records_cannot_complete_threshold(self):
        prefix = "Oct 29 10:15:01 ubuntu-lab"
        message = "Failed password for bob from 203.0.113.42 port 60101 ssh2\n"
        parsed = parse_lines([
            f"{prefix} sshd[1]: {message}",
            f"{prefix} sshd[2]: {message}",
            f"{prefix} sshd[3]: Failed password for bob\n",
            f"{prefix} webapp[4]: {message}",
        ], self.settings)
        self.assertEqual(len(parsed.issues), 1)
        self.assertEqual(detect_repeated_failed_logins(parsed.events, self.settings), [])


if __name__ == "__main__":
    unittest.main()
