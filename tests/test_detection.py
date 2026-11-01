"""Verify repeated failures and timed bursts with positive and negative examples."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

from logsentry.config import DetectionSettings
from logsentry.data import LogEvent
from logsentry.detection import detect_brute_force_attacks, detect_repeated_failed_logins
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


class BruteForceTests(unittest.TestCase):
    def setUp(self):
        self.settings = DetectionSettings(year=2026)
        self.base_time = datetime(2026, 10, 29, 10, tzinfo=timezone.utc)

    def failures(self, seconds):
        return [LogEvent(
            timestamp=self.base_time + timedelta(seconds=offset),
            hostname="ubuntu-lab", event_type="failed_login",
            line_number=number + 1, raw_line=f"failure {number}",
            username="bob", source_ip="203.0.113.42",
            authentication_method="password",
        ) for number, offset in enumerate(seconds)]

    def test_sample_alert_contains_five_original_failures_in_68_seconds(self):
        parsed = read_system_logs(ROOT / "samples/auth.log", self.settings)
        alerts = detect_brute_force_attacks(parsed.events, self.settings)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule, "brute_force")
        self.assertEqual(alert.severity, "High")
        self.assertEqual(alert.hostname, "ubuntu-lab")
        self.assertEqual(alert.source_ip, "203.0.113.42")
        self.assertEqual(alert.usernames, ("bob",))
        self.assertEqual([event.line_number for event in alert.evidence], [4, 5, 6, 7, 8])
        self.assertEqual(alert.evidence[-1].timestamp - alert.evidence[0].timestamp,
                         timedelta(seconds=68))
        self.assertIs(alert.evidence[0], parsed.events[3])
        self.assertIn("Possible brute-force", alert.description)
        self.assertIn("0:01:08", alert.description)

    def test_fewer_than_five_failures_do_not_alert(self):
        for count in range(5):
            with self.subTest(count=count):
                self.assertEqual(detect_brute_force_attacks(self.failures(range(count)), self.settings), [])

    def test_exact_five_minute_boundary_qualifies_but_one_second_over_does_not(self):
        events = self.failures([0, 60, 120, 180, 300])
        self.assertEqual(len(detect_brute_force_attacks(events, self.settings)), 1)
        events[-1] = replace(events[-1], timestamp=self.base_time + timedelta(seconds=301))
        self.assertEqual(detect_brute_force_attacks(events, self.settings), [])

    def test_slow_failures_can_repeat_without_being_a_burst(self):
        events = self.failures([0, 600, 1200, 1800, 2400, 3000])
        self.assertEqual(len(detect_repeated_failed_logins(events, self.settings)), 1)
        self.assertEqual(detect_brute_force_attacks(events, self.settings), [])

    def test_later_burst_is_found_after_initial_window_is_too_slow(self):
        events = self.failures([0, 3600, 3610, 3620, 3630, 3640])
        alert = detect_brute_force_attacks(events, self.settings)[0]
        self.assertEqual(alert.evidence, tuple(events[1:]))
        self.assertEqual(alert.timestamp, events[-1].timestamp)

    def test_settings_control_threshold_and_window(self):
        events = self.failures([0, 60, 120])
        settings = replace(self.settings, brute_force_threshold=3,
                           brute_force_window=timedelta(minutes=2))
        self.assertEqual(len(detect_brute_force_attacks(events, settings)), 1)
        too_short = replace(settings, brute_force_window=timedelta(seconds=119))
        self.assertEqual(detect_brute_force_attacks(events, too_short), [])
        six_required = replace(self.settings, brute_force_threshold=6)
        self.assertEqual(detect_brute_force_attacks(self.failures(range(5)), six_required), [])

    def test_attempts_on_different_hosts_or_ips_do_not_combine(self):
        for changes in ({"hostname": "other-host"}, {"source_ip": "198.51.100.23"}):
            with self.subTest(changes=changes):
                events = self.failures(range(5))
                events[-1] = replace(events[-1], **changes)
                self.assertEqual(detect_brute_force_attacks(events, self.settings), [])

    def test_non_failure_records_and_missing_ips_do_not_count(self):
        for changes in (
            {"event_type": "successful_login"}, {"event_type": "invalid_user"},
            {"event_type": "other"}, {"source_ip": None},
        ):
            with self.subTest(changes=changes):
                events = self.failures(range(5))
                events[-1] = replace(events[-1], **changes)
                self.assertEqual(detect_brute_force_attacks(events, self.settings), [])

    def test_out_of_order_records_are_sorted_without_mutating_input(self):
        events = self.failures([0, 10, 20, 30, 40])
        unordered = [events[4], events[0], events[2], events[1], events[3]]
        original = list(unordered)
        alert = detect_brute_force_attacks(unordered, self.settings)[0]
        self.assertEqual(alert.evidence, tuple(events))
        self.assertEqual(unordered, original)

    def test_all_usernames_in_matching_window_are_preserved(self):
        events = self.failures(range(5))
        events[1] = replace(events[1], username="alice")
        events[2] = replace(events[2], username="admin", invalid_user=True)
        alert = detect_brute_force_attacks(events, self.settings)[0]
        self.assertEqual(alert.usernames, ("admin", "alice", "bob"))
        self.assertEqual(len(alert.evidence), 5)

    def test_overlapping_windows_and_later_bursts_return_one_alert_per_source(self):
        events = self.failures([0, 10, 20, 30, 40, 50, 60, 3600, 3610, 3620, 3630, 3640])
        alerts = detect_brute_force_attacks(events, self.settings)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].evidence, tuple(events[:5]))

    def test_distinct_sources_each_get_an_alert_in_stable_order(self):
        first = self.failures(range(5))
        second = [replace(event, hostname="another-host") for event in first]
        events = second + first
        alerts = detect_brute_force_attacks(events, self.settings)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts, detect_brute_force_attacks(reversed(events), self.settings))

    def test_success_between_failures_does_not_hide_attempt_pattern(self):
        events = self.failures(range(5))
        success = replace(events[0], event_type="successful_login",
                          timestamp=self.base_time + timedelta(seconds=2))
        alerts = detect_brute_force_attacks(events + [success], self.settings)
        self.assertEqual(len(alerts), 1)
        self.assertNotIn(success, alerts[0].evidence)

    def test_equal_timestamps_can_qualify_and_line_order_is_preserved(self):
        events = self.failures([0, 0, 0, 0, 0])
        alert = detect_brute_force_attacks(reversed(events), self.settings)[0]
        self.assertEqual(alert.evidence, tuple(events))

    def test_burst_spanning_midnight_uses_full_datetime(self):
        events = self.failures([0, 30, 60, 90, 120])
        start = datetime(2026, 10, 29, 23, 59, 30, tzinfo=timezone.utc)
        events = [replace(event, timestamp=start + timedelta(seconds=number * 30))
                  for number, event in enumerate(events)]
        alert = detect_brute_force_attacks(events, self.settings)[0]
        self.assertEqual(alert.evidence[-1].timestamp.day, 30)

    def test_invalid_and_unrelated_log_lines_cannot_complete_a_burst(self):
        lines = [
            f"Oct 29 10:15:0{number} ubuntu-lab sshd[{number + 1}]: "
            "Failed password for bob from 203.0.113.42 port 60101 ssh2\n"
            for number in range(4)
        ]
        lines.extend([
            "Oct 29 10:15:04 ubuntu-lab sshd[5]: Failed password for bob\n",
            "Oct 29 10:15:05 ubuntu-lab webapp[6]: "
            "Failed password for bob from 203.0.113.42 port 60101 ssh2\n",
        ])
        parsed = parse_lines(lines, self.settings)
        self.assertEqual(len(parsed.issues), 1)
        self.assertEqual(detect_brute_force_attacks(parsed.events, self.settings), [])


if __name__ == "__main__":
    unittest.main()
