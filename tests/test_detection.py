"""Verify authentication rules with activity that should and should not alert."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

from logsentry.config import DetectionSettings
from logsentry.data import LogEvent
from logsentry.detection import (
    detect_brute_force_attacks,
    detect_invalid_user_attempts,
    detect_repeated_failed_logins,
    detect_success_after_failures,
    detect_suspicious_events,
    detect_suspicious_logins,
)
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


class SuspiciousLoginTests(unittest.TestCase):
    def setUp(self):
        self.settings = DetectionSettings(year=2026)

    def success(self, hour=10, minute=0, second=0, **changes):
        event = LogEvent(
            timestamp=datetime(2026, 10, 29, hour, minute, second, tzinfo=timezone.utc),
            hostname="ubuntu-lab", event_type="successful_login",
            line_number=1, raw_line="sample successful login",
            username="alice", source_ip="192.168.1.20", authentication_method="password",
        )
        return replace(event, **changes)

    def test_sample_flags_two_successes_with_their_specific_reasons(self):
        parsed = read_system_logs(ROOT / "samples/auth.log", self.settings)
        alerts = detect_suspicious_logins(parsed.events, self.settings)
        self.assertEqual(len(alerts), 2)
        bob, alice = alerts
        self.assertEqual(bob.severity, "Medium")
        self.assertEqual(bob.source_ip, "203.0.113.42")
        self.assertEqual(bob.usernames, ("bob",))
        self.assertNotIn("outside configured hours", bob.description)
        self.assertIn("outside configured trusted networks", bob.description)
        self.assertIs(bob.evidence[0], parsed.events[8])
        self.assertEqual(alice.severity, "High")
        self.assertEqual(alice.rule, "suspicious_login")
        self.assertEqual(alice.source_ip, "198.51.100.77")
        self.assertIn("23:45:10", alice.description)
        self.assertIn("outside configured hours", alice.description)
        self.assertIn("outside configured trusted networks", alice.description)
        self.assertIs(alice.evidence[0], parsed.events[11])

    def test_trusted_daytime_and_empty_input_do_not_alert(self):
        self.assertEqual(detect_suspicious_logins([], self.settings), [])
        self.assertEqual(detect_suspicious_logins([self.success()], self.settings), [])

    def test_one_reason_is_medium_and_both_reasons_are_high(self):
        for hour, source, severity, time_reason, ip_reason in (
            (23, "192.168.1.20", "Medium", True, False),
            (10, "203.0.113.42", "Medium", False, True),
            (23, "203.0.113.42", "High", True, True),
        ):
            with self.subTest(hour=hour, source=source):
                alert = detect_suspicious_logins([self.success(hour, source_ip=source)], self.settings)[0]
                self.assertEqual(alert.severity, severity)
                self.assertEqual("outside configured hours" in alert.description, time_reason)
                self.assertEqual("outside configured trusted networks" in alert.description, ip_reason)

    def test_normal_hours_start_inclusive_and_end_exclusive(self):
        for hour, minute, second, should_alert in (
            (5, 59, 59, True), (6, 0, 0, False),
            (21, 59, 59, False), (22, 0, 0, True),
        ):
            with self.subTest(time=(hour, minute, second)):
                alerts = detect_suspicious_logins([self.success(hour, minute, second)], self.settings)
                self.assertEqual(bool(alerts), should_alert)

    def test_configured_local_hour_is_used_in_both_directions(self):
        settings = replace(self.settings, timezone_name="Africa/Lagos")
        # 05:00 UTC is 06:00 local, inside working hours.
        self.assertEqual(detect_suspicious_logins([self.success(5)], settings), [])
        # 21:00 UTC is 22:00 local, outside working hours.
        alert = detect_suspicious_logins([self.success(21)], settings)[0]
        self.assertEqual(alert.severity, "Medium")
        self.assertIn("22:00:00+01:00", alert.description)
        self.assertIn("Africa/Lagos", alert.description)
        self.assertEqual(alert.timestamp.hour, 21)  # Evidence remains in UTC.

    def test_timezone_conversion_handles_local_date_rollover(self):
        settings = replace(self.settings, timezone_name="Africa/Lagos")
        alert = detect_suspicious_logins([self.success(23, 30)], settings)[0]
        self.assertIn("2026-10-30T00:30:00+01:00", alert.description)
        self.assertEqual(alert.timestamp.day, 29)

    def test_timezone_offset_changes_are_used_for_working_hours(self):
        settings = replace(self.settings, timezone_name="America/New_York")
        # July uses UTC-4, January uses UTC-5. At 10:00 UTC only July is 06:00.
        summer = self.success(timestamp=datetime(2026, 7, 1, 10, tzinfo=timezone.utc))
        winter = self.success(timestamp=datetime(2026, 1, 1, 10, tzinfo=timezone.utc))
        self.assertEqual(detect_suspicious_logins([summer], settings), [])
        alert = detect_suspicious_logins([winter], settings)[0]
        self.assertIn("05:00:00-05:00", alert.description)

    def test_night_shift_and_full_day_settings(self):
        night_shift = replace(self.settings, normal_start_hour=22, normal_end_hour=6)
        for hour, should_alert in ((22, False), (23, False), (5, False), (6, True), (12, True)):
            with self.subTest(hour=hour):
                self.assertEqual(bool(detect_suspicious_logins([self.success(hour)], night_shift)), should_alert)
        all_day = replace(self.settings, normal_start_hour=0, normal_end_hour=24)
        for hour in (0, 5, 23):
            self.assertEqual(detect_suspicious_logins([self.success(hour)], all_day), [])

    def test_membership_uses_network_not_private_flag_or_prefix(self):
        for source, should_alert in (
            ("192.168.1.1", False), ("192.168.1.254", False),
            ("192.168.10.20", True), ("192.168.2.20", True),
            ("10.0.0.20", True), ("172.16.1.20", True),
        ):
            with self.subTest(source=source):
                self.assertEqual(bool(detect_suspicious_logins([self.success(source_ip=source)], self.settings)), should_alert)

    def test_public_network_can_be_explicitly_trusted_and_empty_allowlist_flags_all(self):
        event = self.success(source_ip="203.0.113.42")
        settings = replace(self.settings, trusted_networks=("203.0.113.0/24",))
        self.assertEqual(detect_suspicious_logins([event], settings), [])
        settings = replace(self.settings, trusted_networks=())
        self.assertEqual(detect_suspicious_logins([self.success()], settings)[0].severity, "Medium")

    def test_ipv6_and_mixed_network_families(self):
        settings = replace(self.settings, trusted_networks=("192.168.1.0/24", "2001:db8:1::/64"))
        self.assertEqual(detect_suspicious_logins([self.success(source_ip="2001:db8:1::20")], settings), [])
        self.assertEqual(detect_suspicious_logins([self.success()], settings), [])
        event = self.success(source_ip="2001:db8:2::20")
        self.assertEqual(detect_suspicious_logins([event], settings)[0].severity, "Medium")
        ipv6_only = replace(self.settings, trusted_networks=("2001:db8:1::/64",))
        self.assertEqual(detect_suspicious_logins([self.success()], ipv6_only)[0].severity, "Medium")

    def test_ipv4_mapped_ipv6_uses_same_ipv4_trust_policy(self):
        event = self.success(source_ip="::ffff:192.168.1.20")
        self.assertEqual(detect_suspicious_logins([event], self.settings), [])
        event = self.success(source_ip="::ffff:203.0.113.42")
        self.assertEqual(detect_suspicious_logins([event], self.settings)[0].source_ip, "203.0.113.42")

    def test_failures_invalid_user_other_events_and_missing_source_are_skipped(self):
        events = [self.success(23, source_ip="203.0.113.42", event_type=kind)
                  for kind in ("failed_login", "invalid_user", "other")]
        events.append(self.success(23, source_ip=None))
        self.assertEqual(detect_suspicious_logins(events, self.settings), [])

    def test_password_and_publickey_successes_are_both_checked(self):
        events = [self.success(23, authentication_method=method, line_number=number)
                  for number, method in enumerate(("password", "publickey"), start=1)]
        alerts = detect_suspicious_logins(events, self.settings)
        self.assertEqual(len(alerts), 2)
        self.assertTrue(all(alert.severity == "Medium" for alert in alerts))

    def test_each_flagged_event_has_own_evidence_and_stable_order_without_mutation(self):
        earlier = self.success(22, line_number=3)
        later = self.success(23, line_number=5)
        another = self.success(23, line_number=4)
        events = [later, earlier, another]
        original = list(events)
        alerts = detect_suspicious_logins(iter(events), self.settings)
        self.assertEqual([alert.evidence for alert in alerts], [(earlier,), (another,), (later,)])
        self.assertEqual(events, original)
        self.assertEqual(alerts, detect_suspicious_logins(reversed(events), self.settings))

    def test_malformed_success_is_reported_by_parser_instead_of_becoming_an_alert(self):
        parsed = parse_lines([
            "Oct 29 23:45:10 ubuntu-lab sshd[1]: "
            "Accepted password for alice from not-an-ip port 62000 ssh2\n",
        ], self.settings)
        self.assertEqual(len(parsed.issues), 1)
        self.assertEqual(detect_suspicious_logins(parsed.events, self.settings), [])


class SuspiciousEventTests(unittest.TestCase):
    def setUp(self):
        self.settings = DetectionSettings(year=2026)
        self.base_time = datetime(2026, 10, 29, 10, tzinfo=timezone.utc)

    def event(self, seconds, event_type="failed_login", **changes):
        event = LogEvent(
            timestamp=self.base_time + timedelta(seconds=seconds),
            hostname="ubuntu-lab", event_type=event_type,
            line_number=seconds + 1, raw_line=f"{event_type} at {seconds}",
            username="bob", source_ip="203.0.113.42", authentication_method="password",
        )
        return replace(event, **changes)

    def sequence(self):
        return [self.event(0), self.event(10), self.event(20),
                self.event(30, "successful_login")]

    def test_sample_yields_account_success_and_one_invalid_user_finding(self):
        parsed = read_system_logs(ROOT / "samples/auth.log", self.settings)
        alerts = detect_suspicious_events(parsed.events, self.settings)
        self.assertEqual(len(alerts), 2)
        success, invalid = alerts
        self.assertEqual(success.rule, "success_after_failures")
        self.assertEqual(success.severity, "High")
        self.assertEqual(success.usernames, ("bob",))
        self.assertEqual(success.hostname, "ubuntu-lab")
        self.assertEqual(success.source_ip, "203.0.113.42")
        self.assertEqual([event.line_number for event in success.evidence], [4, 5, 6, 7, 8, 9])
        self.assertIs(success.evidence[-1], parsed.events[8])
        self.assertIn("5 failed logins", success.description)
        self.assertIn("requires investigation", success.description)
        self.assertEqual(invalid.rule, "invalid_user")
        self.assertEqual(invalid.severity, "Medium")
        self.assertEqual(invalid.usernames, ("admin",))
        self.assertEqual([event.line_number for event in invalid.evidence], [10, 11])

    def test_empty_and_fewer_failures_do_not_flag_success(self):
        self.assertEqual(detect_suspicious_events([], self.settings), [])
        for count in range(3):
            with self.subTest(count=count):
                events = [self.event(number) for number in range(count)]
                events.append(self.event(10, "successful_login"))
                self.assertEqual(detect_success_after_failures(events, self.settings), [])

    def test_all_three_identity_fields_must_match(self):
        for changes in ({"username": "alice"}, {"hostname": "other-host"},
                        {"source_ip": "198.51.100.23"}):
            with self.subTest(changes=changes):
                events = self.sequence()
                events[-1] = replace(events[-1], **changes)
                self.assertEqual(detect_success_after_failures(events, self.settings), [])

    def test_unrelated_failures_cannot_complete_threshold(self):
        for changes in ({"username": "alice"}, {"hostname": "other-host"},
                        {"source_ip": "198.51.100.23"}):
            with self.subTest(changes=changes):
                events = self.sequence()
                events[0] = replace(events[0], **changes)
                self.assertEqual(detect_success_after_failures(events, self.settings), [])

    def test_failure_at_exact_ten_minutes_is_included_but_one_second_older_is_not(self):
        events = [self.event(0), self.event(10), self.event(20),
                  self.event(600, "successful_login")]
        self.assertEqual(len(detect_success_after_failures(events, self.settings)), 1)
        events[-1] = self.event(601, "successful_login")
        self.assertEqual(detect_success_after_failures(events, self.settings), [])

    def test_expired_failure_is_excluded_from_evidence(self):
        events = [self.event(0), self.event(610), self.event(620), self.event(630),
                  self.event(640, "successful_login")]
        alert = detect_success_after_failures(events, self.settings)[0]
        self.assertEqual(alert.evidence, tuple(events[1:]))
        self.assertIn("3 failed logins", alert.description)

    def test_custom_threshold_and_window_control_correlation(self):
        settings = replace(self.settings, repeated_threshold=2,
                           success_after_failures_window=timedelta(seconds=10))
        events = [self.event(0), self.event(5), self.event(10, "successful_login")]
        self.assertEqual(len(detect_success_after_failures(events, settings)), 1)
        self.assertEqual(detect_success_after_failures(events, self.settings), [])
        events[-1] = self.event(11, "successful_login")
        self.assertEqual(detect_success_after_failures(events, settings), [])

    def test_success_clears_old_failures_before_next_success(self):
        events = self.sequence() + [self.event(40, "successful_login")]
        alerts = detect_success_after_failures(events, self.settings)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].timestamp, self.base_time + timedelta(seconds=30))

    def test_success_below_threshold_also_clears_history(self):
        events = [self.event(0), self.event(10), self.event(20, "successful_login"),
                  self.event(30), self.event(40, "successful_login")]
        self.assertEqual(detect_success_after_failures(events, self.settings), [])

    def test_success_only_clears_matching_account_history(self):
        events = self.sequence()[:-1] + [
            self.event(25, "successful_login", username="alice"),
            self.event(30, "successful_login"),
        ]
        alerts = detect_success_after_failures(events, self.settings)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].usernames, ("bob",))

    def test_new_failure_sequence_after_success_can_alert_again(self):
        events = self.sequence() + [self.event(40), self.event(50), self.event(60),
                                  self.event(70, "successful_login")]
        alerts = detect_success_after_failures(events, self.settings)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0].evidence, tuple(events[:4]))
        self.assertEqual(alerts[1].evidence, tuple(events[4:]))

    def test_future_failures_are_not_correlated_to_earlier_success(self):
        events = [self.event(0, "successful_login"), self.event(1), self.event(2), self.event(3)]
        self.assertEqual(detect_success_after_failures(events, self.settings), [])

    def test_same_timestamp_uses_line_order_before_correlating(self):
        failures = [self.event(0, line_number=number) for number in (1, 2, 3)]
        success = self.event(0, "successful_login", line_number=4)
        self.assertEqual(len(detect_success_after_failures([success] + failures, self.settings)), 1)
        earlier_success = replace(success, line_number=0)
        self.assertEqual(detect_success_after_failures(failures + [earlier_success], self.settings), [])

    def test_out_of_order_records_and_generators_work_without_mutation(self):
        events = self.sequence()
        unordered = [events[3], events[1], events[0], events[2]]
        original = list(unordered)
        alerts = detect_suspicious_events(iter(unordered), self.settings)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].evidence, tuple(events))
        self.assertEqual(unordered, original)

    def test_invalid_accounts_and_non_failure_records_cannot_establish_correlation(self):
        for changes in ({"invalid_user": True}, {"event_type": "invalid_user"},
                        {"event_type": "other"}, {"source_ip": None}, {"username": None}):
            with self.subTest(changes=changes):
                events = self.sequence()
                events[0] = replace(events[0], **changes)
                self.assertEqual(detect_success_after_failures(events, self.settings), [])

    def test_publickey_success_can_follow_password_failures(self):
        events = self.sequence()
        events[-1] = replace(events[-1], authentication_method="publickey")
        alert = detect_success_after_failures(events, self.settings)[0]
        self.assertEqual(alert.severity, "High")
        self.assertIn("requires investigation", alert.description)
        self.assertEqual(alert.evidence[-1].authentication_method, "publickey")

    def test_invalid_user_notice_and_password_record_form_one_finding(self):
        events = [self.event(0, "invalid_user", username="admin", invalid_user=True),
                  self.event(1, username="admin", invalid_user=True)]
        alerts = detect_invalid_user_attempts(reversed(events))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].evidence, tuple(events))
        self.assertIn("same attempt", alerts[0].description)

    def test_invalid_user_failure_alone_is_detected(self):
        event = self.event(0, username="admin", invalid_user=True)
        alerts = detect_invalid_user_attempts([event])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].evidence, (event,))

    def test_invalid_user_groups_keep_accounts_hosts_and_ips_separate(self):
        original = self.event(0, "invalid_user", username="admin", invalid_user=True)
        events = [original, replace(original, hostname="other-host"),
                  replace(original, username="guest"), replace(original, source_ip="198.51.100.23")]
        alerts = detect_invalid_user_attempts(events)
        self.assertEqual(len(alerts), 4)
        self.assertEqual(alerts, detect_invalid_user_attempts(reversed(events)))

    def test_valid_failures_missing_fields_and_other_records_do_not_flag_invalid_users(self):
        events = [self.event(0), self.event(1, "successful_login"),
                  self.event(2, "other", invalid_user=True),
                  self.event(3, "invalid_user", source_ip=None),
                  self.event(4, "invalid_user", username=None)]
        self.assertEqual(detect_invalid_user_attempts(events), [])

    def test_combined_detector_runs_both_rules_on_one_use_iterator(self):
        events = self.sequence() + [self.event(40, "invalid_user", username="admin", invalid_user=True)]
        alerts = detect_suspicious_events(iter(events), self.settings)
        self.assertEqual([alert.rule for alert in alerts], ["success_after_failures", "invalid_user"])
        self.assertEqual(alerts, detect_suspicious_events(reversed(events), self.settings))

    def test_malformed_records_cannot_create_account_success_finding(self):
        prefix = "Oct 29 10:15:01 ubuntu-lab sshd[1]: "
        parsed = parse_lines([
            prefix + "Failed password for bob from 203.0.113.42 port 60101 ssh2\n",
            prefix + "Failed password for bob from 203.0.113.42 port 60101 ssh2\n",
            prefix + "Failed password for bob\n",
            prefix + "Accepted password for bob from 203.0.113.42 port 60101 ssh2\n",
        ], self.settings)
        self.assertEqual(len(parsed.issues), 1)
        self.assertEqual(detect_suspicious_events(parsed.events, self.settings), [])


if __name__ == "__main__":
    unittest.main()
