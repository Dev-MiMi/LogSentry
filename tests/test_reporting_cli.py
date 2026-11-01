"""End-to-end CLI and report checks, including bad input and safe file output."""

from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
from io import StringIO
import os
from pathlib import Path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from logsentry.cli import analyze_log, main
from logsentry.config import DetectionSettings
from logsentry.data import Analysis, ParsedLog
from logsentry.parser import parse_lines
from logsentry.reporting import build_investigation_report, generate_incident_report


ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples/auth.log"


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.settings = DetectionSettings(year=2026)
        self.analysis = analyze_log(SAMPLE, self.settings)

    def test_end_to_end_sample_counts_and_findings(self):
        self.assertEqual(len(self.analysis.parsed.events), 12)
        self.assertEqual(len(self.analysis.alerts), 6)
        self.assertEqual(Counter(alert.severity for alert in self.analysis.alerts), {"High": 3, "Medium": 3})
        report = build_investigation_report(self.analysis)
        for expected in ("Failed logins: 6", "Successful logins: 3", "Total alerts: 6",
                         "High: 3", "Medium: 3", "Critical: 0", "Rejected lines: 0",
                         "success_after_failures", "invalid_user", "brute_force",
                         "repeated_failed_logins", "suspicious_login"):
            self.assertIn(expected, report)
        self.assertIn("not proof", report)

    def test_report_preserves_evidence_line_numbers_and_raw_contents(self):
        report = build_investigation_report(self.analysis)
        for alert in self.analysis.alerts:
            for event in alert.evidence:
                self.assertIn(f"Line {event.line_number}: {event.raw_line}", report)

    def test_report_shows_policy_used_and_time_range(self):
        settings = replace(self.settings, trusted_networks=(), repeated_threshold=4,
                           normal_start_hour=22, normal_end_hour=6)
        report = build_investigation_report(replace(self.analysis, settings=settings))
        self.assertIn("Legacy timestamp starting year: 2026", report)
        self.assertIn("timezone for timestamps and login hours: UTC", report)
        self.assertIn("22:00-06:00", report)
        self.assertIn("Repeated failures: 4", report)
        self.assertIn("None (all sources are unexpected)", report)
        self.assertIn("First event (UTC): 2026-10-29T09:00:12+00:00", report)
        self.assertIn("Last event (UTC): 2026-10-29T23:45:10+00:00", report)

    def test_report_orders_severity_then_time_without_mutating_analysis(self):
        original = self.analysis.alerts
        report = build_investigation_report(self.analysis)
        self.assertLess(report.index("Finding 1: brute_force"), report.index("Finding 4: repeated_failed_logins"))
        self.assertEqual(self.analysis.alerts, original)
        reversed_analysis = replace(self.analysis, alerts=tuple(reversed(original)))
        self.assertEqual(report, build_investigation_report(reversed_analysis))

    def test_rejected_input_is_visible_and_no_alerts_do_not_mean_safe(self):
        parsed = parse_lines(["malformed record\n"], self.settings)
        analysis = Analysis("broken.log", self.settings, parsed, (), datetime.now(timezone.utc))
        report = build_investigation_report(analysis)
        self.assertIn("Coverage: PARTIAL", report)
        self.assertIn("Rejected lines: 1", report)
        self.assertIn("Line 1: Unrecognized log prefix", report)
        self.assertIn("No supported SSH authentication events", report)
        self.assertIn("No alerts were produced from the parsed events under this policy", report)

    def test_empty_input_report_has_explicit_coverage_and_zero_counts(self):
        analysis = replace(self.analysis, parsed=ParsedLog(), alerts=())
        report = build_investigation_report(analysis)
        self.assertIn("Total input lines: 0", report)
        self.assertIn("Total alerts: 0", report)
        self.assertIn("No supported SSH authentication events", report)
        self.assertNotIn("First event (UTC)", report)

    def test_untrusted_text_cannot_insert_headings_or_terminal_controls(self):
        alert = self.analysis.alerts[0]
        evidence = replace(alert.evidence[0], raw_line="text\nFAKE HEADING\x1b[31m\u202eevil")
        alert = replace(alert, evidence=(evidence,), description="reason\nFAKE REASON",
                        hostname="host\x1b", usernames=("bob\nFAKE USER",))
        analysis = replace(self.analysis, source_name="log\nFAKE SOURCE", alerts=(alert,))
        report = build_investigation_report(analysis)
        self.assertNotIn("\nFAKE", report)
        self.assertNotIn("\x1b", report)
        self.assertNotIn("\u202e", report)
        self.assertIn("text\\nFAKE HEADING\\x1b[31m\\u202eevil", report)
        self.assertEqual(evidence.raw_line, "text\nFAKE HEADING\x1b[31m\u202eevil")

    def test_new_report_is_utf8_and_owner_only(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "reports" / "incident.txt"
            self.assertEqual(generate_incident_report("Evidence for José\n", path), path)
            self.assertEqual(path.read_text(encoding="utf-8"), "Evidence for José\n")
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_existing_output_is_preserved(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "existing.txt"
            path.write_text("original evidence", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                generate_incident_report("replacement", path)
            self.assertEqual(path.read_text(), "original evidence")

    @unittest.skipUnless(os.name == "posix", "POSIX symlink and hard-link behavior")
    def test_existing_symlink_and_hardlink_are_not_followed_or_overwritten(self):
        with TemporaryDirectory() as folder:
            target = Path(folder) / "source.log"
            target.write_text("original source")
            symlink = Path(folder) / "symlink.txt"
            symlink.symlink_to(target)
            hardlink = Path(folder) / "hardlink.txt"
            os.link(target, hardlink)
            for path in (symlink, hardlink):
                with self.subTest(path=path), self.assertRaises(FileExistsError):
                    generate_incident_report("replacement", path)
            self.assertEqual(target.read_text(), "original source")


class CommandTests(unittest.TestCase):
    def call(self, arguments):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def sample_args(self):
        return [str(SAMPLE), "--year", "2026", "--timezone", "UTC"]

    def test_command_prints_sample_and_does_not_save_without_output(self):
        with patch("logsentry.cli.generate_incident_report") as save:
            code, report, errors = self.call(self.sample_args())
        self.assertEqual(code, 0)
        self.assertIn("Total alerts: 6", report)
        self.assertEqual(errors, "")
        save.assert_not_called()

    def test_saved_report_equals_terminal_report(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "reports" / "incident.txt"
            code, report, messages = self.call(self.sample_args() + ["--output", str(path)])
            self.assertEqual(code, 0)
            self.assertEqual(path.read_text(encoding="utf-8"), report)
            self.assertIn("Incident report saved", messages)

    def test_output_matching_input_cannot_destroy_log(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "auth.log"
            original = SAMPLE.read_bytes()
            path.write_bytes(original)
            code, report, errors = self.call([str(path), "--year", "2026", "--output", str(path)])
            self.assertEqual(code, 1)
            self.assertIn("already exists", errors)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(report, "")

    def test_missing_file_and_directory_input_return_errors_without_tracebacks(self):
        with TemporaryDirectory() as folder:
            for path in (Path(folder) / "missing.log", Path(folder)):
                with self.subTest(path=path):
                    code, report, errors = self.call([str(path), "--year", "2026"])
                    self.assertEqual(code, 1)
                    self.assertEqual(report, "")
                    self.assertIn("could not analyze", errors)
                    self.assertNotIn("Traceback", errors)

    def test_invalid_utf8_and_input_size_limits_fail_without_a_report(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "auth.log"
            for content in (b"\xff\n", b"x" * 8193):
                with self.subTest(content_length=len(content)):
                    path.write_bytes(content)
                    code, report, errors = self.call([str(path), "--year", "2026"])
                    self.assertEqual(code, 1)
                    self.assertEqual(report, "")
                    self.assertIn("could not analyze", errors)

    def test_partial_parse_displays_and_saves_report_with_exit_three(self):
        with TemporaryDirectory() as folder:
            source = Path(folder) / "auth.log"
            source.write_text(SAMPLE.read_text() + "invalid record\n", encoding="utf-8")
            output = Path(folder) / "incident.txt"
            code, report, messages = self.call([str(source), "--year", "2026", "--output", str(output)])
            self.assertEqual(code, 3)
            self.assertIn("Coverage: PARTIAL", report)
            self.assertIn("Rejected lines: 1", report)
            self.assertIn("Total alerts: 6", report)
            self.assertIn("Line 13:", report)
            self.assertEqual(output.read_text(), report)
            self.assertIn("saved", messages)

    def test_permission_failures_for_input_and_output_are_reported(self):
        with patch("logsentry.cli.read_system_logs", side_effect=PermissionError("not allowed")):
            code, report, errors = self.call(self.sample_args())
            self.assertEqual(code, 1)
            self.assertIn("could not analyze", errors)
        with patch("logsentry.cli.generate_incident_report", side_effect=PermissionError("not allowed")):
            code, report, errors = self.call(self.sample_args() + ["--output", "unused.txt"])
            self.assertEqual(code, 1)
            self.assertIn("could not save", errors)

    def test_custom_policy_reaches_detectors_and_report(self):
        code, report, _ = self.call(self.sample_args() + [
            "--repeated-threshold", "6", "--brute-force-threshold", "6",
            "--normal-start-hour", "0", "--normal-end-hour", "24",
            "--trusted-network", "192.168.1.0/24",
            "--trusted-network", "203.0.113.0/24",
            "--trusted-network", "198.51.100.0/24",
        ])
        self.assertEqual(code, 0)
        self.assertIn("Total alerts: 1", report)  # Only the invalid-user finding remains.
        self.assertIn("Repeated failures: 6", report)
        self.assertIn("Brute-force rule: 6", report)

    def test_empty_trusted_networks_flag_all_successful_sources(self):
        code, report, _ = self.call(self.sample_args() + ["--no-trusted-networks"])
        self.assertEqual(code, 0)
        self.assertIn("Total alerts: 7", report)
        self.assertIn("None (all sources are unexpected)", report)

    def test_invalid_arguments_have_exit_two_and_never_read_log(self):
        cases = [
            [str(SAMPLE)], self.sample_args() + ["--year", "0"],
            self.sample_args() + ["--timezone", "Unknown/Zone"],
            self.sample_args() + ["--brute-force-minutes", "0"],
            self.sample_args() + ["--repeated-threshold", "1"],
            self.sample_args() + ["--success-window-minutes", "-1"],
            self.sample_args() + ["--trusted-network", "not-a-network"],
            self.sample_args() + ["--normal-start-hour", "25"],
            self.sample_args() + ["--no-trusted-networks", "--trusted-network", "10.0.0.0/8"],
            self.sample_args() + ["--brute-force-minutes", "999999999999999999999"],
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments), patch("logsentry.cli.analyze_log") as analyze:
                with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                    with self.assertRaises(SystemExit) as stopped:
                        main(arguments)
                self.assertEqual(stopped.exception.code, 2)
                analyze.assert_not_called()

    def test_error_message_cannot_inject_terminal_control_characters(self):
        with patch("logsentry.cli.analyze_log", side_effect=PermissionError("bad\x1b[31m\nFAKE")):
            code, _, errors = self.call(self.sample_args())
        self.assertEqual(code, 1)
        self.assertNotIn("\x1b", errors)
        self.assertNotIn("\nFAKE", errors)
        self.assertIn("\\x1b", errors)

    def test_python_module_entry_point_runs_successfully(self):
        result = subprocess.run(
            [sys.executable, "-m", "logsentry", "samples/auth.log", "--year", "2026", "--timezone", "UTC"],
            cwd=ROOT, capture_output=True, text=True, check=False, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Total alerts: 6", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_python_module_help_documents_options(self):
        result = subprocess.run([sys.executable, "-m", "logsentry", "--help"],
                                cwd=ROOT, capture_output=True, text=True, check=False, timeout=15)
        self.assertEqual(result.returncode, 0)
        self.assertIn("--output", result.stdout)
        self.assertIn("--trusted-network", result.stdout)
        self.assertIn("partial parsing", result.stdout)


if __name__ == "__main__":
    unittest.main()
