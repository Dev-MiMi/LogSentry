"""Command-line orchestration: call the engine and display or save its report."""

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from typing import Sequence

from .config import DetectionSettings
from .data import Analysis, ParsedLog
from .detection import (
    detect_brute_force_attacks,
    detect_repeated_failed_logins,
    detect_suspicious_events,
    detect_suspicious_logins,
)
from .parser import read_system_logs
from .reporting import _safe_text, build_investigation_report, generate_incident_report


def analyze_log(log_path: str | Path, settings: DetectionSettings) -> Analysis:
    """Combine parsed input and all current detectors into a reusable result.

    This returns data without printing or saving. A Django view can eventually
    call the same function instead of duplicating the security rules.
    """
    parsed = read_system_logs(log_path, settings)  # FEATURE 1.
    return analyze_parsed(parsed, str(log_path), settings)


def analyze_parsed(parsed: ParsedLog, source_name: str, settings: DetectionSettings) -> Analysis:
    """Apply the same rules to a file or to records saved by the collector."""
    alerts = detect_suspicious_events(parsed.events, settings)  # FEATURE 2.
    alerts.extend(detect_repeated_failed_logins(parsed.events, settings))  # FEATURE 4.
    alerts.extend(detect_brute_force_attacks(parsed.events, settings))  # FEATURE 5.
    alerts.extend(detect_suspicious_logins(parsed.events, settings))  # FEATURE 6.
    # FEATURE 7: Each detector attaches its severity and original evidence.
    return Analysis(
        source_name=source_name, settings=settings, parsed=parsed,
        alerts=tuple(alerts), generated_at=datetime.now(timezone.utc),
    )


def _argument_parser() -> argparse.ArgumentParser:
    """Describe the command and let argparse validate argument syntax."""
    parser = argparse.ArgumentParser(
        prog="logsentry", description="Analyze Ubuntu SSH logs and generate an investigation report.",
        epilog="Exit codes: 0 = completed, 1 = input/output error, 2 = invalid arguments, 3 = partial parsing.",
    )
    parser.add_argument("log_file", type=Path, help="Path to a UTF-8 Ubuntu authentication log")
    parser.add_argument("--year", type=int, required=True, help="Starting year for traditional timestamps (required, not guessed)")
    parser.add_argument("--timezone", default="UTC", dest="timezone_name", help="Log and login-policy timezone (default: UTC)")
    parser.add_argument("--output", type=Path, help="Save a new report file; existing files are never overwritten")
    parser.add_argument("--trusted-network", action="append", dest="trusted_networks", metavar="CIDR",
                        help="Trusted subnet; repeat to set several. Replaces the default 192.168.1.0/24")
    parser.add_argument("--no-trusted-networks", action="store_true", help="Treat every successful source IP as unexpected")
    parser.add_argument("--normal-start-hour", type=int, default=6, help="First normal local hour (default: 6)")
    parser.add_argument("--normal-end-hour", type=int, default=22, help="End of normal hours, exclusive (default: 22; 24 allowed)")
    parser.add_argument("--repeated-threshold", type=int, default=3, help="Failures needed for repetition and success correlation (default: 3)")
    parser.add_argument("--brute-force-threshold", type=int, default=5, help="Failures needed for a brute-force burst (default: 5)")
    parser.add_argument("--brute-force-minutes", type=int, default=5, help="Maximum burst duration in minutes (default: 5)")
    parser.add_argument("--success-window-minutes", type=int, default=10, help="Window preceding a successful login (default: 10)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI. Return a process exit code for the entry point."""
    parser = _argument_parser()
    arguments = parser.parse_args(argv)
    if arguments.no_trusted_networks and arguments.trusted_networks:
        parser.error("--no-trusted-networks cannot be combined with --trusted-network")
    networks = () if arguments.no_trusted_networks else tuple(
        arguments.trusted_networks if arguments.trusted_networks is not None else ("192.168.1.0/24",)
    )
    try:
        settings = DetectionSettings(
            year=arguments.year, timezone_name=arguments.timezone_name,
            repeated_threshold=arguments.repeated_threshold,
            brute_force_threshold=arguments.brute_force_threshold,
            brute_force_window=timedelta(minutes=arguments.brute_force_minutes),
            success_after_failures_window=timedelta(minutes=arguments.success_window_minutes),
            trusted_networks=networks, normal_start_hour=arguments.normal_start_hour,
            normal_end_hour=arguments.normal_end_hour,
        )
    except (ValueError, OverflowError) as error:
        parser.error(_safe_text(error))

    try:
        analysis = analyze_log(arguments.log_file, settings)
    except (OSError, ValueError, OverflowError) as error:
        print(f"LogSentry could not analyze the log: {_safe_text(error)}", file=sys.stderr)
        return 1

    report = build_investigation_report(analysis)  # FEATURE 3.
    if arguments.output is not None:
        try:
            generate_incident_report(report, arguments.output)  # FEATURE 8.
        except FileExistsError:
            print("Report output already exists; choose a new --output filename.", file=sys.stderr)
            return 1
        except (OSError, ValueError) as error:
            print(f"LogSentry could not save the report: {_safe_text(error)}", file=sys.stderr)
            return 1
        print(f"Incident report saved to: {_safe_text(arguments.output)}", file=sys.stderr)

    # Findings go to stdout; progress/errors go to stderr for easy redirection.
    print(report, end="")
    return 3 if analysis.parsed.issues else 0
