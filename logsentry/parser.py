"""FEATURE 1: Turn traditional or ISO-timestamped Ubuntu logs into events."""

from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
import re
from typing import Iterable
from zoneinfo import ZoneInfo

from .config import DetectionSettings
from .data import LogEvent, ParsedLog, ParseIssue


# Limits also apply when Django eventually passes uploaded lines to the engine.
MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_LINE_BYTES = 8192
MAX_INPUT_LINES = 100_000

MONTHS = {name: number for number, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
    start=1,
)}

# Anchor the process name, so a different application's message containing
# "Failed password" cannot impersonate an SSH authentication event.
PREFIX = re.compile(
    r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+"
    r"(?P<process>[\w.-]+)(?:\[\d+\])?:\s*(?P<message>.*)$"
)
LOGIN = re.compile(
    r"^(?P<status>Failed|Accepted) (?P<method>\S+) for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)(?:\s+.*)?$"
)
INVALID_USER = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>\S+) "
    r"port (?P<port>\d+)(?:\s+.*)?$"
)


class InputLimitError(ValueError):
    """The input is too large to analyze safely in this batch-based version."""


class TimestampReader:
    """Keep date interpretation together, including a Dec-to-Jan rollover."""

    def __init__(self, settings: DetectionSettings) -> None:
        self.year = settings.year
        self.zone = ZoneInfo(settings.timezone_name)
        self.previous_month: int | None = None

    def parse(self, text: str) -> datetime:
        if not text:
            raise ValueError("Timestamp is missing.")
        # Commit legacy-date state only after the complete time is valid.
        next_year = self.year
        next_month = self.previous_month
        if text[0].isdigit():
            # ISO timestamps supply a year and may also supply an explicit offset.
            date = datetime.fromisoformat(text.replace("Z", "+00:00"))
        else:
            month_text, day, clock = text.split()
            month = MONTHS.get(month_text)
            if month is None:
                raise ValueError("Unknown month in timestamp.")
            # Legacy files are expected in month order. Time ordering within a
            # month may vary; detectors sort the parsed events afterward.
            year = self.year + (self.previous_month == 12 and month == 1)
            hour, minute, second = map(int, clock.split(":"))
            date = datetime(year, month, int(day), hour, minute, second)
            next_year = year
            next_month = month

        if date.tzinfo is None:
            # Some local clocks do not exist, or occur twice, during DST changes.
            # Require an explicit offset rather than silently picking a clock.
            options = [date.replace(tzinfo=self.zone, fold=fold) for fold in (0, 1)]
            valid = [candidate for candidate in options if (
                candidate.astimezone(timezone.utc).astimezone(self.zone)
                .replace(tzinfo=None) == date
            )]
            if not valid:
                raise ValueError("Timestamp is a nonexistent local time.")
            if len({candidate.utcoffset() for candidate in valid}) > 1:
                raise ValueError("Ambiguous local time; use an ISO timestamp with an offset.")
            date = valid[0]

        result = date.astimezone(timezone.utc)
        self.year = next_year
        self.previous_month = next_month
        return result


def parse_log_line(line: str, line_number: int, dates: TimestampReader) -> LogEvent:
    """Parse a record; ValueError means it should be reported as unparsed."""
    match = PREFIX.fullmatch(line)
    if match is None:
        raise ValueError("Unrecognized log prefix.")

    if any(ord(character) < 32 and character != "\t" or ord(character) == 127 for character in line):
        raise ValueError("Log record contains control characters.")
    fields = dict(
        hostname=match["host"],
        line_number=line_number,
        raw_line=line,
    )
    message = match["message"]

    if match["process"] not in {"sshd", "sshd-session"}:
        return LogEvent(timestamp=dates.parse(match["time"]), event_type="other", **fields)

    login = LOGIN.fullmatch(message)
    invalid = INVALID_USER.fullmatch(message)
    details = login or invalid
    if details is None:
        if message.startswith(("Failed ", "Accepted ", "Invalid user ")):
            raise ValueError("Incomplete or unrecognized SSH authentication record.")
        return LogEvent(timestamp=dates.parse(match["time"]), event_type="other", **fields)

    # Validating and normalizing the IP avoids grouping an invalid token as an
    # attacker and groups equivalent IPv6 spellings together.
    try:
        address = ip_address(details["ip"])
    except ValueError as error:
        raise ValueError("Source IP is not a valid IPv4 or IPv6 address.") from error
    if getattr(address, "scope_id", None):
        raise ValueError("Scoped IPv6 addresses are not supported by this log format.")
    # An IPv4-mapped IPv6 address represents the same source as its IPv4 form.
    source_ip = str(getattr(address, "ipv4_mapped", None) or address)
    if not 1 <= int(details["port"]) <= 65535:
        raise ValueError("Source port is outside the valid range.")

    if login:
        is_failure = login["status"] == "Failed"
        if not is_failure and login["invalid"]:
            raise ValueError("An accepted login cannot target an invalid user.")
        return LogEvent(
            timestamp=dates.parse(match["time"]),
            event_type="failed_login" if is_failure else "successful_login",
            username=login["user"],
            source_ip=source_ip,
            authentication_method=login["method"],
            invalid_user=bool(login["invalid"]),
            **fields,
        )

    return LogEvent(
        timestamp=dates.parse(match["time"]),
        event_type="invalid_user",
        username=invalid["user"],
        source_ip=source_ip,
        invalid_user=True,
        **fields,
    )


def parse_lines(lines: Iterable[str], settings: DetectionSettings) -> ParsedLog:
    """Parse lines while keeping rejected records visible in the result."""
    parsed = ParsedLog()
    dates = TimestampReader(settings)
    byte_count = 0
    for line_number, line in enumerate(lines, start=1):
        line_bytes = len(line.encode("utf-8"))
        byte_count += line_bytes
        if byte_count > MAX_INPUT_BYTES or line_number > MAX_INPUT_LINES:
            raise InputLimitError("Log exceeds the 10 MiB or 100,000-line limit.")
        if line_bytes > MAX_LINE_BYTES:
            raise InputLimitError(f"Line {line_number} exceeds the 8 KiB line limit.")

        # Remove ONE physical line ending; embedded newlines remain invalid.
        parsed.total_lines += 1
        if line.endswith("\n"):
            line = line[:-1]
            if line.endswith("\r"):
                line = line[:-1]
        if not line.strip():
            parsed.blank_lines += 1
            continue
        try:
            parsed.events.append(parse_log_line(line, line_number, dates))
        except ValueError as error:
            parsed.issues.append(ParseIssue(line_number, str(error)))

    return parsed


def read_system_logs(log_path: str | Path, settings: DetectionSettings) -> ParsedLog:
    """Read a UTF-8 file without loading it all into memory.

    Missing files and permission errors propagate to the caller, which can
    display them in a terminal or, later, on a Django page. InputLimitError
    means the file exceeds our batch limits; ValueError means invalid UTF-8.
    """
    def bounded_lines(log_file):
        byte_count = 0
        line_number = 0
        while True:
            # Bound even a single maliciously long line before decoding it.
            raw_line = log_file.readline(MAX_LINE_BYTES + 1)
            if not raw_line:
                return
            line_number += 1
            byte_count += len(raw_line)
            if len(raw_line) > MAX_LINE_BYTES:
                raise InputLimitError(f"Line {line_number} exceeds the 8 KiB line limit.")
            if byte_count > MAX_INPUT_BYTES or line_number > MAX_INPUT_LINES:
                raise InputLimitError("Log exceeds the 10 MiB or 100,000-line limit.")
            try:
                yield raw_line.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError(f"Line {line_number} is not valid UTF-8.") from error

    with Path(log_path).open("rb") as log_file:
        return parse_lines(bounded_lines(log_file), settings)
