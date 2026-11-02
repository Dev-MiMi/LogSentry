"""Describe accessible local sources and interpret their records.

syslog: Ubuntu/SSH records with timestamps, using our existing parser.
dpkg: dated package-management events, useful context but no SSH detections.
text: preserve an application's output without inventing event timestamps.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import socket

from .config import DetectionSettings
from .data import LogEvent
from .parser import TimestampReader, parse_log_line


@dataclass(frozen=True)
class Source:
    name: str
    path: Path
    format: str
    year: int
    timezone: str = "UTC"
    hostname: str = socket.gethostname()

    def __post_init__(self):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", self.name):
            raise ValueError("Source name must be 1–64 letters, digits, dots, underscores or hyphens.")
        if self.format not in {"syslog", "dpkg", "text"}:
            raise ValueError("Source format must be syslog, dpkg, or text.")
        if not self.hostname or any(character.isspace() or ord(character) < 32 for character in self.hostname):
            raise ValueError("Source hostname must be a nonempty token.")
        DetectionSettings(year=self.year, timezone_name=self.timezone)
        object.__setattr__(self, "path", Path(self.path).absolute())


def discover_sources(year: int, timezone: str, *, ubuntu_root=Path("/"), termux_prefix=None):
    """Look only at known log paths. Do not recursively read private app files."""
    candidates = [
        ("ubuntu-auth", ubuntu_root / "var/log/auth.log", "syslog"),
        ("ubuntu-dpkg", ubuntu_root / "var/log/dpkg.log", "dpkg"),
        ("ubuntu-apt", ubuntu_root / "var/log/apt/history.log", "text"),
    ]
    prefix = Path(termux_prefix or os.environ.get("PREFIX", "/data/data/com.termux/files/usr"))
    candidates.extend([
        ("termux-dpkg", prefix / "var/log/dpkg.log", "dpkg"),
        ("termux-apt", prefix / "var/log/apt/history.log", "text"),
        ("termux-alternatives", prefix / "var/log/alternatives.log", "text"),
    ])
    result = []
    for name, path, format_name in candidates:
        # lstat avoids following a log-path symlink during discovery. Unreadable
        # existing files are registered so collection can report their error.
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        result.append(Source(name, path, format_name, year, timezone))
    return result


def interpret(line: str, number: int, dates: TimestampReader, source: Source) -> LogEvent | None:
    """None means intentionally unparsed text, NOT a failed parse or safe event."""
    if not line.strip() or source.format == "text":
        return None
    if source.format == "syslog":
        return parse_log_line(line, number, dates)
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (.+)", line)
    if not match:
        raise ValueError("Unrecognized dpkg timestamp or message.")
    if any(ord(character) < 32 and character != "\t" or ord(character) == 127 for character in line):
        raise ValueError("Package record contains control characters.")
    return LogEvent(
        timestamp=dates.parse(match[1] + "T" + match[2]),
        hostname=source.hostname, event_type="package_activity",
        line_number=number, raw_line=line,
    )
