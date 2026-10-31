"""Plain Python records; the engine does not depend on Django or a database."""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import DetectionSettings


def _as_utc(timestamp: datetime) -> datetime:
    """Reject missing timezone information instead of guessing local time."""
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("Timestamps must include a timezone.")
    return timestamp.astimezone(timezone.utc)


@dataclass(frozen=True)
class LogEvent:
    """FEATURE 1: Preserve the parsed facts and their original source line."""

    timestamp: datetime  # Always timezone-aware UTC inside the engine.
    hostname: str
    event_type: str
    line_number: int
    raw_line: str
    username: str | None = None
    source_ip: str | None = None
    authentication_method: str | None = None
    invalid_user: bool = False

    def __post_init__(self) -> None:
        # A frozen record cannot be changed later. Normalize its time once,
        # during construction, so all detectors compare the same clock.
        object.__setattr__(self, "timestamp", _as_utc(self.timestamp))


@dataclass(frozen=True)
class ParseIssue:
    """A line we could not interpret, rather than evidence of a clean log."""

    line_number: int
    reason: str


@dataclass
class ParsedLog:
    events: list[LogEvent] = field(default_factory=list)
    issues: list[ParseIssue] = field(default_factory=list)
    total_lines: int = 0
    blank_lines: int = 0


@dataclass(frozen=True)
class Alert:
    """FEATURES 2 AND 7: A rule finding, priority, and supporting evidence."""

    rule: str
    severity: str
    hostname: str
    source_ip: str
    usernames: tuple[str, ...]
    description: str
    evidence: tuple[LogEvent, ...]

    def __post_init__(self) -> None:
        if self.severity not in {"Critical", "High", "Medium", "Low"}:
            raise ValueError("Unknown alert severity.")
        if not self.evidence:
            raise ValueError("An alert must include supporting log events.")
        # Copy caller-owned sequences into tuples to preserve an alert's facts.
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "usernames", tuple(self.usernames))

    @property
    def timestamp(self) -> datetime:
        # Evidence may be supplied out of order; use its latest actual time.
        return max(event.timestamp for event in self.evidence)


@dataclass(frozen=True)
class Analysis:
    """FEATURE 3: Everything needed to display results or build a report."""

    source_name: str
    settings: DetectionSettings
    parsed: ParsedLog
    alerts: tuple[Alert, ...]
    generated_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "generated_at", _as_utc(self.generated_at))
        object.__setattr__(self, "alerts", tuple(self.alerts))
