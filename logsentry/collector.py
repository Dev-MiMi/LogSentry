"""Local file collector. Run with: python -m logsentry.collector --help.

Sources stay untouched. SQLite holds raw records, source identity and a durable
byte offset. This first collector runs in the same environment as the logs;
it does not open a network listener or install/start an SSH server.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import math
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time

from .collection_sources import Source, discover_sources, interpret
from .collection_store import DEFAULT_DATABASE, RECORDS_PER_SOURCE, open_store, source_rows
from .config import DetectionSettings
from .parser import MAX_LINE_BYTES, TimestampReader
from .reporting import _safe_text


BATCH_LINES = 2000
BATCH_BYTES = 1024 * 1024
MAX_TEXT_LINE_BYTES = 64 * 1024  # APT can list hundreds of packages on one line.


def _now():
    return datetime.now(timezone.utc).isoformat()


def register_source(connection, source: Source) -> int:
    """A name/path identifies one stream. Never silently change its time policy."""
    with connection:
        row = connection.execute("SELECT * FROM sources WHERE name = ? OR path = ?",
                                 (source.name, str(source.path))).fetchone()
        values = (source.name, str(source.path), source.format, source.year, source.timezone, source.hostname)
        if row:
            previous = tuple(row[key] for key in ("name", "path", "format", "year", "timezone", "hostname"))
            if previous != values:
                raise ValueError("Source name/path already registered with different settings; use a new collection database.")
            return row["id"]
        cursor = connection.execute("""
            INSERT INTO sources(name, path, format, year, timezone, hostname, date_year)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (*values, source.year))
        return cursor.lastrowid


def _anchor(stream, offset):
    """Detect copy/truncate/refill even when the inode and file size stay similar."""
    stream.seek(max(0, offset - 256))
    return hashlib.sha256(stream.read(min(offset, 256))).hexdigest()


def _collect_transaction(connection, source_id: int) -> int:
    row = connection.execute("SELECT * FROM sources WHERE id = ?", (source_id,)).fetchone()
    if row is None:
        raise ValueError("Unknown source.")
    source = Source(row["name"], Path(row["path"]), row["format"], row["year"],
                    row["timezone"], row["hostname"])
    # O_NONBLOCK prevents a FIFO from hanging the collector; fstat then rejects
    # every non-regular input. O_NOFOLLOW rejects a swapped symlink at open time.
    fd = os.open(source.path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Log source must be a regular file.")
        database_info = os.stat(connection.execute("PRAGMA database_list").fetchone()[2])
        if (info.st_dev, info.st_ino) == (database_info.st_dev, database_info.st_ino):
            raise ValueError("The collection database cannot be a log source.")
        offset, number, generation = row["offset"], row["line_number"], row["generation"]
        dates = TimestampReader(DetectionSettings(year=row["date_year"], timezone_name=source.timezone))
        dates.previous_month = row["date_month"]
        rotated = row["inode"] is not None and (
            (info.st_dev, info.st_ino) != (row["device"], row["inode"])
            or info.st_size < offset
            or (offset > 0 and _anchor(stream, offset) != row["anchor"])
        )
        if rotated:
            offset, number, generation = 0, 0, generation + 1
            # Keep the last interpreted month/year across rotation; a new Jan
            # legacy record following Dec must still advance to the next year.
        stream.seek(offset)
        received_at, count, byte_count = _now(), 0, 0
        line_limit = MAX_TEXT_LINE_BYTES if source.format == "text" else MAX_LINE_BYTES
        while count < BATCH_LINES and byte_count < BATCH_BYTES:
            raw = stream.readline(line_limit + 1)
            if not raw:
                break
            if len(raw) > line_limit:
                raise ValueError(f"Line {number + 1} exceeds {line_limit // 1024} KiB; collection paused for this source.")
            if not raw.endswith(b"\n"):
                # An application may be halfway through writing a record. Leave
                # its offset unchanged and wait until its terminating newline.
                break
            number += 1
            issue = ""
            try:
                line = raw.decode("utf-8").rstrip("\n").removesuffix("\r")
            except UnicodeDecodeError:
                line = raw.decode("utf-8", errors="backslashreplace").rstrip("\n").removesuffix("\r")
                issue = "Invalid UTF-8; undecodable bytes displayed as escape sequences."
            event = None
            if not issue:
                try:
                    event = interpret(line, number, dates, source)
                except (ValueError, OverflowError) as error:
                    issue = str(error)
            connection.execute("""
                INSERT INTO records(source_id, generation, line_number, received_at,
                    raw_line, timestamp, hostname, event_type, username, source_ip,
                    authentication_method, invalid_user, issue)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (source_id, generation, number, received_at, line,
                  event.timestamp.isoformat() if event else None,
                  event.hostname if event else source.hostname,
                  event.event_type if event else ("unparsed" if issue else "raw_text"),
                  event.username if event else None, event.source_ip if event else None,
                  event.authentication_method if event else None,
                  int(event.invalid_user) if event else 0, issue))
            count += 1
            byte_count += len(raw)
            offset += len(raw)
        # Retention bounds disk and dashboard work. Deletion is visible through
        # a cumulative counter; the original source file remains untouched.
        deleted = connection.execute("""
            DELETE FROM records WHERE source_id = ? AND id < COALESCE(
                (SELECT id FROM records WHERE source_id = ? ORDER BY id DESC LIMIT 1 OFFSET ?), 0)
        """, (source_id, source_id, RECORDS_PER_SOURCE - 1)).rowcount
        connection.execute("""
            UPDATE sources SET device=?, inode=?, offset=?, line_number=?, generation=?,
                date_year=?, date_month=?, anchor=?, last_checked=?, last_received=?,
                last_error='', rotations=rotations+?, dropped=dropped+? WHERE id=?
        """, (info.st_dev, info.st_ino, offset, number, generation,
              dates.year, dates.previous_month, _anchor(stream, offset), received_at,
              received_at if count else row["last_received"], int(rotated), deleted, source_id))
        return count


def collect_source(connection, source_id: int) -> int:
    """Serialize collectors, commit a whole batch, or record an explicit error."""
    try:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            return _collect_transaction(connection, source_id)
    except (OSError, ValueError, OverflowError) as error:
        with connection:
            connection.execute("UPDATE sources SET last_checked=?, last_error=? WHERE id=?",
                               (_now(), _safe_text(error), source_id))
        raise


def _parser():
    parser = argparse.ArgumentParser(description="Collect accessible Ubuntu/Termux log files into private local storage.")
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--discover", action="store_true", help="Register known Ubuntu/Termux log paths that exist")
    parser.add_argument("--file", type=Path, help="Register one explicit log file")
    parser.add_argument("--name", help="Unique name for --file")
    parser.add_argument("--format", choices=("syslog", "dpkg", "text"), default="syslog")
    parser.add_argument("--year", type=int, help="Starting year of the source; required when registering sources")
    parser.add_argument("--timezone", default="UTC", help="Source timezone (default UTC); use the actual source timezone")
    parser.add_argument("--list", action="store_true", help="Show registered sources without reading logs")
    parser.add_argument("--watch", action="store_true", help="Keep collecting until Ctrl+C; otherwise collect one bounded batch")
    parser.add_argument("--interval", type=float, default=1, help="Polling interval in seconds, 0.2–3600 (default 1)")
    return parser


def main(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    if args.file and args.discover:
        parser.error("Choose --file or --discover, not both.")
    if bool(args.file) != bool(args.name):
        parser.error("--file and --name must be used together.")
    if (args.file or args.discover) and args.year is None:
        parser.error("--year is required when registering sources.")
    if not math.isfinite(args.interval) or not 0.2 <= args.interval <= 3600:
        parser.error("--interval must be between 0.2 and 3600 seconds.")
    try:
        if args.year is not None:
            DetectionSettings(year=args.year, timezone_name=args.timezone)
        with open_store(args.database) as connection:
            if args.discover:
                for source in discover_sources(args.year, args.timezone):
                    register_source(connection, source)
            if args.file:
                register_source(connection, Source(args.name, args.file, args.format, args.year, args.timezone))
            if args.watch and not args.list:
                print(f"Watching local logs every {args.interval:g}s. Press Ctrl+C to stop.", flush=True)
            while True:
                # Watch mode only needs source identity, not a count of every
                # stored record on each pass. --list calculates those totals.
                rows = source_rows(connection) if args.list else connection.execute(
                    "SELECT id, name FROM sources ORDER BY id"
                ).fetchall()
                if not rows:
                    print("No sources registered. Use --discover --year YEAR or --file PATH --name NAME --year YEAR.")
                    return 1
                failed = False
                for row in rows:
                    if args.list:
                        print(f"{row['name']}: {row['record_count']} retained records; {_safe_text(row['path'])}; "
                              f"last check: {row['last_checked'] or 'never'}; error: {_safe_text(row['last_error']) or 'none'}")
                        continue
                    try:
                        count = collect_source(connection, row["id"])
                        if count or not args.watch:
                            print(f"{row['name']}: collected {count} new records", flush=True)
                    except (OSError, ValueError, OverflowError) as error:
                        failed = True
                        print(f"{row['name']}: {_safe_text(error)}", file=sys.stderr, flush=True)
                if args.list or not args.watch:
                    return int(failed)
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nCollection stopped. Saved records and positions are retained.")
        return 0
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"Collection failed: {_safe_text(error)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
