"""Private SQLite storage for local collection; independent of Django.

Each transaction saves BOTH new records and the file position. A restart cannot
commit one without the other, so polling the same unchanged file adds nothing.
"""

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat


DEFAULT_DATABASE = Path(__file__).resolve().parents[1] / "runtime" / "collection.sqlite3"
SCHEMA_VERSION = 1
RECORDS_PER_SOURCE = 10_000

SCHEMA = """
CREATE TABLE sources (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    path TEXT NOT NULL UNIQUE,
    format TEXT NOT NULL,
    year INTEGER NOT NULL,
    timezone TEXT NOT NULL,
    hostname TEXT NOT NULL,
    device INTEGER, inode INTEGER,
    offset INTEGER NOT NULL DEFAULT 0,
    line_number INTEGER NOT NULL DEFAULT 0,
    generation INTEGER NOT NULL DEFAULT 0,
    date_year INTEGER NOT NULL,
    date_month INTEGER,
    anchor TEXT NOT NULL DEFAULT '',
    last_checked TEXT,
    last_received TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    rotations INTEGER NOT NULL DEFAULT 0,
    dropped INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id INTEGER NOT NULL REFERENCES sources(id),
    generation INTEGER NOT NULL,
    line_number INTEGER NOT NULL,
    received_at TEXT NOT NULL,
    raw_line TEXT NOT NULL,
    timestamp TEXT,
    hostname TEXT NOT NULL,
    event_type TEXT NOT NULL,
    username TEXT,
    source_ip TEXT,
    authentication_method TEXT,
    invalid_user INTEGER NOT NULL DEFAULT 0,
    issue TEXT NOT NULL DEFAULT '',
    UNIQUE(source_id, generation, line_number)
);
CREATE INDEX records_source_id ON records(source_id, id);
PRAGMA user_version = 1;
"""


def _check_private(path: Path, directory: bool = False) -> None:
    """Refuse symlinks and shared storage for raw authentication evidence."""
    info = path.lstat()
    correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not correct_type or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError(f"Collection storage must be owned by you and private: {path}")
    if not directory and info.st_nlink != 1:
        raise ValueError("Collection database must not be a hard link.")


@contextmanager
def open_store(path: str | Path = DEFAULT_DATABASE, *, readonly: bool = False):
    """Use a 0700 directory and 0600 database; browser reads never create files."""
    path = Path(path).absolute()
    if not readonly:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _check_private(path.parent, directory=True)
    if not readonly and not path.exists() and not path.is_symlink():
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    _check_private(path)
    connection = sqlite3.connect(path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"),
                                 uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 0 and not readonly:
            connection.executescript(SCHEMA)
        elif version != SCHEMA_VERSION:
            raise ValueError("Unsupported collection database version.")
        yield connection
    finally:
        connection.close()


def source_rows(connection):
    """Include retention/coverage counters so zero alerts cannot hide errors."""
    return connection.execute("""
        SELECT sources.*, COUNT(records.id) AS record_count,
               COALESCE(SUM(records.issue != ''), 0) AS issue_count
        FROM sources LEFT JOIN records ON records.source_id = sources.id
        GROUP BY sources.id ORDER BY sources.id
    """).fetchall()


def retained_records(connection, source_id: int):
    return connection.execute(
        "SELECT * FROM records WHERE source_id = ? ORDER BY id", (source_id,)
    ).fetchall()
