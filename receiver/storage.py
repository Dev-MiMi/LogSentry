"""Private inbox and collector credentials, separate from local log evidence.

Collector credentials are registered by hash and can be revoked. A committed inbox
transaction acknowledges receipt only; it does not mean Wazuh has received it.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat


IDENTIFIER = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"
MAX_EVENTS = 10_000
COLLECTORS_SCHEMA = """CREATE TABLE collectors (
    collector_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_seen TEXT,
    pending INTEGER,
    delivery_error TEXT NOT NULL DEFAULT ''
)"""
SCHEMA = """
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collector_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    received_at TEXT NOT NULL,
    UNIQUE(collector_id, event_id)
);
PRAGMA user_version = 1;
"""


class EventConflict(Exception):
    """The same event ID was reused with different contents."""


class InboxFull(Exception):
    """Reject new records rather than silently discarding unforwarded evidence."""


class CollectorRevoked(PermissionError):
    """A credential was revoked between request authentication and storage."""


def check_private(path, *, directory=False):
    info = Path(path).lstat()
    right_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not right_type or info.st_uid != os.getuid() or info.st_mode & 0o077
            or (not directory and info.st_nlink != 1)):
        raise ValueError("Receiver storage must be private, owned by you, and not linked.")


def initialize_credentials(path, collector_id):
    """Create a token once; existing credentials are never overwritten."""
    if not re.fullmatch(IDENTIFIER, collector_id):
        raise ValueError("Use 1–128 letters, digits, dots, underscores or hyphens for the collector ID.")
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_private(path.parent, directory=True)
    credentials = {"collector_id": collector_id, "token": secrets.token_urlsafe(32)}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(credentials, stream)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def read_credentials(path):
    path = Path(path)
    check_private(path.parent, directory=True)
    check_private(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd) as stream:
        credentials = json.loads(stream.read(4096))
    if (not isinstance(credentials, dict)
            or not isinstance(credentials.get("collector_id"), str)
            or not re.fullmatch(IDENTIFIER, credentials["collector_id"])
            or not isinstance(credentials.get("token"), str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", credentials["token"])):
        raise ValueError("Invalid receiver credentials.")
    return credentials


@contextmanager
def open_inbox(path, *, readonly=False):
    path = Path(path).absolute()
    if not readonly:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_private(path.parent, directory=True)
    if not readonly and not path.exists() and not path.is_symlink():
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass  # Another worker created the file; validate it below.
        else:
            os.close(fd)
    check_private(path)
    db = sqlite3.connect(path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"),
                         uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    try:
        if not readonly:
            # Serialize schema initialization as well as concurrent submissions.
            db.execute("BEGIN IMMEDIATE")
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version == 0 and not readonly:
            for statement in SCHEMA.split(";"):
                if statement.strip():
                    db.execute(statement)
            version = 1
        if version == 1 and not readonly:
            db.execute(COLLECTORS_SCHEMA)
            db.execute("PRAGMA user_version = 2")
        elif version not in (1, 2):
            raise ValueError("Unsupported inbox version.")
        if not readonly:
            db.commit()
        yield db
    finally:
        db.close()


def save_batch(path, collector_id, events, *, token_hash=None):
    """Accept the whole validated batch or none; make retries idempotent."""
    received_at = datetime.now(timezone.utc).isoformat()
    accepted = duplicates = 0
    with open_inbox(path) as db, db:
        db.execute("BEGIN IMMEDIATE")
        if token_hash is not None:
            row = db.execute("SELECT revoked FROM collectors WHERE collector_id=? AND token_hash=?",
                             (collector_id, token_hash)).fetchone()
            if not row or row["revoked"]:
                raise CollectorRevoked("Collector access revoked.")
        count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        for event in events:
            payload = json.dumps(event, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
            digest = hashlib.sha256(payload.encode()).hexdigest()
            previous = db.execute(
                "SELECT payload_hash FROM events WHERE collector_id=? AND event_id=?",
                (collector_id, event["event_id"]),
            ).fetchone()
            if previous:
                if previous["payload_hash"] != digest:
                    raise EventConflict()
                duplicates += 1
                continue
            if count + accepted >= MAX_EVENTS:
                raise InboxFull()
            db.execute(
                "INSERT INTO events (collector_id, event_id, payload, payload_hash, received_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (collector_id, event["event_id"], payload, digest, received_at),
            )
            accepted += 1
        db.execute("UPDATE collectors SET last_seen=? WHERE collector_id=?", (received_at, collector_id))
    return {"accepted": accepted, "duplicates": duplicates}


def inbox_summary(path):
    """A read-only browser snapshot, bounded to the latest 100 records."""
    with open_inbox(path, readonly=True) as db:
        db.execute("BEGIN")
        total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        rows = db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 100").fetchall()
    return total, [{**json.loads(row["payload"]), "record_id": row["id"], "collector_id": row["collector_id"],
                    "received_at": row["received_at"]} for row in rows]


def register_collector(path, credentials):
    with open_inbox(path) as db, db:
        db.execute("INSERT INTO collectors(collector_id, token_hash, created_at) VALUES (?, ?, ?)",
                   (credentials["collector_id"], hashlib.sha256(credentials["token"].encode()).hexdigest(),
                    datetime.now(timezone.utc).isoformat()))


def authenticate_collector(path, token):
    digest = hashlib.sha256(token).hexdigest()
    with open_inbox(path, readonly=True) as db:
        row = db.execute("SELECT collector_id FROM collectors WHERE token_hash=? AND revoked=0", (digest,)).fetchone()
    return (row["collector_id"], digest) if row else None


def revoke_collector(path, collector_id):
    with open_inbox(path) as db, db:
        if not db.execute("UPDATE collectors SET revoked=1 WHERE collector_id=?", (collector_id,)).rowcount:
            raise ValueError("Collector not found.")


def collector_status(path):
    with open_inbox(path, readonly=True) as db:
        # Never expose token hashes through the browser.
        return [dict(row) for row in db.execute(
            "SELECT collector_id, revoked, last_seen, pending, delivery_error FROM collectors ORDER BY collector_id")]


def record_heartbeat(path, collector_id, token_hash, pending, delivery_error):
    with open_inbox(path) as db, db:
        changed = db.execute(
            "UPDATE collectors SET last_seen=?, pending=?, delivery_error=? "
            "WHERE collector_id=? AND token_hash=? AND revoked=0",
            (datetime.now(timezone.utc).isoformat(), pending, delivery_error, collector_id, token_hash),
        ).rowcount
        if not changed:
            raise CollectorRevoked("Collector access revoked.")
