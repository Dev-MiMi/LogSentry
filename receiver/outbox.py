"""Durable delivery queue: commit evidence before moving a source cursor.

Network failure never deletes queued events. A lost acknowledgement may cause
redelivery; stable IDs let the receiver deduplicate it after a process restart.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import sqlite3

from logsentry.collection_store import open_store
from .serializers import BatchSerializer, MAX_BODY_BYTES
from .sending import DeliveryError, deliver, event_from_record, heartbeat, validate_endpoint
from .storage import check_private, read_credentials


MAX_PENDING = 20_000
MAX_PENDING_BYTES = 128 * 1024 * 1024
SCHEMA = """
CREATE TABLE config (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL);
CREATE TABLE cursors (source TEXT PRIMARY KEY, record_id INTEGER NOT NULL, dropped INTEGER NOT NULL, warning TEXT NOT NULL);
CREATE TABLE pending (id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL, issue TEXT NOT NULL, size INTEGER NOT NULL);
CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), last_attempt TEXT, last_success TEXT,
                    error TEXT NOT NULL DEFAULT '', failures INTEGER NOT NULL DEFAULT 0, retry_after REAL NOT NULL DEFAULT 0);
INSERT INTO state(id) VALUES (1);
PRAGMA user_version=1;
"""


def write_config(path, config):
    validate_endpoint(config["endpoint"])
    read_credentials(config["credentials"])
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_private(path.parent, directory=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(config, stream)
        stream.flush()
        os.fsync(stream.fileno())


def read_config(path):
    path = Path(path)
    check_private(path.parent, directory=True)
    check_private(path)
    config = json.loads(path.read_text())
    validate_endpoint(config["endpoint"])
    return config


@contextmanager
def open_outbox(path, *, readonly=False):
    path = Path(path).absolute()
    if not readonly:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_private(path.parent, directory=True)
    if not readonly and not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
    check_private(path)
    db = sqlite3.connect(path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"), uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    try:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version == 0 and not readonly:
            db.executescript(SCHEMA)
        elif version != 1:
            raise ValueError("Unsupported outbox version.")
        yield db
    finally:
        db.close()


@contextmanager
def worker_lock(path):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_private(path.parent, directory=True)
    fd = os.open(path.with_suffix(".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        check_private(path.with_suffix(".lock"))
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another delivery worker is already using this outbox.")
        yield
    finally:
        os.close(fd)


def bind_outbox(db, config, collector_id):
    path = Path(config["collection_database"]).absolute()
    info = path.stat()
    binding = json.dumps([config["endpoint"], collector_id, str(path), info.st_dev, info.st_ino])
    with db:
        existing = db.execute("SELECT binding FROM config WHERE id=1").fetchone()
        if existing and existing["binding"] != binding:
            raise ValueError("Outbox destination, collector identity or source database changed; use a separate outbox.")
        db.execute("INSERT OR IGNORE INTO config(id, binding) VALUES (1, ?)", (binding,))


def review_records(path):
    """Expose only a bounded, read-only view for the local operator."""
    with open_outbox(path, readonly=True) as db:
        return [{"id": row["id"], "event": json.loads(row["payload"]), "issue": row["issue"]}
                for row in db.execute("SELECT id, payload, issue FROM pending WHERE issue != '' ORDER BY id LIMIT 50")]


def enqueue(db, collection_database, collector_id, selected_sources):
    """Capture up to 100 records per source each cycle, even while disconnected."""
    with open_store(collection_database, readonly=True) as source_db:
        source_db.execute("BEGIN")
        sources = source_db.execute("SELECT * FROM sources ORDER BY id").fetchall()
        if selected_sources:
            missing = set(selected_sources) - {row["name"] for row in sources}
            if missing:
                raise ValueError("A configured source is not registered with the collector.")
            sources = [row for row in sources if row["name"] in selected_sources]
        for source in sources:
            with db:
                db.execute("BEGIN IMMEDIATE")
                cursor = db.execute("SELECT * FROM cursors WHERE source=?", (source["name"],)).fetchone()
                after = cursor["record_id"] if cursor else 0
                records = source_db.execute("SELECT * FROM records WHERE source_id=? AND id>? ORDER BY id LIMIT 100",
                                            (source["id"], after)).fetchall()
                count, size = db.execute("SELECT COUNT(*), COALESCE(SUM(size), 0) FROM pending").fetchone()
                warning = cursor["warning"] if cursor else ""
                if source["dropped"] > (cursor["dropped"] if cursor else 0):
                    warning = "Source retention removed records; pre-queue coverage may be incomplete."
                for record in records:
                    event = event_from_record(source, record, collector_id)
                    serializer = BatchSerializer(data={"schema_version": 1, "events": [event]})
                    valid = serializer.is_valid()
                    payload = json.dumps(serializer.validated_data["events"][0] if valid else event)
                    byte_count = len(payload.encode())
                    if count >= MAX_PENDING or size + byte_count > MAX_PENDING_BYTES:
                        raise DeliveryError("Outbox full. Collection cursor not advanced; free capacity by restoring delivery.")
                    # Unsupported evidence is retained separately, never silently
                    # truncated or allowed to block valid events from other apps.
                    db.execute("INSERT INTO pending(payload, issue, size) VALUES (?, ?, ?)",
                               (payload, "Record exceeds receiver schema; retained locally for review." if not valid else "", byte_count))
                    count += 1
                    size += byte_count
                    after = record["id"]
                db.execute("INSERT INTO cursors(source, record_id, dropped, warning) VALUES (?, ?, ?, ?) "
                           "ON CONFLICT(source) DO UPDATE SET record_id=excluded.record_id, dropped=excluded.dropped, warning=excluded.warning",
                           (source["name"], after, source["dropped"], warning))


def summary(path):
    with open_outbox(path, readonly=True) as db:
        db.execute("BEGIN")
        state = dict(db.execute("SELECT * FROM state WHERE id=1").fetchone())
        state["pending"], state["quarantined"] = db.execute("SELECT COUNT(*), COALESCE(SUM(issue != ''), 0) FROM pending").fetchone()
        state["warnings"] = [row[0] for row in db.execute("SELECT source || ': ' || warning FROM cursors WHERE warning != ''")]
        return state


def cycle(db, config, credentials, *, now=None):
    now = now or datetime.now(timezone.utc)
    enqueue_error = ""
    try:
        enqueue(db, config["collection_database"], credentials["collector_id"], config.get("sources", []))
    except (OSError, ValueError, sqlite3.Error, DeliveryError):
        enqueue_error = "Queue capture incomplete: check source availability and outbox capacity."
    state = db.execute("SELECT * FROM state WHERE id=1").fetchone()
    if now.timestamp() < state["retry_after"]:
        if enqueue_error:
            with db:
                db.execute("UPDATE state SET error=? WHERE id=1", (enqueue_error,))
        return
    records = []
    events = []
    for row in db.execute("SELECT * FROM pending WHERE issue='' ORDER BY id LIMIT 100"):
        event = json.loads(row["payload"])
        candidate = {"schema_version": 1, "events": [*events, event]}
        if len(json.dumps(candidate).encode()) > MAX_BODY_BYTES:
            break
        records.append(row["id"])
        events.append(event)
    with db:
        db.execute("UPDATE state SET last_attempt=? WHERE id=1", (now.isoformat(),))
    error = ""
    try:
        if events:
            deliver(config["endpoint"], credentials["token"], {"schema_version": 1, "events": events},
                    ca_file=config.get("ca_file"))
            # If this commit fails, retrying the same IDs remains safe.
            with db:
                db.executemany("DELETE FROM pending WHERE id=?", [(record_id,) for record_id in records])
        pending, quarantined = db.execute("SELECT COUNT(*), COALESCE(SUM(issue != ''), 0) FROM pending").fetchone()
        retention = db.execute("SELECT COUNT(*) FROM cursors WHERE warning != ''").fetchone()[0]
        status_error = enqueue_error or ("Some records need local review." if quarantined else "")
        status_error = status_error or ("Source retention changed; coverage may be incomplete." if retention else "")
        heartbeat(config["endpoint"], credentials["token"], pending, status_error, ca_file=config.get("ca_file"))
    except DeliveryError as failure:
        error = str(failure)
    with db:
        if error:
            failures = min(state["failures"] + 1, 9)
            db.execute("UPDATE state SET error=?, failures=?, retry_after=? WHERE id=1",
                       (error, failures, now.timestamp() + min(300, 2 ** failures)))
        else:
            db.execute("UPDATE state SET error=?, failures=0, retry_after=?, last_success=? WHERE id=1",
                       (status_error, now.timestamp() + 2, now.isoformat()))
