"""Durable JSON-lines handoff to Wazuh's localfile reader.

The journal commits intended bytes before append, fsync precedes checkpoint,
and recovery completes a matching partial append. No event is deleted from the
inbox. This acknowledges a local export, never Wazuh receipt or indexing.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from xml.etree.ElementTree import Element, SubElement, indent, tostring

from .storage import check_private, open_inbox
from .wazuh_fields import ssh_fields


MAX_EXPORT_BYTES = 128 * 1024 * 1024
# Wazuh 4.14's JSON reader has a 64 KiB buffer minus its log header.
MAX_LINE_BYTES = 60 * 1024
BATCH_SIZE = 100
ARCHIVE_SCAN_BYTES = 64 * 1024 * 1024
SCHEMA = """
CREATE TABLE state (
    id INTEGER PRIMARY KEY CHECK(id=1),
    binding TEXT NOT NULL DEFAULT '',
    device INTEGER, inode INTEGER,
    offset INTEGER NOT NULL DEFAULT 0,
    tail_hash TEXT NOT NULL DEFAULT '',
    last_record INTEGER NOT NULL DEFAULT 0,
    exported INTEGER NOT NULL DEFAULT 0,
    last_checked TEXT, last_exported TEXT,
    error TEXT NOT NULL DEFAULT '',
    verified_record INTEGER, verified_at TEXT,
    journal BLOB, journal_last_record INTEGER, journal_count INTEGER
);
INSERT INTO state(id) VALUES (1);
PRAGMA user_version=1;
"""


class ExportError(Exception):
    pass


def event_document(row, *, enriched=True):
    payload = json.loads(row["payload"])
    # Field names/transport provenance are controlled here, not copied from
    # arbitrary JSON. Original timestamps and unaltered message stay distinct.
    event = {name: payload[name] for name in (
        "event_id", "platform", "source", "event_type", "observed_at", "occurred_at", "message",
    )}
    event.update(schema_version=1, record_id=row["id"], collector_id=row["collector_id"],
                 received_at=row["received_at"], payload_sha256=row["payload_hash"])
    if enriched:
        event["enrichment_version"] = 1
        ssh = ssh_fields(event)
        if ssh:
            event["ssh"] = ssh
    return {"integration": "logsentry", "logsentry": event}


def encode_record(row):
    data = (json.dumps(event_document(row), ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_LINE_BYTES:
        raise ExportError(f"Record {row['id']} exceeds the 60 KiB Wazuh export limit; export paused without truncation.")
    return data


@contextmanager
def open_state(directory, *, readonly=False):
    directory = Path(directory).absolute()
    if not readonly:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_private(directory, directory=True)
    path = directory / "export.sqlite3"
    if not readonly and not path.exists() and not path.is_symlink():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
    check_private(path)
    db = sqlite3.connect(path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"), uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    try:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if not version and not readonly:
            db.executescript(SCHEMA)
        elif version != 1:
            raise ExportError("Unsupported Wazuh export state version.")
        yield db
    finally:
        db.close()


@contextmanager
def export_lock(directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_private(directory, directory=True)
    path = directory / "export.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        check_private(path)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ExportError("Another Wazuh exporter is already running for this directory.")
        yield
    finally:
        os.close(fd)


def _sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _tail(stream, offset):
    stream.seek(max(0, offset - 4096))
    return hashlib.sha256(stream.read(min(offset, 4096))).hexdigest()


def _open_log(directory, state):
    path = Path(directory) / "events.jsonl"
    # Missing tracked files are an error, not an opportunity to silently skip
    # already-exported events in a newly created replacement.
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    if state["inode"] is None:
        try:
            fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                _sync_directory(directory)
            except BaseException:
                os.close(fd)
                raise
        except FileExistsError:
            fd = os.open(path, flags)
    else:
        fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise ExportError("Wazuh export must be a private, owned regular file without links.")
        if state["inode"] is None and info.st_size:
            raise ExportError("Refusing to adopt a nonempty export without its checkpoint.")
        if state["inode"] is not None and (info.st_dev, info.st_ino) != (state["device"], state["inode"]):
            raise ExportError("Wazuh export file was replaced. Restore it with its state; do not rotate this file.")
        return os.fdopen(fd, "r+b", buffering=0)
    except BaseException:
        os.close(fd)
        raise


def _append_remaining(stream, data):
    remaining = memoryview(data)
    while remaining:
        written = stream.write(remaining)
        if not written:
            raise OSError("Could not append Wazuh export.")
        remaining = remaining[written:]
    os.fsync(stream.fileno())


def _finish_journal(db, stream, state):
    journal = bytes(state["journal"])
    offset = state["offset"]
    size = os.fstat(stream.fileno()).st_size
    if not offset <= size <= offset + len(journal):
        raise ExportError("Export size differs from its journal; paused to preserve evidence.")
    stream.seek(offset)
    existing = stream.read(size - offset)
    if not journal.startswith(existing):
        raise ExportError("Export contents differ from its journal; paused to preserve evidence.")
    stream.seek(size)
    _append_remaining(stream, journal[len(existing):])
    offset += len(journal)
    digest = _tail(stream, offset)
    with db:
        db.execute("UPDATE state SET offset=?, tail_hash=?, last_record=?, exported=exported+?, "
                   "last_exported=?, journal=NULL, journal_last_record=NULL, journal_count=NULL WHERE id=1",
                   (offset, digest, state["journal_last_record"], state["journal_count"],
                    datetime.now(timezone.utc).isoformat()))


def export_once(db, directory, inbox, *, batch_size=BATCH_SIZE):
    """Caller holds export_lock. A bounded batch leaves the receiver writable."""
    if not 1 <= batch_size <= BATCH_SIZE:
        raise ValueError("Batch size must be 1–100.")
    now = datetime.now(timezone.utc).isoformat()
    with db:
        db.execute("UPDATE state SET last_checked=? WHERE id=1", (now,))
    try:
        return _export(db, directory, inbox, batch_size)
    except (OSError, ValueError, sqlite3.Error, ExportError, KeyError) as error:
        message = str(error) if isinstance(error, ExportError) else "Export unavailable; check inbox, file permissions and disk space."
        with db:
            db.execute("UPDATE state SET error=? WHERE id=1", (message,))
        raise ExportError(message) from error


def _export(db, directory, inbox, batch_size):
    # Bind to the actual inbox inode and path. Replacing a database cannot cause
    # an old numeric cursor to skip records from a different installation.
    with open_inbox(inbox, readonly=True) as source:
        info = Path(inbox).stat()
        binding = json.dumps([str(Path(inbox).absolute()), info.st_dev, info.st_ino])
        state = db.execute("SELECT * FROM state WHERE id=1").fetchone()
        if state["binding"] and binding != state["binding"]:
            raise ExportError("Inbox identity changed. Restore it or use a separate export directory.")
        if not state["binding"]:
            with db:
                db.execute("UPDATE state SET binding=? WHERE id=1", (binding,))
        with _open_log(directory, state) as stream:
            if state["inode"] is None:
                info = os.fstat(stream.fileno())
                with db:
                    db.execute("UPDATE state SET device=?, inode=?, tail_hash=? WHERE id=1",
                               (info.st_dev, info.st_ino, _tail(stream, 0)))
                state = db.execute("SELECT * FROM state WHERE id=1").fetchone()
            if os.fstat(stream.fileno()).st_size < state["offset"] or _tail(stream, state["offset"]) != state["tail_hash"]:
                raise ExportError("Export was truncated or its checkpoint tail changed. Restore the original file.")
            recovered = 0
            if state["journal"] is not None:
                recovered = state["journal_count"]
                _finish_journal(db, stream, state)
                state = db.execute("SELECT * FROM state WHERE id=1").fetchone()
            elif os.fstat(stream.fileno()).st_size != state["offset"]:
                raise ExportError("Untracked bytes were added to the export; paused without deleting them.")
            rows = source.execute("SELECT * FROM events WHERE id>? ORDER BY id LIMIT ?",
                                  (state["last_record"], batch_size)).fetchall()
            if rows:
                journal = b"".join(encode_record(row) for row in rows)
                if state["offset"] + len(journal) > MAX_EXPORT_BYTES:
                    raise ExportError("Export reached its 128 MiB cap. No records deleted; operator review required.")
                with db:
                    db.execute("UPDATE state SET journal=?, journal_last_record=?, journal_count=? WHERE id=1",
                               (journal, rows[-1]["id"], len(rows)))
                state = db.execute("SELECT * FROM state WHERE id=1").fetchone()
                _finish_journal(db, stream, state)
            with db:
                db.execute("UPDATE state SET error='' WHERE id=1")
            return recovered + len(rows)


def export_status(directory, inbox):
    """Read-only UI/CLI status; no file path can be selected by an HTTP request."""
    with open_state(directory, readonly=True) as db:
        state = dict(db.execute("SELECT * FROM state WHERE id=1").fetchone())
    state.pop("journal")
    binding = state.pop("binding")
    with open_inbox(inbox, readonly=True) as db:
        info = Path(inbox).stat()
        actual = json.dumps([str(Path(inbox).absolute()), info.st_dev, info.st_ino])
        if binding and binding != actual:
            raise ExportError("Inbox identity differs from the export state.")
        state["pending"] = db.execute("SELECT COUNT(*) FROM events WHERE id>?", (state["last_record"],)).fetchone()[0]
    state["path"] = str(Path(directory).absolute() / "events.jsonl")
    return state


def localfile_xml(directory):
    path = str(Path(directory).absolute() / "events.jsonl")
    if any(char in path for char in ("*", "?", "[", "]", "\n", "\r", "%")):
        raise ExportError("Export path cannot contain Wazuh wildcard/date-pattern characters.")
    root = Element("localfile")
    SubElement(root, "location").text = path
    SubElement(root, "log_format").text = "json"
    SubElement(root, "only-future-events", {"max-size": "128MB"}).text = "no"
    indent(root, space="  ")
    return tostring(root, encoding="unicode")


def verify_archive(directory, inbox, archive, record_id):
    """Match one exact export against an operator-supplied Wazuh JSON archive.

This is evidence about ONE record. It is not remote attestation, an automatic
delivery acknowledgement, or authorization to delete any local evidence.
"""
    with open_state(directory) as db:
        state = db.execute("SELECT * FROM state WHERE id=1").fetchone()
        last = state["last_record"]
        if record_id <= 0 or record_id > last:
            raise ExportError("Choose a record already checkpointed in the export.")
        with open_inbox(inbox, readonly=True) as source:
            info = Path(inbox).stat()
            actual = json.dumps([str(Path(inbox).absolute()), info.st_dev, info.st_ino])
            if state["binding"] != actual:
                raise ExportError("Inbox identity differs from the export being verified.")
            row = source.execute("SELECT * FROM events WHERE id=?", (record_id,)).fetchone()
        if row is None:
            raise ExportError("Record is no longer in the inbox; cannot verify its evidence.")
        # Existing milestone 3 exports are immutable and remain verifiable.
        expected = (event_document(row), event_document(row, enriched=False))
        fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        matched = False
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ExportError("Archive must be a regular local file.")
            if info.st_size > ARCHIVE_SCAN_BYTES:
                stream.seek(info.st_size - ARCHIVE_SCAN_BYTES)
                stream.readline(1024 * 1024)
            remaining = ARCHIVE_SCAN_BYTES
            while remaining > 0:
                line = stream.readline(min(1024 * 1024, remaining))
                if not line:
                    break
                remaining -= len(line)
                try:
                    observed = json.loads(line)
                    if not isinstance(observed, dict) or observed.get("decoder", {}).get("name") != "json":
                        continue
                    if not isinstance(observed.get("manager"), dict) or not observed["manager"].get("name"):
                        continue
                    full_log = observed.get("full_log")
                    if isinstance(full_log, str) and json.loads(full_log) in expected:
                        matched = True
                        break
                except (ValueError, AttributeError, RecursionError):
                    continue
        if not matched:
            raise ExportError("No matching decoded event in the last 64 MiB of this archive. Manager receipt remains unverified.")
        with db:
            db.execute("UPDATE state SET verified_record=?, verified_at=? WHERE id=1",
                       (record_id, datetime.now(timezone.utc).isoformat()))
