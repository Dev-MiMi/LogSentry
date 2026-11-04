"""Manually deliver real retained records; no fictional input or automatic replay."""

import hashlib
import ipaddress
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.request import HTTPSHandler
import ssl
import uuid

from logsentry.collection_store import open_store
from .serializers import MAX_BODY_BYTES


class DeliveryError(Exception):
    pass


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        # Never carry a collector token to a destination chosen by a redirect.
        return None


def validate_endpoint(endpoint):
    try:
        url = urlsplit(endpoint)
        valid_port = url.port is None or 1 <= url.port <= 65535
    except ValueError as error:
        raise DeliveryError("Invalid receiver URL.") from error
    try:
        is_loopback = ipaddress.ip_address(url.hostname or "").is_loopback
    except ValueError:
        is_loopback = False
    if (url.scheme not in ("http", "https") or not url.hostname or not valid_port
            or url.username is not None or url.password is not None or url.query or url.fragment
            or url.path != "/api/v1/events/"):
        raise DeliveryError("Use an HTTP(S) URL ending in /api/v1/events/ without credentials or query parameters.")
    if url.scheme == "http" and not is_loopback:
        raise DeliveryError("HTTP is allowed only for a literal loopback IP. Use HTTPS elsewhere.")
    return endpoint


def event_from_record(source, record, collector_id):
    identity = json.dumps([collector_id, source["name"], record["id"],
                           record["received_at"], record["raw_line"]])
    return {
        "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, hashlib.sha256(identity.encode()).hexdigest())),
        "platform": "termux" if source["name"].startswith("termux-") else "linux",
        "source": source["name"], "event_type": record["event_type"] or "unparsed",
        "observed_at": (record["timestamp"] or record["received_at"])
        if source["format"] == "sshd_capture" else record["received_at"],
        "occurred_at": None if source["format"] == "sshd_capture" else record["timestamp"],
        "message": record["raw_line"],
    }


def collected_batch(database, credentials, source_name, *, after_record=0, limit=100):
    """Read a stable snapshot. Original evidence and collector offsets are untouched."""
    with open_store(database, readonly=True) as db:
        db.execute("BEGIN")
        source = db.execute("SELECT * FROM sources WHERE name=?", (source_name,)).fetchone()
        if source is None:
            raise DeliveryError("Source is not registered with the local collector.")
        records = db.execute(
            "SELECT * FROM records WHERE source_id=? AND id>? ORDER BY id LIMIT ?",
            (source["id"], after_record, limit),
        ).fetchall()
    events = [event_from_record(source, record, credentials["collector_id"]) for record in records]
    return {"schema_version": 1, "events": events}, records[-1]["id"] if records else after_record


def request_json(endpoint, token, payload, *, ca_file=None):
    body = json.dumps(payload).encode("utf-8")
    if len(body) > MAX_BODY_BYTES:
        raise DeliveryError("Batch exceeds 256 KiB. Reduce --limit.")
    request = Request(endpoint, data=body, method="POST", headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json",
    })
    try:
        handlers = [NoRedirects()]
        if ca_file:
            handlers.append(HTTPSHandler(context=ssl.create_default_context(cafile=str(ca_file))))
        with build_opener(*handlers).open(request, timeout=15) as response:
            return response.status, json.loads(response.read(4096))
    except HTTPError as error:
        raise DeliveryError(f"Receiver returned HTTP {error.code}. Delivery not acknowledged.") from error
    except (URLError, OSError, ValueError, RecursionError) as error:
        raise DeliveryError("Delivery was not acknowledged. Queued events can be retried with the same IDs.") from error


def deliver(endpoint, token, batch, *, ca_file=None):
    endpoint = validate_endpoint(endpoint)
    status, result = request_json(endpoint, token, batch, ca_file=ca_file)
    if (status not in (200, 201) or not isinstance(result, dict)
            or result.get("status") != "stored" or result.get("schema_version") != 1
            or type(result.get("accepted")) is not int or type(result.get("duplicates")) is not int
            or min(result["accepted"], result["duplicates"]) < 0
            or result["accepted"] + result["duplicates"] != len(batch["events"])):
        raise DeliveryError("Invalid receipt. Retry with the same cursor and event IDs.")
    return result


def heartbeat(endpoint, token, pending, error, *, ca_file=None):
    endpoint = validate_endpoint(endpoint).removesuffix("events/") + "heartbeat/"
    status, result = request_json(endpoint, token, {"pending": pending, "delivery_error": error[:256]}, ca_file=ca_file)
    if status != 200 or result != {"status": "recorded"}:
        raise DeliveryError("Heartbeat was not acknowledged.")
