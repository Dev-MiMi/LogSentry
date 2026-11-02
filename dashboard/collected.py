"""Read local collected records; HTTP requests never read arbitrary source paths."""

from datetime import datetime, timezone
import hashlib
import json
import logging
import sqlite3

from django.conf import settings
from django.http import Http404, JsonResponse
from django.shortcuts import render
from django.template.loader import render_to_string
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_safe

from logsentry.cli import analyze_parsed
from logsentry.collection_store import open_store, retained_records, source_rows
from logsentry.config import DetectionSettings
from logsentry.data import LogEvent, ParsedLog, ParseIssue
from logsentry.reporting import SEVERITY_ORDER, _safe_text
from .templatetags.display_time import readable_timestamp


logger = logging.getLogger(__name__)
STALE_AFTER_SECONDS = 15
RULE_LABELS = {
    "brute_force": "Possible brute-force attack",
    "success_after_failures": "Success after failed logins",
    "repeated_failed_logins": "Repeated failed logins",
    "suspicious_login": "Unusual login time or source",
    "invalid_user": "Invalid account attempt",
}


def _analysis(source, records):
    """Analyze one source independently to avoid counting duplicate feeds twice."""
    parsed = ParsedLog(total_lines=len(records))
    for record in records:
        if record["issue"]:
            parsed.issues.append(ParseIssue(record["id"], record["issue"]))
        if record["timestamp"]:
            parsed.events.append(LogEvent(
                timestamp=datetime.fromisoformat(record["timestamp"]),
                hostname=record["hostname"], event_type=record["event_type"],
                # Persistent record IDs break ties across file rotations.
                line_number=record["id"], raw_line=record["raw_line"],
                username=record["username"], source_ip=record["source_ip"],
                authentication_method=record["authentication_method"],
                invalid_user=bool(record["invalid_user"]),
            ))
        if not record["raw_line"].strip():
            parsed.blank_lines += 1
    policy = DetectionSettings(year=source["year"], timezone_name=source["timezone"])
    return analyze_parsed(parsed, source["name"], policy)


def _findings(analysis):
    result = []
    for alert in sorted(analysis.alerts, key=lambda item: (SEVERITY_ORDER[item.severity], item.timestamp)):
        # Evidence changes produce a different link; an old link never silently
        # opens an unrelated finding because its table position moved.
        identity = [alert.rule, alert.hostname, alert.source_ip,
                    [event.line_number for event in alert.evidence]]
        key = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
        result.append({"id": key, "alert": alert, "label": RULE_LABELS.get(alert.rule, alert.rule)})
    return result


def _revision(sources):
    """A heartbeat alone must not rebuild thousands of records and findings."""
    snapshot = [{key: value for key, value in source.items() if key != "last_checked"}
                for source in sources]
    # Include the policy so a changed default also invalidates the displayed findings.
    policy = repr(DetectionSettings(year=2026))
    # A timezone change must refresh existing browser tabs even if no new logs
    # arrived; otherwise their event labels would retain the old display zone.
    return hashlib.sha256(json.dumps([snapshot, policy, settings.TIME_ZONE], sort_keys=True).encode()).hexdigest()


def _collection_state(source, now):
    """Report observations, not a claim that a process is definitely running."""
    checked = source["last_checked"]
    if source["last_error"]:
        label, attention = "Collection error", True
    elif not checked:
        label, attention = "Not checked yet", True
    elif (now - datetime.fromisoformat(checked)).total_seconds() > STALE_AFTER_SECONDS:
        label, attention = "No check in 15s · collector may be stopped", True
    else:
        label, attention = f"Checked recently · {source['issue_count']} parsing issues", False
    return {"id": source["id"], "last_checked": readable_timestamp(checked, "Not checked"),
            "label": label, "attention": attention}


def _read(source_id, known_revision=None):
    with open_store(settings.LOGSENTRY_COLLECTION_DATABASE, readonly=True) as connection:
        # A consistent read snapshot pairs source counters with their records.
        connection.execute("BEGIN")
        sources = [dict(row) for row in source_rows(connection)]
        selected = next((row for row in sources if row["id"] == source_id), None)
        if source_id is not None and selected is None:
            raise Http404("Source not found")
        revision = _revision(sources)
        records = retained_records(connection, source_id) if selected and revision != known_revision else []
    return sources, selected, records, revision


@never_cache
@require_safe
def collected_logs(request, source_id=None):
    # Only this fixed page can be refreshed; request parameters never choose a file.
    updating = request.headers.get("X-LogSentry-Update") == "1"
    known_revision = request.GET.get("revision") if updating else None
    context = {}
    try:
        sources, source, records, revision = _read(source_id, known_revision)
    except FileNotFoundError:
        if source_id is not None:
            if updating:
                return JsonResponse({"error": "Source is no longer available."}, status=404)
            raise Http404("Source not found")
        sources, source, records = [], None, []
        revision = _revision(sources)
    except Http404:
        if updating:
            return JsonResponse({"error": "Source is no longer available."}, status=404)
        raise
    except (OSError, ValueError, sqlite3.Error):
        logger.exception("Could not read collected logs")
        if updating:
            return JsonResponse({"error": "Collected logs could not be loaded."}, status=503)
        return render(request, "dashboard/collected.html", {**context, "storage_error": True}, status=503)
    states = [_collection_state(item, datetime.now(timezone.utc)) for item in sources]
    if updating and revision == known_revision:
        return JsonResponse({"revision": revision, "html": None, "states": states})
    for item, state in zip(sources, states):
        item["collection_state"] = state
    context.update(sources=sources, source=source, revision=revision)
    if source:
        analysis = _analysis(source, records)
        context.update(analysis=analysis, findings=_findings(analysis),
                       records=[{**dict(row), "raw_display": _safe_text(row["raw_line"])}
                                for row in reversed(records[-200:])],
                       record_limit=200)
    if updating:
        # Django escapes raw log content before it enters this HTML fragment.
        # JavaScript never interpolates raw log text into markup.
        return JsonResponse({"revision": revision, "states": states,
                             "html": render_to_string("dashboard/collected_content.html", context, request)})
    return render(request, "dashboard/collected.html", context)


@never_cache
@require_safe
def collected_alert(request, source_id, finding_id):
    try:
        _, source, records, _ = _read(source_id)
    except FileNotFoundError:
        raise Http404("Source not found")
    except (OSError, ValueError, sqlite3.Error):
        logger.exception("Could not read collected evidence")
        return render(request, "dashboard/collected.html",
                      {"storage_error": True}, status=503)
    analysis = _analysis(source, records)
    row = next((row for row in _findings(analysis) if row["id"] == finding_id), None)
    if row is None:
        raise Http404("Finding changed or is no longer in retained records. Return to the source.")
    by_id = {record["id"]: dict(record) for record in records}
    return render(request, "dashboard/collected_alert.html", {
        "source": source, "row": row,
        "evidence": [{**by_id[event.line_number], "raw_display": _safe_text(event.raw_line)}
                     for event in row["alert"].evidence],
    })
