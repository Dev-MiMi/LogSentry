"""Authenticated collector inbox and evidence investigation pages."""

import ipaddress
import logging
import sqlite3
from datetime import datetime, timezone

from django.conf import settings
from django.contrib.auth.decorators import login_not_required
from django.http import Http404
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_safe
from rest_framework.exceptions import APIException, AuthenticationFailed, ParseError, PermissionDenied
from rest_framework import serializers
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from logsentry.reporting import _safe_text
from .authentication import CollectorAuthentication
from .serializers import BatchSerializer, MAX_BODY_BYTES
from .storage import CollectorRevoked, EventConflict, InboxFull, collector_status, inbox_summary, open_inbox, record_heartbeat, save_batch
from .outbox import summary as outbox_summary
from .wazuh_export import ExportError, event_document, export_status
from .wazuh_rules import event_rules, rule_catalogue


logger = logging.getLogger(__name__)


class PayloadTooLarge(APIException):
    status_code = 413
    default_detail = "Request exceeds 256 KiB. Send a smaller batch."


class BoundedJSONParser(JSONParser):
    def parse(self, stream, media_type=None, parser_context=None):
        from io import BytesIO

        # Bound the bytes actually read, not just the caller's Content-Length.
        body = stream.read(MAX_BODY_BYTES + 1)
        if len(body) > MAX_BODY_BYTES:
            raise PayloadTooLarge()
        try:
            return super().parse(BytesIO(body), media_type, parser_context)
        except RecursionError:
            raise ParseError("JSON nesting is too deep.")


@method_decorator(never_cache, name="dispatch")
@method_decorator(login_not_required, name="dispatch")
class ReceiveEvents(APIView):
    authentication_classes = [CollectorAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [BoundedJSONParser]
    http_method_names = ["post", "options"]

    def initial(self, request, *args, **kwargs):
        request.get_host()  # Enforce Django's explicit allowed-host list.
        try:
            loopback = ipaddress.ip_address(request.META.get("REMOTE_ADDR", "")).is_loopback
        except ValueError:
            loopback = False
        if not request.is_secure() and not loopback:
            raise PermissionDenied("HTTPS is required outside loopback.")
        super().initial(request, *args, **kwargs)

    def post(self, request):
        batch = BatchSerializer(data=request.data)
        batch.is_valid(raise_exception=True)
        try:
            result = save_batch(settings.LOGSENTRY_RECEIVER_DATABASE,
                                request.user.collector_id, batch.validated_data["events"],
                                token_hash=request.user.token_hash)
        except EventConflict:
            return Response({"detail": "Event ID already exists with different contents. No events accepted."}, status=409)
        except InboxFull:
            return Response({"detail": "Inbox full. No events accepted; retain this batch at the collector."}, status=507)
        except CollectorRevoked:
            # Revocation may race with a request already authenticated.
            raise AuthenticationFailed("Collector access revoked.")
        except (OSError, ValueError, sqlite3.Error):
            logger.error("Receiver could not save a batch; inspect local storage configuration.")
            return Response({"detail": "Event storage unavailable. Retry with the same event IDs."}, status=503)
        return Response({"schema_version": 1, **result, "status": "stored"},
                        status=201 if result["accepted"] else 200)


@never_cache
@require_safe
def inbox(request):
    context = {"receiver_page": True, "configured": False, "events": [], "total": 0}
    try:
        context["collectors"] = collector_status(settings.LOGSENTRY_RECEIVER_DATABASE)
        context["configured"] = any(not row["revoked"] for row in context["collectors"])
        for row in context["collectors"]:
            row["contact_state"] = "No contact yet"
            if row["last_seen"]:
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(row["last_seen"])).total_seconds()
                row["contact_state"] = "Seen recently" if age <= 30 else "Contact is stale"
    except (OSError, ValueError, sqlite3.Error):
        pass
    try:
        context["total"], context["events"] = inbox_summary(settings.LOGSENTRY_RECEIVER_DATABASE)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, sqlite3.Error):
        context["storage_error"] = True
        return render(request, "receiver/inbox.html", context, status=503)
    for event in context["events"]:
        event["message"] = _safe_text(event["message"])
    try:
        context["outbox"] = outbox_summary(settings.LOGSENTRY_OUTBOX_DATABASE)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, sqlite3.Error):
        context["outbox_error"] = True
    try:
        context["wazuh"] = export_status(settings.LOGSENTRY_WAZUH_DIRECTORY, settings.LOGSENTRY_RECEIVER_DATABASE)
        checked = context["wazuh"]["last_checked"]
        context["wazuh"]["stale"] = not checked or (
            datetime.now(timezone.utc) - datetime.fromisoformat(checked)).total_seconds() > 15
    except FileNotFoundError:
        pass
    except (OSError, ValueError, sqlite3.Error, ExportError):
        context["wazuh_error"] = True
    return render(request, "receiver/inbox.html", context)


@never_cache
@require_safe
def wazuh_rules(request):
    return render(request, "receiver/wazuh_rules.html", {
        "receiver_page": True, "rules": rule_catalogue(),
    })


@never_cache
@require_safe
def investigate(request, record_id):
    context = {"receiver_page": True}
    try:
        with open_inbox(settings.LOGSENTRY_RECEIVER_DATABASE, readonly=True) as db:
            row = db.execute("SELECT * FROM events WHERE id=?", (record_id,)).fetchone()
        if row is None:
            raise Http404("Event not found.")
        document = event_document(row)
        context["event"] = document["logsentry"]
        context["rules"] = event_rules(document)
        context["event"]["message"] = _safe_text(context["event"]["message"])
    except FileNotFoundError:
        raise Http404("Event not found.")
    except (OSError, ValueError, sqlite3.Error):
        context["storage_error"] = True
        return render(request, "receiver/investigate.html", context, status=503)
    return render(request, "receiver/investigate.html", context)


class HeartbeatSerializer(serializers.Serializer):
    pending = serializers.IntegerField(min_value=0, max_value=100_000)
    delivery_error = serializers.CharField(max_length=256, allow_blank=True, trim_whitespace=False)


class Heartbeat(ReceiveEvents):
    def post(self, request):
        data = HeartbeatSerializer(data=request.data)
        data.is_valid(raise_exception=True)
        try:
            record_heartbeat(settings.LOGSENTRY_RECEIVER_DATABASE, request.user.collector_id,
                             request.user.token_hash, **data.validated_data)
        except CollectorRevoked:
            raise AuthenticationFailed("Collector access revoked.")
        except (OSError, ValueError, sqlite3.Error):
            return Response({"detail": "Status storage unavailable."}, status=503)
        return Response({"status": "recorded"})
