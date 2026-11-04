"""Local web inbox and authenticated POST endpoint; Wazuh delivery comes later."""

import ipaddress
import logging
import sqlite3

from django.conf import settings
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_safe
from rest_framework.exceptions import APIException, ParseError, PermissionDenied
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from logsentry.reporting import _safe_text
from .authentication import CollectorAuthentication
from .serializers import BatchSerializer, MAX_BODY_BYTES
from .storage import EventConflict, InboxFull, inbox_summary, read_credentials, save_batch


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
                                request.user.collector_id, batch.validated_data["events"])
        except EventConflict:
            return Response({"detail": "Event ID already exists with different contents. No events accepted."}, status=409)
        except InboxFull:
            return Response({"detail": "Inbox full. No events accepted; retain this batch at the collector."}, status=507)
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
        credentials = read_credentials(settings.LOGSENTRY_RECEIVER_CREDENTIALS)
        context.update(configured=True, collector_id=credentials["collector_id"])
    except (OSError, ValueError):
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
    return render(request, "receiver/inbox.html", context)
