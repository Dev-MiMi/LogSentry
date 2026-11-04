"""Bearer authentication, bound to the identity in a private local credential file."""

from dataclasses import dataclass
import sqlite3

from django.conf import settings
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import APIException, AuthenticationFailed

from .storage import authenticate_collector


class ReceiverUnavailable(APIException):
    status_code = 503
    default_detail = "Receiver unavailable. Check its local configuration."


@dataclass(frozen=True)
class Collector:
    collector_id: str
    token_hash: str
    is_authenticated: bool = True


class CollectorAuthentication(BaseAuthentication):
    def authenticate(self, request):
        header = get_authorization_header(request).split()
        if len(header) != 2 or header[0].lower() != b"bearer" or len(header[1]) > 256:
            raise AuthenticationFailed("Valid collector credentials required.")
        try:
            identity = authenticate_collector(settings.LOGSENTRY_RECEIVER_DATABASE, header[1])
        except (OSError, ValueError, sqlite3.Error):
            raise ReceiverUnavailable()
        if identity is None:
            raise AuthenticationFailed("Valid collector credentials required.")
        return Collector(*identity), None

    def authenticate_header(self, request):
        return "Bearer"
