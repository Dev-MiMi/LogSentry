"""Provision/import/revoke collector tokens without exposing them in shell output."""

from pathlib import Path
import sqlite3

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from receiver.storage import initialize_credentials, read_credentials, register_collector, revoke_collector


class Command(BaseCommand):
    help = "Enroll, import legacy credentials, or revoke a collector. Tokens are never printed."

    def add_arguments(self, parser):
        actions = parser.add_subparsers(dest="action", required=True)
        enroll = actions.add_parser("enroll")
        enroll.add_argument("--collector-id", required=True)
        enroll.add_argument("--output", type=Path, required=True)
        migrate = actions.add_parser("import")
        migrate.add_argument("--credentials", type=Path, default=settings.LOGSENTRY_RECEIVER_CREDENTIALS)
        revoke = actions.add_parser("revoke")
        revoke.add_argument("--collector-id", required=True)

    def handle(self, *args, **options):
        try:
            if options["action"] == "revoke":
                revoke_collector(settings.LOGSENTRY_RECEIVER_DATABASE, options["collector_id"])
                self.stdout.write("Collector revoked; its stored records remain available.")
                return
            if options["action"] == "enroll":
                path = options["output"].absolute()
                initialize_credentials(path, options["collector_id"])
            else:
                path = options["credentials"]
            register_collector(settings.LOGSENTRY_RECEIVER_DATABASE, read_credentials(path))
        except (OSError, ValueError, sqlite3.Error) as error:
            raise CommandError(f"Collector configuration failed: {error}") from error
        self.stdout.write("Collector registered. Securely copy its private credential file to that collector.")
        self.stdout.write("An existing identity cannot be reused or silently re-enabled after revocation.")
