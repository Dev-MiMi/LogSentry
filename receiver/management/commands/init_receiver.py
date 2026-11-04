import sqlite3

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from receiver.storage import initialize_credentials, open_inbox, read_credentials, register_collector


class Command(BaseCommand):
    help = "Provision one collector and a private inbox; never print or overwrite its token."

    def add_arguments(self, parser):
        parser.add_argument("--collector-id", required=True)

    def handle(self, *args, **options):
        try:
            # Check storage first, so a storage failure cannot consume a new token.
            with open_inbox(settings.LOGSENTRY_RECEIVER_DATABASE):
                pass
            initialize_credentials(settings.LOGSENTRY_RECEIVER_CREDENTIALS, options["collector_id"])
            register_collector(settings.LOGSENTRY_RECEIVER_DATABASE,
                               read_credentials(settings.LOGSENTRY_RECEIVER_CREDENTIALS))
        except (OSError, ValueError, sqlite3.Error) as error:
            raise CommandError(f"Receiver setup failed: {error}") from error
        self.stdout.write(self.style.SUCCESS("Receiver configured."))
        self.stdout.write(f"Private credentials: {settings.LOGSENTRY_RECEIVER_CREDENTIALS}")
        self.stdout.write("Keep credentials private. Open http://127.0.0.1:8000/receiver/ after starting Django.")
