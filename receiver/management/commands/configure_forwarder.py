from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from receiver.outbox import write_config
from receiver.sending import DeliveryError


class Command(BaseCommand):
    help = "Save a local delivery destination and credential-file path (no secrets in arguments)."

    def add_arguments(self, parser):
        parser.add_argument("--endpoint", required=True)
        parser.add_argument("--credentials", type=Path, default=settings.LOGSENTRY_RECEIVER_CREDENTIALS)
        parser.add_argument("--source", action="append", default=[], help="Repeat to select sources; omitted means all registered sources.")
        parser.add_argument("--ca-file", type=Path, help="Trusted CA bundle for a private TLS certificate.")

    def handle(self, *args, **options):
        ca_file = options["ca_file"]
        if ca_file and not ca_file.is_file():
            raise CommandError("CA bundle does not exist.")
        config = {
            "endpoint": options["endpoint"], "credentials": str(options["credentials"].absolute()),
            "collection_database": str(settings.LOGSENTRY_COLLECTION_DATABASE), "sources": options["source"],
            "ca_file": str(ca_file.absolute()) if ca_file else None,
        }
        try:
            write_config(settings.LOGSENTRY_FORWARDER_CONFIG, config)
        except (OSError, ValueError, DeliveryError) as error:
            raise CommandError(str(error)) from error
        self.stdout.write("Forwarder configured. Run: python manage.py forward_events --watch")
