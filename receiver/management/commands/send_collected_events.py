import sqlite3

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from receiver.sending import DeliveryError, collected_batch, deliver
from receiver.serializers import BatchSerializer
from receiver.storage import read_credentials


class Command(BaseCommand):
    help = "Send a bounded batch of real saved local records to the web inbox."

    def add_arguments(self, parser):
        parser.add_argument("--source", required=True, help="Registered local source name.")
        parser.add_argument("--endpoint", default="http://127.0.0.1:8000/api/v1/events/")
        parser.add_argument("--after-record", type=int, default=0)
        parser.add_argument("--limit", type=int, default=100)

    def handle(self, *args, **options):
        if not 1 <= options["limit"] <= 100 or options["after_record"] < 0:
            raise CommandError("Use --limit 1–100 and --after-record 0 or greater.")
        try:
            credentials = read_credentials(settings.LOGSENTRY_RECEIVER_CREDENTIALS)
            batch, cursor = collected_batch(
                settings.LOGSENTRY_COLLECTION_DATABASE, credentials, options["source"],
                after_record=options["after_record"], limit=options["limit"],
            )
            if not batch["events"]:
                self.stdout.write("No retained records after this cursor.")
                return
            serializer = BatchSerializer(data=batch)
            if not serializer.is_valid():
                raise DeliveryError("A saved record cannot fit the receiver schema. Inspect its source; no records sent.")
            result = deliver(options["endpoint"], credentials["token"], serializer.validated_data)
        except (OSError, ValueError, sqlite3.Error, DeliveryError) as error:
            raise CommandError(str(error)) from error
        self.stdout.write(f"Stored: {result['accepted']}; already present: {result['duplicates']}.")
        self.stdout.write(f"Next batch for source {options['source']}: --after-record {cursor}")
        self.stdout.write("This confirms the LogSentry inbox receipt only. Wazuh forwarding is not connected.")
