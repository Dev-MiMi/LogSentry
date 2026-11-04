import json
import sqlite3

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from logsentry.reporting import _safe_text
from receiver.outbox import review_records, summary


class Command(BaseCommand):
    help = "Show local delivery status; optionally inspect retained records needing review."

    def add_arguments(self, parser):
        parser.add_argument("--review", action="store_true", help="Print up to 50 retained problem records; may contain sensitive evidence.")

    def handle(self, *args, **options):
        try:
            state = summary(settings.LOGSENTRY_OUTBOX_DATABASE)
            self.stdout.write(json.dumps(state, indent=2))
            if options["review"]:
                for row in review_records(settings.LOGSENTRY_OUTBOX_DATABASE):
                    self.stdout.write(_safe_text(json.dumps(row, ensure_ascii=True)))
        except (OSError, ValueError, sqlite3.Error) as error:
            raise CommandError(f"Delivery status unavailable: {error}") from error
