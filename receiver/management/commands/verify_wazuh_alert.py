import json
from pathlib import Path
import sqlite3

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from receiver.wazuh_alerts import verified_alert
from receiver.wazuh_export import ExportError


class Command(BaseCommand):
    help = "Read-only check of one exported record in a supplied Wazuh alerts.json file."

    def add_arguments(self, parser):
        parser.add_argument("--alerts", type=Path, required=True)
        parser.add_argument("--record-id", type=int, required=True)

    def handle(self, *args, **options):
        try:
            result = verified_alert(settings.LOGSENTRY_WAZUH_DIRECTORY,
                                    settings.LOGSENTRY_RECEIVER_DATABASE,
                                    options["alerts"], options["record_id"])
        except (OSError, ValueError, sqlite3.Error, ExportError) as error:
            raise CommandError(f"Alert verification unavailable: {error}") from error
        self.stdout.write(json.dumps(result, indent=2))
