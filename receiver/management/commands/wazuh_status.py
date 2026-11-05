import json
from pathlib import Path
import sqlite3

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from receiver.wazuh_export import ExportError, export_status, localfile_xml, verify_archive


class Command(BaseCommand):
    help = "Show export state/configuration, or verify one record in a supplied Wazuh archive."

    def add_arguments(self, parser):
        parser.add_argument("--localfile", action="store_true", help="Print the Wazuh localfile XML for this installation.")
        parser.add_argument("--archive", type=Path, help="Local Wazuh archives.json (or an authenticated copy from the manager).")
        parser.add_argument("--record-id", type=int)

    def handle(self, *args, **options):
        if bool(options["archive"]) != (options["record_id"] is not None):
            raise CommandError("Use --archive and --record-id together.")
        try:
            if options["localfile"]:
                if options["archive"]:
                    raise CommandError("Choose configuration output or archive verification.")
                self.stdout.write(localfile_xml(settings.LOGSENTRY_WAZUH_DIRECTORY))
                return
            if options["archive"]:
                # Verification reads a checkpointed event and updates separate
                # status columns transactionally; it must work while watch runs.
                verify_archive(settings.LOGSENTRY_WAZUH_DIRECTORY, settings.LOGSENTRY_RECEIVER_DATABASE,
                               options["archive"], options["record_id"])
                self.stdout.write("Exact decoded event matched in the supplied manager archive. Other records remain unverified.")
            status = export_status(settings.LOGSENTRY_WAZUH_DIRECTORY, settings.LOGSENTRY_RECEIVER_DATABASE)
        except (OSError, ValueError, sqlite3.Error, ExportError) as error:
            raise CommandError(f"Wazuh export status unavailable: {error}") from error
        self.stdout.write(json.dumps(status, indent=2))
