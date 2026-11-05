import sqlite3
import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from receiver.wazuh_export import ExportError, export_lock, export_once, open_state


class Command(BaseCommand):
    help = "Export received events as JSON lines for Wazuh; never claim manager acknowledgement."

    def add_arguments(self, parser):
        parser.add_argument("--watch", action="store_true", help="Export new events every two seconds.")

    def handle(self, *args, **options):
        try:
            with export_lock(settings.LOGSENTRY_WAZUH_DIRECTORY), open_state(settings.LOGSENTRY_WAZUH_DIRECTORY) as db:
                last_error = None
                while True:
                    try:
                        count = export_once(db, settings.LOGSENTRY_WAZUH_DIRECTORY, settings.LOGSENTRY_RECEIVER_DATABASE)
                        if count or last_error:
                            self.stdout.write(f"Exported {count} records locally. Wazuh receipt requires separate verification.")
                        last_error = None
                    except ExportError as error:
                        if not options["watch"]:
                            raise
                        if str(error) != last_error:
                            self.stderr.write(str(error))
                        last_error = str(error)
                    self.stdout.flush()
                    if not options["watch"]:
                        return
                    time.sleep(2)
        except KeyboardInterrupt:
            self.stdout.write("Stopped. Inbox and export checkpoint retained.")
        except (OSError, ValueError, sqlite3.Error, ExportError) as error:
            raise CommandError(str(error)) from error
