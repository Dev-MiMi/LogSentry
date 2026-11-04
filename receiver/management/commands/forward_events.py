import sqlite3
import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from receiver.outbox import bind_outbox, cycle, open_outbox, read_config, summary, worker_lock
from receiver.storage import read_credentials
from receiver.sending import DeliveryError


class Command(BaseCommand):
    help = "Queue saved records and deliver automatically; failed deliveries survive restarts."

    def add_arguments(self, parser):
        parser.add_argument("--watch", action="store_true")

    def handle(self, *args, **options):
        try:
            config = read_config(settings.LOGSENTRY_FORWARDER_CONFIG)
            credentials = read_credentials(config["credentials"])
            with worker_lock(settings.LOGSENTRY_OUTBOX_DATABASE), open_outbox(settings.LOGSENTRY_OUTBOX_DATABASE) as db:
                bind_outbox(db, config, credentials["collector_id"])
                previous = None
                while True:
                    bind_outbox(db, config, credentials["collector_id"])
                    cycle(db, config, credentials)
                    state = summary(settings.LOGSENTRY_OUTBOX_DATABASE)
                    current = (state["pending"], state["quarantined"], state["error"])
                    if current != previous:
                        self.stdout.write(f"Pending: {current[0]}; needs review: {current[1]}; status: {current[2] or 'receiver reachable'}")
                        self.stdout.flush()
                        previous = current
                    if not options["watch"]:
                        if state["error"]:
                            raise CommandError(state["error"])
                        return
                    time.sleep(2)
        except KeyboardInterrupt:
            self.stdout.write("Stopped. Unacknowledged records remain in the outbox.")
        except (OSError, ValueError, KeyError, sqlite3.Error, DeliveryError) as error:
            raise CommandError(f"Forwarder stopped; queued records retained: {error}") from error
