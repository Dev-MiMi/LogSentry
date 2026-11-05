"""Offline recovery, credential isolation and browser access regression checks."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client, TestCase, override_settings

from logsentry.collection_sources import Source
from logsentry.collection_store import open_store
from logsentry.collector import collect_source, register_source
from .outbox import bind_outbox, cycle, enqueue, open_outbox, summary, worker_lock
from .sending import DeliveryError
from .storage import (authenticate_collector, initialize_credentials, open_inbox, read_credentials,
                      register_collector, revoke_collector, save_batch)


@override_settings(ALLOWED_HOSTS=["testserver", "127.0.0.1"])
class DeliveryTests(TestCase):
    def setUp(self):
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.collection = self.root / "collector" / "collection.sqlite3"
        self.inbox = self.root / "receiver" / "events.sqlite3"
        self.outbox = self.root / "outbox" / "queue.sqlite3"
        credentials_path = self.root / "tokens" / "collector.json"
        initialize_credentials(credentials_path, "device-one")
        self.credentials = read_credentials(credentials_path)
        register_collector(self.inbox, self.credentials)
        self.config = {"endpoint": "http://127.0.0.1:8000/api/v1/events/", "collection_database": str(self.collection), "sources": []}
        self.log = self.root / "real-service.log"
        self.log.write_text("service started\nservice stopped\n")
        with open_store(self.collection) as db:
            self.source_id = register_source(db, Source("service", self.log, "text", 2026))
            collect_source(db, self.source_id)
        config = override_settings(LOGSENTRY_RECEIVER_DATABASE=self.inbox, LOGSENTRY_OUTBOX_DATABASE=self.outbox,
                                   LOGSENTRY_WAZUH_DIRECTORY=self.root / "wazuh")
        config.enable()
        self.addCleanup(config.disable)
        self.now = datetime.now(timezone.utc)

    def submit(self, endpoint, token, batch, **kwargs):
        response = self.client.post("/api/v1/events/", json.dumps(batch), content_type="application/json",
                                    HTTP_AUTHORIZATION=f"Bearer {token}")
        if response.status_code not in (200, 201):
            raise DeliveryError(f"HTTP {response.status_code}")
        return response.json()

    def beat(self, endpoint, token, pending, error, **kwargs):
        response = self.client.post("/api/v1/heartbeat/", json.dumps({"pending": pending, "delivery_error": error}),
                                    content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {token}")
        self.assertEqual(response.status_code, 200)

    def test_offline_queue_survives_restart_source_deletion_and_lost_ack(self):
        with open_outbox(self.outbox) as db:
            bind_outbox(db, self.config, self.credentials["collector_id"])
            with patch("receiver.outbox.deliver", side_effect=DeliveryError("offline")):
                cycle(db, self.config, self.credentials, now=self.now)
        self.assertEqual(summary(self.outbox)["pending"], 2)
        # The queue has copied evidence; original collector retention cannot erase it.
        with open_store(self.collection) as db, db:
            db.execute("DELETE FROM records")
        def commit_without_ack(*args, **kwargs):
            self.submit(*args, **kwargs)
            raise DeliveryError("acknowledgement lost")
        with open_outbox(self.outbox) as db:
            bind_outbox(db, self.config, self.credentials["collector_id"])
            with patch("receiver.outbox.deliver", side_effect=commit_without_ack):
                cycle(db, self.config, self.credentials, now=self.now + timedelta(seconds=10))
        self.assertEqual(summary(self.outbox)["pending"], 2)
        with open_outbox(self.outbox) as db:
            with patch("receiver.outbox.deliver", side_effect=self.submit), patch("receiver.outbox.heartbeat", side_effect=self.beat):
                cycle(db, self.config, self.credentials, now=self.now + timedelta(seconds=30))
        self.assertEqual(summary(self.outbox)["pending"], 0)
        with open_inbox(self.inbox, readonly=True) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT pending FROM collectors").fetchone()[0], 0)

    def test_backoff_still_queues_new_records_and_credentials_revoke(self):
        with open_outbox(self.outbox) as db:
            with patch("receiver.outbox.deliver", side_effect=DeliveryError("offline")) as delivery:
                cycle(db, self.config, self.credentials, now=self.now)
                with self.log.open("a") as stream:
                    stream.write("new activity\n")
                with open_store(self.collection) as source_db:
                    collect_source(source_db, self.source_id)
                cycle(db, self.config, self.credentials, now=self.now + timedelta(seconds=1))
                self.assertEqual(delivery.call_count, 1)
        self.assertEqual(summary(self.outbox)["pending"], 3)
        revoke_collector(self.inbox, "device-one")
        with open_outbox(self.outbox) as db:
            with patch("receiver.outbox.deliver", side_effect=self.submit):
                cycle(db, self.config, self.credentials, now=self.now + timedelta(seconds=30))
        self.assertEqual(summary(self.outbox)["pending"], 3)
        self.assertIn("401", summary(self.outbox)["error"])

    def test_queue_bound_transaction_and_invalid_records_retained(self):
        with open_outbox(self.outbox) as db:
            with patch("receiver.outbox.MAX_PENDING", 1):
                with self.assertRaises(DeliveryError):
                    enqueue(db, self.collection, "device-one", [])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM cursors").fetchone()[0], 0)
            with self.log.open("a") as stream:
                stream.write("x" * 9000 + "\n")
            with open_store(self.collection) as source_db:
                collect_source(source_db, self.source_id)
                with source_db:
                    source_db.execute("UPDATE sources SET dropped=10")
            with patch("receiver.outbox.deliver", side_effect=self.submit), patch("receiver.outbox.heartbeat", side_effect=self.beat):
                cycle(db, self.config, self.credentials, now=self.now)
        status = summary(self.outbox)
        self.assertEqual((status["pending"], status["quarantined"]), (1, 1))
        self.assertTrue(status["warnings"])
        self.assertIn("review", status["error"])

    def test_queue_binding_and_worker_lock_prevent_conflicting_workers(self):
        with worker_lock(self.outbox):
            with self.assertRaises(ValueError):
                with worker_lock(self.outbox):
                    pass
        with open_outbox(self.outbox) as db:
            bind_outbox(db, self.config, "device-one")
            for collector, endpoint in (("device-two", self.config["endpoint"]), ("device-one", "https://other.example/api/v1/events/")):
                with self.assertRaises(ValueError):
                    bind_outbox(db, {**self.config, "endpoint": endpoint}, collector)

    def test_independent_credentials_and_revocation_are_enforced(self):
        other_path = self.root / "tokens" / "two.json"
        initialize_credentials(other_path, "device-two")
        other = read_credentials(other_path)
        register_collector(self.inbox, other)
        revoke_collector(self.inbox, "device-one")
        self.assertIsNone(authenticate_collector(self.inbox, self.credentials["token"].encode()))
        self.assertEqual(authenticate_collector(self.inbox, other["token"].encode())[0], "device-two")
        with self.assertRaises(PermissionError):
            save_batch(self.inbox, "device-one", [], token_hash="revoked")
        with open_inbox(self.inbox, readonly=True) as db:
            columns = {row[1] for row in db.execute("PRAGMA table_info(collectors)")}
            self.assertNotIn("token", columns)

    def test_milestone_one_database_migrates_without_losing_events(self):
        with open_inbox(self.inbox) as db, db:
            db.execute("DROP TABLE collectors")
            db.execute("PRAGMA user_version=1")
        register_collector(self.inbox, self.credentials)
        self.assertIsNotNone(authenticate_collector(self.inbox, self.credentials["token"].encode()))

    def test_login_required_for_all_evidence_and_status_pages(self):
        for path in ("/", "/collected/", "/collected/1/", "/collected/1/alerts/example/", "/receiver/"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response.url.startswith("/accounts/login/"))
        self.assertEqual(self.client.get("/accounts/login/").status_code, 200)
        # Browser session authentication cannot authorize ingestion.
        user = get_user_model().objects.create_user("reviewer", password="long-test-password")
        self.client.force_login(user)
        self.assertEqual(self.client.get("/receiver/").status_code, 200)
        self.assertEqual(self.client.post("/api/v1/events/", "{}", content_type="application/json").status_code, 401)
        self.assertEqual(self.client.get("/accounts/logout/").status_code, 405)

    def test_login_csrf_open_redirect_and_logout(self):
        get_user_model().objects.create_user("reviewer", password="long-test-password")
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.post("/accounts/login/", {"username": "reviewer", "password": "long-test-password"}).status_code, 403)
        client.get("/accounts/login/")
        response = client.post("/accounts/login/", {
            "username": "reviewer", "password": "long-test-password", "next": "https://untrusted.example/",
            "csrfmiddlewaretoken": client.cookies["csrftoken"].value,
        })
        self.assertEqual(response.url, "/receiver/")
        response = client.post("/accounts/logout/", {"csrfmiddlewaretoken": client.cookies["csrftoken"].value})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(client.get("/receiver/").status_code, 302)
