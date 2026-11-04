"""Boundary and delivery tests; all artificial records use temporary stores."""

from concurrent.futures import ThreadPoolExecutor
from io import StringIO
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.error import HTTPError
import uuid

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import Client, TestCase, override_settings
from django.contrib.auth import get_user_model

from logsentry.collection_sources import Source
from logsentry.collection_store import open_store
from logsentry.collector import collect_source, register_source
from .serializers import MAX_BODY_BYTES
from .sending import DeliveryError, NoRedirects, collected_batch, deliver, validate_endpoint
from .storage import initialize_credentials, open_inbox, read_credentials, register_collector, save_batch


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class ReceiverTests(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.database = self.root / "private" / "events.sqlite3"
        self.credentials = self.database.parent / "credentials.json"
        self.collection = self.root / "collection" / "collection.sqlite3"
        config = override_settings(
            LOGSENTRY_RECEIVER_DATABASE=self.database,
            LOGSENTRY_RECEIVER_CREDENTIALS=self.credentials,
            LOGSENTRY_COLLECTION_DATABASE=self.collection,
        )
        config.enable()
        self.addCleanup(config.disable)
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(get_user_model().objects.create_user(username="reviewer"))
        self.event = {
            "event_id": str(uuid.uuid4()), "platform": "android", "source": "selected-app",
            "event_type": "notification", "observed_at": "2026-11-04T12:00:00+01:00",
            "occurred_at": None, "message": "A test-only observable event",
        }
        self.batch = {"schema_version": 1, "events": [self.event]}

    def provision(self):
        initialize_credentials(self.credentials, "my-collector")
        register_collector(self.database, read_credentials(self.credentials))
        return read_credentials(self.credentials)["token"]

    def assert_no_events(self):
        with open_inbox(self.database, readonly=True) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)

    def post(self, token, batch=None, **extra):
        return self.client.post("/api/v1/events/", data=json.dumps(batch or self.batch),
                                content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {token}", **extra)

    def test_empty_inbox_creates_no_files(self):
        response = self.client.get("/receiver/")
        self.assertContains(response, "No events received yet")
        self.assertContains(response, "Receiver not configured")
        self.assertContains(response, "Wazuh forwarding is not connected yet")
        self.assertFalse(self.database.parent.exists())

    def test_setup_private_no_token_printed_and_no_overwrite(self):
        output = StringIO()
        call_command("init_receiver", collector_id="linux-pc", stdout=output)
        original = read_credentials(self.credentials)
        self.assertNotIn(original["token"], output.getvalue())
        self.assertEqual(self.credentials.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.database.parent.stat().st_mode & 0o777, 0o700)
        with self.assertRaises(CommandError):
            call_command("init_receiver", collector_id="replacement", stdout=output)
        self.assertEqual(read_credentials(self.credentials), original)

    def test_unauthenticated_requests_cannot_write_and_cookie_is_not_auth(self):
        self.provision()
        self.client.cookies["sessionid"] = "fake-session"
        for token in ("", "incorrect", "x" * 1000):
            response = self.post(token)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.headers["WWW-Authenticate"], "Bearer")
        self.assert_no_events()

    def test_unconfigured_receiver_fails_closed(self):
        self.assertEqual(self.post("some-token").status_code, 503)
        self.assertFalse(self.database.exists())

    def test_accepts_then_deduplicates_and_identity_is_server_assigned(self):
        token = self.provision()
        response = self.post(token)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["accepted"], 1)
        retry = self.post(token)
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(retry.json()["duplicates"], 1)
        with open_inbox(self.database, readonly=True) as db:
            records = db.execute("SELECT * FROM events").fetchall()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["collector_id"], "my-collector")
        data = json.loads(records[0]["payload"])
        self.assertEqual(data["observed_at"], "2026-11-04T11:00:00+00:00")
        self.assertIsNone(data["occurred_at"])
        self.assertIn("no-store", response.headers["Cache-Control"])
        self.assertFalse(self.collection.exists())

    def test_different_payload_same_id_rolls_back_whole_batch(self):
        token = self.provision()
        self.post(token)
        changed = {**self.event, "message": "changed"}
        new = {**self.event, "event_id": str(uuid.uuid4())}
        response = self.post(token, {"schema_version": 1, "events": [new, changed]})
        self.assertEqual(response.status_code, 409)
        with open_inbox(self.database, readonly=True) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)

    def test_bad_batches_rejected_without_creating_storage(self):
        token = self.provision()
        cases = [
            {"schema_version": 2, "events": [self.event]},
            {"schema_version": 1, "events": []},
            {"schema_version": 1, "events": [self.event, self.event]},
            {"schema_version": 1, "events": [{**self.event, "event_id": str(uuid.uuid4())} for _ in range(101)]},
            {**self.batch, "collector_id": "forged-device"},
        ]
        for field, value in (
            ("event_id", "invalid"), ("platform", "unknown"), ("source", "../secret"),
            ("event_type", "foo\nbar"), ("observed_at", "2026-11-04T12:00:00"),
            ("occurred_at", "not-a-date"), ("message", "x" * 8193),
            ("message", "\ud800"), ("path", "/etc/passwd"),
            ("received_at", "2026-11-04T00:00:00Z"),
        ):
            cases.append({"schema_version": 1, "events": [{**self.event, field: value}]})
        for batch in cases:
            with self.subTest(batch=str(batch)[:150]):
                self.assertEqual(self.post(token, batch).status_code, 400)
        self.assert_no_events()

    def test_body_size_json_and_content_type_limits(self):
        token = self.provision()
        for body, content_type, code in (
            ("{" + " " * MAX_BODY_BYTES, "application/json", 413),
            ("{", "application/json", 400),
            ("[" * 2000 + "0" + "]" * 2000, "application/json", 400),
            (json.dumps(self.batch), "text/plain", 415),
        ):
            response = self.client.post("/api/v1/events/", body, content_type=content_type,
                                        HTTP_AUTHORIZATION=f"Bearer {token}")
            self.assertEqual(response.status_code, code)
        self.assert_no_events()

    def test_cleartext_remote_blocked_https_allowed_and_proxy_header_not_trusted(self):
        token = self.provision()
        for extra in ({}, {"HTTP_X_FORWARDED_PROTO": "https"}):
            response = self.post(token, REMOTE_ADDR="192.0.2.3", **extra)
            self.assertEqual(response.status_code, 403)
        self.assert_no_events()
        self.assertEqual(self.post(token, REMOTE_ADDR="192.0.2.3", secure=True).status_code, 201)

    def test_methods_host_and_query_parameters(self):
        token = self.provision()
        self.assertEqual(self.client.get("/api/v1/events/", HTTP_AUTHORIZATION=f"Bearer {token}").status_code, 405)
        self.assertEqual(self.post(token, HTTP_HOST="unexpected.example").status_code, 400)
        self.assertEqual(self.client.post("/receiver/").status_code, 403)  # CSRF-protected page.
        response = self.client.post("/api/v1/events/?token=" + token, data=json.dumps(self.batch), content_type="application/json")
        self.assertEqual(response.status_code, 401)
        self.assert_no_events()

    def test_inbox_escapes_evidence_and_shows_wat_without_credentials(self):
        token = self.provision()
        self.event["message"] = "<script>alert(1)</script>\x1b[31m"
        self.post(token)
        response = self.client.get("/receiver/")
        self.assertContains(response, "&lt;script&gt;")
        self.assertNotContains(response, "<script>")
        self.assertContains(response, "\\x1b")
        self.assertContains(response, "4 Nov 2026, 12:00:00 PM WAT")
        self.assertContains(response, "Not available")
        self.assertNotContains(response, token)
        self.assertContains(response, "my-collector")
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_storage_errors_generic_and_retry_can_succeed(self):
        token = self.provision()
        with patch("receiver.views.save_batch", side_effect=sqlite3.OperationalError("/secret/path")):
            with self.assertLogs("receiver.views", level="ERROR"):
                response = self.post(token)
        self.assertEqual(response.status_code, 503)
        self.assertNotContains(response, "/secret/path", status_code=503)
        self.assertEqual(self.post(token).status_code, 201)

    def test_storage_refuses_links_or_public_credentials(self):
        token = self.provision()
        target = self.root / "untouched"
        target.write_text("private evidence")
        self.database.unlink()
        self.database.symlink_to(target)
        self.assertEqual(self.post(token).status_code, 503)
        self.assertEqual(target.read_text(), "private evidence")
        self.credentials.chmod(0o644)
        with self.assertRaises(ValueError):
            read_credentials(self.credentials)

    def test_full_inbox_allows_duplicate_retry_but_no_partial_new_batch(self):
        token = self.provision()
        with patch("receiver.storage.MAX_EVENTS", 1):
            self.assertEqual(self.post(token).status_code, 201)
            self.assertEqual(self.post(token).status_code, 200)
            self.event["event_id"] = str(uuid.uuid4())
            self.assertEqual(self.post(token).status_code, 507)

    def test_concurrent_retries_create_one_record(self):
        self.provision()
        with ThreadPoolExecutor(max_workers=4) as pool:
            outcomes = list(pool.map(lambda _: save_batch(self.database, "my-collector", [self.event]), range(4)))
        self.assertEqual(sum(item["accepted"] for item in outcomes), 1)
        self.assertEqual(sum(item["duplicates"] for item in outcomes), 3)

    def add_collected(self):
        path = self.root / "service.log"
        path.write_text("service started\nservice stopped\n")
        with open_store(self.collection) as db:
            source_id = register_source(db, Source("local-service", path, "text", 2026))
            collect_source(db, source_id)

    def test_saved_collector_records_reach_api_with_stable_ids_and_cursor(self):
        token = self.provision()
        self.add_collected()
        credentials = read_credentials(self.credentials)
        batch, cursor = collected_batch(self.collection, credentials, "local-service", limit=1)
        repeated, _ = collected_batch(self.collection, credentials, "local-service", limit=1)
        self.assertEqual(batch, repeated)
        self.assertEqual(batch["events"][0]["message"], "service started")
        self.assertIsNone(batch["events"][0]["occurred_at"])
        self.assertEqual(self.post(token, batch).status_code, 201)
        next_batch, next_cursor = collected_batch(self.collection, credentials, "local-service", after_record=cursor)
        self.assertEqual(next_batch["events"][0]["message"], "service stopped")
        self.assertGreater(next_cursor, cursor)
        with open_store(self.collection, readonly=True) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM records").fetchone()[0], 2)

    def test_manual_sender_uses_saved_data_and_never_prints_token(self):
        token = self.provision()
        self.add_collected()
        def submit(endpoint, secret, batch):
            self.assertEqual(secret, token)
            return self.post(secret, batch).json()
        output = StringIO()
        with patch("receiver.management.commands.send_collected_events.deliver", side_effect=submit):
            call_command("send_collected_events", source="local-service", limit=1, stdout=output)
        self.assertIn("Stored: 1", output.getvalue())
        self.assertIn("--after-record", output.getvalue())
        self.assertNotIn(token, output.getvalue())

    def test_sender_preserves_direct_ssh_observation_without_inventing_event_time(self):
        self.provision()
        path = self.root / "observed.jsonl"
        path.write_text(json.dumps({
            "version": 1, "observed_at": "2026-11-04T09:00:00+00:00", "hostname": "localhost",
            "message": "Accepted publickey for alice from 127.0.0.1 port 12345 ssh2",
        }) + "\n")
        with open_store(self.collection) as db:
            source_id = register_source(db, Source("local-ssh", path, "sshd_capture", 2026))
            collect_source(db, source_id)
        batch, _ = collected_batch(self.collection, read_credentials(self.credentials), "local-ssh")
        self.assertEqual(batch["events"][0]["observed_at"], "2026-11-04T09:00:00+00:00")
        self.assertIsNone(batch["events"][0]["occurred_at"])

    def test_sender_restricts_destination_and_redirects(self):
        self.assertEqual(validate_endpoint("http://127.0.0.1:8000/api/v1/events/"), "http://127.0.0.1:8000/api/v1/events/")
        self.assertEqual(validate_endpoint("https://receiver.example/api/v1/events/"), "https://receiver.example/api/v1/events/")
        for url in ("http://192.0.2.1/api/v1/events/", "file:///tmp/file", "https://a:b@receiver.example/api/v1/events/", "https://receiver.example/wrong", "http://localhost:8000/api/v1/events/"):
            with self.assertRaises(DeliveryError):
                validate_endpoint(url)
        self.assertIsNone(NoRedirects().redirect_request(None, None, 302, "", {}, "https://other.example"))

    def test_sender_refuses_errors_and_invalid_acknowledgements(self):
        for side_effect in (OSError("secret"), HTTPError("https://receiver.example", 503, "failed", {}, None)):
            with patch("receiver.sending.build_opener") as factory:
                factory.return_value.open.side_effect = side_effect
                with self.assertRaises(DeliveryError):
                    deliver("http://127.0.0.1/api/v1/events/", "secret", self.batch)
        with patch("receiver.sending.build_opener") as factory:
            response = factory.return_value.open.return_value.__enter__.return_value
            response.status = 201
            response.read.return_value = b'{"status":"stored","schema_version":1,"accepted":0,"duplicates":0}'
            with self.assertRaises(DeliveryError):
                deliver("http://127.0.0.1/api/v1/events/", "secret", self.batch)
