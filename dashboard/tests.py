"""The homepage uses only collected records, with no example-data fallback."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from django.urls import reverse

from logsentry.collection_sources import Source
from logsentry.collection_store import open_store
from logsentry.collector import collect_source, register_source


@override_settings(ALLOWED_HOSTS=["testserver", "localhost", "127.0.0.1"])
class DashboardTests(SimpleTestCase):
    def setUp(self):
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.database = self.root / "private" / "collection.sqlite3"
        override = override_settings(LOGSENTRY_COLLECTION_DATABASE=self.database)
        override.enable()
        self.addCleanup(override.disable)

    def register_log(self):
        path = self.root / "application.log"
        path.write_text("Application started\n")
        with open_store(self.database) as db:
            source_id = register_source(db, Source("my-system-log", path, "text", 2026))
            collect_source(db, source_id)
        return source_id

    def test_empty_homepage_has_no_fictional_records_or_alerts(self):
        # A file-analysis call here would reintroduce the deleted sample flow.
        with patch("logsentry.cli.analyze_log", side_effect=AssertionError("No sample reads")):
            response = self.client.get(reverse("dashboard:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/collected.html")
        self.assertContains(response, "No collected sources yet")
        self.assertNotContains(response, "Sample workspace")
        self.assertNotContains(response, "ubuntu-lab")
        self.assertNotContains(response, "Possible brute-force attack")
        self.assertEqual(response.context["sources"], [])
        self.assertFalse(self.database.parent.exists())

    def test_homepage_lists_only_registered_sources_with_working_record_links(self):
        source_id = self.register_log()
        response = self.client.get("/")
        self.assertEqual([source["name"] for source in response.context["sources"]], ["my-system-log"])
        self.assertEqual(response.context["sources"][0]["record_count"], 1)
        detail_url = reverse("dashboard:collected_source", args=[source_id])
        self.assertContains(response, detail_url)
        detail = self.client.get(detail_url)
        self.assertContains(detail, "Application started")
        self.assertContains(detail, "Collected system logs")
        self.assertContains(detail, "WAT (UTC+1)")

    def test_old_sample_alert_urls_are_removed(self):
        for url in ("/alerts/1/", "/alerts/6/"):
            self.assertEqual(self.client.get(url).status_code, 404)

    def test_homepage_live_update_and_existing_collected_link_share_saved_sources(self):
        initial = self.client.get("/", HTTP_X_LOGSENTRY_UPDATE="1").json()
        self.assertIn("No collected sources yet", initial["html"])
        self.register_log()
        home = self.client.get("/", {"revision": initial["revision"]}, HTTP_X_LOGSENTRY_UPDATE="1")
        existing = self.client.get("/collected/", HTTP_X_LOGSENTRY_UPDATE="1")
        self.assertEqual(home.json()["revision"], existing.json()["revision"])
        self.assertEqual(home.json()["html"], existing.json()["html"])
        self.assertIn("my-system-log", home.json()["html"])
        self.assertContains(self.client.get("/"), "/static/dashboard/collected.js")

    def test_homepage_failure_stays_visible_without_sample_fallback(self):
        with patch("dashboard.collected.open_store", side_effect=PermissionError("/secret/location")):
            with self.assertLogs("dashboard.collected", level="ERROR"):
                response = self.client.get("/")
        self.assertEqual(response.status_code, 503)
        self.assertContains(response, "Collected logs could not be loaded", status_code=503)
        self.assertNotContains(response, "/secret/location", status_code=503)
        self.assertNotContains(response, "Sample workspace", status_code=503)

    def test_request_cannot_choose_a_file_or_database(self):
        self.register_log()
        with patch("dashboard.collected.open_store", wraps=open_store) as opened:
            response = self.client.get("/?log_file=tests/fixtures/ssh_auth.log&database=/etc/passwd")
        self.assertEqual(response.status_code, 200)
        opened.assert_called_once_with(self.database, readonly=True)
        self.assertNotContains(response, "ubuntu-lab")

    def test_homepage_http_methods_security_headers_and_host_validation(self):
        response = self.client.get("/")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("no-store", response.headers["Cache-Control"])
        self.assertEqual(self.client.head("/").status_code, 200)
        self.assertEqual(self.client.post("/").status_code, 405)
        self.assertEqual(self.client.get("/", HTTP_HOST="unexpected.example").status_code, 400)

    def test_homepage_does_not_save_reports_or_mutate_the_store(self):
        self.register_log()
        before = self.database.read_bytes()
        with patch("logsentry.reporting.generate_incident_report") as save:
            self.client.get("/")
            self.client.get("/", HTTP_X_LOGSENTRY_UPDATE="1")
        save.assert_not_called()
        self.assertEqual(before, self.database.read_bytes())
