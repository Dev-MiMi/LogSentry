"""HTTP checks for real local collection, using an isolated temporary store."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from django.urls import reverse

from logsentry.collection_sources import Source
from logsentry.collection_store import open_store
from logsentry.collector import collect_source, register_source


FAILURE = "2026-11-01T12:00:00+00:00 ubuntu sshd[12]: Failed password for alice from 203.0.113.8 port 2222 ssh2\n"


@override_settings(ALLOWED_HOSTS=["testserver"])
class CollectedPagesTests(SimpleTestCase):
    def setUp(self):
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.database = self.root / "private" / "collection.sqlite3"
        override = override_settings(LOGSENTRY_COLLECTION_DATABASE=self.database)
        override.enable()
        self.addCleanup(override.disable)

    def add_source(self, text=FAILURE * 5, name="ubuntu-auth", format_name="syslog"):
        path = self.root / (name + ".log")
        path.write_text(text)
        with open_store(self.database) as db:
            source_id = register_source(db, Source(name, path, format_name, 2026))
            collect_source(db, source_id)
        return source_id, path

    def source_url(self, source_id):
        return reverse("dashboard:collected_source", args=[source_id])

    def test_empty_collection_page_does_not_create_database(self):
        response = self.client.get("/collected/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No collected sources yet")
        self.assertNotContains(response, "Fictional sample data")
        self.assertFalse(self.database.parent.exists())

    def test_saved_events_generate_findings_with_correct_source_and_evidence(self):
        source_id, path = self.add_source()
        # Removing the source proves HTTP uses saved records rather than rereading
        # a user-selected file. Collection failures are handled by the collector.
        path.unlink()
        response = self.client.get(self.source_url(source_id))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["analysis"].alerts), 2)
        self.assertContains(response, "Possible brute-force attack")
        self.assertNotContains(response, "Sample workspace")
        self.assertContains(response, "ubuntu-auth")
        for finding in response.context["findings"]:
            url = reverse("dashboard:collected_alert", args=[source_id, finding["id"]])
            self.assertContains(response, url)
            detail = self.client.get(url)
            self.assertEqual(detail.status_code, 200)
            self.assertContains(detail, FAILURE.strip())
            self.assertEqual(len(detail.context["evidence"]), 5)

    def test_findings_are_isolated_between_sources(self):
        one, _ = self.add_source(FAILURE * 2, "one")
        two, _ = self.add_source(FAILURE * 2, "two")
        for source_id in (one, two):
            response = self.client.get(self.source_url(source_id))
            self.assertEqual(response.context["findings"], [])

    def test_raw_text_escaped_and_collection_time_not_claimed_as_event_time(self):
        source_id, _ = self.add_source('<script>alert("x")</script>\x1b[31m\n', "app", "text")
        response = self.client.get(self.source_url(source_id))
        self.assertContains(response, "&lt;script&gt;")
        self.assertNotContains(response, "<script>")
        self.assertNotContains(response, "\x1b")
        self.assertContains(response, "\\x1b")
        self.assertContains(response, "Not available")
        self.assertContains(response, "SSH login rules do not assess")

    def test_collection_error_parse_issue_rotation_and_retention_are_visible(self):
        source_id, path = self.add_source("broken syslog\n")
        with open_store(self.database) as db:
            with db:
                db.execute("UPDATE sources SET rotations=1, dropped=7 WHERE id=?", (source_id,))
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                collect_source(db, source_id)
        response = self.client.get(self.source_url(source_id))
        self.assertContains(response, "Collection paused")
        self.assertContains(response, "Partial parsing")
        self.assertContains(response, "Unrecognized log prefix")
        self.assertContains(response, "Retention removed 7")
        self.assertContains(response, "file replacement/truncation")

    def test_moved_finding_does_not_open_unrelated_evidence(self):
        source_id, path = self.add_source()
        response = self.client.get(self.source_url(source_id))
        finding = next(row for row in response.context["findings"] if row["alert"].rule == "repeated_failed_logins")
        url = reverse("dashboard:collected_alert", args=[source_id, finding["id"]])
        with path.open("a") as stream:
            stream.write(FAILURE)
        with open_store(self.database) as db:
            collect_source(db, source_id)
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_missing_sources_and_findings_are_404_and_methods_restricted(self):
        source_id, _ = self.add_source()
        urls = ("/collected/", self.source_url(source_id))
        for url in urls:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertIn("no-store", response.headers["Cache-Control"])
            self.assertEqual(response.headers["X-Frame-Options"], "DENY")
            self.assertEqual(self.client.head(url).status_code, 200)
            self.assertEqual(self.client.post(url).status_code, 405)
        self.assertEqual(self.client.get("/collected/999/").status_code, 404)
        self.assertEqual(self.client.get(f"/collected/{source_id}/alerts/not-found/").status_code, 404)

    def test_query_cannot_choose_collection_database_or_source_file(self):
        source_id, _ = self.add_source()
        with patch("dashboard.collected.open_store", wraps=open_store) as opened:
            response = self.client.get(self.source_url(source_id) + "?database=/etc/passwd&file=/etc/shadow")
        self.assertEqual(response.status_code, 200)
        opened.assert_called_once_with(self.database, readonly=True)

    def test_storage_error_is_generic_and_homepage_shows_collection_empty_state(self):
        with patch("dashboard.collected.open_store", side_effect=PermissionError("/private/secret")):
            with self.assertLogs("dashboard.collected", level="ERROR"):
                response = self.client.get("/collected/")
        self.assertEqual(response.status_code, 503)
        self.assertNotContains(response, "/private/secret", status_code=503)
        self.assertContains(response, "could not be loaded", status_code=503)
        homepage = self.client.get("/")
        self.assertEqual(homepage.status_code, 200)
        self.assertContains(homepage, "No collected sources yet")
        self.assertNotContains(homepage, "Sample workspace")

    def test_record_display_is_bounded_while_analysis_uses_retained_history(self):
        source_id, _ = self.add_source(FAILURE * 205)
        response = self.client.get(self.source_url(source_id))
        self.assertEqual(len(response.context["records"]), 200)
        self.assertEqual(len(response.context["analysis"].parsed.events), 205)

    def update(self, source_id=None, revision=""):
        url = self.source_url(source_id) if source_id else "/collected/"
        return self.client.get(url, {"revision": revision}, HTTP_X_LOGSENTRY_UPDATE="1")

    def test_update_after_append_includes_new_records_findings_and_escaped_text(self):
        source_id, path = self.add_source(FAILURE * 2)
        initial = self.update(source_id).json()
        self.assertNotIn("Repeated failed logins", initial["html"])
        with path.open("a") as stream:
            stream.write(FAILURE + "<script>alert('log')</script>\n")
        with open_store(self.database) as db:
            collect_source(db, source_id)
        response = self.update(source_id, initial["revision"])
        data = response.json()
        self.assertNotEqual(data["revision"], initial["revision"])
        self.assertIn("Repeated failed logins", data["html"])
        self.assertIn("&lt;script&gt;", data["html"])
        self.assertNotIn("<script>", data["html"])
        self.assertIn("4 shown / 4 retained", data["html"])
        self.assertNotIn("<html", data["html"])
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_unchanged_heartbeat_returns_state_without_reanalyzing_records(self):
        source_id, _ = self.add_source()
        page = self.client.get(self.source_url(source_id))
        revision = page.context["revision"]
        with open_store(self.database) as db:
            collect_source(db, source_id)  # Heartbeat changes, records do not.
        with patch("dashboard.collected.retained_records") as read_records, patch("dashboard.collected._analysis") as analyze:
            response = self.update(source_id, revision)
        read_records.assert_not_called()
        analyze.assert_not_called()
        self.assertIsNone(response.json()["html"])
        self.assertEqual(response.json()["revision"], revision)
        self.assertIn("Checked recently", response.json()["states"][0]["label"])

    def test_stopped_collector_and_recovery_update_state_without_new_events(self):
        source_id, _ = self.add_source()
        revision = self.update(source_id).json()["revision"]
        with open_store(self.database) as db:
            with db:
                db.execute("UPDATE sources SET last_checked='2000-01-01T00:00:00+00:00'")
        data = self.update(source_id, revision).json()
        self.assertIsNone(data["html"])
        self.assertTrue(data["states"][0]["attention"])
        self.assertIn("may be stopped", data["states"][0]["label"])
        with open_store(self.database) as db:
            collect_source(db, source_id)
        data = self.update(source_id, revision).json()
        self.assertFalse(data["states"][0]["attention"])

    def test_collection_error_and_recovery_invalidate_fragment_without_new_records(self):
        source_id, path = self.add_source()
        revision = self.update(source_id).json()["revision"]
        with open_store(self.database) as db:
            with patch("logsentry.collector.os.open", side_effect=PermissionError("denied")):
                with self.assertRaises(PermissionError):
                    collect_source(db, source_id)
        failed = self.update(source_id, revision).json()
        self.assertIn("Collection paused", failed["html"])
        self.assertTrue(failed["states"][0]["attention"])
        with open_store(self.database) as db:
            collect_source(db, source_id)
        recovered = self.update(source_id, failed["revision"]).json()
        self.assertNotIn("Collection paused", recovered["html"])
        self.assertFalse(recovered["states"][0]["attention"])

    def test_empty_page_discovers_newly_registered_source_on_update(self):
        initial = self.update().json()
        self.assertEqual(initial["states"], [])
        self.assertIn("No collected sources", initial["html"])
        self.add_source()
        data = self.update(revision=initial["revision"]).json()
        self.assertNotEqual(data["revision"], initial["revision"])
        self.assertIn("ubuntu-auth", data["html"])

    def test_update_errors_are_generic_json_and_methods_restricted(self):
        response = self.update(999)
        self.assertEqual(response.status_code, 404)
        self.assertIn("error", response.json())
        self.add_source()
        self.assertEqual(self.update(999).status_code, 404)
        with patch("dashboard.collected.open_store", side_effect=PermissionError("/secret/path")):
            with self.assertLogs("dashboard.collected", level="ERROR"):
                response = self.update()
        self.assertEqual(response.status_code, 503)
        self.assertNotContains(response, "/secret/path", status_code=503)
        self.assertIn("error", response.json())
        self.assertEqual(self.client.post("/collected/", HTTP_X_LOGSENTRY_UPDATE="1").status_code, 405)

    def test_page_offers_pause_and_local_script_but_evidence_stays_static(self):
        source_id, _ = self.add_source()
        response = self.client.get(self.source_url(source_id))
        self.assertContains(response, "Pause updates")
        self.assertContains(response, '/static/dashboard/collected.js')
        self.assertContains(response, 'data-revision="' + response.context["revision"] + '"')
        finding = response.context["findings"][0]
        evidence = self.client.get(reverse("dashboard:collected_alert", args=[source_id, finding["id"]]))
        self.assertNotContains(evidence, 'collected.js')
        self.assertContains(self.client.get("/"), 'collected.js')
