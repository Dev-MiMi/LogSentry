"""Milestone 4: meaningful boundaries, evidence preservation and investigation."""

from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase as UnitTestCase
from unittest.mock import patch
from xml.etree import ElementTree

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from deploy.wazuh.test_rules import document, run_scenario, scenarios
from .storage import open_inbox, save_batch
from .wazuh_alerts import verified_alert
from .wazuh_export import ExportError, event_document, export_lock, export_once, open_state, verify_archive
from .wazuh_fields import ssh_fields
from .wazuh_rules import RULES


class WazuhFieldsTests(UnitTestCase):
    def test_syslog_and_direct_capture(self):
        event = document()["logsentry"]
        parsed = event["ssh"]
        self.assertEqual((parsed["hostname"], parsed["username"], parsed["source_ip"]),
                         ("test-host", "alice", "192.0.2.10"))
        raw = {**event, "source": "local-ssh", "occurred_at": None,
               "message": "Accepted publickey for root from ::ffff:127.0.0.1 port 45678 ssh2",
               "event_type": "successful_login"}
        actual = ssh_fields(raw)
        self.assertEqual((actual["kind"], actual["source_ip"], actual["time_basis"]),
                         ("successful_login", "127.0.0.1", "observed_at"))
        self.assertEqual(raw["message"], "Accepted publickey for root from ::ffff:127.0.0.1 port 45678 ssh2")
        self.assertIsNone(ssh_fields({**raw, "source": "other-app"}))

    def test_classification_and_format_cannot_forge_ssh(self):
        event = document()["logsentry"]
        for changes in (
            {"platform": "android"}, {"event_type": "notification"},
            {"event_type": "successful_login"},
            {"message": event["message"].replace("sshd[10]", "myapp")},
            {"message": event["message"] + "\nAccepted publickey for root"},
            {"message": event["message"].replace("192.0.2.10", "not-an-ip")},
            {"message": event["message"].replace("44000", "99999")},
            {"message": event["message"].replace("Failed password", "Accepted key")},
            {"message": event["message"] + "\x1b[31m"},
            {"message": "x" * 8193}, {"occurred_at": "2026-11-06T14:00:00"},
        ):
            with self.subTest(changes=changes):
                self.assertIsNone(ssh_fields({**event, **changes}))

    def test_scope_keys_and_ip_normalization(self):
        baseline = document()["logsentry"]["ssh"]
        for changes in ({"collector": "other"}, {"host": "other"}, {"source": "other"}, {"ip": "192.0.2.11"}):
            other = document(**changes)["logsentry"]["ssh"]
            self.assertNotEqual(baseline["source_key"], other["source_key"])
            self.assertNotEqual(baseline["account_key"], other["account_key"])
        user = document(user="other")["logsentry"]["ssh"]
        self.assertEqual(baseline["source_key"], user["source_key"])
        self.assertNotEqual(baseline["account_key"], user["account_key"])
        self.assertEqual(baseline["source_key"], document(ip="::ffff:192.0.2.10")["logsentry"]["ssh"]["source_key"])

    def test_rules_catalogue_and_structure(self):
        root = ElementTree.parse(Path(__file__).resolve().parents[1] / "deploy/wazuh/logsentry_rules.xml")
        rules = {rule.attrib["id"]: rule for rule in root.findall("rule")}
        self.assertEqual(len(root.findall("rule")), len(rules))
        self.assertEqual(set(rules), set(RULES))
        for key, rule in rules.items():
            self.assertEqual(int(rule.attrib["level"]), RULES[key][0])
            for parent in (rule.findtext("if_sid"), rule.findtext("if_matched_sid")):
                if parent:
                    self.assertIn(parent, rules)
        for key in ("110020", "110021"):
            self.assertEqual(rules[key].findtext("same_field"), "logsentry.ssh.source_key")
            self.assertEqual(rules[key].findtext("different_field"), "logsentry.event_id")
        self.assertEqual(rules["110022"].findtext("same_field"), "logsentry.ssh.account_key")

    def test_logtest_runner_rejects_missing_phases_and_errors(self):
        from subprocess import CompletedProcess
        good = "**Phase 3: Completed filtering (rules).\n id: '110010'\n level: '5'\n"
        with patch("deploy.wazuh.test_rules.subprocess.run", return_value=CompletedProcess([], 0, good, "")):
            run_scenario("unused", [document()], ["110010"])
            with self.assertRaises(RuntimeError):
                run_scenario("unused", [document(), document()], ["110010", "110010"])
        with patch("deploy.wazuh.test_rules.subprocess.run", return_value=CompletedProcess([], 0, good, "ERROR loading rules")):
            with self.assertRaises(RuntimeError):
                run_scenario("unused", [document()], ["110010"])
        self.assertGreaterEqual(len(list(scenarios())), 20)


@override_settings(ALLOWED_HOSTS=["testserver"])
class WazuhInvestigationTests(TestCase):
    def setUp(self):
        folder = TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.inbox = self.root / "receiver/events.sqlite3"
        self.export = self.root / "wazuh"
        options = override_settings(LOGSENTRY_RECEIVER_DATABASE=self.inbox,
                                    LOGSENTRY_WAZUH_DIRECTORY=self.export)
        options.enable()
        self.addCleanup(options.disable)
        self.client.force_login(get_user_model().objects.create_user("investigator"))
        base = document()["logsentry"]
        self.event = {key: base[key] for key in ("event_id", "platform", "source", "event_type", "occurred_at", "observed_at", "message")}
        save_batch(self.inbox, "test-pc", [self.event])
        with open_inbox(self.inbox, readonly=True) as db:
            self.row = db.execute("SELECT * FROM events").fetchone()

    def export_event(self):
        with export_lock(self.export), open_state(self.export) as db:
            export_once(db, self.export, self.inbox)

    def alert(self, doc=None):
        return {"decoder": {"name": "json"}, "manager": {"name": "test-only"},
                "rule": {"id": "110010", "level": 5},
                "full_log": json.dumps(doc or event_document(self.row))}

    def test_enrichment_preserves_original_evidence_and_old_exports_verify(self):
        self.export_event()
        payload = event_document(self.row)
        self.assertEqual(payload["logsentry"]["message"], self.event["message"])
        self.assertEqual(payload["logsentry"]["payload_sha256"], self.row["payload_hash"])
        archive = self.root / "archive.json"
        archive.write_text(json.dumps(self.alert(event_document(self.row, enriched=False))) + "\n")
        verify_archive(self.export, self.inbox, archive, 1)
        original = (self.export / "events.jsonl").read_bytes()
        self.export_event()
        self.assertEqual((self.export / "events.jsonl").read_bytes(), original)

    def test_exact_alert_verification_rejects_wrong_content_rule_and_level(self):
        self.export_event()
        alerts = self.root / "alerts.json"
        altered = deepcopy(event_document(self.row))
        altered["logsentry"]["message"] = "changed"
        for entry in (
            self.alert(altered), {**self.alert(), "rule": {"id": "999999", "level": 5}},
            {**self.alert(), "rule": {"id": "110010", "level": 10}},
            {**self.alert(), "manager": {}}, {**self.alert(), "decoder": {"name": "other"}},
        ):
            alerts.write_text(json.dumps(entry) + "\n")
            with self.assertRaises(ExportError):
                verified_alert(self.export, self.inbox, alerts, 1)
        alerts.write_text('null\n{"rule":null}\n' + json.dumps(self.alert()) + "\n")
        result = verified_alert(self.export, self.inbox, alerts, 1)
        self.assertTrue(result["manager_alert_verified"])
        self.assertFalse(result["dashboard_indexing_verified"])
        self.assertNotIn("message", result)
        out = StringIO()
        call_command("verify_wazuh_alert", alerts=alerts, record_id=1, stdout=out)
        self.assertEqual(json.loads(out.getvalue())["rule_id"], "110010")
        with self.assertRaises(CommandError):
            call_command("verify_wazuh_alert", alerts=alerts, record_id=2, stdout=StringIO())
        link = self.root / "linked.json"
        link.symlink_to(alerts)
        with self.assertRaises(OSError):
            verified_alert(self.export, self.inbox, link, 1)

    def test_investigation_authentication_privacy_and_wat(self):
        response = self.client.get("/receiver/events/1/")
        self.assertContains(response, "192.0.2.10")
        self.assertContains(response, "6 Nov 2026, 3:00:00 PM WAT")
        self.assertContains(response, "Guidance, not confirmed Wazuh alerts")
        self.assertContains(response, self.event["event_id"])
        self.assertIn("no-store", response.headers["Cache-Control"])
        self.assertEqual(self.client.get("/receiver/events/999999/").status_code, 404)
        self.assertEqual(self.client.get("/receiver/wazuh-rules/").status_code, 200)
        self.client.logout()
        self.assertEqual(self.client.get("/receiver/events/1/").status_code, 302)
        self.assertEqual(self.client.get("/receiver/wazuh-rules/").status_code, 302)

    def test_investigation_escapes_evidence_and_read_only(self):
        event = {**self.event, "event_id": "7254b00e-e6a7-4d6b-b313-f19628632b41", "message": "<script>alert(1)</script>\x1b[31m"}
        save_batch(self.inbox, "test-pc", [event])
        response = self.client.get("/receiver/events/2/")
        self.assertContains(response, "&lt;script&gt;")
        self.assertNotContains(response, "<script>")
        self.assertContains(response, "\\x1b")
        self.assertFalse(self.export.exists())
        with patch("receiver.views.open_inbox", side_effect=ValueError("private details")):
            failed = self.client.get("/receiver/events/1/")
        self.assertEqual(failed.status_code, 503)
        self.assertNotContains(failed, "private details", status_code=503)
