"""Real HTTPS transport with isolated credentials and a temporary certificate."""

import json
from pathlib import Path
import shutil
import ssl
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
from unittest import skipUnless
import uuid
from wsgiref.simple_server import WSGIRequestHandler, make_server

from django.core.wsgi import get_wsgi_application
from django.test import SimpleTestCase, override_settings

from .sending import DeliveryError, deliver, heartbeat
from .storage import initialize_credentials, open_inbox, read_credentials, register_collector


class TLSHandler(WSGIRequestHandler):
    def get_environ(self):
        environ = super().get_environ()
        environ["wsgi.url_scheme"] = "https"
        return environ

    def log_message(self, format, *args):
        pass


@skipUnless(shutil.which("openssl"), "openssl is needed for the real TLS check")
@override_settings(ALLOWED_HOSTS=["127.0.0.1", "localhost"])
class HTTPSTests(SimpleTestCase):
    def test_certificate_validation_delivery_retry_and_heartbeat(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            certificate, key = root / "certificate.pem", root / "key.pem"
            result = subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-keyout", str(key), "-out", str(certificate), "-subj", "/CN=127.0.0.1",
                "-addext", "subjectAltName=IP:127.0.0.1",
            ], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0)
            path = root / "private" / "credentials.json"
            database = root / "private" / "events.sqlite3"
            initialize_credentials(path, "tls-test")
            credentials = read_credentials(path)
            register_collector(database, credentials)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            server = make_server("127.0.0.1", 0, get_wsgi_application(), handler_class=TLSHandler)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = Thread(target=server.serve_forever, daemon=True)
            with override_settings(LOGSENTRY_RECEIVER_DATABASE=database):
                thread.start()
                try:
                    endpoint = f"https://127.0.0.1:{server.server_port}/api/v1/events/"
                    batch = {"schema_version": 1, "events": [{
                        "event_id": str(uuid.uuid4()), "platform": "linux", "source": "isolated-tls-test",
                        "event_type": "raw_text", "observed_at": "2026-11-04T12:00:00Z",
                        "message": "Test evidence never enters the normal inbox.",
                    }]}
                    with self.assertRaises(DeliveryError):
                        deliver(endpoint, credentials["token"], batch)
                    with self.assertRaises(DeliveryError):
                        deliver(endpoint.replace("127.0.0.1", "localhost"), credentials["token"], batch, ca_file=certificate)
                    self.assertEqual(deliver(endpoint, credentials["token"], batch, ca_file=certificate)["accepted"], 1)
                    self.assertEqual(deliver(endpoint, credentials["token"], batch, ca_file=certificate)["duplicates"], 1)
                    heartbeat(endpoint, credentials["token"], 0, "", ca_file=certificate)
                    with open_inbox(database, readonly=True) as db:
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)
                        self.assertEqual(db.execute("SELECT pending FROM collectors").fetchone()[0], 0)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)
