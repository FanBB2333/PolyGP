import http.client
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "hip"))
sys.path.insert(0, str(ROOT / "autologin"))
import hip_identity as hip
import control


class IdentityTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / "hipreport.conf"
        self.env = mock.patch.dict(os.environ, {"POLYGP_HIP_CONF": str(self.path)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.reference = (ROOT / "hip/hipreport.conf.example").read_text()
        self.original = hip.random_identity()
        self.path.write_text(hip.replace_identity(self.reference, self.original))

    def test_export_import_save_preserves_other_hip_settings_and_private_mode(self):
        before = hip.snapshot()
        candidate = hip.random_identity()
        imported = hip.import_identity(json.dumps(hip.document(candidate)))
        self.assertEqual(imported, candidate)
        after = hip.save(imported, before["revision"])
        self.assertEqual(after["identity"], candidate)
        self.assertEqual(hip.replace_identity(self.path.read_text(), self.original),
                         hip.replace_identity(self.reference, self.original))
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(hip.snapshot()["identity"], candidate)
        with self.assertRaisesRegex(ValueError, "changed elsewhere"):
            hip.save(self.original, before["revision"])
        self.assertEqual(hip.snapshot()["identity"], candidate)

    def test_conf_import_never_executes_input_or_imports_other_settings(self):
        marker = self.path.parent / "executed"
        content = hip.replace_identity(self.reference, self.original)
        content += f'OTHER="$(touch {marker})"\n'
        self.assertEqual(hip.import_identity(content), self.original)
        malicious = dict(self.original, HOST_NAME=f"$(touch {marker})")
        with self.assertRaises(ValueError):
            hip.import_identity(json.dumps(malicious))
        self.assertFalse(marker.exists())
        self.assertEqual(hip.snapshot()["identity"], self.original)

    def test_rejects_invalid_duplicates_oversize_and_example_values(self):
        for candidate in (
            dict(self.original, HOST_ID="bad"),
            dict(self.original, NIC_MAC="FF-FF-FF-FF-FF-FF"),
            dict(self.original, NIC_MAC="00-00-00-00-00-00"),
            dict(self.original, HOST_NAME="12345"),
            dict(self.original, HOST_ID="00000000-0000-0000-0000-000000000000"),
            dict(self.original, OTHER="unexpected"),
        ):
            with self.subTest(candidate=list(candidate)):
                with self.assertRaises(ValueError):
                    hip.validate(candidate)
        for content in ('{"HOST_NAME":"A","HOST_NAME":"B"}',
                        'HOST_NAME="A"\nHOST_NAME="B"', "x" * 65537,
                        json.dumps(dict(hip.document(self.original), version=2))):
            with self.assertRaises(ValueError):
                hip.import_identity(content)

    def test_missing_config_can_be_created_and_failed_write_keeps_existing(self):
        self.path.unlink()
        self.assertEqual(hip.snapshot()["revision"], "missing")
        hip.save(self.original, "missing")
        before = self.path.read_text()
        with mock.patch.object(hip.os, "replace", side_effect=OSError("read-only volume")):
            with self.assertRaises(OSError):
                hip.save(hip.random_identity(), hip.snapshot()["revision"])
        self.assertEqual(self.path.read_text(), before)
        self.assertEqual(list(self.path.parent.glob(".hip-*")), [])

    def test_generation_is_explicit_and_new_installations_get_distinct_identities(self):
        # The committed reference must not contain any usable identity. This
        # guard requires no knowledge of the maintainer's private values.
        reference_values = hip.parse_conf(self.reference)
        self.assertEqual(reference_values, dict.fromkeys(hip.KEYS, ""))
        with self.assertRaises(ValueError):
            hip.validate(reference_values)
        candidate = hip.random_identity()
        self.assertEqual(hip.validate(candidate), candidate)
        for key in hip.KEYS:
            self.assertNotEqual(candidate[key], self.original[key])
        self.assertEqual(hip.snapshot()["identity"], self.original)
        target = self.path.parent / "fresh" / "hipreport.conf"
        subprocess.run([sys.executable, str(ROOT / "hip/gen-hipreport-conf.py"), "--out", str(target)],
                       check=True, capture_output=True)
        generated = hip.validate(hip.parse_conf(target.read_text()))
        self.assertNotEqual(generated, self.original)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_session_identity_survives_default_edits_and_resume_and_wins_in_report(self):
        tunnel = control.Tunnel({"resume": False})
        session = {"cookie": "test"}
        environment = tunnel._hip_environment(session)
        candidate = hip.random_identity()
        hip.save(candidate, hip.snapshot()["revision"])
        resumed = control.Tunnel({"resume": False})
        resumed_env = resumed._hip_environment(json.loads(json.dumps(session)))
        for key in hip.KEYS:
            self.assertEqual(environment["POLYGP_SESSION_" + key], self.original[key])
            self.assertEqual(resumed_env["POLYGP_SESSION_" + key], self.original[key])
        new_env = tunnel._hip_environment({"cookie": "new-session"})
        self.assertEqual(new_env["POLYGP_SESSION_HOST_ID"], candidate["HOST_ID"])
        rendered = subprocess.run(["/bin/sh", str(ROOT / "hip/polyu-hipreport.sh"),
                                   "--host-id", candidate["HOST_ID"]], env=resumed_env,
                                  check=True, capture_output=True, text=True)
        report = ET.fromstring(rendered.stdout)
        self.assertEqual(report.findtext("host-id"), self.original["HOST_ID"])
        self.assertEqual(report.findtext("host-name"), self.original["HOST_NAME"])
        self.assertEqual(report.findtext(".//mac-address"), self.original["NIC_MAC"])
        self.path.unlink()
        failed = subprocess.run(["/bin/sh", str(ROOT / "hip/polyu-hipreport.sh")],
                                capture_output=True, text=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertNotIn("<hip-report>", failed.stdout)

    def test_authenticated_http_workflow_and_no_get_or_cross_origin_writes(self):
        tunnel = control.Tunnel({"resume": False})
        handler = type("HIPTestHandler", (control.Handler,), {"tunnel": tunnel, "token": "test-token"})
        server = control.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        def request(method, path, data=None, token="test-token", custom=True):
            connection = http.client.HTTPConnection(*server.server_address)
            try:
                headers = {"X-Token": token, "Content-Type": "application/x-www-form-urlencoded"}
                if custom:
                    headers["X-PolyGP-HIP"] = "1"
                connection.request(method, path, urlencode(data or {}), headers)
                response = connection.getresponse()
                body = response.read().decode()
                return response.status, json.loads(body) if body.startswith("{") else body
            finally:
                connection.close()
        self.assertEqual(request("GET", "/hip", token="wrong")[0], 403)
        self.assertEqual(request("GET", "/hip/generate")[0], 405)
        self.assertEqual(request("POST", "/hip/save", custom=False)[0], 403)
        _, saved = request("GET", "/hip")
        _, candidate = request("POST", "/hip/generate")
        self.assertEqual(hip.snapshot()["identity"], self.original)
        payload = {"content": json.dumps(hip.document(candidate["identity"]))}
        self.assertEqual(request("POST", "/hip/validate", payload)[0], 200)
        self.assertEqual(hip.snapshot()["identity"], self.original)
        payload["revision"] = saved["revision"]
        self.assertEqual(request("POST", "/hip/save", payload)[0], 200)
        self.assertEqual(request("POST", "/hip/save", payload)[0], 409)
        self.assertEqual(hip.snapshot()["identity"], candidate["identity"])


if __name__ == "__main__":
    unittest.main()
