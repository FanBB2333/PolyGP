import socket
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "autologin"))
import gp_saml_login as gp


SUCCESS_XML = b"""\
<response>
  <status>Success</status>
  <saml-auth-method>REDIRECT</saml-auth-method>
  <saml-request>aHR0cHM6Ly9hZGZzLmV4YW1wbGUv</saml-request>
</response>
"""


class Response:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


class PreloginRetryTests(unittest.TestCase):
    def test_retries_temporary_dns_failure_then_succeeds(self):
        opener = mock.Mock()
        opener.open.side_effect = [
            urllib.error.URLError(
                socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")
            ),
            urllib.error.URLError(
                socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")
            ),
            Response(SUCCESS_XML),
        ]
        messages = []

        with mock.patch.object(gp.urllib.request, "build_opener", return_value=opener), \
             mock.patch.object(gp.time, "sleep") as sleep:
            result = gp.prelogin("researchvpn.polyu.edu.hk", True, log=messages.append)

        self.assertEqual(result, ("REDIRECT", "https://adfs.example/"))
        self.assertEqual(opener.open.call_count, 3)
        self.assertEqual(sleep.call_args_list, [mock.call(1.0), mock.call(2.0)])
        self.assertIn("attempt 1/5", messages[0])
        self.assertIn("attempt 2/5", messages[1])

    def test_does_not_retry_permanent_dns_failure(self):
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.URLError(
            socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        )

        with mock.patch.object(gp.urllib.request, "build_opener", return_value=opener), \
             mock.patch.object(gp.time, "sleep") as sleep, \
             self.assertRaises(SystemExit):
            gp.prelogin("bad.invalid", True)

        self.assertEqual(opener.open.call_count, 1)
        sleep.assert_not_called()

    def test_stops_retrying_when_cancelled(self):
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.URLError(
            socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")
        )
        cancelled = mock.Mock(side_effect=[False, True])

        with mock.patch.object(gp.urllib.request, "build_opener", return_value=opener), \
             self.assertRaisesRegex(SystemExit, "prelogin cancelled"):
            gp.prelogin("researchvpn.polyu.edu.hk", True, retry_delay=0,
                        log=lambda _message: None, cancelled=cancelled)

        self.assertEqual(opener.open.call_count, 1)


if __name__ == "__main__":
    unittest.main()
