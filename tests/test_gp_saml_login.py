import socket
import sys
import types
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


class VncScreenTests(unittest.TestCase):
    def test_parses_xvfb_size_and_ignores_depth(self):
        self.assertEqual(gp.vnc_screen_size("1600x900x24"), (1600, 900))
        self.assertEqual(gp.vnc_screen_size(" 1366X768 "), (1366, 768))

    def test_invalid_or_tiny_size_uses_default(self):
        self.assertEqual(gp.vnc_screen_size("not-a-size"), gp.DEFAULT_VNC_SCREEN)
        self.assertEqual(gp.vnc_screen_size("100x100x24"), gp.DEFAULT_VNC_SCREEN)


class ClickGateTests(unittest.TestCase):
    def test_click_hook_accepts_only_trusted_window_input(self):
        self.assertIn("event.isTrusted !== true", gp.USER_CLICK_INIT_SCRIPT)
        self.assertIn('window.addEventListener("pointerdown"', gp.USER_CLICK_INIT_SCRIPT)
        self.assertNotIn('document.addEventListener("pointerdown"', gp.USER_CLICK_INIT_SCRIPT)

    def test_user_clicked_consumes_flag_from_a_frame(self):
        class Frame:
            def __init__(self):
                self.clicked = True

            def evaluate(self, script):
                if "=== true" in script:
                    clicked, self.clicked = self.clicked, False
                    return clicked
                return None

        frame = Frame()
        page = types.SimpleNamespace(frames=[frame])

        self.assertTrue(gp._user_clicked(page))
        self.assertFalse(frame.clicked)
        self.assertFalse(gp._user_clicked(page))

    def test_auto_fill_waits_for_a_trusted_browser_click(self):
        class Response:
            url = "https://adfs.example/"
            headers = {gp.H_COOKIE: "cookie", gp.H_USER: "user"}

        class Page:
            def __init__(self):
                self.frames = []
                self.response_handler = None
                self.waits = 0
                self.url = "https://adfs.example/"
                self.evaluated_scripts = []

            def set_content(self, _entry):
                pass

            def add_init_script(self, _script):
                pass

            def evaluate(self, script):
                self.evaluated_scripts.append(script)

            def on(self, event, handler):
                if event == "response":
                    self.response_handler = handler

            def wait_for_timeout(self, _milliseconds):
                self.waits += 1
                if self.waits == 8:
                    self.response_handler(Response())

        class Context:
            def __init__(self, page):
                self.page = page
                self.init_scripts = []

            def add_init_script(self, script):
                self.init_scripts.append(script)

            def new_page(self):
                return self.page

        class Browser:
            def __init__(self, context):
                self.context = context
                self.closed = False

            def new_context(self, **_kwargs):
                return self.context

            def close(self):
                self.closed = True

        page = Page()
        context = Context(page)
        browser = Browser(context)

        class Playwright:
            def __init__(self):
                self.chromium = types.SimpleNamespace(
                    launch=lambda **_kwargs: browser)

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        fake_sync = types.ModuleType("playwright.sync_api")
        fake_sync.sync_playwright = lambda: Playwright()
        fake_playwright = types.ModuleType("playwright")
        fake_playwright.sync_api = fake_sync
        clicks = []

        def user_clicked(_page):
            clicks.append(True)
            return len(clicks) >= 3

        with mock.patch.dict(sys.modules, {
            "playwright": fake_playwright,
            "playwright.sync_api": fake_sync,
        }), mock.patch.object(gp, "_user_clicked", side_effect=user_clicked), \
                mock.patch.object(gp, "_prefill", return_value=True) as prefill:
            got = gp.browser_login("<html></html>", "POST", 2, False, None,
                                   "auto")

        self.assertEqual(got[gp.H_COOKIE], "cookie")
        prefill.assert_called_once()
        self.assertGreaterEqual(len(clicks), 3)
        self.assertEqual(context.init_scripts, [gp.USER_CLICK_INIT_SCRIPT])
        self.assertEqual(page.evaluated_scripts, [gp.USER_CLICK_INIT_SCRIPT])
        self.assertTrue(browser.closed)

if __name__ == "__main__":
    unittest.main()
