import inspect
import socket
import sys
import time
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


class FakeInput:
    def __init__(self, visible=True, enabled=True, **attrs):
        self._visible, self._enabled, self._attrs = visible, enabled, attrs

    def is_visible(self):
        return self._visible

    def is_enabled(self):
        return self._enabled

    def get_attribute(self, name):
        return self._attrs.get(name)


def fake_page(*inputs):
    frame = types.SimpleNamespace(
        locator=lambda _selector: types.SimpleNamespace(all=lambda: list(inputs)))
    return types.SimpleNamespace(frames=[frame])


class CodePromptTests(unittest.TestCase):
    """The published prompt is what tells the panel the login has reached its
    MFA step, so it must not fire on the pages that come before it."""

    def test_credential_form_publishes_no_prompt(self):
        page = fake_page(
            FakeInput(id="userNameInput", name="UserName", placeholder="someone@example.com"),
            FakeInput(id="passwordInput", name="Password", placeholder="Password"))
        self.assertEqual(gp._find_code_input(page), (None, None, ""))

    def test_code_field_publishes_its_prompt(self):
        code = FakeInput(id="otpCode", name="otp", placeholder="Enter your code")
        _frame, loc, desc = gp._find_code_input(fake_page(code))
        self.assertIs(loc, code)
        self.assertEqual(desc, "Enter your code")

    def test_hidden_code_field_publishes_no_prompt(self):
        page = fake_page(FakeInput(visible=False, id="otpCode", placeholder="Enter your code"))
        self.assertEqual(gp._find_code_input(page), (None, None, ""))

    def test_credential_field_is_skipped_even_when_its_wording_matches(self):
        """ADFS labels its password field in the portal's own words, which can
        carry a term the code pattern also looks for. The field is identified
        by id, so such wording must not promote it to the MFA prompt."""
        page = fake_page(
            FakeInput(id="passwordInput", name="Password",
                      placeholder="NetPassword or passcode"),
            FakeInput(id="otpCode", placeholder="Enter your code"))
        _frame, _loc, desc = gp._find_code_input(page)
        self.assertEqual(desc, "Enter your code")


class FakeLocator:
    def __init__(self, items):
        self._items = list(items)

    def all(self):
        return list(self._items)

    def count(self):
        return len(self._items)

    @property
    def first(self):
        return self._items[0]


class FakeChoice:
    def __init__(self, text):
        self._text = text

    def is_visible(self):
        return True

    def inner_text(self):
        return self._text

    def get_attribute(self, _name):
        return None


class FakeFrame:
    def __init__(self, inputs=(), user_field=None, choices=()):
        self._inputs = list(inputs)
        self._user = user_field
        self._choices = [FakeChoice(t) for t in choices]

    def locator(self, selector):
        if selector == gp.SEL_USER:
            return FakeLocator([self._user] if self._user else [])
        if selector == "select option":
            return FakeLocator([])
        return FakeLocator(self._inputs)

    def get_by_role(self, _role):
        return FakeLocator(self._choices)


class StageTests(unittest.TestCase):
    """The published stage is what the panel's flow strip (and the /code
    gate) run on, so it must mirror what is actually on the page."""

    def _stage(self, frame):
        feed = gp.LoginFeed()
        gp._pump_feed(types.SimpleNamespace(frames=[frame]), feed,
                      lambda *_: None)
        return feed.snapshot()

    def test_credential_form_is_the_credentials_stage(self):
        snap = self._stage(FakeFrame(user_field=FakeInput(id="userNameInput")))
        self.assertEqual(snap["stage"], "credentials")

    def test_a_code_field_wins_over_a_lingering_credential_form(self):
        frame = FakeFrame(
            inputs=[FakeInput(id="otpCode", placeholder="Enter your code")],
            user_field=FakeInput(id="userNameInput"))
        snap = self._stage(frame)
        self.assertEqual(snap["stage"], "code")

    def test_a_choice_page_is_the_choice_stage(self):
        snap = self._stage(FakeFrame(choices=["PolyU Staff", "research"]))
        self.assertEqual(snap["stage"], "choice")
        self.assertIn("research", snap["choices"])

    def test_a_bare_page_reports_no_stage(self):
        self.assertEqual(self._stage(FakeFrame())["stage"], "")

    def test_discarding_the_attempt_resets_the_stage(self):
        feed = gp.LoginFeed()
        feed.set_stage("code")
        feed.discard_pending()
        self.assertEqual(feed.snapshot()["stage"], "")

    def test_services_survive_navigation_without_collecting_auth_buttons(self):
        remembered = mock.Mock()
        feed = gp.LoginFeed(on_service_options=remembered)
        for frame in (
            FakeFrame(user_field=FakeInput(id="userNameInput"), choices=["Sign in"]),
            FakeFrame(choices=["research", "PolyU Staff", "Back"]),
            FakeFrame(inputs=[FakeInput(id="otpCode")], choices=["Verify"]),
            FakeFrame(),
        ):
            gp._pump_feed(types.SimpleNamespace(frames=[frame]), feed, lambda *_: None)
        self.assertEqual(feed.snapshot()["service_options"], ["research", "PolyU Staff"])
        remembered.assert_called_once_with(["research", "PolyU Staff"])



class FakeError:
    def __init__(self, text, visible=True):
        self._text, self._visible = text, visible

    def is_visible(self):
        return self._visible

    def inner_text(self):
        return self._text


class CodeVerdictTests(unittest.TestCase):
    """After the panel's code is submitted, the box stays locked until the
    page gives a verdict: it moves on, shows an error, or goes quiet."""

    def _frame(self, code_field=True, errors=()):
        frame = FakeFrame(
            inputs=[FakeInput(id="otpCode", placeholder="Enter your code")]
                   if code_field else [])
        frame._errors = [FakeError(t) for t in errors]
        original = frame.locator

        def locator(selector):
            if selector in gp.ERROR_SELECTORS:
                return FakeLocator(frame._errors if selector == "[role=alert]" else [])
            return original(selector)
        frame.locator = locator
        return frame

    def _pump(self, feed, frame):
        gp._pump_feed(types.SimpleNamespace(frames=[frame]), feed, lambda *_: None)

    def test_offer_queues_and_submit_marks_in_flight(self):
        feed = gp.LoginFeed()
        feed.offer("123456")
        self.assertEqual(feed.snapshot()["code_state"], "queued")
        self.assertTrue(feed.code_busy())
        # Typing needs a submit control; the fake has none, so Enter is the
        # path — either way the code is marked as submitted.
        frame = self._frame()
        frame._inputs[0].fill = lambda _v: None
        frame._inputs[0].press = lambda _k: None
        self._pump(feed, frame)
        self.assertEqual(feed.snapshot()["code_state"], "submitting")
        self.assertTrue(feed.code_busy())

    def test_page_moving_on_settles_the_code(self):
        feed = gp.LoginFeed()
        feed.mark_submitted("")
        self._pump(feed, self._frame(code_field=False))
        self.assertEqual(feed.snapshot()["code_state"], "")
        self.assertFalse(feed.code_busy())

    def test_a_new_error_on_the_page_rejects_the_code(self):
        feed = gp.LoginFeed()
        feed.mark_submitted("")
        self._pump(feed, self._frame(errors=["Incorrect code. Try again."]))
        snap = feed.snapshot()
        self.assertEqual(snap["code_state"], "rejected")
        self.assertEqual(snap["code_note"], "Incorrect code. Try again.")
        self.assertFalse(feed.code_busy())

    def test_an_error_shown_before_the_submit_needs_time_to_count(self):
        feed = gp.LoginFeed()
        feed.mark_submitted("Incorrect code. Try again.")
        frame = self._frame(errors=["Incorrect code. Try again."])
        self._pump(feed, frame)
        self.assertEqual(feed.snapshot()["code_state"], "submitting")
        with mock.patch.object(gp.time, "time",
                               return_value=time.time() + gp.SAME_ERROR_AFTER + 1):
            self._pump(feed, frame)
        self.assertEqual(feed.snapshot()["code_state"], "rejected")

    def test_silence_eventually_unlocks_the_box(self):
        feed = gp.LoginFeed()
        feed.mark_submitted("")
        with mock.patch.object(gp.time, "time",
                               return_value=time.time() + gp.SUBMIT_TIMEOUT + 1):
            self._pump(feed, self._frame())
        snap = feed.snapshot()
        self.assertEqual(snap["code_state"], "stale")
        self.assertIn("no answer", snap["code_note"])
        self.assertFalse(feed.code_busy())

    def test_hidden_or_empty_error_elements_are_ignored(self):
        frame = self._frame(errors=[])
        frame._errors = [FakeError("Hidden", visible=False), FakeError("   ")]
        self.assertEqual(gp._visible_error_text(frame), "")


class LoginTimeoutTests(unittest.TestCase):
    def test_summary_names_the_step_the_page_stood_at(self):
        e = gp.LoginTimeout(1800, "credentials", "https://adfs.example/ls/?x", "Sign in")
        self.assertEqual(e.summary(), "login not finished within 30 min — "
                         "the sign-in page was still waiting for the NetID and password")
        self.assertEqual(gp.LoginTimeout(90, "code", "", "").summary(),
                         "login not finished within 90 s — the page was still waiting for the MFA code")
        self.assertIn("never handed over the login cookie", gp.LoginTimeout(60, "", "", "").summary())

    def test_cli_message_and_diagnostics_keep_the_page_dump(self):
        e = gp.LoginTimeout(1800, "credentials", "https://adfs.example/ls/?x", "Sign in / New Student")
        self.assertIsInstance(e, SystemExit)
        self.assertIn("stalled at: https://adfs.example/ls/?x", str(e))
        self.assertIn("--keep-open", str(e))
        self.assertEqual(e.diagnostics(), ["login timed out at https://adfs.example/ls/?x",
                                           "the page said: Sign in / New Student"])
        self.assertEqual(gp.LoginTimeout(60, "", "", "").diagnostics(), [])

    def test_browser_login_reports_the_stage_it_stood_at(self):
        class Page:
            frames = []
            url = "https://adfs.example/ls/"
            def set_content(self, _e): pass
            def add_init_script(self, _s): pass
            def evaluate(self, _s): pass
            def on(self, _ev, _h): pass
            def wait_for_timeout(self, _ms): pass
            def inner_text(self, _sel): return "Sign in\nNew Student"
        class Context:
            def add_init_script(self, _s): pass
            def new_page(self): return Page()
        class Browser:
            def new_context(self, **_k): return Context()
            def close(self): pass
        class Playwright:
            chromium = types.SimpleNamespace(launch=lambda **_k: Browser())
            def __enter__(self): return self
            def __exit__(self, *_a): return False
        fake_sync = types.ModuleType("playwright.sync_api")
        fake_sync.sync_playwright = lambda: Playwright()
        fake_playwright = types.ModuleType("playwright")
        fake_playwright.sync_api = fake_sync
        feed = gp.LoginFeed()
        feed.set_stage("credentials")

        with mock.patch.dict(sys.modules, {"playwright": fake_playwright,
                                           "playwright.sync_api": fake_sync}), \
                self.assertRaises(gp.LoginTimeout) as caught:
            gp.browser_login("<html></html>", "POST", 0, False, None, "auto",
                             None, feed, log=lambda _m: None)

        e = caught.exception
        self.assertEqual((e.stage, e.where, e.text),
                         ("credentials", "https://adfs.example/ls/", "Sign in / New Student"))
        self.assertEqual(feed.stage(), "")   # the feed is reset for the next login


class ServiceChoiceFeedTests(unittest.TestCase):
    def test_choice_is_trimmed_and_readable_across_threads(self):
        feed = gp.LoginFeed()
        self.assertEqual(feed.choice(), "")
        feed.set_choice("  PolyU (Staff) ")
        self.assertEqual(feed.choice(), "PolyU (Staff)")
        feed.set_choice("")
        self.assertEqual(feed.choice(), "")

    def test_login_reads_the_service_from_the_feed_at_the_picker_only(self):
        """browser_login's --vpn-choice seeds the feed when it has no pick of
        its own (CLI use) and never overrides one; with a feed the click is
        attempted only while the page is at a selection step."""
        src = inspect.getsource(gp.browser_login)
        self.assertIn("if feed is not None and choice and not feed.choice():", src)
        self.assertIn("feed.set_choice(choice)", src)
        self.assertIn('feed.stage() == "choice"', src)


class AuthenticatePhaseTests(unittest.TestCase):
    def test_auth_command_exchanges_the_prelogin_cookie(self):
        cmd = gp.build_openconnect_auth("vpn.example", "user1", gateway=True)
        self.assertIn("--authenticate", cmd)
        self.assertIn("--usergroup=gateway:prelogin-cookie", cmd)
        self.assertIn("--passwd-on-stdin", cmd)
        self.assertIn("--user=user1", cmd)
        self.assertEqual(cmd[-1], "vpn.example")

    def test_parse_reads_the_shell_style_variables(self):
        out = (
            "COOKIE='user:u:authcookie:abc=='\n"
            "HOST='158.132.0.1'\n"
            "CONNECT_URL='https://vpn.example/ssl-vpn'\n"
            "FINGERPRINT='pin-sha256:xyz'\n"
            "RESOLVE='vpn.example:158.132.0.1'\n"
            "not a variable line\n"
        )
        auth = gp.parse_authenticate(out)
        self.assertEqual(auth["COOKIE"], "user:u:authcookie:abc==")
        self.assertEqual(auth["FINGERPRINT"], "pin-sha256:xyz")
        self.assertEqual(auth["CONNECT_URL"], "https://vpn.example/ssl-vpn")
        self.assertNotIn("not a variable line", auth.values())

    def test_tunnel_command_uses_cookie_and_certificate_pin(self):
        cmd = gp.build_openconnect_tunnel(
            "https://vpn.example/ssl-vpn", "pin-sha256:xyz",
            "vpn.example:158.132.0.1", Path("/opt/hip.sh"), "socks",
            11937, 86400, "0.0.0.0")
        self.assertIn("--cookie-on-stdin", cmd)
        self.assertIn("--servercert=pin-sha256:xyz", cmd)
        self.assertIn("--resolve=vpn.example:158.132.0.1", cmd)
        self.assertIn("--script-tun", cmd)
        self.assertEqual(cmd[-1], "https://vpn.example/ssl-vpn")
        # The one-shot prelogin flags belong to the auth phase only.
        self.assertNotIn("--passwd-on-stdin", cmd)
        self.assertTrue(not any(a.startswith("--usergroup") for a in cmd))


class FillArmedTests(unittest.TestCase):
    """`fill_armed` distinguishes "credentials are about to be typed for you"
    from "nothing happens until you click in the browser"."""

    def test_snapshot_reports_and_resets_the_armed_flag(self):
        feed = gp.LoginFeed()
        self.assertFalse(feed.snapshot()["fill_armed"])
        feed.set_fill_armed(True)
        self.assertTrue(feed.snapshot()["fill_armed"])
        feed.set_fill_armed(False)
        self.assertFalse(feed.snapshot()["fill_armed"])

    def test_discarding_a_cancelled_attempt_disarms(self):
        feed = gp.LoginFeed()
        feed.set_fill_armed(True)
        feed.discard_pending()
        self.assertFalse(feed.snapshot()["fill_armed"])

    def test_a_queued_code_is_not_reported_as_a_page_prompt(self):
        """The panel's flow strip advances on `prompt`, never on `pending`:
        offering a code must not make the login look further along."""
        feed = gp.LoginFeed()
        feed.offer("123456")
        snapshot = feed.snapshot()
        self.assertTrue(snapshot["pending"])
        self.assertEqual(snapshot["prompt"], "")


if __name__ == "__main__":
    unittest.main()
