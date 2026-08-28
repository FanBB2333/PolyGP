import stat
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "autologin"))
import control


class TunnelCancellationTests(unittest.TestCase):
    def test_late_browser_callback_cannot_clear_new_login(self):
        tunnel = control.Tunnel({})
        tunnel.generation = 2
        tunnel.browser_ready = True

        tunnel._set_browser_ready(False, generation=1)
        self.assertTrue(tunnel.browser_ready)

        tunnel._set_browser_ready(False, generation=2)
        self.assertFalse(tunnel.browser_ready)

    def test_stop_invalidates_login_before_openconnect_starts(self):
        for state in ("awaiting-login", "connecting"):
            with self.subTest(state=state):
                tunnel = control.Tunnel({})
                tunnel.state = state
                tunnel.generation = 3

                with mock.patch.object(tunnel, "log"):
                    stopped, _message = tunnel.stop()

                self.assertTrue(stopped)
                self.assertEqual(tunnel.state, "idle")
                self.assertEqual(tunnel.generation, 4)

    def test_stop_clears_reconnecting_state_during_process_exit_race(self):
        tunnel = control.Tunnel({})
        tunnel.state = "reconnecting"
        tunnel.generation = 3

        with mock.patch.object(tunnel, "log"):
            stopped, message = tunnel.stop()

        self.assertTrue(stopped)
        self.assertEqual(message, "disconnected")
        self.assertEqual(tunnel.state, "idle")
        self.assertEqual(tunnel.generation, 4)


class TunnelStatusTests(unittest.TestCase):
    def test_configuration_records_connected_state_and_expiry(self):
        tunnel = control.Tunnel({})

        with mock.patch.object(tunnel, "log"):
            tunnel._consume_openconnect_line(
                "Configured as 10.8.16.25, with SSL connected and ESP disabled"
            )
            tunnel._consume_openconnect_line(
                "Session authentication will expire at Tue Aug 25 22:25:13 2026"
            )

        self.assertEqual(tunnel.state, "connected")
        self.assertEqual(tunnel.ip, "10.8.16.25")
        self.assertEqual(tunnel.expiry, "Tue Aug 25 22:25:13 2026")
        self.assertIsNotNone(tunnel.expiry_epoch)

    def test_loss_stays_reconnecting_until_getconfig_completes(self):
        tunnel = control.Tunnel({})
        tunnel.state = "connected"
        tunnel.ip = "10.8.16.25"

        with mock.patch.object(tunnel, "log"):
            tunnel._consume_openconnect_line(
                "GPST Dead Peer Detection detected dead peer!"
            )
            reconnecting_since = tunnel.since

            # Repeated failures must not reset the duration, and completing the
            # TLS handshake alone does not mean the tunnel is usable yet.
            tunnel._consume_openconnect_line(
                "Failed to open HTTPS connection to researchvpn.polyu.edu.hk"
            )
            tunnel._consume_openconnect_line(
                "Connected to HTTPS on researchvpn.polyu.edu.hk with ciphersuite (TLS1.2)"
            )

            self.assertEqual(tunnel.state, "reconnecting")
            self.assertEqual(tunnel.since, reconnecting_since)

            tunnel._consume_openconnect_line(
                "Tunnel timeout (rekey interval) is 180 minutes."
            )

        self.assertEqual(tunnel.state, "connected")
        self.assertEqual(tunnel.detail, "tunnel restored; IP 10.8.16.25")


class CredentialFillGateTests(unittest.TestCase):
    """The panel's fill button is accepted in every mode that fills at all.

    Auto mode's trusted-click gate exists so a *page script* cannot make the
    browser type stored credentials at it — hence the isTrusted check in
    USER_CLICK_INIT_SCRIPT. A button on the control panel is not a page, and
    the gate never bounded what a panel caller could do anyway: /save can set
    fill_mode to manual and /fill straight after. Refusing here only cost the
    user the shorter path through the NetID step.
    """

    def _tunnel(self, fill_mode):
        tunnel = control.Tunnel({"fill_mode": fill_mode})
        tunnel.state = "awaiting-login"
        return tunnel

    def test_auto_mode_also_accepts_the_panel_button(self):
        tunnel = self._tunnel("auto")

        with mock.patch.object(control.gp, "credentials", return_value=("id", "pw")):
            ok, message = tunnel.request_fill()

        self.assertTrue(ok)
        self.assertEqual(message, "filling the credential form and submitting")
        self.assertTrue(tunnel.feed.snapshot()["fill_pending"])

    def test_manual_mode_keeps_panel_fill_button(self):
        tunnel = self._tunnel("manual")

        with mock.patch.object(control.gp, "credentials", return_value=("id", "pw")):
            ok, message = tunnel.request_fill()

        self.assertTrue(ok)
        self.assertEqual(message, "filling the credential form and submitting")
        self.assertTrue(tunnel.feed.snapshot()["fill_pending"])

    def test_fill_switched_off_still_refuses(self):
        tunnel = self._tunnel("off")

        with mock.patch.object(control.gp, "credentials", return_value=("id", "pw")):
            ok, message = tunnel.request_fill()

        self.assertFalse(ok)
        self.assertEqual(message, "credential fill is switched off in the settings")
        self.assertFalse(tunnel.feed.snapshot()["fill_pending"])

    def test_without_stored_credentials_the_button_says_so(self):
        """Otherwise the toast promises a fill that quietly does nothing."""
        tunnel = self._tunnel("auto")

        with mock.patch.object(control.gp, "credentials", return_value=(None, None)):
            ok, message = tunnel.request_fill()

        self.assertFalse(ok)
        self.assertEqual(message, "no credentials stored — type them in the browser")
        self.assertFalse(tunnel.feed.snapshot()["fill_pending"])

    def test_fill_needs_a_login_in_progress(self):
        tunnel = control.Tunnel({"fill_mode": "auto"})

        ok, _message = tunnel.request_fill()

        self.assertFalse(ok)
        self.assertFalse(tunnel.feed.snapshot()["fill_pending"])


class CodeGateTests(unittest.TestCase):
    """A code is accepted only while the login page is actually at its MFA
    step — the panel must never take input the page cannot receive."""

    def test_code_while_idle_is_refused(self):
        tunnel = control.Tunnel({})

        ok, message = tunnel.submit_code("123456")

        self.assertFalse(ok)
        self.assertIn("no login waiting", message)
        self.assertEqual(tunnel.state, "idle")
        self.assertFalse(tunnel.feed.snapshot()["pending"])

    def test_code_before_the_mfa_stage_is_refused(self):
        tunnel = control.Tunnel({})
        tunnel.state = "awaiting-login"
        tunnel.feed.set_stage("credentials")

        ok, message = tunnel.submit_code("654321")

        self.assertFalse(ok)
        self.assertIn("not asking for a code yet", message)
        self.assertFalse(tunnel.feed.snapshot()["pending"])

    def test_a_second_code_waits_for_the_verdict_on_the_first(self):
        tunnel = control.Tunnel({})
        tunnel.state = "awaiting-login"
        tunnel.feed.set_stage("code")
        tunnel.feed.mark_submitted("")

        ok, message = tunnel.submit_code("111111")

        self.assertFalse(ok)
        self.assertIn("already on its way", message)
        self.assertFalse(tunnel.feed.snapshot()["pending"])

    def test_code_at_the_mfa_stage_reaches_the_feed(self):
        tunnel = control.Tunnel({})
        tunnel.state = "awaiting-login"
        tunnel.feed.set_stage("code")

        with mock.patch.object(tunnel, "log"):
            ok, message = tunnel.submit_code("654321")

        self.assertTrue(ok)
        self.assertIn("typed into the page", message)
        self.assertEqual(tunnel.feed.take(), "654321")

    def test_stopping_login_discards_a_queued_code(self):
        tunnel = control.Tunnel({})
        tunnel.state = "awaiting-login"
        tunnel.feed.offer("123456")

        with mock.patch.object(tunnel, "log"):
            ok, _message = tunnel.stop()

        self.assertTrue(ok)
        self.assertFalse(tunnel.feed.snapshot()["pending"])


class SessionFileTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "session.json"
        patcher = mock.patch.object(control, "SESSION_FILE", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_round_trip_is_owner_only(self):
        control.save_session({"cookie": "c", "host": "h"})
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(control.load_session(), {"cookie": "c", "host": "h"})
        control.clear_session()
        self.assertIsNone(control.load_session())

    def test_garbage_or_cookieless_file_reads_as_no_session(self):
        self.path.write_text("not json")
        self.assertIsNone(control.load_session())
        self.path.write_text('{"host": "h"}')
        self.assertIsNone(control.load_session())

    def test_resume_off_keeps_the_cookie_off_disk(self):
        """POLYGP_RESUME=off must mean no MFA-bypassing credential at rest,
        not merely 'do not use it at boot'."""
        tunnel = control.Tunnel({"resume": False})
        tunnel._remember({"cookie": "c"})
        self.assertIsNone(control.load_session())

        tunnel = control.Tunnel({"resume": True})
        tunnel._remember({"cookie": "c"})
        self.assertIsNotNone(control.load_session())

    def test_resume_knob_defaults_on_and_parses_off(self):
        with mock.patch.dict(control.os.environ, {}, clear=False):
            control.os.environ.pop("POLYGP_RESUME", None)
            self.assertTrue(control.build_opts()["resume"])
        with mock.patch.dict(control.os.environ, {"POLYGP_RESUME": "off"}):
            self.assertFalse(control.build_opts()["resume"])


class ResumeTests(unittest.TestCase):
    """resume() must only hand openconnect a cookie that could plausibly still
    be alive, and must never chain into a surprise SAML/MFA login."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "session.json"
        patcher = mock.patch.object(control, "SESSION_FILE", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tunnel = control.Tunnel({"host": "vpn.example", "gateway": True})

    def _save(self, **overrides):
        record = {"cookie": "c", "host": "vpn.example", "gateway": True,
                  "target": "vpn.example", "fingerprint": "", "resolve": "",
                  "expiry_epoch": None, "saved_at": time.time()}
        record.update(overrides)
        control.save_session(record)

    def test_no_file_is_a_quiet_no(self):
        ok, message = self.tunnel.resume()
        self.assertFalse(ok)
        self.assertEqual(message, "no saved session")
        self.assertEqual(self.tunnel.state, "idle")

    def test_other_portals_session_is_refused_but_kept(self):
        self._save(host="other.example")
        ok, message = self.tunnel.resume()
        self.assertFalse(ok)
        self.assertIn("different portal", message)
        self.assertIsNotNone(control.load_session())

    def test_expired_session_is_refused_and_forgotten(self):
        self._save(expiry_epoch=time.time() - 10)
        ok, message = self.tunnel.resume()
        self.assertFalse(ok)
        self.assertIn("expired", message)
        self.assertIsNone(control.load_session())

    def test_valid_session_starts_the_tunnel_thread(self):
        self._save()
        with mock.patch.object(control.threading, "Thread") as thread, \
                mock.patch.object(self.tunnel, "log"):
            ok, _message = self.tunnel.resume()
        self.assertTrue(ok)
        self.assertEqual(self.tunnel.state, "connecting")
        self.assertEqual(thread.call_args.kwargs.get("args", ())[2], True)


class ShutdownSignalTests(unittest.TestCase):
    """openconnect logs the session off on SIGINT/SIGTERM and keeps it on
    SIGHUP, so which signal each exit path sends is load-bearing."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "session.json"
        patcher = mock.patch.object(control, "SESSION_FILE", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        control.save_session({"cookie": "c", "host": "h"})

    def _live_proc(self):
        return types.SimpleNamespace(
            poll=lambda: None, terminate=mock.Mock(), kill=mock.Mock(),
            wait=mock.Mock(return_value=0), send_signal=mock.Mock())

    def test_panel_disconnect_logs_off_and_forgets_the_session(self):
        tunnel = control.Tunnel({})
        tunnel.state = "connected"
        tunnel.proc = proc = self._live_proc()
        with mock.patch.object(tunnel, "log"):
            ok, _message = tunnel.stop()
        self.assertTrue(ok)
        proc.terminate.assert_called_once()          # SIGTERM: gateway logoff
        self.assertIsNone(control.load_session())    # dead cookie forgotten

    def test_container_shutdown_hangs_up_and_keeps_the_session(self):
        tunnel = control.Tunnel({})
        tunnel.state = "connected"
        tunnel.proc = proc = self._live_proc()
        with mock.patch.object(tunnel, "log"):
            tunnel.hangup()
        proc.send_signal.assert_called_once_with(control.signal.SIGHUP)
        proc.terminate.assert_not_called()
        self.assertIsNotNone(control.load_session())  # resumable next boot


if __name__ == "__main__":
    unittest.main()
