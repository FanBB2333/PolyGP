import sys
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
    def test_auto_mode_cannot_be_triggered_by_panel_button(self):
        tunnel = control.Tunnel({"fill_mode": "auto"})
        tunnel.state = "awaiting-login"

        ok, message = tunnel.request_fill()

        self.assertFalse(ok)
        self.assertEqual(message, "set credential fill to manual to use this button")
        self.assertFalse(tunnel.feed.snapshot()["fill_pending"])

    def test_manual_mode_keeps_panel_fill_button(self):
        tunnel = control.Tunnel({"fill_mode": "manual"})
        tunnel.state = "awaiting-login"

        ok, message = tunnel.request_fill()

        self.assertTrue(ok)
        self.assertEqual(message, "filling the credential form and submitting")
        self.assertTrue(tunnel.feed.snapshot()["fill_pending"])


class CodeFirstLoginTests(unittest.TestCase):
    def test_code_submitted_while_idle_starts_a_fresh_login(self):
        tunnel = control.Tunnel({})

        with mock.patch.object(tunnel, "_run"), \
                mock.patch.object(control.threading, "Thread") as thread, \
                mock.patch.object(tunnel, "log"):
            ok, message = tunnel.submit_code("123456")

        self.assertTrue(ok)
        self.assertIn("fresh SAML login", message)
        self.assertEqual(tunnel.state, "awaiting-login")
        self.assertEqual(tunnel.feed.take(), "123456")
        thread.assert_called_once()
        self.assertTrue(thread.call_args.kwargs["daemon"])
        self.assertIs(thread.call_args.kwargs["args"][1], tunnel.feed)

    def test_code_submitted_during_login_keeps_using_the_active_feed(self):
        tunnel = control.Tunnel({})
        tunnel.state = "awaiting-login"

        with mock.patch.object(tunnel, "start") as start, \
                mock.patch.object(tunnel, "log"):
            ok, message = tunnel.submit_code("654321")

        self.assertTrue(ok)
        self.assertIn("typed in", message)
        start.assert_not_called()
        self.assertEqual(tunnel.feed.take(), "654321")

    def test_stopping_login_discards_a_queued_code(self):
        tunnel = control.Tunnel({})
        tunnel.state = "awaiting-login"
        tunnel.feed.offer("123456")

        with mock.patch.object(tunnel, "log"):
            ok, _message = tunnel.stop()

        self.assertTrue(ok)
        self.assertFalse(tunnel.feed.snapshot()["pending"])


if __name__ == "__main__":
    unittest.main()
