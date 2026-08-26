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


if __name__ == "__main__":
    unittest.main()
