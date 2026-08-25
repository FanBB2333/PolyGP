import sys
import unittest
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "autologin"))
import control


class TunnelCancellationTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
