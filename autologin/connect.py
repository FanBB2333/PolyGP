#!/usr/bin/env python3
"""Fully-automated PolyU GlobalProtect connect (gpclient + headless SAML).

Spawns `gpclient --browser remote`, watches its output for the auth URL,
runs auth.py to complete SAML + MFA headlessly, then feeds the captured
`globalprotectcallback:...` back to gpclient's stdin. gpclient still does the
two-stage SAML, HIP submission and the tunnel — this only replaces the human
who used to open the browser and paste the callback.

Run on a Linux host/container where gpclient is installed, with the same
Playwright setup as auth.py. Selectors etc. live in auth.py.

  POLYGP_PORTAL          portal host           (default staffvpn.polyu.edu.hk)
  POLYGP_NETID           passed as --user      (also used by auth.py)
  POLYGP_GP_OS           spoofed --os          (default Windows)
  POLYGP_GP_VERSION      --client-version      (default 6.2.8-243)
  POLYGP_HIP             --hip script path
  Plus creds/seed as documented in auth.py / mfa.py.
"""
import os
import re
import subprocess
import sys
import threading

import auth

# gpclient prints something like  http://100.x.y.z:33455/2b1e...-uuid
URL_RE = re.compile(r"https?://[0-9A-Za-z_.-]+:\d+/[0-9a-fA-F-]{16,}")


def build_cmd() -> list[str]:
    portal = os.environ.get("POLYGP_PORTAL", "staffvpn.polyu.edu.hk")
    cmd = ["gpclient", "--fix-openssl", "connect", portal,
           "--os", os.environ.get("POLYGP_GP_OS", "Windows"),
           "--client-version", os.environ.get("POLYGP_GP_VERSION", "6.2.8-243"),
           "--browser", "remote", "-v"]
    if os.environ.get("POLYGP_NETID"):
        cmd += ["--user", os.environ["POLYGP_NETID"]]
    if os.environ.get("POLYGP_HIP"):
        cmd += ["--hip", os.environ["POLYGP_HIP"]]
    # gpclient >= 2.6 needs a non-root user for gpauth; caller handles sudo/user.
    return cmd


def main() -> None:
    headful = "--headful" in sys.argv
    debug_dir = os.environ.get("POLYGP_DEBUG_DIR")
    cmd = build_cmd()
    print(f"[connect] launching: {' '.join(cmd)}", file=sys.stderr)

    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, bufsize=1)

    handled = threading.Event()

    def pump():
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            if handled.is_set():
                continue
            m = URL_RE.search(line)
            if m:
                handled.set()
                url = m.group(0)
                print(f"[connect] auth url found; running headless SAML…",
                      file=sys.stderr)
                try:
                    cb = auth.run(url, headful=headful, debug_dir=debug_dir)
                except SystemExit as e:
                    print(f"[connect] auth failed: {e}", file=sys.stderr)
                    proc.terminate()
                    return
                assert proc.stdin is not None
                proc.stdin.write(cb + "\n")
                proc.stdin.flush()
                print("[connect] callback fed to gpclient", file=sys.stderr)

    t = threading.Thread(target=pump, daemon=True)
    t.start()
    rc = proc.wait()
    t.join(timeout=2)
    sys.exit(rc)


if __name__ == "__main__":
    main()
