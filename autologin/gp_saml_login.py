#!/usr/bin/env python3
"""Interactive SAML login for PolyU GlobalProtect, for use with plain openconnect.

Why this exists: openconnect's --external-browser handoff does not work for
GlobalProtect's SAML REDIRECT flow (upstream issues #446 / #672 / #829). The
browser reaches "Login Successful!" but openconnect never receives the result,
and fails with "Failed to parse XML server response". The values it needs
(prelogin-cookie, saml-username) are returned in HTTP *response headers*, which
a normal browser window never shows.

So this opens a real Chromium window, you log in by hand (NetID + password +
phone MFA), and it reads those headers off the wire and hands them to
openconnect together with the bundled HIP report script.

    python3 gp_saml_login.py                     # log in, then serve SOCKS on :11937
    python3 gp_saml_login.py --mode tun          # log in, build a real tun device
    python3 gp_saml_login.py --print-only        # log in, just print the cookie

Unlike auth.py in this directory, no TOTP seed or stored password is needed:
the login itself is done by you, in the browser.

Two connection modes:

  socks (default) - openconnect runs with --script-tun + ocproxy, so the whole
      TCP/IP stack lives in userspace: no tun device, no route or DNS changes,
      no sudo. It just serves SOCKS5 on 127.0.0.1:<port>. Point your proxy tool
      (Surge, etc.) at that port for PolyU destinations and it stays in charge
      of the rest of the machine's networking.

  tun - the conventional setup: a utun device plus split routes for PolyU
      subnets, installed system-wide. Needs sudo. Note this fights with a proxy
      tool that uses fake-IP DNS: openconnect adds a bypass route sending the
      VPN server's own address to the physical gateway, and a fake IP routed
      there is a black hole, which kills the tunnel (dead-peer loop).
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

DEFAULT_HOST = "researchvpn.polyu.edu.hk"
HIP_SCRIPT = Path(__file__).resolve().parent.parent / "hip" / "polyu-hipreport.sh"

# openconnect must report the same OS/version the HIP report claims, or PolyU's
# HIP policy rejects the (Windows Defender) anti-malware block as inconsistent.
GP_OS = "win"
GP_CLIENT_VERSION = "6.2.8-243"

# What GlobalProtect sends back once SAML succeeds.
H_STATUS = "saml-auth-status"
H_COOKIE = "prelogin-cookie"
H_USER = "saml-username"


def prelogin(host: str, gateway: bool) -> tuple[str, str]:
    """Run GP prelogin; return (saml_method, decoded_saml_request)."""
    path = "/ssl-vpn/prelogin.esp" if gateway else "/global-protect/prelogin.esp"
    url = f"https://{host}{path}?tmp=tmp&clientVer=4100&clientos=Windows"

    # PolyU's portal is an old TLS stack; be permissive here (this request carries
    # no secrets, and openconnect verifies the certificate on the real connection).
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Deliberately ignore http(s)_proxy from the environment. openconnect does not
    # use them either, so honouring them here would authenticate over a different
    # path than the tunnel is built on. A stale value also hangs this request: a
    # shell exporting https_proxy=https://host:port makes urllib attempt TLS against
    # a plain-HTTP proxy, which stalls until the handshake times out.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ctx),
    )
    req = urllib.request.Request(url, method="POST", data=b"")
    try:
        with opener.open(req, timeout=20) as r:
            xml = r.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError) as e:
        raise SystemExit(f"could not reach {host}: {e}\n"
                         f"Check the portal is reachable: curl -sk https://{host}{path}")

    root = ET.fromstring(xml)
    get = lambda tag: (root.findtext(tag) or "").strip()

    if get("status") != "Success":
        raise SystemExit(f"prelogin failed: {get('status')} {get('msg')}")

    method = get("saml-auth-method")
    request = get("saml-request")
    if not method or not request:
        raise SystemExit(
            "server did not offer SAML at this endpoint; "
            f"try {'--portal' if gateway else '--gateway'}"
        )
    return method, base64.b64decode(request).decode("utf-8", "replace")


def browser_login(entry: str, method: str, timeout: int, keep_open: bool,
                  channel: str | None) -> dict[str, str]:
    """Open a browser for the user to log in; capture the GP response headers."""
    from playwright.sync_api import sync_playwright

    got: dict[str, str] = {}
    body_cookie = re.compile(r"<prelogin-cookie>([^<]+)</prelogin-cookie>")
    body_user = re.compile(r"<saml-username>([^<]+)</saml-username>")

    def on_response(resp):
        if got.get(H_COOKIE):
            return
        try:
            headers = resp.headers  # already lower-cased by Playwright
        except Exception:
            return
        if H_COOKIE in headers:
            got[H_COOKIE] = headers[H_COOKIE]
            got[H_USER] = headers.get(H_USER, "")
            got[H_STATUS] = headers.get(H_STATUS, "")
            got["url"] = resp.url
            return
        # Fallback: some deployments only put the values in the body.
        ctype = headers.get("content-type", "")
        if not any(t in ctype for t in ("html", "xml", "text", "json")):
            return
        try:
            text = resp.text()
        except Exception:
            return
        m = body_cookie.search(text)
        if m:
            got[H_COOKIE] = m.group(1)
            u = body_user.search(text)
            got[H_USER] = u.group(1) if u else ""
            got["url"] = resp.url

    with sync_playwright() as p:
        launch = {"headless": False, "args": ["--window-size=1100,850"]}
        if channel:
            launch["channel"] = channel  # e.g. your installed Chrome / Edge
        browser = p.chromium.launch(**launch)
        ctx = browser.new_context(ignore_https_errors=True)
        page = ctx.new_page()
        page.on("response", on_response)

        print("[gp] browser opening — log in with your NetID, password and phone MFA",
              file=sys.stderr)
        if method.upper() == "REDIRECT":
            page.goto(entry, wait_until="domcontentloaded")
        else:  # POST: saml-request is a full HTML page that self-submits
            page.set_content(entry)

        deadline = time.time() + timeout
        while time.time() < deadline and not got.get(H_COOKIE):
            page.wait_for_timeout(500)

        if got.get(H_COOKIE) and keep_open:
            print("[gp] captured — press Enter to close the browser", file=sys.stderr)
            input()
        browser.close()

    if not got.get(H_COOKIE):
        raise SystemExit(
            f"timed out after {timeout}s without seeing a {H_COOKIE} header.\n"
            "If the browser did reach \"Login Successful!\", the server may put the "
            "value elsewhere — rerun with --keep-open and check the Network tab."
        )
    return got


def build_openconnect(host: str, user: str, gateway: bool, hip: Path,
                      mode: str, socks_port: int) -> list[str]:
    usergroup = "gateway:prelogin-cookie" if gateway else "portal:prelogin-cookie"
    cmd = [
        "openconnect",
        "--protocol=gp",
        f"--os={GP_OS}",
        f"--version-string={GP_CLIENT_VERSION}",
        f"--usergroup={usergroup}",
        "--passwd-on-stdin",
        f"--csd-wrapper={hip}",
    ]
    if user:
        cmd.append(f"--user={user}")

    if mode == "socks":
        # Userspace TCP/IP: openconnect hands the tunnel to ocproxy over a pipe
        # instead of a tun device, so nothing about the system's networking moves.
        # -k: keepalive, so an idle session survives the gateway and any stateful
        # firewall between here and it (the connection may cross a proxy hop).
        cmd += ["--script-tun", "--script", f"ocproxy -k 30 -D {socks_port}"]
    else:
        cmd.insert(0, "sudo")  # a real tun device and system routes need root

    cmd.append(host)
    return cmd


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host", nargs="?", default=DEFAULT_HOST, help=f"VPN host (default {DEFAULT_HOST})")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--gateway", action="store_true", default=True,
                      help="SAML against the gateway endpoint (default)")
    mode.add_argument("--portal", dest="gateway", action="store_false",
                      help="SAML against the portal endpoint instead")
    ap.add_argument("--mode", choices=["socks", "tun"], default="socks",
                    help="socks = userspace SOCKS5 via ocproxy, touches no routes and needs "
                         "no sudo (default); tun = conventional utun device + system routes")
    ap.add_argument("--socks-port", type=int, default=11937,
                    help="port for SOCKS mode (default 11937; matches the PolyU-VPN "
                         "entry in the Surge profile)")
    ap.add_argument("--print-only", action="store_true",
                    help="print the captured cookie and the openconnect command; do not connect")
    ap.add_argument("--keep-open", action="store_true",
                    help="keep the browser open after capture (for inspection)")
    ap.add_argument("--browser", choices=["chromium", "chrome", "msedge"], default="chromium",
                    help="chromium = Playwright's bundled build (default); "
                         "chrome / msedge = the copy installed on this machine")
    ap.add_argument("--timeout", type=int, default=300, help="seconds to wait for login (default 300)")
    ap.add_argument("--hip", type=Path, default=HIP_SCRIPT, help=f"HIP script (default {HIP_SCRIPT})")
    a = ap.parse_args()

    if not a.hip.is_file():
        raise SystemExit(f"HIP script not found: {a.hip}")
    if a.mode == "socks" and not shutil.which("ocproxy"):
        raise SystemExit("socks mode needs ocproxy: brew install ocproxy "
                         "(or use --mode tun)")

    method, entry = prelogin(a.host, a.gateway)
    print(f"[gp] {a.host}: SAML {method} via {entry.split('?')[0]}", file=sys.stderr)

    channel = None if a.browser == "chromium" else a.browser
    got = browser_login(entry, method, a.timeout, a.keep_open, channel)
    user = got.get(H_USER, "")
    print(f"[gp] captured {H_COOKIE} for user={user or '(unknown)'}", file=sys.stderr)

    cmd = build_openconnect(a.host, user, a.gateway, a.hip, a.mode, a.socks_port)

    if a.print_only:
        print(f"\n{H_COOKIE}: {got[H_COOKIE]}")
        print(f"{H_USER}: {user}\n")
        print("echo <cookie> | " + " ".join(shlex.quote(c) for c in cmd))
        return

    if a.mode == "socks":
        print(f"[gp] SOCKS5 will listen on 127.0.0.1:{a.socks_port} — "
              "no routes or DNS are touched; Ctrl+C to disconnect", file=sys.stderr)
    print(f"[gp] connecting: {' '.join(shlex.quote(c) for c in cmd)}", file=sys.stderr)
    # openconnect honours https_proxy/http_proxy from the environment. Strip them,
    # for the same reason prelogin ignores them: the tunnel has to be built over the
    # path we just authenticated on. A sudo'd run gets this for free (sudo sanitises
    # the environment); socks mode has no sudo, so do it explicitly. A shell that
    # exported https_proxy=https://... would otherwise abort with
    # "Only http or socks(5) proxies supported".
    env = {k: v for k, v in os.environ.items()
           if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "ftp_proxy")}

    # sudo prompts on the tty, so it does not clash with the cookie on stdin.
    sys.exit(subprocess.run(cmd, input=got[H_COOKIE] + "\n", text=True, env=env).returncode)


if __name__ == "__main__":
    main()
