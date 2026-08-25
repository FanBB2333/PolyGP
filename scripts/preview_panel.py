#!/usr/bin/env python3
"""Preview the control panel UI without the container.

The panel's whole frontend is the PAGE string in autologin/control.py; this
serves it on localhost with a mocked /status, so a style change is visible by
editing control.py and refreshing the browser — no image rebuild, no tunnel
touched. PAGE is re-read from the file on every request.

    python3 scripts/preview_panel.py            # http://127.0.0.1:11938/
    python3 scripts/preview_panel.py --port 8000 --state awaiting-login

The mock answers the panel's action buttons and moves through the states the
way a real login would (Log in -> awaiting-login, Send code -> connected,
Disconnect -> idle). To jump straight to any state, open
    /mock?state=idle|awaiting-login|connecting|connected|failed
"""
from __future__ import annotations

import argparse
import ast
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

CONTROL = Path(__file__).resolve().parent.parent / "autologin" / "control.py"

STATES = ("idle", "awaiting-login", "connecting", "connected", "failed")
DETAIL = {
    "idle": "disconnected",
    "awaiting-login": "opening the browser",
    "connecting": "authenticated as HH\\example-user",
    "connected": "tunnel IP 10.8.16.25",
    "failed": "login failed: browser login timed out",
}
# Enough variety to exercise the log colouring (tag, ok, warn, err, tokens).
LOGS = [
    "[control] state -> awaiting-login: opening the browser",
    "[control] SAML REDIRECT via https://adfs.polyu.edu.hk/adfs/ls/",
    "[gp] navigation retry after Error: net::ERR_ABORTED",
    "[control] verification code received from the panel",
    "[control] state -> connecting: authenticated as HH\\example-user",
    "Connected to 198.18.71.133:443",
    "Connected to HTTPS on researchvpn.polyu.edu.hk with ciphersuite (TLS1.2)",
    "Configured as 10.8.16.25, with SSL connected and DTLS disabled",
    "Session authentication will expire at Tue Aug 25 22:25:13 2026",
    "SOCKS server listening on 0.0.0.0:11937",
]


def page() -> str:
    """The PAGE string, fresh from control.py — parsed, not imported, so the
    preview needs none of the login stack (gp_saml_login pulls in playwright)."""
    tree = ast.parse(CONTROL.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if any(getattr(t, "id", "") == "PAGE" for t in node.targets):
                return ast.literal_eval(node.value)
    raise SystemExit(f"no PAGE string found in {CONTROL}")


def status(state: str) -> dict:
    connected = state == "connected"
    awaiting = state == "awaiting-login"
    return {
        "state": state,
        "detail": DETAIL[state],
        "tunnel_ip": "10.8.16.25" if connected else "",
        "session_expires": "Tue Aug 25 22:25:13 2026" if connected else "",
        "session_expires_epoch": time.time() + 7.5 * 3600 if connected else None,
        "timezone": "America/New_York",
        "socks_port": 11937,
        "portal": "researchvpn.polyu.edu.hk",
        "vpn_choice": "research",
        "seconds_in_state": 2119,
        "logs": LOGS,
        "mfa": {
            "pending": False,
            "prompt": "Enter the code from your phone" if awaiting else "",
            "fill_pending": False,
        },
        "settings": {
            "portal": "researchvpn.polyu.edu.hk",
            "saml_endpoint": "gateway",
            "vpn_choice": "research",
            "fill_mode": "auto",
            "auto_relogin": "on",
            "netid": "example-user",
            "netpass_set": True,
            "vpn_options": ["research", "PolyU (Student)"],
            "login_timeout": "600",
            "reconnect_timeout": "86400",
        },
        # about:blank keeps the Browser pane's iframe harmless in the preview.
        "vnc": {"port": 6080, "password": "", "url": "about:blank"},
        "config": {
            "SOCKS port": 11937,
            "HIP script": "/opt/polygp/hip/hipreport.sh",
            "env file": "/opt/polygp/.env",
        },
    }


# What each action button does to the mocked state, so clicking through the
# panel walks the same path a real login does.
ACTIONS = {
    "/login": "awaiting-login",
    "/renew": "awaiting-login",
    "/code": "connected",
    "/fill": "awaiting-login",
    "/logout": "idle",
    "/save": None,
    "/set": None,
    "/reload": None,
}


class Handler(BaseHTTPRequestHandler):
    state = "connected"

    def log_message(self, *a):
        pass

    def _send(self, code: int, body: str, ctype="text/html; charset=utf-8") -> None:
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self._route()

    def do_POST(self):
        self._route()

    def _route(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        cls = type(self)
        if path == "/":
            return self._send(200, page().replace("__TOKEN_QUERY__", ""))
        if path == "/status":
            return self._send(200, json.dumps(status(cls.state)),
                              "application/json; charset=utf-8")
        if path == "/logs":
            return self._send(200, "\n".join(LOGS), "text/plain; charset=utf-8")
        if path == "/mock":
            want = (parse_qs(urlparse(self.path).query).get("state") or [""])[0]
            if want not in STATES:
                return self._send(400, f"state must be one of {', '.join(STATES)}",
                                  "text/plain")
            cls.state = want
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
            return
        if path in ACTIONS:
            if ACTIONS[path]:
                cls.state = ACTIONS[path]
            return self._send(200, json.dumps(
                {"ok": True, "message": f"(preview) {path[1:]} — state is now {cls.state}"}),
                "application/json; charset=utf-8")
        self._send(404, "not found", "text/plain")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=11938)
    ap.add_argument("--state", choices=STATES, default="connected",
                    help="state the mock starts in (default: connected)")
    args = ap.parse_args()

    page()  # fail now, not on the first request, if control.py will not parse
    Handler.state = args.state
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"preview at http://127.0.0.1:{args.port}/  "
          f"(switch states via /mock?state=...)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
