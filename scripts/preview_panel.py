#!/usr/bin/env python3
"""Preview the control panel UI without the container.

The panel frontend is autologin/panel.html. This serves it on localhost with
a mocked /status, so a style change is visible by
editing panel.html and refreshing the browser — no image rebuild, no tunnel
touched. The template is re-read from the file on every request.

    python3 scripts/preview_panel.py            # http://127.0.0.1:11938/
    python3 scripts/preview_panel.py --port 8000 --state awaiting-login

The mock answers the panel's action buttons and moves through the states the
way a real login would: Log in -> awaiting-login (the credential form, then
the service picker, then the MFA prompt, a few seconds each), Verify at the MFA
stage -> connecting -> connected, Disconnect -> idle. To jump straight to any
state, open
    /mock?state=idle|awaiting-login|connecting|connected|reconnecting|failed|unavailable
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

PANEL = Path(__file__).resolve().parent.parent / "autologin" / "panel.html"

STATES = ("idle", "awaiting-login", "connecting", "connected", "reconnecting",
          "failed", "unavailable")
DETAIL = {
    "idle": "Ready to connect. Click Log in when you are ready.",
    "awaiting-login": "opening the browser",
    "connecting": "authenticated as HH\\demo-netid",
    "connected": "tunnel IP 10.8.16.25",
    "reconnecting": "tunnel interrupted; OpenConnect is retrying",
    "failed": "login failed: browser login timed out",
    "unavailable": "control service is unavailable",
}
# Enough variety to exercise the log colouring (tag, ok, warn, err, tokens).
LOGS = [
    "[control] state -> awaiting-login: opening the browser",
    "[control] SAML REDIRECT via https://adfs.polyu.edu.hk/adfs/ls/",
    "[gp] navigation retry after Error: net::ERR_ABORTED",
    "[control] verification code received from the panel",
    "[control] state -> connecting: authenticated as HH\\demo-netid",
    "Connected to 198.18.71.133:443",
    "Connected to HTTPS on researchvpn.polyu.edu.hk with ciphersuite (TLS1.2)",
    "Configured as 10.8.16.25, with SSL connected and DTLS disabled",
    "Session authentication will expire at Tue Aug 25 22:25:13 2026",
    "SOCKS server listening on 0.0.0.0:11937",
    "GPST Dead Peer Detection detected dead peer!",
    "[control] state -> reconnecting: tunnel interrupted; OpenConnect is retrying",
    "Failed to open HTTPS connection to researchvpn.polyu.edu.hk",
    "sleep 10s, remaining timeout 86400s",
]

BOOT = time.time()


def mock_logs() -> list[str]:
    """LOGS plus a tail that grows one line every few seconds (capped), so the
    Logs pane has enough to scroll and its tail-follow can be watched live."""
    beats = min(300, int((time.time() - BOOT) / 3))
    return LOGS * 3 + [f"[control] heartbeat {n + 1} — mock line for scrolling"
                       for n in range(beats)]


def page() -> str:
    """Serve the same template as the container, without importing its login stack."""
    return PANEL.read_text()


# How long the mocked awaiting-login spends on each pre-MFA page, so the flow
# strip walks its NetID and Service stations before the code prompt appears.
CREDENTIALS_FOR = 6.0
CHOICE_FOR = 4.0


def mock_stage(state: str, in_state: float) -> str:
    if state != "awaiting-login":
        return ""
    if in_state < CREDENTIALS_FOR:
        return "credentials"
    if in_state < CREDENTIALS_FOR + CHOICE_FOR:
        return "choice"
    return "code"


# How long a submitted code is "on its way" before the mocked page answers.
CODE_VERDICT_AFTER = 3.0
BAD_CODE = "000000"
BAD_CODE_NOTE = "Incorrect verification code. Please try again."


def mock_code(stage: str, sent_at: float | None, bad: bool) -> tuple[str, str]:
    """(code_state, code_note) for the mocked MFA step."""
    if stage != "code" or sent_at is None:
        return "", ""
    if time.time() - sent_at < CODE_VERDICT_AFTER:
        return "submitting", ""
    return ("rejected", BAD_CODE_NOTE) if bad else ("", "")


def status(state: str, since: float, code_sent_at: float | None = None,
           code_bad: bool = False, stage_override: str = "") -> dict:
    session_active = state in ("connected", "reconnecting")
    in_state = time.time() - since
    stage = stage_override or mock_stage(state, in_state)
    asking = stage == "code"
    code_state, code_note = mock_code(stage, code_sent_at, code_bad)
    return {
        "state": state,
        "detail": DETAIL[state],
        "tunnel_ip": "10.8.16.25" if session_active else "",
        "session_expires": "Tue Aug 25 22:25:13 2026" if session_active else "",
        "session_expires_epoch": time.time() + 7.5 * 3600 if session_active else None,
        "timezone": "America/New_York",
        "socks_port": 11937,
        "portal": MOCK_SETTINGS["portal"],
        "vpn_choice": MOCK_SETTINGS["vpn_choice"],
        "seconds_in_state": round(in_state),
        "logs": mock_logs()[-40:],
        "mfa": {
            "pending": False,
            "prompt": "Enter the code from your phone" if asking else "",
            "fill_pending": False,
            "stage": stage,
            # Auto mode waits for a trusted click in the browser; the mock
            # keeps it armed over the credential stage so the NetID station's
            # "Click in Browser" affordance can be seen.
            "fill_armed": stage == "credentials",
            # A sent code is "submitting" for a moment, then the page answers:
            # 000000 is rejected with the page's own words, anything else
            # takes the login on to connecting (see /code in _route).
            "code_state": code_state,
            "code_note": code_note,
            "page_error": code_note,
        },
        "settings": {
            **MOCK_SETTINGS,
            "vpn_options": ["research", "PolyU (Student)"],
        },
        # about:blank keeps the Browser pane's iframe harmless in the preview.
        "vnc": {"port": 6080, "password": "", "url": "about:blank",
                "screen_width": 1600, "screen_height": 900,
                "browser_ready": state in ("awaiting-login", "connecting") and stage != "opening"},
        "config": {
            "SOCKS port": 11937,
            "HIP script": "/opt/polygp/hip/hipreport.sh",
            "env file": "/opt/polygp/.env",
        },
    }


# What each action button does to the mocked state, so clicking through the
# panel walks the same path a real login does.  /code is special-cased in
# _route: like the real backend it is accepted only at the MFA stage, where it
# completes the login.
# Settings the preview lets the panel change (the real backend keeps them
# in its option overrides); read back through /status like the real one.
DEFAULT_SETTINGS = {
    "portal": "researchvpn.polyu.edu.hk", "saml_endpoint": "gateway",
    "vpn_choice": "research", "fill_mode": "auto", "auto_relogin": "on",
    "netid": "demo-netid", "netpass_set": True,
    "login_timeout": "600", "reconnect_timeout": "86400",
}
MOCK_SETTINGS = dict(DEFAULT_SETTINGS)

ACTIONS = {
    "/login": "awaiting-login",
    "/renew": "awaiting-login",
    "/fill": "awaiting-login",
    "/logout": "idle",
    "/save": None,
    "/set": None,
    "/reload": None,
}

# How long the mocked openconnect handoff takes before "connected".
CONNECT_AFTER = 4.0


class Handler(BaseHTTPRequestHandler):
    state = "connected"
    since = time.time()
    generation = 0
    code_sent_at: float | None = None
    code_bad = False
    stage_override = ""
    fail_action = ""

    @classmethod
    def set_state(cls, state: str) -> None:
        cls.state, cls.since = state, time.time()
        cls.generation += 1
        cls.code_sent_at, cls.code_bad = None, False
        cls.stage_override = ""

    @classmethod
    def set_state_later(cls, state: str, delay: float) -> None:
        gen = cls.generation
        # A /mock jump or another action in the meantime wins over the timer.
        def flip():
            if cls.generation == gen:
                cls.set_state(state)
        threading.Timer(delay, flip).start()

    def log_message(self, *a):
        pass

    def _param(self, name: str) -> str:
        """A request parameter, from the query string or the form body."""
        params = parse_qs(urlparse(self.path).query)
        if self.command == "POST":
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            for k, v in parse_qs(body).items():
                params.setdefault(k, v)
        return (params.get(name) or [""])[0]

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
            if cls.state == "unavailable":
                return self._send(503, json.dumps({"error": "preview status unavailable"}),
                                  "application/json; charset=utf-8")
            return self._send(200, json.dumps(
                status(cls.state, cls.since, cls.code_sent_at, cls.code_bad,
                       cls.stage_override)),
                "application/json; charset=utf-8")
        if path == "/logs":
            return self._send(200, "\n".join(mock_logs()), "text/plain; charset=utf-8")
        if path == "/mock":
            want = (parse_qs(urlparse(self.path).query).get("state") or [""])[0]
            if want not in STATES:
                return self._send(400, f"state must be one of {', '.join(STATES)}",
                                  "text/plain")
            cls.set_state(want)
            params = parse_qs(urlparse(self.path).query)
            stage = (params.get("stage") or [""])[0]
            if want == "awaiting-login" and stage in ("opening", "credentials", "choice", "code"):
                cls.stage_override = stage
            cls.fail_action = (params.get("fail_action") or [""])[0]
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
            return
        if path == "/code":
            # Mirror the real backend's gate: a code lands only while the
            # login page is at the MFA stage; then it finishes the login.
            if cls.state != "awaiting-login":
                return self._send(200, json.dumps(
                    {"ok": False, "message": "(preview) no login waiting for "
                     f"input (state: {cls.state})"}),
                    "application/json; charset=utf-8")
            stage = cls.stage_override or mock_stage(cls.state, time.time() - cls.since)
            if stage != "code":
                return self._send(200, json.dumps(
                    {"ok": False, "message": "(preview) the login page is not "
                     "asking for a code yet"}),
                    "application/json; charset=utf-8")
            if mock_code(stage, cls.code_sent_at, cls.code_bad)[0] == "submitting":
                return self._send(200, json.dumps(
                    {"ok": False, "message": "(preview) a code is already on "
                     "its way — wait for the page's answer"}),
                    "application/json; charset=utf-8")
            code = self._param("code")
            cls.code_sent_at, cls.code_bad = time.time(), code == BAD_CODE
            if not cls.code_bad:
                # The page accepts it once the verdict delay is over, and
                # openconnect takes over from there.
                gen = cls.generation
                def accept():
                    if cls.generation == gen:
                        cls.set_state("connecting")
                        cls.set_state_later("connected", CONNECT_AFTER)
                threading.Timer(CODE_VERDICT_AFTER, accept).start()
            return self._send(200, json.dumps(
                {"ok": True, "message": "(preview) code sent — it is typed into the page"}),
                "application/json; charset=utf-8")
        if path in ("/set", "/save"):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            form = {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}
            if cls.fail_action == "save":
                cls.fail_action = ""
                return self._send(409, json.dumps(
                    {"ok": False, "message": "Preview: settings could not be saved. Try again."}),
                    "application/json; charset=utf-8")
            pairs = ({form.get("key", ""): form.get("value", "")}
                     if path == "/set" else form)
            for k, v in pairs.items():
                if k in MOCK_SETTINGS:
                    MOCK_SETTINGS[k] = v.strip()
                elif k == "netpass" and v:
                    MOCK_SETTINGS["netpass_set"] = True
            return self._send(200, json.dumps(
                {"ok": True, "message": "(preview) saved " + ", ".join(pairs)}),
                "application/json; charset=utf-8")
        if path in ACTIONS:
            if path == "/reload":
                MOCK_SETTINGS.clear()
                MOCK_SETTINGS.update(DEFAULT_SETTINGS)
            if ACTIONS[path]:
                cls.set_state(ACTIONS[path])
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

    page()  # fail now, not on the first request, if the template is missing
    Handler.set_state(args.state)
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"preview at http://127.0.0.1:{args.port}/  "
          f"(switch states via /mock?state=...)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
