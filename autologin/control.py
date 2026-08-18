#!/usr/bin/env python3
"""HTTP control plane for the PolyGP container.

Turns the one-shot script into a long-lived service. Without it the container is
a single connection attempt that dies with the session; with it the tunnel is
something you start, stop and inspect over HTTP:

    GET  /            status page with the links below
    GET  /status      JSON: state, tunnel IP, session expiry, socks port
    POST /login       begin a SAML login; drive the browser via noVNC
    POST /logout      disconnect and go back to idle
    GET  /logs        recent openconnect output

/login and /logout also answer GET, so they work by typing the URL in a browser.

The login itself still happens in the browser on the container's virtual
display: /login opens the PolyU page there and returns immediately, then you
complete NetID + MFA over noVNC. When credentials are configured the form is
filled in for you and only MFA is left.

Set $CONTROL_TOKEN to require ?token=... on every request — worth doing if the
port is reachable by anyone but you, since these endpoints control the VPN.
"""
from __future__ import annotations

import html
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gp_saml_login as gp

# openconnect announces these once the tunnel is up; worth surfacing as status.
RE_CONFIGURED = re.compile(r"Configured as ([0-9a-fA-F:.]+)")
RE_EXPIRY = re.compile(r"Session authentication will expire at (.+)")


class Tunnel:
    """Owns the login thread and the openconnect process, and their state."""

    def __init__(self, opts: dict) -> None:
        self.opts = opts
        self.lock = threading.Lock()
        self.proc: subprocess.Popen | None = None
        self.worker: threading.Thread | None = None
        self.state = "idle"          # idle|awaiting-login|connecting|connected|failed
        self.detail = ""
        self.ip = ""
        self.expiry = ""
        self.since = time.time()
        self.logs: deque[str] = deque(maxlen=400)

    # -- helpers --------------------------------------------------------------
    def _set(self, state: str, detail: str = "") -> None:
        self.state, self.detail, self.since = state, detail, time.time()
        self.log(f"[control] state -> {state}" + (f": {detail}" if detail else ""))

    def log(self, line: str) -> None:
        self.logs.append(line.rstrip())
        print(line.rstrip(), file=sys.stderr, flush=True)

    def busy(self) -> bool:
        return self.state in ("awaiting-login", "connecting", "connected")

    # -- lifecycle ------------------------------------------------------------
    def start(self) -> tuple[bool, str]:
        with self.lock:
            if self.busy():
                return False, f"already {self.state}"
            self._set("awaiting-login", "opening the browser")
            self.ip = self.expiry = ""
            self.worker = threading.Thread(target=self._run, daemon=True)
            self.worker.start()
            return True, "login started — complete it in the browser over noVNC"

    def stop(self) -> tuple[bool, str]:
        with self.lock:
            proc, self.proc = self.proc, None
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            return True, "disconnected"
        if self.state == "awaiting-login":
            # The browser thread is blocked waiting for a login that is not
            # coming; it gives up on its own timeout.
            self._set("idle", "login abandoned")
            return True, "login cancelled (the browser closes at its timeout)"
        return False, "not connected"

    def _run(self) -> None:
        o = self.opts
        try:
            method, entry = gp.prelogin(o["host"], o["gateway"])
            self.log(f"[control] SAML {method} via {entry.split('?')[0]}")
            got = gp.browser_login(entry, method, o["timeout"], False, None, o["fill"])
        except BaseException as e:                  # SystemExit included
            self._set("failed", f"login failed: {e}")
            return

        user = got.get(gp.H_USER, "")
        self._set("connecting", f"authenticated as {user or 'unknown'}")

        cmd = gp.build_openconnect(o["host"], user, o["gateway"], o["hip"], "socks",
                                   o["socks_port"], o["reconnect_timeout"],
                                   o["socks_bind"])
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1, env=gp.openconnect_env())
        except OSError as e:
            self._set("failed", f"could not start openconnect: {e}")
            return

        with self.lock:
            self.proc = proc
        assert proc.stdin is not None
        proc.stdin.write(got[gp.H_COOKIE] + "\n")
        proc.stdin.flush()

        assert proc.stdout is not None
        for line in proc.stdout:
            self.log(line)
            if m := RE_CONFIGURED.search(line):
                self.ip = m.group(1)
                self._set("connected", f"tunnel IP {self.ip}")
            elif m := RE_EXPIRY.search(line):
                self.expiry = m.group(1).strip()

        rc = proc.wait()
        with self.lock:
            self.proc = None
        # A terminate() from /logout is an intended stop, not a failure.
        self._set("idle" if rc in (0, -15, 143) else "failed",
                  f"openconnect exited ({rc})")

    def status(self) -> dict:
        return {
            "state": self.state,
            "detail": self.detail,
            "tunnel_ip": self.ip,
            "session_expires": self.expiry,
            "socks_port": self.opts["socks_port"],
            "portal": self.opts["host"],
            "seconds_in_state": round(time.time() - self.since),
        }


PAGE = """<!doctype html>
<meta charset="utf-8"><title>PolyGP</title>
<style>
 body{{font:15px/1.6 system-ui,sans-serif;max-width:44rem;margin:3rem auto;padding:0 1rem;
      color:#1a1a1a;background:#fbfbfa}}
 h1{{font-size:1.4rem;margin:0 0 .2rem}}
 .s{{display:inline-block;padding:.15rem .6rem;border-radius:1rem;font-size:.85rem;
     background:#e8e8e6}}
 .connected{{background:#d6f0dc}} .failed{{background:#f6d9d9}}
 table{{border-collapse:collapse;margin:1.2rem 0;width:100%}}
 td{{padding:.35rem .6rem;border-bottom:1px solid #e6e6e3;vertical-align:top}}
 td:first-child{{color:#666;width:11rem}}
 a.btn{{display:inline-block;margin-right:.5rem;padding:.4rem .9rem;border:1px solid #ccc;
        border-radius:.4rem;text-decoration:none;color:inherit;background:#fff}}
 pre{{background:#f2f2ef;padding:.8rem;border-radius:.4rem;overflow-x:auto;font-size:.8rem}}
</style>
<h1>PolyGP</h1>
<p><span class="s {state}">{state}</span> {detail}</p>
<table>
 <tr><td>portal</td><td>{portal}</td></tr>
 <tr><td>tunnel IP</td><td>{tunnel_ip}</td></tr>
 <tr><td>session expires</td><td>{session_expires}</td></tr>
 <tr><td>SOCKS5</td><td>127.0.0.1:{socks_port}</td></tr>
</table>
<p>
 <a class="btn" href="/login{q}">login</a>
 <a class="btn" href="/logout{q}">logout</a>
 <a class="btn" href="/status{q}">status (JSON)</a>
 <a class="btn" href="/logs{q}">logs</a>
</p>
<p>After <b>login</b>, complete NetID and MFA in the browser at
 <a href="{novnc}">{novnc}</a>.</p>
<pre>{tail}</pre>
"""


class Handler(BaseHTTPRequestHandler):
    tunnel: Tunnel
    token: str
    novnc: str

    def log_message(self, *a):  # keep openconnect's output readable
        pass

    def _send(self, code: int, body: str, ctype="text/html; charset=utf-8") -> None:
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _authed(self) -> bool:
        if not self.token:
            return True
        supplied = ""
        if "?" in self.path:
            from urllib.parse import parse_qs, urlparse
            supplied = (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
        return supplied == self.token or self.headers.get("X-Token") == self.token

    def do_GET(self):
        self._route()

    def do_POST(self):
        self._route()

    def _route(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if not self._authed():
            return self._send(403, "forbidden: bad or missing token", "text/plain")

        t = self.tunnel
        if path == "/status":
            return self._send(200, json.dumps(t.status(), indent=2),
                              "application/json; charset=utf-8")
        if path == "/logs":
            return self._send(200, "\n".join(t.logs), "text/plain; charset=utf-8")
        if path == "/login":
            ok, msg = t.start()
            return self._send(200 if ok else 409, self._page(msg))
        if path == "/logout":
            ok, msg = t.stop()
            return self._send(200 if ok else 409, self._page(msg))
        if path == "/":
            return self._send(200, self._page(""))
        self._send(404, "not found", "text/plain")

    def _page(self, note: str) -> str:
        s = self.tunnel.status()
        q = f"?token={self.token}" if self.token else ""
        return PAGE.format(
            state=html.escape(s["state"]),
            detail=html.escape(note or s["detail"]),
            portal=html.escape(s["portal"]),
            tunnel_ip=html.escape(s["tunnel_ip"] or "—"),
            session_expires=html.escape(s["session_expires"] or "—"),
            socks_port=s["socks_port"],
            novnc=html.escape(self.novnc),
            q=q,
            tail=html.escape("\n".join(list(self.tunnel.logs)[-25:]) or "(no output yet)"),
        )


def main() -> None:
    env = os.environ.get
    opts = {
        "host": env("PORTAL", gp.DEFAULT_HOST),
        "gateway": env("SAML_ENDPOINT", "gateway") != "portal",
        "hip": Path(env("POLYGP_HIP", str(gp.HIP_SCRIPT))),
        "socks_port": int(env("SOCKS_PORT", "11937")),
        "socks_bind": env("SOCKS_BIND_IN_CONTAINER", "0.0.0.0"),
        "timeout": int(env("LOGIN_TIMEOUT", "600")),
        "reconnect_timeout": int(env("RECONNECT_TIMEOUT", "86400")),
        "fill": env("POLYGP_NO_FILL", "") != "1",
    }
    port = int(env("CONTROL_PORT", "11936"))

    Handler.tunnel = Tunnel(opts)
    Handler.token = env("CONTROL_TOKEN", "")
    Handler.novnc = env("NOVNC_URL", f"http://<this-host>:{env('VNC_PORT', '6080')}/vnc.html")

    if env("AUTO_LOGIN", "1") == "1":
        Handler.tunnel.start()

    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[control] listening on :{port}", file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        Handler.tunnel.stop()


if __name__ == "__main__":
    main()
