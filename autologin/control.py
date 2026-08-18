#!/usr/bin/env python3
"""HTTP control plane for the PolyGP container.

Turns the one-shot script into a long-lived service. Without it the container is
a single connection attempt that dies with the session; with it the tunnel is
something you start, stop and inspect from one page:

    GET  /            the control panel; every action is a button on it
    GET  /status      JSON: state, tunnel IP, session expiry, socks port
    POST /login       begin a SAML login; drive the browser via noVNC
    POST /logout      disconnect and go back to idle
    POST /reload      re-read the mounted .env, applied at the next login
    GET  /logs        recent openconnect output

The action endpoints answer GET too, redirecting back to the panel, so they can
be poked from a URL bar. The login itself still happens in the browser on the
container's virtual display: /login opens the PolyU page there and returns, then
you finish NetID + MFA over noVNC. With credentials configured the form is
filled in, and POLYGP_VPN_CHOICE picks the service option that follows.

Set $CONTROL_TOKEN to require ?token=... on every request — worth doing once the
port is reachable by anyone but you, since these endpoints control the VPN and
can log in with stored credentials.
"""
from __future__ import annotations

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
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gp_saml_login as gp

# openconnect announces these once the tunnel is up; worth surfacing as status.
RE_CONFIGURED = re.compile(r"Configured as ([0-9a-fA-F:.]+)")
RE_EXPIRY = re.compile(r"Session authentication will expire at (.+)")


def load_env_file(path: Path) -> dict[str, str]:
    """Parse a KEY=VALUE .env file. Not a shell: no expansion, no exports."""
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k] = v
    return out


def build_opts() -> dict:
    env = os.environ.get
    return {
        "host": env("PORTAL", gp.DEFAULT_HOST),
        "gateway": env("SAML_ENDPOINT", "gateway") != "portal",
        "hip": Path(env("POLYGP_HIP", str(gp.HIP_SCRIPT))),
        "socks_port": int(env("SOCKS_PORT", "11937")),
        "socks_bind": env("SOCKS_BIND_IN_CONTAINER", "0.0.0.0"),
        "timeout": int(env("LOGIN_TIMEOUT", "600")),
        "reconnect_timeout": int(env("RECONNECT_TIMEOUT", "86400")),
        "fill": env("POLYGP_NO_FILL", "") != "1",
        "choice": env("POLYGP_VPN_CHOICE", "") or None,
    }


class Tunnel:
    """Owns the login thread and the openconnect process, and their state."""

    def __init__(self, opts: dict) -> None:
        self.opts = opts
        self.lock = threading.Lock()
        self.proc: subprocess.Popen | None = None
        self.state = "idle"          # idle|awaiting-login|connecting|connected|failed
        self.detail = ""
        self.ip = ""
        self.expiry = ""
        self.since = time.time()
        self.logs: deque[str] = deque(maxlen=400)

    def _set(self, state: str, detail: str = "") -> None:
        self.state, self.detail, self.since = state, detail, time.time()
        self.log(f"[control] state -> {state}" + (f": {detail}" if detail else ""))

    def log(self, line: str) -> None:
        for part in str(line).rstrip().splitlines() or [""]:
            self.logs.append(part)
        print(str(line).rstrip(), file=sys.stderr, flush=True)

    def busy(self) -> bool:
        return self.state in ("awaiting-login", "connecting", "connected")

    def start(self) -> tuple[bool, str]:
        with self.lock:
            if self.busy():
                return False, f"already {self.state}"
            self._set("awaiting-login", "opening the browser")
            self.ip = self.expiry = ""
            threading.Thread(target=self._run, daemon=True).start()
            return True, "login started — finish it in the browser over noVNC"

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
            # The browser thread is blocked on a login that is not coming; it
            # gives up on its own timeout.
            self._set("idle", "login abandoned")
            return True, "login cancelled (the browser closes at its timeout)"
        return False, "not connected"

    def reload(self) -> tuple[bool, str]:
        path = Path(os.environ.get("POLYGP_ENV_FILE", "/opt/polygp/.env"))
        if not path.is_file():
            return False, f"no env file at {path}"
        try:
            values = load_env_file(path)
        except OSError as e:
            return False, f"could not read {path}: {e}"
        os.environ.update(values)
        self.opts = build_opts()
        self.log(f"[control] reloaded {len(values)} settings from {path}")
        note = "reloaded; applies to the next login"
        if self.state == "connected":
            note += " (the current tunnel keeps its old settings)"
        return True, note

    def _run(self) -> None:
        o = self.opts
        try:
            method, entry = gp.prelogin(o["host"], o["gateway"])
            self.log(f"[control] SAML {method} via {entry.split('?')[0]}")
            got = gp.browser_login(entry, method, o["timeout"], False, None,
                                   o["fill"], o["choice"])
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
            "vpn_choice": self.opts["choice"] or "",
            "seconds_in_state": round(time.time() - self.since),
            "logs": list(self.logs)[-40:],
        }


PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PolyGP</title>
<style>
:root{
  --bg:#eef2f5; --card:#fff; --ink:#33414c; --muted:#7d8b96; --line:#dde5ea;
  --blue:#8fabc2; --blue-deep:#6f8fa8; --blue-soft:#e4ecf2;
  --ok:#9db89f; --ok-soft:#e6efe6; --bad:#c39189; --bad-soft:#f4e5e3;
  --warn:#c9b18c; --warn-soft:#f4ece0;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
     font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif}
main{max-width:46rem;margin:0 auto;padding:3rem 1.25rem 4rem}
header{margin-bottom:1.75rem}
h1{margin:0;font-size:1.55rem;font-weight:600;letter-spacing:-.01em}
.portal{color:var(--muted);font-size:.92rem;margin-top:.15rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:.75rem;
      padding:1.25rem 1.4rem;margin-bottom:1.1rem}
.statusline{display:flex;align-items:center;gap:.7rem;flex-wrap:wrap}
.pill{display:inline-flex;align-items:center;gap:.45rem;padding:.28rem .8rem;
      border-radius:2rem;font-size:.86rem;font-weight:500;
      background:var(--blue-soft);color:var(--blue-deep)}
.pill::before{content:"";width:.5rem;height:.5rem;border-radius:50%;
              background:currentColor;opacity:.75}
.pill.connected{background:var(--ok-soft);color:#5c7a5f}
.pill.failed{background:var(--bad-soft);color:#9c5f56}
.pill[data-s="awaiting-login"],.pill[data-s="connecting"]{background:var(--warn-soft);color:#8a7047}
.detail{color:var(--muted);font-size:.9rem}
dl{display:grid;grid-template-columns:auto 1fr;gap:.55rem 1.4rem;margin:1.15rem 0 0}
dt{color:var(--muted);font-size:.88rem}
dd{margin:0;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.actions{display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:1.1rem}
button{font:inherit;font-size:.93rem;padding:.55rem 1.15rem;border-radius:.55rem;
       border:1px solid var(--line);background:#fff;color:var(--ink);cursor:pointer;
       transition:background .15s,border-color .15s,opacity .15s}
button:hover:not(:disabled){background:var(--blue-soft);border-color:var(--blue)}
button.primary{background:var(--blue);border-color:var(--blue);color:#fff}
button.primary:hover:not(:disabled){background:var(--blue-deep);border-color:var(--blue-deep)}
button:disabled{opacity:.45;cursor:default}
.note{min-height:1.3rem;font-size:.9rem;color:var(--blue-deep);margin:0 0 1.1rem}
.hint{color:var(--muted);font-size:.9rem;margin:0 0 1.1rem}
a{color:var(--blue-deep)}
h2{font-size:.82rem;text-transform:uppercase;letter-spacing:.07em;
   color:var(--muted);font-weight:600;margin:0 0 .7rem}
pre{margin:0;background:#f6f8fa;border:1px solid var(--line);border-radius:.5rem;
    padding:.85rem 1rem;font-size:.79rem;line-height:1.55;max-height:19rem;
    overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;color:#4a5862}
</style></head><body><main>
<header>
  <h1>PolyGP</h1>
  <div class="portal" id="portal">&nbsp;</div>
</header>

<div class="card">
  <div class="statusline">
    <span class="pill" id="pill">loading</span>
    <span class="detail" id="detail"></span>
  </div>
  <dl>
    <dt>Tunnel IP</dt><dd id="ip">—</dd>
    <dt>Session expires</dt><dd id="exp">—</dd>
    <dt>SOCKS5</dt><dd id="socks">—</dd>
    <dt>VPN choice</dt><dd id="choice">—</dd>
  </dl>
</div>

<div class="actions">
  <button class="primary" id="b-login">Log in</button>
  <button id="b-logout">Disconnect</button>
  <button id="b-reload">Reload .env</button>
</div>
<p class="note" id="note"></p>

<p class="hint">Finish NetID and MFA in the browser at
  <a href="__NOVNC__" target="_blank" rel="noreferrer">__NOVNC__</a>.</p>

<div class="card">
  <h2>Recent output</h2>
  <pre id="logs">—</pre>
</div>

<script>
const Q = "__TOKEN_QUERY__";
const $ = id => document.getElementById(id);
let busy = false;

function render(s){
  $("portal").textContent = s.portal;
  const pill = $("pill");
  pill.textContent = s.state;
  pill.className = "pill " + s.state;
  pill.dataset.s = s.state;
  $("detail").textContent = s.detail || "";
  $("ip").textContent = s.tunnel_ip || "—";
  $("exp").textContent = s.session_expires || "—";
  $("socks").textContent = "127.0.0.1:" + s.socks_port;
  $("choice").textContent = s.vpn_choice || "—";
  $("logs").textContent = (s.logs || []).join("\n") || "—";
  const connected = s.state === "connected";
  const active = connected || s.state === "awaiting-login" || s.state === "connecting";
  $("b-login").disabled = busy || active;
  $("b-logout").disabled = busy || !active;
  $("b-reload").disabled = busy;
}

async function poll(){
  try{ render(await (await fetch("/status" + Q)).json()); }catch(e){}
}

async function act(name){
  busy = true; $("note").textContent = "…";
  try{
    const r = await fetch("/" + name + Q, {
      method: "POST", headers: {"Accept": "application/json"}
    });
    const d = await r.json();
    $("note").textContent = d.message || "";
  }catch(e){
    $("note").textContent = "request failed: " + e;
  }
  busy = false;
  await poll();
}

$("b-login").onclick  = () => act("login");
$("b-logout").onclick = () => act("logout");
$("b-reload").onclick = () => act("reload");
poll(); setInterval(poll, 2500);
</script>
</main></body></html>
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
        q = parse_qs(urlparse(self.path).query).get("token") or [""]
        return q[0] == self.token or self.headers.get("X-Token") == self.token

    def _wants_json(self) -> bool:
        return "application/json" in (self.headers.get("Accept") or "")

    def do_GET(self):
        self._route()

    def do_POST(self):
        self._route()

    def _result(self, ok: bool, msg: str) -> None:
        """JSON for the panel's fetch; a redirect for a hand-typed URL."""
        if self._wants_json():
            return self._send(200 if ok else 409, json.dumps({"ok": ok, "message": msg}),
                              "application/json; charset=utf-8")
        self.send_response(303)
        self.send_header("Location", "/" + (f"?token={self.token}" if self.token else ""))
        self.end_headers()

    def _route(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        if not self._authed():
            return self._send(403, "forbidden: bad or missing token", "text/plain")

        t = self.tunnel
        if path == "/status":
            return self._send(200, json.dumps(t.status(), indent=2),
                              "application/json; charset=utf-8")
        if path == "/logs":
            return self._send(200, "\n".join(t.logs), "text/plain; charset=utf-8")
        if path == "/login":
            return self._result(*t.start())
        if path == "/logout":
            return self._result(*t.stop())
        if path == "/reload":
            return self._result(*t.reload())
        if path == "/":
            page = (PAGE.replace("__NOVNC__", self.novnc)
                        .replace("__TOKEN_QUERY__", f"?token={self.token}" if self.token else ""))
            return self._send(200, page)
        self._send(404, "not found", "text/plain")


def main() -> None:
    env = os.environ.get
    Handler.tunnel = Tunnel(build_opts())
    Handler.token = env("CONTROL_TOKEN", "")
    Handler.novnc = env("NOVNC_URL", f"http://{env('PUBLIC_HOST', 'localhost')}:"
                                     f"{env('VNC_PORT', '6080')}/vnc.html")
    port = int(env("CONTROL_PORT", "11936"))

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
