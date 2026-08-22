#!/usr/bin/env python3
"""HTTP control plane for the PolyGP container.

Turns the one-shot script into a long-lived service. Without it the container is
a single connection attempt that dies with the session; with it the tunnel is
something you start, stop and inspect from one page:

    GET  /            the control panel; every action is a button on it
    GET  /status      JSON: state, tunnel IP, session expiry, socks port
    POST /login       begin a SAML login; drive the browser via noVNC
    POST /renew       drop the session and start a fresh login right away
    POST /code        type an MFA/verification code into the login page
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
        # Bumped on every start(); a _run() thread checks it against the value it
        # was handed and goes quiet once a newer run has superseded it, so an old
        # thread winding down after /renew's stop() can't clobber the new one's
        # state.
        self.generation = 0
        # Mailbox for typing an MFA code from the panel; replaced on every
        # start() so a code left over from an abandoned attempt cannot leak
        # into the next one.
        self.feed = gp.LoginFeed()

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
            self.generation += 1
            gen = self.generation
            self._set("awaiting-login", "opening the browser")
            self.ip = self.expiry = ""
            self.feed = gp.LoginFeed()
            threading.Thread(target=self._run, args=(gen, self.feed),
                             daemon=True).start()
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
            # Set synchronously (rather than leaving it to _run()'s tail, which
            # only notices once the closed stdout pipe unblocks it) so a stop()
            # immediately followed by start() — as renew() does — does not find
            # a stale "connected" and refuse.
            self._set("idle", "disconnected")
            return True, "disconnected"
        if self.state == "awaiting-login":
            # The browser thread is blocked on a login that is not coming; it
            # gives up on its own timeout.
            self._set("idle", "login abandoned")
            return True, "login cancelled (the browser closes at its timeout)"
        return False, "not connected"

    def renew(self) -> tuple[bool, str]:
        """Disconnect (if connected) and start a fresh login — for a session near expiry."""
        self.stop()
        return self.start()

    def submit_code(self, code: str) -> tuple[bool, str]:
        """Queue an MFA code for the login thread to type into the page."""
        code = (code or "").strip()
        if not code:
            return False, "empty code"
        if len(code) > 32:
            return False, "that does not look like a verification code"
        if self.state != "awaiting-login":
            return False, f"no login waiting for input (state: {self.state})"
        self.feed.offer(code)
        self.log("[control] verification code received from the panel")
        return True, "code sent — it is typed in as soon as the field is on the page"

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

    def _run(self, gen: int, feed: gp.LoginFeed) -> None:
        o = self.opts
        try:
            method, entry = gp.prelogin(o["host"], o["gateway"])
            self.log(f"[control] SAML {method} via {entry.split('?')[0]}")
            got = gp.browser_login(entry, method, o["timeout"], False, None,
                                   o["fill"], o["choice"], feed)
        except BaseException as e:                  # SystemExit included
            if gen == self.generation:
                self._set("failed", f"login failed: {e}")
            return

        if gen != self.generation:
            return  # a newer /login or /renew superseded this attempt

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
            if gen == self.generation:
                self._set("failed", f"could not start openconnect: {e}")
            return

        with self.lock:
            if gen != self.generation:
                proc.terminate()  # superseded before we even got to hand off the cookie
                return
            self.proc = proc
        assert proc.stdin is not None
        proc.stdin.write(got[gp.H_COOKIE] + "\n")
        proc.stdin.flush()

        assert proc.stdout is not None
        for line in proc.stdout:
            self.log(line)
            if gen != self.generation:
                continue  # keep draining the pipe, but a newer run now owns state
            if m := RE_CONFIGURED.search(line):
                self.ip = m.group(1)
                self._set("connected", f"tunnel IP {self.ip}")
            elif m := RE_EXPIRY.search(line):
                self.expiry = m.group(1).strip()

        rc = proc.wait()
        if gen == self.generation:
            with self.lock:
                self.proc = None
            # A terminate() from /logout or /renew is an intended stop, not a failure.
            self._set("idle" if rc in (0, -15, 143) else "failed",
                      f"openconnect exited ({rc})")

    def status(self) -> dict:
        o = self.opts
        return {
            "state": self.state,
            "detail": self.detail,
            "tunnel_ip": self.ip,
            "session_expires": self.expiry,
            "socks_port": o["socks_port"],
            "portal": o["host"],
            "vpn_choice": o["choice"] or "",
            "seconds_in_state": round(time.time() - self.since),
            "logs": list(self.logs)[-40:],
            # What the login page is asking for right now, so the panel can
            # take an MFA code without the noVNC round-trip.
            "mfa": self.feed.snapshot(),
            # The panel builds its own noVNC link so it works from whatever host
            # you reached this page on, and carries the password so nobody has
            # to retype it. Anyone who can load the panel can therefore reach
            # the browser session too — set CONTROL_TOKEN if that matters.
            "vnc": {
                "port": int(os.environ.get("VNC_PORT", "6080")),
                "password": os.environ.get("VNC_PASSWORD", ""),
                "url": os.environ.get("NOVNC_URL", ""),
            },
            # Shown on the settings pane, so what the container actually runs
            # with is visible without reading compose or docker inspect.
            "config": {
                "portal": o["host"],
                "SAML endpoint": "gateway" if o["gateway"] else "portal",
                "SOCKS port": o["socks_port"],
                "VPN choice": o["choice"] or "(none)",
                "auto-fill credentials": "on" if o["fill"] else "off",
                "NetID": os.environ.get("POLYGP_NETID") or "(not set)",
                "login timeout": f"{o['timeout']}s",
                "reconnect window": f"{o['reconnect_timeout']}s",
                "HIP script": str(o["hip"]),
                "env file": os.environ.get("POLYGP_ENV_FILE", "/opt/polygp/.env"),
            },
        }


PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PolyGP</title>
<style>
:root{
  --bg:#eef2f5; --card:#fff; --side:#f6f9fb; --ink:#33414c; --muted:#7d8b96;
  --line:#dde5ea; --blue:#8fabc2; --blue-deep:#6f8fa8; --blue-soft:#e4ecf2;
  --ok:#e6efe6; --ok-ink:#5c7a5f; --bad:#f4e5e3; --bad-ink:#9c5f56;
  --warn:#f4ece0; --warn-ink:#8a7047;
}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--ink);
     font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif}
.app{display:grid;grid-template-columns:15.5rem 1fr;gap:1.1rem;
     max-width:64rem;margin:0 auto;padding:1.6rem 1.25rem;min-height:100%}

aside{background:var(--side);border:1px solid var(--line);border-radius:.75rem;
      padding:1.15rem 1rem;display:flex;flex-direction:column;gap:.9rem;
      align-self:start;position:sticky;top:1.6rem}
.brand{font-size:1.2rem;font-weight:600;letter-spacing:-.01em}
.portal{color:var(--muted);font-size:.85rem;margin-top:-.65rem;overflow-wrap:anywhere}
.pill{display:inline-flex;align-items:center;gap:.45rem;padding:.26rem .75rem;
      border-radius:2rem;font-size:.84rem;font-weight:500;align-self:flex-start;
      background:var(--blue-soft);color:var(--blue-deep)}
.pill::before{content:"";width:.48rem;height:.48rem;border-radius:50%;
              background:currentColor;opacity:.75}
.pill.connected{background:var(--ok);color:var(--ok-ink)}
.pill.failed{background:var(--bad);color:var(--bad-ink)}
.pill[data-s="awaiting-login"],.pill[data-s="connecting"]{background:var(--warn);color:var(--warn-ink)}

nav{display:flex;flex-direction:column;gap:.15rem;border-top:1px solid var(--line);
    padding-top:.9rem}
nav button{text-align:left;background:none;border:0;border-radius:.45rem;
           padding:.48rem .65rem;font:inherit;font-size:.93rem;color:var(--ink);
           cursor:pointer;transition:background .12s,color .12s}
nav button:hover{background:var(--blue-soft)}
nav button.active{background:var(--blue-soft);color:var(--blue-deep);font-weight:600}

.acts{display:flex;flex-direction:column;gap:.45rem;border-top:1px solid var(--line);
      padding-top:.9rem}
button.act{font:inherit;font-size:.92rem;padding:.5rem 1rem;border-radius:.5rem;
      border:1px solid var(--line);background:#fff;color:var(--ink);cursor:pointer;
      transition:background .15s,border-color .15s,opacity .15s}
button.act:hover:not(:disabled){background:var(--blue-soft);border-color:var(--blue)}
button.act.primary{background:var(--blue);border-color:var(--blue);color:#fff}
button.act.primary:hover:not(:disabled){background:var(--blue-deep);border-color:var(--blue-deep)}
button.act:disabled{opacity:.42;cursor:default}
.note{min-height:1.2rem;font-size:.85rem;color:var(--blue-deep);margin:0}

.content{background:var(--card);border:1px solid var(--line);border-radius:.75rem;
         padding:1.5rem 1.7rem;min-width:0}
.pane{display:none}
.pane.active{display:block}
h2{font-size:1.02rem;font-weight:600;margin:0 0 1.1rem}
dl{display:grid;grid-template-columns:auto 1fr;gap:.6rem 1.5rem;margin:0}
dt{color:var(--muted);font-size:.89rem}
dd{margin:0;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.hint{color:var(--muted);font-size:.89rem;margin:1.3rem 0 0}
a{color:var(--blue-deep)}
pre{margin:0;background:#f6f8fa;border:1px solid var(--line);border-radius:.5rem;
    padding:.85rem 1rem;font-size:.79rem;line-height:1.55;max-height:32rem;
    overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;color:#4a5862}
.big{display:inline-block;background:var(--blue);color:#fff;text-decoration:none;
     font-size:1.05rem;font-weight:600;padding:.95rem 1.9rem;border-radius:.6rem;
     transition:background .15s}
.big:hover{background:var(--blue-deep)}
.mfa{display:none;margin:0 0 1.3rem;padding:1rem 1.15rem;border:1px solid var(--line);
     border-radius:.6rem;background:var(--blue-soft)}
.mfa.show{display:block}
.mfa .row{display:flex;gap:.6rem}
.mfa input{flex:1;min-width:0;font:inherit;font-size:1.1rem;letter-spacing:.14em;
           font-variant-numeric:tabular-nums;padding:.55rem .85rem;
           border:1px solid var(--line);border-radius:.5rem;background:#fff;
           color:var(--ink)}
.mfa input:focus{outline:2px solid var(--blue);outline-offset:1px}
.mfa .hint{margin:.6rem 0 0}
iframe{width:100%;height:34rem;border:1px solid var(--line);border-radius:.5rem;
       background:#fff}
@media (max-width:44rem){
  .app{grid-template-columns:1fr}
  aside{position:static}
  nav{flex-direction:row;flex-wrap:wrap}
  .acts{flex-direction:row}
}
</style></head><body>
<div class="app">
  <aside>
    <div class="brand">PolyGP</div>
    <div class="portal" id="portal">&nbsp;</div>
    <span class="pill" id="pill">loading</span>
    <nav>
      <button data-pane="overview" class="active">Overview</button>
      <button data-pane="browser">Browser</button>
      <button data-pane="logs">Logs</button>
      <button data-pane="settings">Settings</button>
    </nav>
    <div class="acts">
      <button class="act primary" id="b-login">Log in</button>
      <button class="act" id="b-renew" title="Disconnect and log in again — for a session near expiry">Renew</button>
      <button class="act" id="b-logout">Disconnect</button>
    </div>
    <p class="note" id="note"></p>
  </aside>

  <section class="content">
    <div class="pane active" id="p-overview">
      <h2>Overview</h2>
      <dl>
        <dt>State</dt><dd id="o-state">—</dd>
        <dt>Detail</dt><dd id="o-detail">—</dd>
        <dt>Tunnel IP</dt><dd id="o-ip">—</dd>
        <dt>Session expires</dt><dd id="o-exp">—</dd>
        <dt>SOCKS5</dt><dd id="o-socks">—</dd>
        <dt>VPN choice</dt><dd id="o-choice">—</dd>
      </dl>
      <p class="hint">Point your proxy tool at the SOCKS5 address above. Nothing on
        this machine is rerouted on its own.</p>
    </div>

    <div class="pane" id="p-browser">
      <h2>Browser</h2>
      <div class="mfa" id="mfa">
        <div class="row">
          <input id="mfa-code" inputmode="numeric" autocomplete="one-time-code"
                 placeholder="Verification code" maxlength="32">
          <button class="act primary" id="b-code">Send</button>
        </div>
        <p class="hint" id="mfa-hint"></p>
      </div>
      <a class="big" id="novnc-open" href="#" target="_blank" rel="noreferrer">
        Open the login browser &nbsp;&rarr;</a>
      <p class="hint" style="margin:.9rem 0 1.1rem">The link signs in to VNC for
        you. Use it in a separate tab if the frame below will not take keyboard
        focus.</p>
      <iframe id="novnc" title="noVNC" src="about:blank"></iframe>
    </div>

    <div class="pane" id="p-logs">
      <h2>Recent output</h2>
      <pre id="logs">—</pre>
    </div>

    <div class="pane" id="p-settings">
      <h2>Settings</h2>
      <dl id="cfg"></dl>
      <p class="hint">Edit <code>.env</code> on the host, then reload. Changes take
        effect at the next login; a tunnel already up keeps its own settings.</p>
      <div class="acts" style="border:0;padding-top:.9rem">
        <button class="act" id="b-reload" style="align-self:flex-start">Reload .env</button>
      </div>
    </div>
  </section>
</div>

<script>
const Q = "__TOKEN_QUERY__";
let novncUrl = "";
const $ = id => document.getElementById(id);
let busy = false, pane = "overview", framed = false;

document.querySelectorAll("nav button").forEach(b => b.onclick = () => {
  pane = b.dataset.pane;
  document.querySelectorAll("nav button").forEach(x => x.classList.toggle("active", x === b));
  document.querySelectorAll(".pane").forEach(p => p.classList.toggle("active", p.id === "p-" + pane));
  if (pane === "browser" && !framed && novncUrl) { $("novnc").src = novncUrl; framed = true; }
});

function render(s){
  $("portal").textContent = s.portal;
  const pill = $("pill");
  pill.textContent = s.state;
  pill.className = "pill " + s.state;
  pill.dataset.s = s.state;
  $("o-state").textContent  = s.state;
  $("o-detail").textContent = s.detail || "—";
  $("o-ip").textContent     = s.tunnel_ip || "—";
  $("o-exp").textContent    = s.session_expires || "—";
  $("o-socks").textContent  = "127.0.0.1:" + s.socks_port;
  $("o-choice").textContent = s.vpn_choice || "—";
  $("logs").textContent     = (s.logs || []).join("\n") || "—";

  // Built here rather than server-side so the host matches however you reached
  // this page — localhost, a tailnet address, a cloud domain — and so the VNC
  // password rides along instead of being retyped.
  const v = s.vnc || {};
  novncUrl = v.url || (location.protocol + "//" + location.hostname + ":" + v.port +
    "/vnc.html?autoconnect=1&resize=scale&reconnect=1" +
    (v.password ? "&password=" + encodeURIComponent(v.password) : ""));
  $("novnc-open").href = novncUrl;
  if (pane === "browser" && !framed) { $("novnc").src = novncUrl; framed = true; }

  const cfg = $("cfg");
  cfg.textContent = "";
  for (const [k, v] of Object.entries(s.config || {})){
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd"); dd.textContent = v;
    cfg.append(dt, dd);
  }

  const active = ["connected","awaiting-login","connecting"].includes(s.state);
  $("b-login").disabled  = busy || active;
  $("b-renew").disabled  = busy || !active;
  $("b-logout").disabled = busy || !active;
  $("b-reload").disabled = busy;

  // MFA code entry: faster than typing through the VNC round-trip. Shown only
  // while a login is waiting; the code is queued server-side and typed into
  // the page the moment a code field is there, so it can be entered early.
  const m = s.mfa || {};
  const awaiting = s.state === "awaiting-login";
  $("mfa").classList.toggle("show", awaiting);
  $("b-code").disabled = busy || !awaiting;
  $("mfa-hint").textContent = !awaiting ? "" :
    m.pending ? "Code queued — it is typed in as soon as the field appears." :
    m.prompt  ? "The page is asking for: " + m.prompt :
    "No code field on the page yet. You can send the code early; it is typed in the moment the field appears. The browser view below stays available as a fallback.";
}

async function poll(){
  try{ render(await (await fetch("/status" + Q)).json()); }catch(e){}
}

async function act(name){
  busy = true; $("note").textContent = "…";
  try{
    const r = await fetch("/" + name + Q, {method:"POST", headers:{"Accept":"application/json"}});
    $("note").textContent = (await r.json()).message || "";
  }catch(e){ $("note").textContent = "request failed: " + e; }
  busy = false;
  await poll();
}

async function sendCode(){
  const v = $("mfa-code").value.trim();
  if (!v) return;
  busy = true; $("note").textContent = "…";
  try{
    const r = await fetch("/code" + Q, {method:"POST",
      headers:{"Accept":"application/json",
               "Content-Type":"application/x-www-form-urlencoded"},
      body:"code=" + encodeURIComponent(v)});
    const j = await r.json();
    $("note").textContent = j.message || "";
    if (j.ok) $("mfa-code").value = "";
  }catch(e){ $("note").textContent = "request failed: " + e; }
  busy = false;
  await poll();
}

$("b-login").onclick  = () => act("login");
$("b-renew").onclick  = () => act("renew");
$("b-logout").onclick = () => act("logout");
$("b-reload").onclick = () => act("reload");
$("b-code").onclick   = sendCode;
$("mfa-code").addEventListener("keydown", e => { if (e.key === "Enter") sendCode(); });
poll(); setInterval(poll, 2500);
</script>
</body></html>
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
        if path == "/renew":
            return self._result(*t.renew())
        if path == "/code":
            code = (parse_qs(urlparse(self.path).query).get("code") or [""])[0]
            if not code and self.command == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
                code = (parse_qs(body).get("code") or [""])[0]
            return self._result(*t.submit_code(code))
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
