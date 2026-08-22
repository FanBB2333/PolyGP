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
    POST /fill        fill + submit the credential form (manual fill mode)
    POST /set         change one option (key/value), applied at the next login
    POST /save        change several options at once (form fields by name)
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
    # POLYGP_FILL_MODE: auto (fill + submit on login start), manual (only after
    # the panel's Fill button), off. POLYGP_NO_FILL=1 is the older off switch.
    fill_mode = env("POLYGP_FILL_MODE", "").strip().lower()
    if fill_mode not in ("auto", "manual", "off"):
        fill_mode = "off" if env("POLYGP_NO_FILL", "") == "1" else "auto"
    return {
        "host": env("PORTAL", gp.DEFAULT_HOST),
        "gateway": env("SAML_ENDPOINT", "gateway") != "portal",
        "hip": Path(env("POLYGP_HIP", str(gp.HIP_SCRIPT))),
        "socks_port": int(env("SOCKS_PORT", "11937")),
        "socks_bind": env("SOCKS_BIND_IN_CONTAINER", "0.0.0.0"),
        "timeout": int(env("LOGIN_TIMEOUT", "600")),
        "reconnect_timeout": int(env("RECONNECT_TIMEOUT", "86400")),
        "fill_mode": fill_mode,
        "choice": env("POLYGP_VPN_CHOICE", "") or None,
    }


# What /set and /save may change, and how a value is validated. Everything
# here is an in-memory override: it applies to the next login and survives
# until the container restarts or /reload re-reads .env over it. The
# persistent place for these is still the mounted .env.
SETTABLE = {
    "portal": ("PORTAL", "host"),
    "saml_endpoint": ("SAML_ENDPOINT", ("gateway", "portal")),
    "vpn_choice": ("POLYGP_VPN_CHOICE", None),          # free text; empty = pick by hand
    "fill_mode": ("POLYGP_FILL_MODE", ("auto", "manual", "off")),
    "netid": ("POLYGP_NETID", None),
    "netpass": ("POLYGP_NETPASS", None),                # empty = keep the stored one
    "login_timeout": ("LOGIN_TIMEOUT", "int"),
    "reconnect_timeout": ("RECONNECT_TIMEOUT", "int"),
}


def _validate_option(key: str, value: str) -> str | None:
    """None if `value` is acceptable for `key`, else the complaint."""
    _, allowed = SETTABLE[key]
    if allowed == "int":
        if not value.isdigit() or not 0 < int(value) <= 604800:
            return f"{key} needs a number of seconds"
    elif allowed == "host":
        if not re.fullmatch(r"[A-Za-z0-9.\-:]+", value or ""):
            return "portal must be a bare hostname (no scheme, no spaces)"
    elif allowed is not None and value not in allowed:
        return f"{key} must be one of {', '.join(allowed)}"
    return None


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
        # Options seen on the login pages (PolyU's service-selection step
        # among them), kept after the login ends so the settings dropdown can
        # suggest the real texts instead of a guess.
        self.vpn_options: list[str] = []

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

    def request_fill(self) -> tuple[bool, str]:
        """Trigger the credential prefill from the panel (manual fill mode)."""
        if self.state != "awaiting-login":
            return False, f"no login waiting for input (state: {self.state})"
        if self.opts["fill_mode"] == "off":
            return False, "credential fill is switched off in the settings"
        self.feed.request_fill()
        return True, "filling the credential form and submitting"

    def set_option(self, key: str, value: str) -> tuple[bool, str]:
        """Change one whitelisted option; takes effect at the next login."""
        return self.save_options({key: value})

    def save_options(self, pairs: dict[str, str]) -> tuple[bool, str]:
        """Validate a batch of options, then apply them all or none."""
        cleaned: dict[str, str] = {}
        for key, value in pairs.items():
            if key not in SETTABLE:
                return False, f"unknown option {key!r}"
            value = (value or "").strip()
            if key == "netpass" and not value:
                continue  # an empty password field means "keep the stored one"
            if err := _validate_option(key, value):
                return False, err
            cleaned[key] = value
        if not cleaned:
            return False, "nothing to save"
        for key, value in cleaned.items():
            os.environ[SETTABLE[key][0]] = value
            self.log(f"[control] {key} set"
                     + ("" if key == "netpass" else f" to {value!r}"))
        self.opts = build_opts()
        what = ", ".join(cleaned)
        note = f"saved {what} — applies to the next login"
        if self.state == "connected":
            note += " (the current tunnel keeps its old settings)"
        return True, note

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
                                   o["fill_mode"], o["choice"], feed)
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
        mfa = self.feed.snapshot()
        # Remember the last non-empty sighting; the login page moves on (or
        # the login ends) but the suggestions should stay.
        if choices := mfa.pop("choices", []):
            self.vpn_options = choices
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
            "mfa": mfa,
            # The options the panel can change through /set and /save. The
            # password itself is never reported — only whether one is stored.
            "settings": {
                "portal": o["host"],
                "saml_endpoint": "gateway" if o["gateway"] else "portal",
                "vpn_choice": o["choice"] or "",
                "fill_mode": o["fill_mode"],
                "netid": os.environ.get("POLYGP_NETID", ""),
                "netpass_set": bool(os.environ.get("POLYGP_NETPASS")),
                # Suggestions for the VPN service field: what the login pages
                # actually offered last time (buttons/radios/options), so the
                # dropdown lists PolyU's real texts rather than a guess.
                "vpn_options": self.vpn_options,
                "login_timeout": str(o["timeout"]),
                "reconnect_timeout": str(o["reconnect_timeout"]),
            },
            # The panel builds its own noVNC link so it works from whatever host
            # you reached this page on, and carries the password so nobody has
            # to retype it. Anyone who can load the panel can therefore reach
            # the browser session too — set CONTROL_TOKEN if that matters.
            "vnc": {
                "port": int(os.environ.get("VNC_PORT", "6080")),
                "password": os.environ.get("VNC_PASSWORD", ""),
                "url": os.environ.get("NOVNC_URL", ""),
            },
            # Read-only facts for the settings pane (the adjustable ones are
            # in "settings" above, rendered as form fields instead).
            "config": {
                "SOCKS port": o["socks_port"],
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
.note{min-height:1.2rem;font-size:.85rem;color:var(--blue-deep);margin:0;
      border-top:1px solid var(--line);padding-top:.9rem}

.content{background:var(--card);border:1px solid var(--line);border-radius:.75rem;
         padding:1.5rem 1.7rem;min-width:0}
.pane{display:none}
.pane.active{display:block}
h2{font-size:1.02rem;font-weight:600;margin:0 0 1.1rem}
dl{display:grid;grid-template-columns:auto 1fr;gap:.6rem 1.5rem;margin:0}
dt{color:var(--muted);font-size:.89rem}
dd{margin:0;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.hint{color:var(--muted);font-size:.89rem;margin:1rem 0 0}
a{color:var(--blue-deep)}
pre{margin:0;background:#f6f8fa;border:1px solid var(--line);border-radius:.5rem;
    padding:.85rem 1rem;font-size:.79rem;line-height:1.55;max-height:32rem;
    overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;color:#4a5862}
button.act{font:inherit;font-size:.92rem;padding:.55rem 1.15rem;border-radius:.5rem;
      border:1px solid var(--line);background:#fff;color:var(--ink);cursor:pointer;
      transition:background .15s,border-color .15s,opacity .15s}
button.act:hover:not(:disabled){background:var(--blue-soft);border-color:var(--blue)}
button.act.primary{background:var(--blue);border-color:var(--blue);color:#fff}
button.act.primary:hover:not(:disabled){background:var(--blue-deep);border-color:var(--blue-deep)}
button.act:disabled{opacity:.42;cursor:default}
.big{display:inline-block;background:var(--blue);color:#fff;text-decoration:none;
     font-size:1.05rem;font-weight:600;padding:.95rem 1.9rem;border-radius:.6rem;
     transition:background .15s}
.big:hover{background:var(--blue-deep)}
iframe{width:100%;height:34rem;border:1px solid var(--line);border-radius:.5rem;
       background:#fff}

/* Overview dashboard */
.hero{border:1px solid var(--line);border-radius:.7rem;padding:1.1rem 1.3rem;
      margin:0 0 1rem;background:var(--blue-soft)}
.hero.connected{background:var(--ok)}
.hero.failed{background:var(--bad)}
.hero[data-s="awaiting-login"],.hero[data-s="connecting"]{background:var(--warn)}
.hero-state{font-size:1.3rem;font-weight:650;display:flex;align-items:center;
            gap:.6rem;color:var(--blue-deep)}
.hero.connected .hero-state{color:var(--ok-ink)}
.hero.failed .hero-state{color:var(--bad-ink)}
.hero[data-s="awaiting-login"] .hero-state,.hero[data-s="connecting"] .hero-state{color:var(--warn-ink)}
.hero-state .dot{width:.65rem;height:.65rem;border-radius:50%;background:currentColor}
.hero-detail{color:var(--muted);font-size:.9rem;margin-top:.25rem;overflow-wrap:anywhere}
.cards{display:grid;grid-template-columns:repeat(2,1fr);gap:.9rem}
.card{border:1px solid var(--line);border-radius:.7rem;padding:.8rem 1rem;min-width:0}
.card .k{font-size:.74rem;color:var(--muted);text-transform:uppercase;
         letter-spacing:.07em;margin-bottom:.2rem}
.card .v{font-size:1.16rem;font-weight:600;font-variant-numeric:tabular-nums;
         overflow-wrap:anywhere;line-height:1.35}
.card.wide{grid-column:1/-1}
.bar{height:.45rem;border-radius:.3rem;background:var(--line);margin:.6rem 0 .35rem;
     overflow:hidden}
.bar i{display:block;height:100%;width:0;background:var(--blue);border-radius:.3rem;
       transition:width .4s}
.card .sub{font-size:.82rem;color:var(--muted)}

/* Form cards: section title, two-column grid, label above a rounded input. */
.panelcard{border:1px solid var(--line);border-radius:.7rem;padding:1.15rem 1.3rem;
           margin-top:1rem}
.form{display:grid;grid-template-columns:1fr 1fr;gap:.95rem 1.4rem;margin:0 0 1.1rem}
.field{display:flex;flex-direction:column;gap:.35rem;min-width:0}
.field.wide{grid-column:1/-1}
.field label{font-size:.86rem;font-weight:500;color:var(--ink)}
.field input,.field select{font:inherit;font-size:.95rem;width:100%;min-width:0;
      padding:.55rem .8rem;border:1px solid var(--line);border-radius:.6rem;
      background:#fff;color:var(--ink)}
.field input::placeholder{color:var(--muted);opacity:.8}
.field input:focus,.field select:focus{outline:2px solid var(--blue);outline-offset:1px}
.field .fhint{font-size:.8rem;color:var(--muted)}
.row-acts{display:flex;gap:.6rem;flex-wrap:wrap;align-items:center}
.inline-row{display:flex;gap:.5rem}
.inline-row input{flex:1}

@media (max-width:44rem){
  .app{grid-template-columns:1fr}
  aside{position:static}
  nav{flex-direction:row;flex-wrap:wrap}
  .form{grid-template-columns:1fr}
  .cards{grid-template-columns:1fr}
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
    <p class="note" id="note"></p>
  </aside>

  <section class="content">
    <div class="pane active" id="p-overview">
      <div class="hero" id="hero">
        <div class="hero-state"><span class="dot"></span><span id="o-state">—</span></div>
        <div class="hero-detail" id="o-detail">&nbsp;</div>
      </div>
      <div class="cards">
        <div class="card"><div class="k">Tunnel IP</div><div class="v" id="o-ip">—</div></div>
        <div class="card"><div class="k">SOCKS5 proxy</div><div class="v" id="o-socks">—</div></div>
        <div class="card"><div class="k">VPN choice</div><div class="v" id="o-choice">—</div></div>
        <div class="card"><div class="k">In this state for</div><div class="v" id="o-uptime">—</div></div>
        <div class="card wide">
          <div class="k">Session expires</div>
          <div class="v" id="o-exp">—</div>
          <div class="bar"><i id="o-bar"></i></div>
          <div class="sub" id="o-left">&nbsp;</div>
        </div>
      </div>

      <div class="panelcard" id="logincard">
        <h2 id="lc-title">Log in</h2>

        <div id="lc-idle">
          <div class="form">
            <div class="field">
              <label for="f-netid">NetID</label>
              <input id="f-netid" data-key="netid" autocomplete="username">
            </div>
            <div class="field">
              <label for="f-netpass">NetPassword</label>
              <input id="f-netpass" data-key="netpass" type="password"
                     autocomplete="current-password">
            </div>
            <div class="field">
              <label for="f-choice">VPN service</label>
              <input id="f-choice" data-key="vpn_choice" list="vpnopts"
                     placeholder="e.g. research — empty to pick in the browser">
            </div>
            <div class="field">
              <label for="f-fill">Credential fill</label>
              <select id="f-fill" data-key="fill_mode">
                <option value="auto">Auto — submit when the form appears</option>
                <option value="manual">Manual — wait for Fill &amp; log in</option>
                <option value="off">Off — type them in the browser</option>
              </select>
            </div>
          </div>
          <div class="row-acts">
            <button class="act primary" id="b-login">Log in</button>
            <span class="fhint">Fields are saved when you log in. MFA is confirmed
              on your phone or with a code below.</span>
          </div>
        </div>

        <div id="lc-wait" style="display:none">
          <p class="hint" id="lc-step" style="margin:0 0 1rem"></p>
          <div class="form" id="mfa-field">
            <div class="field wide">
              <label for="mfa-code">Verification code</label>
              <div class="inline-row">
                <input id="mfa-code" inputmode="numeric" autocomplete="one-time-code"
                       placeholder="From your phone / authenticator" maxlength="32">
                <button class="act primary" id="b-code">Send</button>
              </div>
              <span class="fhint" id="mfa-hint"></span>
            </div>
          </div>
          <div class="row-acts">
            <button class="act primary" id="b-fill" style="display:none">Fill &amp; log in</button>
            <button class="act" id="b-cancel">Cancel</button>
          </div>
        </div>

        <div id="lc-conn" style="display:none">
          <div class="row-acts">
            <button class="act primary" id="b-renew">Renew session</button>
            <button class="act" id="b-logout">Disconnect</button>
            <span class="fhint">Renew drops the tunnel and starts a fresh login —
              use it when the session above is close to expiry.</span>
          </div>
        </div>
      </div>
    </div>

    <div class="pane" id="p-browser">
      <h2>Browser</h2>
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
      <div class="panelcard" style="margin-top:0">
        <h2>Connection</h2>
        <div class="form">
          <div class="field">
            <label for="s-portal">Portal</label>
            <input id="s-portal" data-key="portal">
          </div>
          <div class="field">
            <label for="s-saml">SAML endpoint</label>
            <select id="s-saml" data-key="saml_endpoint">
              <option value="gateway">gateway</option>
              <option value="portal">portal</option>
            </select>
          </div>
          <div class="field">
            <label for="s-choice">VPN service</label>
            <input id="s-choice" data-key="vpn_choice" list="vpnopts"
                   placeholder="matched against the page — empty to pick by hand">
          </div>
          <div class="field">
            <label for="s-timeout">Login timeout (seconds)</label>
            <input id="s-timeout" data-key="login_timeout" type="number"
                   min="60" max="7200" step="60">
          </div>
          <div class="field">
            <label for="s-reconnect">Reconnect window (seconds)</label>
            <input id="s-reconnect" data-key="reconnect_timeout" type="number"
                   min="300" max="604800" step="300">
          </div>
        </div>
      </div>

      <div class="panelcard">
        <h2>Credentials</h2>
        <div class="form">
          <div class="field">
            <label for="s-netid">NetID</label>
            <input id="s-netid" data-key="netid" autocomplete="off">
          </div>
          <div class="field">
            <label for="s-netpass">NetPassword</label>
            <input id="s-netpass" data-key="netpass" type="password" autocomplete="off">
          </div>
          <div class="field wide">
            <label for="s-fill">Credential fill</label>
            <select id="s-fill" data-key="fill_mode">
              <option value="auto">Auto — fill &amp; submit when the form appears</option>
              <option value="manual">Manual — only after I press Fill &amp; log in</option>
              <option value="off">Off — type them in the browser</option>
            </select>
          </div>
        </div>
      </div>

      <div class="row-acts" style="margin-top:1rem">
        <button class="act primary" id="b-save">Save</button>
        <button class="act" id="b-reload">Reload .env</button>
      </div>
      <p class="hint">Saved values apply to the next login and last until the
        container restarts or <code>.env</code> is reloaded over them. For a
        permanent change, edit <code>.env</code> on the host.</p>

      <div class="panelcard">
        <h2>Runtime</h2>
        <dl id="cfg"></dl>
      </div>
    </div>
  </section>
</div>

<datalist id="vpnopts"></datalist>

<script>
const Q = "__TOKEN_QUERY__";
let novncUrl = "";
const $ = id => document.getElementById(id);
let busy = false, pane = "overview", framed = false;
// Fields the user has edited and not yet saved: the poller must not overwrite
// them with the server's (older) values.
const dirty = new Set();

document.querySelectorAll("nav button").forEach(b => b.onclick = () => {
  pane = b.dataset.pane;
  document.querySelectorAll("nav button").forEach(x => x.classList.toggle("active", x === b));
  document.querySelectorAll(".pane").forEach(p => p.classList.toggle("active", p.id === "p-" + pane));
  if (pane === "browser" && !framed && novncUrl) { $("novnc").src = novncUrl; framed = true; }
});

for (const el of document.querySelectorAll("[data-key]"))
  el.addEventListener("input", () => dirty.add(el));

// "Wed Aug 19 11:42:42 2026" (openconnect prints ctime) -> Date or null.
function parseExpiry(str){
  const m = /^\w{3} (\w{3}) +(\d+) (\d+):(\d+):(\d+) (\d{4})$/.exec((str || "").trim());
  if (!m) return null;
  const mon = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"].indexOf(m[1]);
  if (mon < 0) return null;
  return new Date(+m[6], mon, +m[2], +m[3], +m[4], +m[5]);
}

function fmtDur(sec){
  sec = Math.max(0, Math.round(sec));
  const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600),
        mi = Math.floor(sec % 3600 / 60);
  if (d) return d + "d " + h + "h";
  if (h) return h + "h " + mi + "m";
  if (mi) return mi + "m";
  return sec + "s";
}

function render(s){
  $("portal").textContent = s.portal;
  const pill = $("pill");
  pill.textContent = s.state;
  pill.className = "pill " + s.state;
  pill.dataset.s = s.state;

  // Overview dashboard
  const hero = $("hero");
  hero.className = "hero " + s.state;
  hero.dataset.s = s.state;
  $("o-state").textContent  = s.state.replace("-", " ");
  $("o-detail").textContent = s.detail || " ";
  $("o-ip").textContent     = s.tunnel_ip || "—";
  $("o-socks").textContent  = "127.0.0.1:" + s.socks_port;
  $("o-choice").textContent = s.vpn_choice || "—";
  $("o-uptime").textContent = fmtDur(s.seconds_in_state);
  const exp = s.state === "connected" ? parseExpiry(s.session_expires) : null;
  $("o-exp").textContent = s.session_expires || "—";
  if (exp){
    const left = (exp - Date.now()) / 1000;
    $("o-left").textContent = left > 0 ? fmtDur(left) + " left" : "expired — renew to keep the tunnel";
    $("o-bar").style.width = Math.max(0, Math.min(100, left / 864)) + "%"; // of a 24h session
  } else {
    $("o-left").textContent = " ";
    $("o-bar").style.width = "0";
  }

  $("logs").textContent = (s.logs || []).join("\n") || "—";

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
  for (const [k, val] of Object.entries(s.config || {})){
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd"); dd.textContent = val;
    cfg.append(dt, dd);
  }

  const st = s.settings || {};
  const m = s.mfa || {};

  // The login card follows the state machine: a credential form when idle,
  // the MFA step while a login is under way, session actions once connected.
  const awaiting  = s.state === "awaiting-login";
  const inLogin   = awaiting || s.state === "connecting";
  const connected = s.state === "connected";
  $("lc-idle").style.display = inLogin || connected ? "none" : "";
  $("lc-wait").style.display = inLogin ? "" : "none";
  $("lc-conn").style.display = connected ? "" : "none";
  $("lc-title").textContent =
    connected ? "Session" :
    s.state === "connecting" ? "Connecting" :
    awaiting ? "Login in progress" : "Log in";
  $("lc-step").textContent = s.detail || "";
  $("mfa-field").style.display = awaiting ? "" : "none";
  $("b-fill").style.display = awaiting && st.fill_mode === "manual" ? "" : "none";
  $("b-fill").textContent = m.fill_pending ? "Filling…" : "Fill & log in";
  $("mfa-hint").textContent = !awaiting ? "" :
    m.pending ? "Code queued — typed in as soon as the field appears." :
    m.prompt  ? "The page asks for: " + m.prompt :
    "Send it early if you like — it is typed the moment the field appears. The Browser pane is the fallback.";

  // The password is never sent back; the placeholder says whether one is stored.
  const pp = st.netpass_set ? "stored — leave empty to keep it" : "not set";
  $("f-netpass").placeholder = pp;
  $("s-netpass").placeholder = pp;

  // VPN service suggestions: the option texts the login pages actually showed
  // (captured live), plus the current value. Free text still allowed.
  const opts = [...new Set([...(st.vpn_options || []), st.vpn_choice, "research"])]
    .filter(Boolean);
  const dl = $("vpnopts");
  if (dl.dataset.have !== opts.join("\x1f")){
    dl.dataset.have = opts.join("\x1f");
    dl.textContent = "";
    for (const o of opts) dl.append(new Option(o));
  }

  // Sync form fields from the server, except ones being edited right now.
  for (const el of document.querySelectorAll("[data-key]")){
    const val = st[el.dataset.key];
    if (val === undefined || el === document.activeElement || dirty.has(el)) continue;
    if (el.tagName === "SELECT" && ![...el.options].some(o => o.value === val))
      el.add(new Option(val, val));   // keep an unlisted .env value visible
    el.value = val;
  }

  for (const id of ["b-login","b-renew","b-logout","b-cancel","b-reload","b-save","b-code","b-fill"])
    $(id).disabled = busy;
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

// Save every [data-key] field inside `scope`. An empty password field is
// skipped (meaning: keep the stored one).
async function save(scopeId){
  const body = new URLSearchParams();
  const fields = document.getElementById(scopeId).querySelectorAll("[data-key]");
  for (const el of fields){
    if (el.dataset.key === "netpass" && !el.value) continue;
    body.set(el.dataset.key, el.value);
  }
  busy = true; $("note").textContent = "…";
  let ok = false;
  try{
    const r = await fetch("/save" + Q, {method:"POST",
      headers:{"Accept":"application/json",
               "Content-Type":"application/x-www-form-urlencoded"},
      body: body.toString()});
    const j = await r.json();
    $("note").textContent = j.message || "";
    ok = j.ok;
    if (ok){
      for (const el of fields) dirty.delete(el);
      $("f-netpass").value = "";
      $("s-netpass").value = "";
    }
  }catch(e){ $("note").textContent = "request failed: " + e; }
  busy = false;
  await poll();
  return ok;
}

$("b-login").onclick  = async () => { if (await save("lc-idle")) act("login"); };
$("b-save").onclick   = () => save("p-settings");
$("b-renew").onclick  = () => act("renew");
$("b-logout").onclick = () => act("logout");
$("b-cancel").onclick = () => act("logout");
$("b-reload").onclick = () => act("reload");
$("b-fill").onclick   = () => act("fill");
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

    def _param(self, name: str) -> str:
        """A request parameter, from the query string or the form body."""
        if not hasattr(self, "_params"):
            self._params = parse_qs(urlparse(self.path).query)
            if self.command == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
                for k, v in parse_qs(body).items():
                    self._params.setdefault(k, v)
        return (self._params.get(name) or [""])[0]

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
            return self._result(*t.submit_code(self._param("code")))
        if path == "/fill":
            return self._result(*t.request_fill())
        if path == "/set":
            return self._result(*t.set_option(self._param("key"),
                                              self._param("value")))
        if path == "/save":
            self._param("")  # force query+body parsing into _params
            pairs = {k: (self._params.get(k) or [""])[0]
                     for k in SETTABLE if k in self._params}
            return self._result(*t.save_options(pairs))
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
