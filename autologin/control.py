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
/* Layout follows macOS System Settings: a sidebar of icon rows, and content
   made of inset grouped lists where each row is "label left, control right".
   The palette stays the Morandi blue this panel has always used. */
:root{
  --bg:#eef2f5; --group:#fff; --side:#f6f9fb;
  --label:#2c3841; --value:#7d8b96; --sep:#e7edf1; --line:#dde5ea;
  --accent:#8fabc2; --accent-deep:#6f8fa8; --accent-soft:#e4ecf2;
  --ok:#7d9b80; --ok-bg:#e9f0e9; --bad:#b0716a; --bad-bg:#f6e9e7;
  --warn:#a8895c; --warn-bg:#f6efe4;
  --radius:.85rem; --row:3.4rem;
}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--label);
     font:14.5px/1.5 -apple-system,BlinkMacSystemFont,"SF Pro Text","Segoe UI",system-ui,sans-serif;
     -webkit-font-smoothing:antialiased}
.app{display:grid;grid-template-columns:14.5rem 1fr;gap:1.15rem;
     margin:0;padding:1.5rem;min-height:100%}

/* ---- sidebar ---- */
aside{background:var(--side);border:1px solid var(--line);border-radius:var(--radius);
      padding:1rem .7rem;display:flex;flex-direction:column;gap:.85rem;
      align-self:start;position:sticky;top:1.5rem}
.brand{display:flex;align-items:center;gap:.6rem;padding:0 .35rem}
.brand-mark{width:2.1rem;height:2.1rem;border-radius:.55rem;flex:none;
            background:var(--accent);color:#fff;display:grid;place-items:center;
            font-size:.78rem;font-weight:700;letter-spacing:.02em}
.brand-name{font-size:1rem;font-weight:600;line-height:1.2}
.brand-sub{font-size:.76rem;color:var(--value);overflow-wrap:anywhere;line-height:1.3}
nav{display:flex;flex-direction:column;gap:.1rem}
nav button{display:flex;align-items:center;gap:.6rem;text-align:left;width:100%;
           background:none;border:0;border-radius:.55rem;padding:.5rem .55rem;
           font:inherit;font-size:.92rem;color:var(--label);cursor:pointer;
           transition:background .12s}
nav button:hover{background:var(--accent-soft)}
nav button.active{background:var(--accent);color:#fff}
nav button svg{width:1.05rem;height:1.05rem;flex:none;stroke:currentColor;
               fill:none;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round;
               opacity:.9}
.side-foot{margin-top:auto;padding:.7rem .35rem 0;border-top:1px solid var(--line)}
.pill{display:inline-flex;align-items:center;gap:.4rem;padding:.22rem .6rem;
      border-radius:2rem;font-size:.78rem;font-weight:500;
      background:var(--accent-soft);color:var(--accent-deep)}
.pill::before{content:"";width:.42rem;height:.42rem;border-radius:50%;background:currentColor}
.pill.connected{background:var(--ok-bg);color:var(--ok)}
.pill.failed{background:var(--bad-bg);color:var(--bad)}
.pill[data-s="awaiting-login"],.pill[data-s="connecting"]{background:var(--warn-bg);color:var(--warn)}

/* ---- content ---- */
.content{min-width:0}
.pane{display:none}
.pane.active{display:block}
h1{font-size:1.45rem;font-weight:650;letter-spacing:-.015em;margin:.1rem 0 1rem}
h2{font-size:.76rem;font-weight:600;color:var(--value);text-transform:uppercase;
   letter-spacing:.06em;margin:1.5rem .9rem .45rem}
.foot{font-size:.8rem;color:var(--value);margin:.5rem .9rem 0;line-height:1.45;
      max-width:56rem}

/* Grouped inset list: rows separated by a hairline that starts after the
   label gutter, the way Apple insets its separators. */
.group{background:var(--group);border-radius:var(--radius);overflow:hidden;
       box-shadow:0 1px 2px rgba(44,56,65,.05)}
.row{display:flex;align-items:center;gap:1rem;min-height:var(--row);
     padding:.55rem 1rem;position:relative}
.row + .row::before{content:"";position:absolute;left:1rem;right:0;top:0;
                    height:1px;background:var(--sep)}
.row .k{flex:1 1 auto;min-width:0;font-size:.92rem}
.row .k small{display:block;font-size:.78rem;color:var(--value);line-height:1.35;
              margin-top:.1rem}
.row .v{flex:0 0 auto;color:var(--value);font-size:.92rem;text-align:right;
        font-variant-numeric:tabular-nums;overflow-wrap:anywhere;max-width:60%}
.row .v.strong{color:var(--label);font-weight:550}
.row.col{flex-direction:column;align-items:stretch;gap:.5rem}

/* An action row: full-width, centered accent text (iOS "Sign Out" pattern). */
.row.action{justify-content:center;padding:0}
.row.action button{width:100%;min-height:var(--row);background:none;border:0;
     font:inherit;font-size:.95rem;font-weight:550;color:var(--accent-deep);
     cursor:pointer;transition:background .12s}
.row.action button:hover:not(:disabled){background:var(--accent-soft)}
.row.action button:disabled{color:var(--value);opacity:.55;cursor:default}

/* Controls sit on the right of their row and share one height. */
.row input{flex:0 0 auto;width:min(60%,15rem);height:2.1rem;font:inherit;
     font-size:.92rem;text-align:right;padding:0 .65rem;color:var(--label);
     border:1px solid var(--line);border-radius:.5rem;background:#fff;
     -webkit-appearance:none;appearance:none}
.row input::placeholder{color:var(--value);opacity:.75}
.row input:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:transparent}
.row input[type=number]{-moz-appearance:textfield}
.row input::-webkit-outer-spin-button,
.row input::-webkit-inner-spin-button{-webkit-appearance:none;margin:0}

/* Segmented control: one tap instead of opening a menu. */
.seg{flex:0 0 auto;display:inline-flex;align-items:stretch;height:2.1rem;
     background:#eff3f6;border-radius:.55rem;padding:.15rem;gap:.15rem}
.seg button{display:flex;align-items:center;font:inherit;font-size:.85rem;
     padding:0 .8rem;border:0;border-radius:.42rem;background:none;
     color:var(--label);cursor:pointer;white-space:nowrap;
     transition:background .15s,box-shadow .15s}
.seg button.on{background:#fff;box-shadow:0 1px 2px rgba(44,56,65,.12);font-weight:550}
.seg button:disabled{opacity:.5;cursor:default}

/* Buttons outside groups (status card, browser pane). */
.btn{font:inherit;font-size:.88rem;font-weight:500;padding:.45rem 1rem;
     border-radius:.55rem;border:1px solid var(--line);background:#fff;
     color:var(--label);cursor:pointer;white-space:nowrap;
     transition:background .15s,border-color .15s,opacity .15s}
.btn:hover:not(:disabled){background:var(--accent-soft);border-color:var(--accent)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn.primary:hover:not(:disabled){background:var(--accent-deep);border-color:var(--accent-deep)}
.btn:disabled{opacity:.45;cursor:default}

/* Status card: what the tunnel is doing, plus the actions that fit that state. */
.status{background:var(--group);border-radius:var(--radius);padding:1.05rem 1.15rem;
        display:flex;align-items:center;gap:1rem;flex-wrap:wrap;
        box-shadow:0 1px 2px rgba(44,56,65,.05)}
.status .dot{width:.7rem;height:.7rem;border-radius:50%;flex:none;
             background:var(--accent-deep)}
.status.connected .dot{background:var(--ok)}
.status.failed .dot{background:var(--bad)}
.status[data-s="awaiting-login"] .dot,.status[data-s="connecting"] .dot{background:var(--warn)}
.status-main{display:flex;align-items:center;gap:.75rem;flex:1 1 14rem;min-width:0}
.status-title{font-size:1.1rem;font-weight:600;letter-spacing:-.01em;
              text-transform:capitalize}
.status-sub{font-size:.83rem;color:var(--value);overflow-wrap:anywhere}
.status-acts{display:flex;gap:.5rem;flex:0 0 auto}

.bar{height:.4rem;border-radius:.25rem;background:var(--sep);overflow:hidden}
.bar i{display:block;height:100%;width:0;border-radius:.25rem;
       background:var(--accent);transition:width .4s}

/* Toast: action results, so the sidebar no longer has to carry them. */
.toast{position:fixed;left:50%;bottom:1.4rem;transform:translate(-50%,1.5rem);
       background:rgba(44,56,65,.94);color:#fff;font-size:.86rem;
       padding:.55rem 1.05rem;border-radius:2rem;max-width:min(34rem,90vw);
       box-shadow:0 6px 18px rgba(44,56,65,.22);opacity:0;pointer-events:none;
       transition:opacity .2s,transform .2s;z-index:9}
.toast.show{opacity:1;transform:translate(-50%,0)}

/* One element per line, so each can carry its own severity colour. */
.logbox{padding:.5rem 0;height:calc(100vh - 12rem);min-height:20rem;overflow:auto;
        font:.78rem/1.65 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.ln{padding:.03rem 1rem;white-space:pre-wrap;overflow-wrap:anywhere;color:#5b6a75}
.ln:hover{background:#f6f9fb}
.ln.err{color:var(--bad);background:rgba(176,113,106,.07)}
.ln.warn{color:var(--warn)}
.ln.ok{color:var(--ok)}
.ln .tag{font-weight:650;color:var(--accent-deep)}
.ln.err .tag,.ln.warn .tag,.ln.ok .tag{color:inherit}
.ln .tok{color:var(--label);font-weight:500}
.logbox .empty{padding:1rem;color:var(--value)}
iframe{display:block;width:100%;height:33rem;border:0;background:#fff}
.big{display:inline-flex;align-items:center;gap:.5rem;background:var(--accent);
     color:#fff;text-decoration:none;font-size:1rem;font-weight:600;
     padding:.85rem 1.6rem;border-radius:.7rem;transition:background .15s}
.big:hover{background:var(--accent-deep)}

@media (max-width:46rem){
  .app{grid-template-columns:1fr;gap:.9rem}
  aside{position:static}
  nav{flex-direction:row;flex-wrap:wrap}
  nav button{width:auto}
  .row input{width:min(70%,12rem)}
}
</style></head><body>
<div class="app">
  <aside>
    <div class="brand">
      <div class="brand-mark">GP</div>
      <div style="min-width:0">
        <div class="brand-name">PolyGP</div>
        <div class="brand-sub" id="portal">&nbsp;</div>
      </div>
    </div>
    <nav>
      <button data-pane="overview" class="active">
        <svg viewBox="0 0 16 16"><path d="M2.6 12.2a6 6 0 1 1 10.8 0"/><path d="M8 8.6l3.1-2.4"/></svg>
        Overview</button>
      <button data-pane="browser">
        <svg viewBox="0 0 16 16"><rect x="2" y="3" width="12" height="8.5" rx="1.4"/><path d="M6 14h4"/></svg>
        Browser</button>
      <button data-pane="logs">
        <svg viewBox="0 0 16 16"><path d="M3 4.5h10M3 8h10M3 11.5h6"/></svg>
        Logs</button>
      <button data-pane="settings">
        <svg viewBox="0 0 16 16"><path d="M2.5 5h11M2.5 11h11"/><circle cx="6" cy="5" r="1.6"/><circle cx="10.5" cy="11" r="1.6"/></svg>
        Settings</button>
    </nav>
    <div class="side-foot"><span class="pill" id="pill">loading</span></div>
  </aside>

  <section class="content">
    <!-- ================= Overview ================= -->
    <div class="pane active" id="p-overview">
      <h1>Overview</h1>

      <div class="status" id="status">
        <div class="status-main">
          <span class="dot"></span>
          <div style="min-width:0">
            <div class="status-title" id="o-state">—</div>
            <div class="status-sub" id="o-detail">&nbsp;</div>
          </div>
        </div>
        <div class="status-acts">
          <button class="btn" id="b-cancel">Cancel</button>
          <button class="btn" id="b-renew">Renew</button>
          <button class="btn" id="b-logout">Disconnect</button>
        </div>
      </div>

      <!-- shown while idle / failed -->
      <div id="signin">
        <h2>Sign in</h2>
        <div class="group">
          <div class="row"><div class="k">NetID</div>
            <input id="f-netid" data-key="netid" autocomplete="username"></div>
          <div class="row"><div class="k">NetPassword</div>
            <input id="f-netpass" data-key="netpass" type="password"
                   autocomplete="current-password"></div>
          <div class="row"><div class="k">VPN service</div>
            <input id="f-choice" data-key="vpn_choice" list="vpnopts"
                   placeholder="research"></div>
          <div class="row"><div class="k">Credential fill</div>
            <div class="seg" id="f-fill" data-key="fill_mode">
              <button data-v="auto">Auto</button>
              <button data-v="manual">Manual</button>
              <button data-v="off">Off</button>
            </div></div>
          <div class="row action"><button id="b-login">Log in</button></div>
        </div>
        <p class="foot" id="signin-foot"></p>
      </div>

      <!-- shown while a login is running -->
      <div id="signing">
        <h2>Verification</h2>
        <div class="group">
          <div class="row"><div class="k">Code<small id="mfa-hint"></small></div>
            <input id="mfa-code" inputmode="numeric" autocomplete="one-time-code"
                   maxlength="32" placeholder="From your phone"></div>
          <div class="row action"><button id="b-code">Send code</button></div>
          <div class="row action" id="fill-row"><button id="b-fill">Fill &amp; log in</button></div>
        </div>
        <p class="foot">The code is typed into the login page for you — no need to
          use the browser view unless something goes wrong.</p>
      </div>

      <h2>Connection</h2>
      <div class="group">
        <div class="row"><div class="k">Tunnel IP</div><div class="v strong" id="o-ip">—</div></div>
        <div class="row"><div class="k">SOCKS5 proxy</div><div class="v strong" id="o-socks">—</div></div>
        <div class="row"><div class="k">VPN service</div><div class="v" id="o-choice">—</div></div>
        <div class="row"><div class="k">In this state for</div><div class="v" id="o-uptime">—</div></div>
      </div>
      <p class="foot">Point your proxy tool at the SOCKS5 address. Nothing on this
        machine is rerouted on its own.</p>

      <div id="session">
        <h2>Session</h2>
        <div class="group">
          <div class="row"><div class="k">Expires</div><div class="v strong" id="o-exp">—</div></div>
          <div class="row col">
            <div class="bar"><i id="o-bar"></i></div>
            <div class="v" style="text-align:left;max-width:none" id="o-left">&nbsp;</div>
          </div>
        </div>
      </div>
    </div>

    <!-- ================= Browser ================= -->
    <div class="pane" id="p-browser">
      <h1>Browser</h1>
      <div class="status" style="justify-content:space-between">
        <div class="status-main"><div style="min-width:0">
          <div class="status-title" style="font-size:.98rem">Login browser</div>
          <div class="status-sub">Signed in to VNC for you. Open it in its own tab
            if the frame will not take keyboard focus.</div>
        </div></div>
        <a class="big" id="novnc-open" href="#" target="_blank" rel="noreferrer">Open &nbsp;&rarr;</a>
      </div>
      <h2>Live view</h2>
      <div class="group"><iframe id="novnc" title="noVNC" src="about:blank"></iframe></div>
    </div>

    <!-- ================= Logs ================= -->
    <div class="pane" id="p-logs">
      <h1>Logs</h1>
      <h2>Recent output</h2>
      <div class="group"><div class="logbox" id="logs"></div></div>
    </div>

    <!-- ================= Settings ================= -->
    <div class="pane" id="p-settings">
      <h1>Settings</h1>

      <h2>Connection</h2>
      <div class="group">
        <div class="row"><div class="k">Portal</div>
          <input id="s-portal" data-key="portal"></div>
        <div class="row"><div class="k">SAML endpoint</div>
          <div class="seg" id="s-saml" data-key="saml_endpoint">
            <button data-v="gateway">Gateway</button>
            <button data-v="portal">Portal</button>
          </div></div>
        <div class="row"><div class="k">VPN service</div>
          <input id="s-choice" data-key="vpn_choice" list="vpnopts"
                 placeholder="pick by hand"></div>
        <div class="row"><div class="k">Login timeout<small>seconds to finish MFA</small></div>
          <input id="s-timeout" data-key="login_timeout" type="number" min="60" max="7200" step="60"></div>
        <div class="row"><div class="k">Reconnect window<small>how long to retry after a drop</small></div>
          <input id="s-reconnect" data-key="reconnect_timeout" type="number" min="300" max="604800" step="300"></div>
      </div>

      <h2>Credentials</h2>
      <div class="group">
        <div class="row"><div class="k">NetID</div>
          <input id="s-netid" data-key="netid" autocomplete="off"></div>
        <div class="row"><div class="k">NetPassword</div>
          <input id="s-netpass" data-key="netpass" type="password" autocomplete="off"></div>
        <div class="row"><div class="k">Credential fill</div>
          <div class="seg" id="s-fill" data-key="fill_mode">
            <button data-v="auto">Auto</button>
            <button data-v="manual">Manual</button>
            <button data-v="off">Off</button>
          </div></div>
      </div>
      <p class="foot"><b>Auto</b> submits the form as soon as it appears.
        <b>Manual</b> waits for the Fill &amp; log in button.
        <b>Off</b> leaves it to you in the browser view.</p>

      <div class="group" style="margin-top:1rem">
        <div class="row action"><button id="b-save">Save changes</button></div>
        <div class="row action"><button id="b-reload">Reload .env</button></div>
      </div>
      <p class="foot">Saved values apply to the next login and last until the
        container restarts or <code>.env</code> is reloaded over them. Edit
        <code>.env</code> on the host for a permanent change.</p>

      <h2>Runtime</h2>
      <div class="group" id="cfg"></div>
    </div>
  </section>
</div>

<datalist id="vpnopts"></datalist>
<div class="toast" id="toast"></div>

<script>
const Q = "__TOKEN_QUERY__";
const $ = id => document.getElementById(id);
let novncUrl = "", busy = false, pane = "overview", framed = false;
// Fields edited but not yet saved: the poller must not overwrite them.
const dirty = new Set();

document.querySelectorAll("nav button").forEach(b => b.onclick = () => {
  pane = b.dataset.pane;
  document.querySelectorAll("nav button").forEach(x => x.classList.toggle("active", x === b));
  document.querySelectorAll(".pane").forEach(p => p.classList.toggle("active", p.id === "p-" + pane));
  if (pane === "logs") poll();
  if (pane === "browser" && !framed && novncUrl) { $("novnc").src = novncUrl; framed = true; }
});

// A field is either an <input> or a segmented control; these two hide the
// difference from the sync and save paths.
const isSeg = el => el.classList.contains("seg");
function fval(el){ return isSeg(el) ? (el.dataset.value || "") : el.value; }
function fset(el, v){
  if (isSeg(el)){
    el.dataset.value = v;
    for (const b of el.children) b.classList.toggle("on", b.dataset.v === v);
  } else el.value = v;
}

for (const el of document.querySelectorAll("[data-key]")){
  if (isSeg(el)){
    for (const b of el.children) b.onclick = () => {
      if (busy) return;
      fset(el, b.dataset.v);
      dirty.add(el);
    };
  } else el.addEventListener("input", () => dirty.add(el));
}

let toastTimer = 0;
function toast(msg){
  if (!msg) return;
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 4000);
}

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

  const awaiting  = s.state === "awaiting-login";
  const inLogin   = awaiting || s.state === "connecting";
  const connected = s.state === "connected";

  const card = $("status");
  card.className = "status " + s.state;
  card.dataset.s = s.state;
  $("o-state").textContent  = s.state.replace("-", " ");
  $("o-detail").textContent = s.detail || " ";

  // Only the actions that make sense for this state.
  $("b-cancel").style.display = inLogin ? "" : "none";
  $("b-renew").style.display  = connected ? "" : "none";
  $("b-logout").style.display = connected ? "" : "none";
  $("signin").style.display   = inLogin || connected ? "none" : "";
  $("signing").style.display  = inLogin ? "" : "none";
  $("session").style.display  = connected ? "" : "none";

  $("o-ip").textContent     = s.tunnel_ip || "—";
  $("o-socks").textContent  = "127.0.0.1:" + s.socks_port;
  $("o-choice").textContent = s.vpn_choice || "—";
  $("o-uptime").textContent = fmtDur(s.seconds_in_state);

  const exp = connected ? parseExpiry(s.session_expires) : null;
  $("o-exp").textContent = s.session_expires || "—";
  if (exp){
    const left = (exp - Date.now()) / 1000;
    $("o-left").textContent = left > 0 ? fmtDur(left) + " left"
                                       : "expired — renew to keep the tunnel";
    $("o-bar").style.width = Math.max(0, Math.min(100, left / 864)) + "%"; // of ~24h
  }

  if (pane !== "logs") renderLogs(s.logs || []);   // the pane pulls the full buffer itself

  // Built here rather than server-side so the host matches however you reached
  // this page, and so the VNC password rides along instead of being retyped.
  const v = s.vnc || {};
  novncUrl = v.url || (location.protocol + "//" + location.hostname + ":" + v.port +
    "/vnc.html?autoconnect=1&resize=scale&reconnect=1" +
    (v.password ? "&password=" + encodeURIComponent(v.password) : ""));
  $("novnc-open").href = novncUrl;
  if (pane === "browser" && !framed) { $("novnc").src = novncUrl; framed = true; }

  const cfg = $("cfg");
  const want = Object.entries(s.config || {});
  if (cfg.dataset.have !== JSON.stringify(want)){
    cfg.dataset.have = JSON.stringify(want);
    cfg.textContent = "";
    for (const [k, val] of want){
      const row = document.createElement("div"); row.className = "row";
      const kk = document.createElement("div"); kk.className = "k"; kk.textContent = k;
      const vv = document.createElement("div"); vv.className = "v"; vv.textContent = val;
      row.append(kk, vv); cfg.append(row);
    }
  }

  const st = s.settings || {}, m = s.mfa || {};
  $("signin-foot").textContent = st.netpass_set
    ? "Password stored — leave it empty to keep it."
    : "No password stored; it is typed into the browser instead.";
  const pp = st.netpass_set ? "stored" : "not set";
  $("f-netpass").placeholder = pp;
  $("s-netpass").placeholder = pp;

  $("fill-row").style.display = st.fill_mode === "manual" ? "" : "none";
  $("b-fill").textContent = m.fill_pending ? "Filling…" : "Fill & log in";
  $("mfa-hint").textContent =
    m.pending ? "queued — typed in as soon as the field appears" :
    m.prompt  ? "the page asks for: " + m.prompt :
    "can be sent before the page asks";

  // VPN service suggestions: the option texts the login pages actually showed.
  const opts = [...new Set([...(st.vpn_options || []), st.vpn_choice, "research"])].filter(Boolean);
  const dl = $("vpnopts");
  if (dl.dataset.have !== opts.join("\x1f")){
    dl.dataset.have = opts.join("\x1f");
    dl.textContent = "";
    for (const o of opts) dl.append(new Option(o));
  }

  for (const el of document.querySelectorAll("[data-key]")){
    const val = st[el.dataset.key];
    if (val === undefined || el === document.activeElement || dirty.has(el)) continue;
    fset(el, val);
  }

  for (const id of ["b-login","b-renew","b-logout","b-cancel","b-reload","b-save","b-code","b-fill"])
    $(id).disabled = busy;
  for (const b of document.querySelectorAll(".seg button")) b.disabled = busy;
}

// Log colouring. Lines are server text (they can quote a remote page), so every
// piece goes in through textContent - nothing here builds markup from a line.
const RE_ERR  = /\b(error|fail(ed|ure|s)?|denied|invalid|refused|unable|cannot|could not|not found|rejected)\b/i;
// Not a bare "timeout": openconnect states the rekey and idle timeouts as
// ordinary configuration lines, which are not warnings.
const RE_WARN = /\b(warn(ing)?|dead peer|timed out|retry|retrying|abandoned|stale|skipped)\b/i;
const RE_OK   = /\b(connected|configured as|success(fully)?|established|captured|submitted|authenticated)\b/i;
// Split on, and recognise, the tokens worth picking out of a line.
const TOKENS = /(https?:\/\/[^\s'"]+|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b)/g;
const IS_TOKEN = /^(?:https?:\/\/[^\s'"]+|\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)$/;

function severity(t){
  // A retry line names the error it is recovering from ("navigation retry
  // after Error: ..."), so it has to be caught before the error rule or a
  // hiccup that self-healed reads as a failure.
  if (/\bretry(ing)?\b/i.test(t)) return " warn";
  if (RE_ERR.test(t))  return " err";
  if (RE_WARN.test(t)) return " warn";
  if (RE_OK.test(t))   return " ok";
  return "";
}

function logLine(text){
  const div = document.createElement("div");
  div.className = "ln" + severity(text);
  let rest = text;
  const tag = /^\[(control|gp)\]\s*/.exec(text);
  if (tag){
    const el = document.createElement("span");
    el.className = "tag";
    el.textContent = tag[0].trimEnd();
    div.append(el, " ");
    rest = text.slice(tag[0].length);
  }
  for (const part of rest.split(TOKENS)){
    if (!part) continue;
    if (IS_TOKEN.test(part)){
      const el = document.createElement("span");
      el.className = "tok";
      el.textContent = part;
      div.append(el);
    } else div.append(part);
  }
  return div;
}

function renderLogs(lines){
  const box = $("logs");
  const key = lines.length + "|" + (lines[lines.length - 1] || "");
  if (box.dataset.have === key) return;
  box.dataset.have = key;
  // Follow the tail only when already parked at it, so scrolling back to read
  // something does not get yanked away by the next poll.
  const atEnd = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  box.textContent = "";
  if (!lines.length){
    const e = document.createElement("div");
    e.className = "empty";
    e.textContent = "No output yet.";
    box.append(e);
    return;
  }
  const frag = document.createDocumentFragment();
  for (const l of lines) frag.append(logLine(l));
  box.append(frag);
  if (atEnd) box.scrollTop = box.scrollHeight;
}

async function poll(){
  try{ render(await (await fetch("/status" + Q)).json()); }catch(e){}
  // /status carries only the tail; the Logs pane shows the whole buffer.
  if (pane === "logs"){
    try{
      const t = await (await fetch("/logs" + Q)).text();
      renderLogs(t ? t.split("\n") : []);
    }catch(e){}
  }
}

async function act(name){
  busy = true;
  try{
    const r = await fetch("/" + name + Q, {method:"POST", headers:{"Accept":"application/json"}});
    toast((await r.json()).message);
  }catch(e){ toast("request failed: " + e); }
  busy = false;
  await poll();
}

async function post(path, body){
  busy = true;
  let j = {};
  try{
    const r = await fetch(path + Q, {method:"POST",
      headers:{"Accept":"application/json",
               "Content-Type":"application/x-www-form-urlencoded"},
      body});
    j = await r.json();
    toast(j.message);
  }catch(e){ toast("request failed: " + e); }
  busy = false;
  await poll();
  return j.ok;
}

async function sendCode(){
  const v = $("mfa-code").value.trim();
  if (!v) return;
  if (await post("/code", "code=" + encodeURIComponent(v))) $("mfa-code").value = "";
}

// Save every [data-key] field inside `scope`. An empty password means "keep".
async function save(scopeId){
  const body = new URLSearchParams();
  const fields = $(scopeId).querySelectorAll("[data-key]");
  for (const el of fields){
    if (el.dataset.key === "netpass" && !fval(el)) continue;
    body.set(el.dataset.key, fval(el));
  }
  const ok = await post("/save", body.toString());
  if (ok){
    for (const el of fields) dirty.delete(el);
    $("f-netpass").value = "";
    $("s-netpass").value = "";
  }
  return ok;
}

$("b-login").onclick  = async () => { if (await save("signin")) act("login"); };
$("b-save").onclick   = () => save("p-settings");
$("b-renew").onclick  = () => act("renew");
$("b-logout").onclick = () => act("logout");
$("b-cancel").onclick = () => act("logout");
$("b-reload").onclick = () => act("reload");
$("b-fill").onclick   = () => act("fill");
$("b-code").onclick   = sendCode;
$("mfa-code").addEventListener("keydown", e => { if (e.key === "Enter") sendCode(); });
// Enter anywhere in the sign-in group logs in, like a native form.
for (const el of $("signin").querySelectorAll("input"))
  el.addEventListener("keydown", e => { if (e.key === "Enter") $("b-login").click(); });

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
