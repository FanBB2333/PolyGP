#!/usr/bin/env python3
"""HTTP control plane for the PolyGP container.

Turns the one-shot script into a long-lived service. Without it the container is
a single connection attempt that dies with the session; with it the tunnel is
something you start, stop and inspect from one page:

    GET  /            the control panel; every action is a button on it
    GET  /status      JSON: state, tunnel IP, session expiry, socks port
    POST /login       begin a SAML login; drive the browser via noVNC
    POST /renew       drop the session and start a fresh login right away
    POST /code        queue an MFA code (starts a fresh login while idle)
    POST /fill        fill + submit the credential form (manual fill mode)
    POST /set         change one option (key/value), applied at the next login
    POST /save        change several options at once (form fields by name)
    POST /logout      disconnect and go back to idle
    POST /reload      re-read the mounted .env, applied at the next login
    GET  /logs        recent openconnect output

The action endpoints answer GET too, redirecting back to the panel, so they can
be poked from a URL bar. The login itself still happens in the browser on the
container's virtual display: /login creates a fresh SAML request only when you
ask for a login, then you finish NetID + MFA over noVNC. You may also submit an
MFA code while the service is idle; that starts the same fresh login and keeps
the code queued until the page asks for it. With credentials configured, the
form is filled after the first click in the login page, and POLYGP_VPN_CHOICE
picks the service option that follows.

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

# openconnect keeps running while it retries a broken transport, so process
# liveness alone cannot describe whether the tunnel is currently usable.  These
# messages are emitted when its established data path is lost.  A successful
# getconfig response is followed by the tunnel timeout line and marks the point
# where the transport is usable again; a bare "Connected to HTTPS" is too early
# because the following HTTP exchange can still fail.
RE_RECONNECTING = re.compile(
    r"(?:"
    r"(?:GPST\s+)?Dead Peer Detection detected dead peer|"
    r"(?:Read|Write) error on (?:SSL|DTLS) session|"
    r"Packet (?:receive|send) error|"
    r"SSL connection failure|"
    r"Failed to (?:reconnect to host|open HTTPS connection)|"
    r"Error reading HTTP response|"
    r"\bsleep \d+s, remaining timeout \d+s"
    r")",
    re.IGNORECASE,
)
RE_RECONNECTED = re.compile(r"Tunnel timeout \(rekey interval\) is ", re.IGNORECASE)

# How long to wait after an unexpected openconnect death before the automatic
# re-login kicks off — long enough for the transient network hiccup that
# usually killed it (a failed periodic HIP recheck) to pass, short enough to
# feel immediate.
RELOGIN_DELAY = 5.0


def parse_expiry_epoch(text: str) -> float | None:
    """openconnect prints the expiry as a bare ctime string in its own local
    timezone (UTC in this container). Parsed here — same process, same libc
    timezone — time.mktime inverts that formatting to a correct absolute epoch,
    which the browser can then show in the viewer's zone and count down against
    without a timezone guess."""
    try:
        return time.mktime(time.strptime(text.strip(), "%a %b %d %H:%M:%S %Y"))
    except (ValueError, OverflowError):
        return None


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
    # POLYGP_FILL_MODE: auto (fill + submit after one click in the login page),
    # manual (only after the panel's Fill button), off. POLYGP_NO_FILL=1 is the
    # older off switch.
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
        # Start a fresh login by itself when the tunnel dies underneath a live
        # session (openconnect treats a failed periodic HIP recheck as fatal:
        # it logs the session out and exits, so reconnecting is not enough).
        "auto_relogin": env("POLYGP_AUTO_RELOGIN", "on").strip().lower() != "off",
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
    "auto_relogin": ("POLYGP_AUTO_RELOGIN", ("on", "off")),
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
        # idle|awaiting-login|connecting|connected|reconnecting|failed
        self.state = "idle"
        self.browser_ready = False
        self.detail = ""
        self.ip = ""
        self.expiry = ""
        self.expiry_epoch: float | None = None
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

    def session_active(self) -> bool:
        return self.state in ("connected", "reconnecting")

    def _set_browser_ready(self, ready: bool, generation: int | None = None) -> None:
        with self.lock:
            # A cancelled browser can finish after /renew has already started
            # the next one.  Its late callback must not hide the new browser
            # from the panel.
            if generation is not None and generation != self.generation:
                return
            self.browser_ready = bool(ready)

    def busy(self) -> bool:
        return self.state in ("awaiting-login", "connecting") or self.session_active()

    def start(self, initial_code: str | None = None) -> tuple[bool, str]:
        """Start a fresh login, optionally queuing an MFA code first.

        Keeping the optional code in the new feed is important: ``start``
        replaces the feed on every attempt so input from an abandoned attempt
        cannot leak into the next one.  A code submitted while idle therefore
        has to be installed at the same time as the new feed, before the
        prelogin/browser thread is launched.
        """
        with self.lock:
            if self.busy():
                return False, f"already {self.state}"
            self.generation += 1
            gen = self.generation
            self._set("awaiting-login", "opening the browser")
            self.browser_ready = False
            self.ip = self.expiry = ""
            self.expiry_epoch = None
            self.feed = gp.LoginFeed()
            if initial_code:
                self.feed.offer(initial_code)
            threading.Thread(target=self._run, args=(gen, self.feed),
                             daemon=True).start()
            if initial_code:
                return True, ("code received — opening a fresh SAML login; "
                              "it will be entered when the page asks")
            return True, "login started — finish it in the browser over noVNC"

    def stop(self) -> tuple[bool, str]:
        with self.lock:
            previous_state = self.state
            if previous_state in ("awaiting-login", "connecting", "connected", "reconnecting"):
                # Invalidate an in-flight prelogin/browser/openconnect handoff.
                # In particular, this lets a prelogin retry wait notice Logout
                # immediately instead of opening the browser afterwards.
                self.generation += 1
            self.browser_ready = False
            # A code queued for the old SAML page must not remain visible or be
            # typed into a later attempt after Logout/Renew.
            self.feed.discard_pending()
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
        if previous_state in ("awaiting-login", "connecting"):
            # The cancellation callback lets the browser thread close promptly
            # instead of waiting for the configured login timeout.
            self._set("idle", "login abandoned")
            return True, "login cancelled (the browser closed)"
        if previous_state in ("connected", "reconnecting"):
            # The reader thread may have observed process exit and cleared
            # self.proc just before it publishes the final state.
            self._set("idle", "disconnected")
            return True, "disconnected"
        return False, "not connected"

    def renew(self) -> tuple[bool, str]:
        """Disconnect (if connected) and start a fresh login — for a session near expiry."""
        self.stop()
        return self.start()

    def submit_code(self, code: str) -> tuple[bool, str]:
        """Queue an MFA code, starting a fresh login when none is running.

        Starting from an idle/failed state is the code-first path: no SAML URL
        exists before this method accepts the code, so the request is generated
        as late as possible.  During an active login the existing mailbox path
        is retained, allowing a replacement code after a failed MFA attempt.
        """
        code = (code or "").strip()
        if not code:
            return False, "empty code"
        if len(code) > 32:
            return False, "that does not look like a verification code"

        # Do not hold self.lock while calling start(): it acquires the same
        # lock.  A concurrent /login can win the race; in that case the second
        # block below simply queues this code in the now-active feed.
        with self.lock:
            state = self.state
        if state in ("idle", "failed"):
            started, message = self.start(initial_code=code)
            if started:
                self.log("[control] verification code received; starting a fresh login")
                return True, message

        with self.lock:
            if self.state != "awaiting-login":
                return False, f"no login waiting for input (state: {self.state})"
            self.feed.offer(code)
        self.log("[control] verification code received from the panel")
        return True, "code sent — it is typed in as soon as the field is on the page"

    def request_fill(self) -> tuple[bool, str]:
        """Trigger the credential prefill from the panel (manual fill mode)."""
        if self.state != "awaiting-login":
            return False, f"no login waiting for input (state: {self.state})"
        fill_mode = self.opts.get("fill_mode", "off")
        if fill_mode != "manual":
            if fill_mode == "off":
                return False, "credential fill is switched off in the settings"
            return False, "set credential fill to manual to use this button"
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
        if self.session_active():
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
        if self.session_active():
            note += " (the current tunnel keeps its old settings)"
        return True, note

    def _consume_openconnect_line(self, line: str) -> None:
        """Update the public state from one line of openconnect output."""
        if m := RE_CONFIGURED.search(line):
            self.ip = m.group(1)
            self._set("connected", f"tunnel IP {self.ip}")
        elif m := RE_EXPIRY.search(line):
            self.expiry = m.group(1).strip()
            self.expiry_epoch = parse_expiry_epoch(self.expiry)
        elif self.session_active() and RE_RECONNECTING.search(line):
            if self.state != "reconnecting":
                self._set("reconnecting", "tunnel interrupted; OpenConnect is retrying")
        elif self.state == "reconnecting" and RE_RECONNECTED.search(line):
            detail = "tunnel restored"
            if self.ip:
                detail += f"; IP {self.ip}"
            self._set("connected", detail)

    def _run(self, gen: int, feed: gp.LoginFeed) -> None:
        o = self.opts
        try:
            method, entry = gp.prelogin(
                o["host"], o["gateway"],
                log=lambda message: self.log(f"[control] {message}"),
                cancelled=lambda: gen != self.generation,
            )
            if gen != self.generation:
                return
            self.log(f"[control] SAML {method} via {entry.split('?')[0]}")
            on_browser_ready = lambda ready: self._set_browser_ready(ready, gen)
            got = gp.browser_login(entry, method, o["timeout"], False, None,
                                   o["fill_mode"], o["choice"], feed,
                                   on_browser_ready,
                                   cancelled=lambda: gen != self.generation)
        except BaseException as e:                  # SystemExit included
            self._set_browser_ready(False, gen)
            if gen == self.generation:
                feed.discard_pending()
                self._set("failed", f"login failed: {e}")
            return

        self._set_browser_ready(False, gen)

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
            self._consume_openconnect_line(line)

        rc = proc.wait()
        if gen == self.generation:
            with self.lock:
                self.proc = None
            # A terminate() from /logout or /renew is an intended stop, not a failure.
            clean = rc in (0, -15, 143)
            had_session = self.session_active()
            self._set("idle" if clean else "failed", f"openconnect exited ({rc})")
            # A session that dies underneath us is gone for good: openconnect
            # logs it out on the way down (a failed HIP recheck ends here), so
            # only a fresh SAML login brings the tunnel back. Start one now so
            # the panel is already waiting on MFA instead of sitting failed
            # until someone notices. One attempt only — if that login fails or
            # times out, it stays failed rather than paging the phone forever.
            if not clean and had_session and self.opts["auto_relogin"]:
                self._auto_relogin(gen)

    def _auto_relogin(self, gen: int) -> None:
        """Kick off a delayed start(); a manual /login, /renew or /logout in
        the meantime bumps the generation and wins over it."""
        def kick():
            time.sleep(RELOGIN_DELAY)
            if gen != self.generation:
                return
            self.log("[control] session lost — starting a new login "
                     "automatically (set auto_relogin off to disable)")
            self.start()
        threading.Thread(target=kick, daemon=True).start()

    def status(self) -> dict:
        o = self.opts
        mfa = self.feed.snapshot()
        screen_width, screen_height = gp.vnc_screen_size()
        # Remember the last non-empty sighting; the login page moves on (or
        # the login ends) but the suggestions should stay.
        if choices := mfa.pop("choices", []):
            self.vpn_options = choices
        return {
            "state": self.state,
            "detail": self.detail,
            "tunnel_ip": self.ip,
            "session_expires": self.expiry,
            "session_expires_epoch": self.expiry_epoch,
            # The container's timezone (set from the egress IP at boot); the
            # panel shows times in it so they read as local to the tunnel.
            "timezone": os.environ.get("TZ", "") or time.tzname[0],
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
                "auto_relogin": "on" if o["auto_relogin"] else "off",
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
                "screen_width": screen_width,
                "screen_height": screen_height,
                "browser_ready": self.browser_ready,
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
.pill.unknown{background:var(--sep);color:var(--value)}
.pill[data-s="awaiting-login"],.pill[data-s="connecting"],.pill.reconnecting{
  background:var(--warn-bg);color:var(--warn)}

/* ---- content ---- */
.content{min-width:0}
.pane{display:none}
.pane.active{display:block}
h1{font-size:1.45rem;font-weight:650;letter-spacing:-.015em;margin:.1rem 0 1rem}
h2{font-size:.76rem;font-weight:600;color:var(--value);text-transform:uppercase;
   letter-spacing:.06em;margin:1.5rem .9rem .45rem}
.foot{font-size:.8rem;color:var(--value);margin:.5rem .9rem 0;line-height:1.45;
      max-width:56rem}

/* Overview sections sit side by side as small cards on a wide (16:9) window
   instead of one long column, so a row never stretches across the whole
   screen. Each card still hides/shows as a unit under the state logic, and
   the grid packs whatever is visible. */
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(23rem,100%),1fr));
       gap:1.15rem;align-items:start;margin-top:1.15rem}
.card{min-width:0}
.card h2{margin-top:.15rem}

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

/* Combo: a free-text input plus an explicit dropdown of the captured
   options. The native <datalist> was unreliable here — its popover filters
   on the current value and often refuses to open at all. */
.combo{position:relative;flex:0 0 auto;width:min(60%,15rem)}
.row .combo input{width:100%;padding-right:2rem}
.combo-btn{position:absolute;top:50%;right:.25rem;transform:translateY(-50%);
     width:1.6rem;height:1.6rem;padding:0;border:0;border-radius:.4rem;
     background:none;color:var(--value);cursor:pointer;display:grid;place-items:center}
.combo-btn:hover:not(:disabled){background:var(--accent-soft);color:var(--accent-deep)}
.combo-btn:disabled{opacity:.5;cursor:default}
.combo-btn svg{width:.95rem;height:.95rem;stroke:currentColor;fill:none;
     stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.combo-menu{position:absolute;top:calc(100% + .35rem);right:0;min-width:100%;
     max-width:22rem;max-height:14rem;overflow:auto;background:var(--group);
     border:1px solid var(--line);border-radius:.6rem;padding:.3rem;z-index:6;
     box-shadow:0 8px 24px rgba(44,56,65,.16)}
.combo-menu button{display:block;width:100%;text-align:left;font:inherit;
     font-size:.88rem;padding:.4rem .6rem;border:0;border-radius:.4rem;
     background:none;color:var(--label);cursor:pointer;white-space:nowrap;
     overflow:hidden;text-overflow:ellipsis}
.combo-menu button:hover{background:var(--accent-soft)}
.combo-menu .none{padding:.45rem .6rem;font-size:.8rem;color:var(--value)}

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
.status.unknown .dot{background:var(--value)}
.status[data-s="awaiting-login"] .dot,.status[data-s="connecting"] .dot,
.status.reconnecting .dot{background:var(--warn)}
.status-main{display:flex;align-items:center;gap:.75rem;flex:1 1 14rem;min-width:0}
.status-title{font-size:1.1rem;font-weight:600;letter-spacing:-.01em;
              text-transform:capitalize}
.status-sub{font-size:.83rem;color:var(--value);overflow-wrap:anywhere}
.status-acts{display:flex;gap:.5rem;flex:0 0 auto}

.bar{height:.4rem;border-radius:.25rem;background:var(--sep);overflow:hidden}
.bar i{display:block;height:100%;width:0;border-radius:.25rem;
       background:var(--accent);transition:width .4s}

/* Login flow: the stations a login passes through, left to right. The active
   station is highlighted, finished ones get a check, and the two inputs a
   login needs (the Log in button, the MFA code) live inside their stations,
   so it is obvious at which step each one acts. */
.flow-wrap{margin-top:1.15rem;display:flex;align-items:stretch;gap:.3rem;
     padding:1rem 1.1rem;overflow-x:auto}
.fstep{flex:1 1 0;min-width:8.8rem;display:flex;flex-direction:column;gap:.5rem;
     padding:.6rem .65rem;border-radius:.7rem;transition:background .2s,opacity .2s}
.fstep.todo{opacity:.62}
.fstep.active{background:var(--accent-soft)}
.fstep.active.error{background:var(--bad-bg)}
.fstep.active.warn{background:var(--warn-bg)}
.fstep.active.ok{background:var(--ok-bg)}
.ftop{display:flex;align-items:center;gap:.5rem}
.fdot{width:1.45rem;height:1.45rem;border-radius:50%;flex:none;display:grid;
     place-items:center;font-size:.76rem;font-weight:650;
     background:var(--sep);color:var(--value);transition:background .2s}
.fstep.active .fdot{background:var(--accent-deep);color:#fff}
.fstep.active.error .fdot{background:var(--bad)}
.fstep.active.warn .fdot{background:var(--warn)}
.fstep.active.ok .fdot,.fstep.done .fdot{background:var(--ok);color:#fff}
.fname{font-size:.88rem;font-weight:600}
.fsub{font-size:.74rem;line-height:1.4;color:var(--value);overflow-wrap:anywhere}
.fstep.active.error .fsub{color:var(--bad)}
.fjoin{flex:0 0 1.2rem;height:2px;border-radius:1px;background:var(--line);
     align-self:flex-start;margin-top:1.31rem}
.fjoin.done{background:var(--accent)}
.fbtn{align-self:flex-start}
.fcode{display:flex;gap:.35rem}
.fcode input{flex:1 1 auto;min-width:0;height:2.05rem;font:inherit;
     font-size:.88rem;padding:0 .6rem;color:var(--label);
     border:1px solid var(--line);border-radius:.5rem;background:#fff;
     -webkit-appearance:none;appearance:none}
.fcode input::placeholder{color:var(--value);opacity:.75}
.fcode input:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:transparent}
.fcode input:disabled{background:var(--sep);opacity:.7}
.fsend{height:2.05rem;padding:0 .75rem;border:0;border-radius:.5rem;font:inherit;
     font-size:.85rem;font-weight:550;background:var(--accent);color:#fff;
     cursor:pointer;flex:none;transition:background .15s,opacity .15s}
.fsend:hover:not(:disabled){background:var(--accent-deep)}
.fsend:disabled{opacity:.45;cursor:default}

/* Toast: action results, so the sidebar no longer has to carry them. */
.toast{position:fixed;left:50%;bottom:1.4rem;transform:translate(-50%,1.5rem);
       background:rgba(44,56,65,.94);color:#fff;font-size:.86rem;
       padding:.55rem 1.05rem;border-radius:2rem;max-width:min(34rem,90vw);
       box-shadow:0 6px 18px rgba(44,56,65,.22);opacity:0;pointer-events:none;
       transition:opacity .2s,transform .2s;z-index:9}
.toast.show{opacity:1;transform:translate(-50%,0)}

/* Logs toolbar: search, severity/source chips, scroll shortcuts. */
.logbar{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap;margin:.35rem 0 .6rem}
.logbar input{flex:1 1 11rem;min-width:8rem;height:2.1rem;font:inherit;font-size:.88rem;
     padding:0 .65rem;color:var(--label);border:1px solid var(--line);
     border-radius:.55rem;background:#fff;-webkit-appearance:none;appearance:none}
.logbar input::placeholder{color:var(--value);opacity:.75}
.logbar input:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:transparent}
.chipset{display:inline-flex;align-items:center;gap:.35rem}
.chipset button{height:2.1rem;padding:0 .8rem;font:inherit;font-size:.85rem;
     border:1px solid var(--line);border-radius:.55rem;background:#fff;
     color:var(--value);cursor:pointer;white-space:nowrap;
     transition:background .15s,border-color .15s,color .15s}
.chipset button:hover{border-color:var(--accent)}
.chipset button.on{background:var(--accent-soft);border-color:var(--accent);
     color:var(--accent-deep);font-weight:550}
.chipset button.on[data-lv=err]{background:var(--bad-bg);border-color:var(--bad);color:var(--bad)}
.chipset button.on[data-lv=warn]{background:var(--warn-bg);border-color:var(--warn);color:var(--warn)}
.chipset button.on[data-lv=ok]{background:var(--ok-bg);border-color:var(--ok);color:var(--ok)}
.logcount{font-size:.78rem;color:var(--value);white-space:nowrap}

/* One element per line, so each can carry its own severity colour. */
.logbox{padding:.5rem 0;height:calc(100vh - 15rem);min-height:20rem;overflow:auto;
        font:.78rem/1.65 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.ln{display:flex;gap:.6rem;padding:.03rem 1rem .03rem .6rem;color:#5b6a75}
.ln:hover{background:#f6f9fb}
.ln .no{flex:none;min-width:3ch;text-align:right;color:var(--value);opacity:.55;
        user-select:none;font-variant-numeric:tabular-nums}
.ln .tx{min-width:0;white-space:pre-wrap;overflow-wrap:anywhere}
.ln mark.hit{background:var(--warn-bg);color:inherit;border-radius:.15rem;
        padding:0 .05rem;font-weight:600}
.ln.err{color:var(--bad);background:rgba(176,113,106,.07)}
.ln.warn{color:var(--warn)}
.ln.ok{color:var(--ok)}
.ln .tag{font-weight:650;color:var(--accent-deep)}
.ln.err .tag,.ln.warn .tag,.ln.ok .tag{color:inherit}
.ln .tok{color:var(--label);font-weight:500}
.logbox .empty{padding:1rem;color:var(--value)}

/* noVNC preserves the remote framebuffer's aspect ratio in local-scaling
   mode.  A full-width, fixed-height iframe therefore turns a wide panel into
   a letterboxed strip.  The frame below is sized by fitVnc() to the largest
   rectangle that fits the available panel height; the CSS dimensions are a
   useful first paint before JavaScript has measured the pane. */
.novnc-shell{--vnc-aspect:1.422222;
     width:100%;display:flex;justify-content:center;align-items:flex-start;
     background:transparent;min-height:16rem}
.novnc-frame{position:relative;flex:0 0 auto;width:min(100%,calc((100vh - 13rem)*var(--vnc-aspect)));
     max-width:100%;aspect-ratio:var(--vnc-aspect);background:#000;
     border-radius:var(--radius);overflow:hidden;
     box-shadow:0 1px 2px rgba(44,56,65,.16)}
.novnc-frame iframe{display:block;width:100%;height:100%;border:0;background:#000}
.novnc-overlay{position:absolute;inset:0;display:flex;flex-direction:column;
     align-items:center;justify-content:center;gap:.35rem;padding:1.5rem;
     text-align:center;color:#dce4e9;background:#252a2e}
.novnc-overlay[hidden]{display:none}
.novnc-overlay strong{font-size:1rem;font-weight:600}
.novnc-overlay span{max-width:34rem;color:#aebbc4;font-size:.85rem;line-height:1.5}
.big{display:inline-flex;align-items:center;gap:.5rem;background:var(--accent);
     color:#fff;text-decoration:none;font-size:1rem;font-weight:600;
     padding:.85rem 1.6rem;border-radius:.7rem;transition:background .15s}
.big:hover{background:var(--accent-deep)}
.big.disabled{opacity:.45;pointer-events:none;cursor:default}

@media (max-width:46rem){
  .app{grid-template-columns:1fr;gap:.9rem}
  aside{position:static}
  nav{flex-direction:row;flex-wrap:wrap}
  nav button{width:auto}
  .row input{width:min(70%,12rem)}
  .row .combo{width:min(70%,12rem)}
  .novnc-shell{min-height:0}
  .novnc-frame{width:100%}
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

      <!-- The login, as a left-to-right flow. Each station carries the input
           that acts at that step, so the buttons explain themselves. -->
      <div class="group flow-wrap" id="flow" aria-label="Login progress">
        <div class="fstep" id="fs-start">
          <div class="ftop"><span class="fdot">1</span><span class="fname">Start</span></div>
          <button class="btn primary fbtn" id="b-login">Log in</button>
          <div class="fsub" id="fs-start-sub">Opens a fresh SAML login in the container browser.</div>
        </div>
        <div class="fjoin"></div>
        <div class="fstep" id="fs-netid">
          <div class="ftop"><span class="fdot">2</span><span class="fname">NetID</span></div>
          <button class="btn fbtn" id="b-fill" hidden>Fill &amp; log in</button>
          <div class="fsub" id="fs-netid-sub">The browser signs in with your NetID.</div>
        </div>
        <div class="fjoin"></div>
        <div class="fstep" id="fs-code">
          <div class="ftop"><span class="fdot">3</span><span class="fname">MFA code</span></div>
          <div class="fcode">
            <input id="mfa-code" inputmode="numeric" autocomplete="one-time-code"
                   maxlength="32" placeholder="Code" aria-label="MFA code">
            <button class="fsend" id="b-code">Send</button>
          </div>
          <div class="fsub" id="mfa-hint"></div>
        </div>
        <div class="fjoin"></div>
        <div class="fstep" id="fs-tunnel">
          <div class="ftop"><span class="fdot">4</span><span class="fname">Tunnel</span></div>
          <div class="fsub" id="fs-tunnel-sub">openconnect brings the VPN up.</div>
        </div>
        <div class="fjoin"></div>
        <div class="fstep" id="fs-done">
          <div class="ftop"><span class="fdot">5</span><span class="fname">Connected</span></div>
          <div class="fsub" id="fs-done-sub">SOCKS5 proxy ready.</div>
        </div>
      </div>

      <div class="cards">

      <!-- shown while idle / failed -->
      <div class="card" id="signin">
        <h2>Sign in</h2>
        <div class="group">
          <div class="row"><div class="k">NetID</div>
            <input id="f-netid" data-key="netid" autocomplete="username"></div>
          <div class="row"><div class="k">NetPassword</div>
            <input id="f-netpass" data-key="netpass" type="password"
                   autocomplete="current-password"></div>
          <div class="row"><div class="k">VPN service</div>
            <div class="combo">
              <input id="f-choice" data-key="vpn_choice" placeholder="research">
              <button class="combo-btn" type="button" aria-label="Show choices">
                <svg viewBox="0 0 16 16"><path d="M4.5 6.5 8 10l3.5-3.5"/></svg>
              </button>
              <div class="combo-menu" hidden></div>
            </div></div>
          <div class="row"><div class="k">Credential fill</div>
            <div class="seg" id="f-fill" data-key="fill_mode">
              <button data-v="auto">Auto</button>
              <button data-v="manual">Manual</button>
              <button data-v="off">Off</button>
            </div></div>
        </div>
        <p class="foot" id="signin-foot"></p>
      </div>

      <div class="card">
        <h2>Connection</h2>
        <div class="group">
          <div class="row"><div class="k">Tunnel IP</div><div class="v strong" id="o-ip">—</div></div>
          <div class="row"><div class="k">SOCKS5 proxy</div><div class="v strong" id="o-socks">—</div></div>
          <div class="row"><div class="k">VPN service</div><div class="v" id="o-choice">—</div></div>
          <div class="row"><div class="k">In this state for</div><div class="v" id="o-uptime">—</div></div>
        </div>
        <p class="foot">Point your proxy tool at the SOCKS5 address. Nothing on this
          machine is rerouted on its own.</p>
      </div>

      <div class="card" id="session">
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
    </div>

    <!-- ================= Browser ================= -->
    <div class="pane" id="p-browser">
      <h1>Browser</h1>
      <div class="status" style="justify-content:space-between">
        <div class="status-main"><div style="min-width:0">
          <div class="status-title" style="font-size:.98rem">Login browser</div>
          <div class="status-sub" id="novnc-sub">The login browser is shown at the
            largest size that fits this window. Open it in its own tab if needed.</div>
        </div></div>
        <a class="big" id="novnc-open" href="#" target="_blank" rel="noreferrer"
           aria-label="Open VNC in a new tab">Open full screen &nbsp;&rarr;</a>
      </div>
      <h2>Live view</h2>
      <div class="novnc-shell" id="novnc-shell">
        <div class="novnc-frame" id="novnc-frame">
          <iframe id="novnc" title="noVNC" src="about:blank"></iframe>
          <div class="novnc-overlay" id="novnc-overlay" role="status" aria-live="polite" hidden>
            <strong id="novnc-message-title">Waiting for the login browser</strong>
            <span id="novnc-message">Start a login to open Chromium on the virtual display.</span>
          </div>
        </div>
      </div>
    </div>

    <!-- ================= Logs ================= -->
    <div class="pane" id="p-logs">
      <h1>Logs</h1>
      <h2>Recent output</h2>
      <div class="logbar">
        <input id="log-q" type="search" placeholder="Search logs"
               aria-label="Search logs">
        <div class="chipset" id="log-lv" aria-label="Severity filter">
          <button data-lv="err" class="on">Error</button>
          <button data-lv="warn" class="on">Warn</button>
          <button data-lv="ok" class="on">OK</button>
          <button data-lv="info" class="on">Info</button>
        </div>
        <div class="chipset" id="log-src" aria-label="Source filter">
          <button data-src="control" class="on">control</button>
          <button data-src="gp" class="on">gp</button>
          <button data-src="oc" class="on">openconnect</button>
        </div>
        <span class="logcount" id="log-count"></span>
        <span style="flex:1 1 0"></span>
        <button class="btn" id="log-top" title="Scroll to the first line">Top</button>
        <button class="btn" id="log-end" title="Scroll to the latest line">End</button>
        <button class="btn" id="log-copy" title="Copy the visible lines">Copy</button>
      </div>
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
          <div class="combo">
            <input id="s-choice" data-key="vpn_choice" placeholder="pick by hand">
            <button class="combo-btn" type="button" aria-label="Show choices">
              <svg viewBox="0 0 16 16"><path d="M4.5 6.5 8 10l3.5-3.5"/></svg>
            </button>
            <div class="combo-menu" hidden></div>
          </div></div>
        <div class="row"><div class="k">Login timeout<small>seconds to finish MFA</small></div>
          <input id="s-timeout" data-key="login_timeout" type="number" min="60" max="7200" step="60"></div>
        <div class="row"><div class="k">Reconnect window<small>how long to retry after a drop</small></div>
          <input id="s-reconnect" data-key="reconnect_timeout" type="number" min="300" max="604800" step="300"></div>
        <div class="row"><div class="k">Auto re-login<small>start a new login if the session dies</small></div>
          <div class="seg" id="s-relogin" data-key="auto_relogin">
            <button data-v="on">On</button>
            <button data-v="off">Off</button>
          </div></div>
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
      <p class="foot"><b>Auto</b> submits the form after one trusted click in Browser.
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

<div class="toast" id="toast"></div>

<script>
const Q = "__TOKEN_QUERY__";
const $ = id => document.getElementById(id);
let novncUrl = "", busy = false, pane = "overview", framed = false, lastState = "";
let statusSeen = false, missedPolls = 0;
let vncAspect = 1280 / 900, vncBrowserReady = true, vncFitFrame = 0;
let vpnOpts = [];   // option texts captured from the login pages
// Fields edited but not yet saved: the poller must not overwrite them.
const dirty = new Set();

document.querySelectorAll("nav button").forEach(b => b.onclick = () => {
  pane = b.dataset.pane;
  document.querySelectorAll("nav button").forEach(x => x.classList.toggle("active", x === b));
  document.querySelectorAll(".pane").forEach(p => p.classList.toggle("active", p.id === "p-" + pane));
  // Opening Logs lands on the tail: the box is rendered while hidden (its
  // geometry reads as zero there), so the parked-at-end heuristic alone
  // cannot place it, and the newest lines are what the pane is opened for.
  if (pane === "logs")
    poll().then(() => { const x = $("logs"); x.scrollTop = x.scrollHeight; });
  if (pane === "browser"){
    if (!framed && novncUrl) { $("novnc").src = novncUrl; framed = true; }
    scheduleVncFit();
  }
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

// The VPN service dropdowns: list every captured option, unfiltered, and put
// the picked one into the input (which stays free text for anything else).
for (const box of document.querySelectorAll(".combo")){
  const input = box.querySelector("input"),
        btn = box.querySelector(".combo-btn"),
        menu = box.querySelector(".combo-menu");
  btn.onclick = () => {
    if (!menu.hidden){ menu.hidden = true; return; }
    menu.textContent = "";
    if (!vpnOpts.length){
      const d = document.createElement("div");
      d.className = "none";
      d.textContent = "No options seen yet — they are captured during a login.";
      menu.append(d);
    }
    for (const o of vpnOpts){
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = o;
      b.onclick = () => { fset(input, o); dirty.add(input); menu.hidden = true; };
      menu.append(b);
    }
    menu.hidden = false;
  };
}
// Any click outside a combo closes its menu.
document.addEventListener("click", e => {
  for (const box of document.querySelectorAll(".combo"))
    if (!box.contains(e.target)) box.querySelector(".combo-menu").hidden = true;
});

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

function updateVncAspect(v){
  const width = Number(v && v.screen_width), height = Number(v && v.screen_height);
  if (Number.isFinite(width) && Number.isFinite(height) && width > 0 && height > 0)
    vncAspect = width / height;
  // Older containers do not report browser_ready; preserve their previous
  // behaviour and let the state/URL decide whether the frame is useful.
  vncBrowserReady = typeof (v && v.browser_ready) === "boolean" ? v.browser_ready : true;
  const shell = $("novnc-shell");
  if (shell) shell.style.setProperty("--vnc-aspect", String(vncAspect));
  scheduleVncFit();
}

function fitVnc(){
  if (pane !== "browser") return;
  const shell = $("novnc-shell"), frame = $("novnc-frame");
  if (!shell || !frame) return;
  const maxWidth = shell.clientWidth;
  if (!maxWidth) return;
  // Size from the shell's place in the document, not from the current scroll
  // position: the frame must keep one size while the page scrolls under it,
  // so the wheel only ever moves the page.  Width is derived from the height
  // limit, so the iframe and the remote framebuffer keep the same ratio even
  // on an ultrawide panel; 16px leaves breathing room below the frame.
  const shellTop = shell.getBoundingClientRect().top + window.scrollY;
  const maxHeight = Math.max(240, window.innerHeight - shellTop - 16);
  const width = Math.max(1, Math.floor(Math.min(maxWidth, maxHeight * vncAspect)));
  const height = Math.max(1, Math.floor(width / vncAspect));
  frame.style.width = width + "px";
  frame.style.height = height + "px";
}

function scheduleVncFit(){
  if (vncFitFrame) return;
  vncFitFrame = requestAnimationFrame(() => { vncFitFrame = 0; fitVnc(); });
}

function updateVncView(state, detail, fillMode){
  const frame = $("novnc-frame"), iframe = $("novnc"), overlay = $("novnc-overlay");
  const open = $("novnc-open"), sub = $("novnc-sub");
  if (!frame || !iframe || !overlay) return;
  const hasUrl = Boolean(novncUrl && novncUrl !== "about:blank");
  const browserExpected = state === "awaiting-login" || state === "connecting";
  const showFrame = browserExpected && hasUrl && vncBrowserReady;
  const messages = {
    idle: ["No login browser", "Click Log in, or submit an MFA code on Overview to open a fresh SAML login."],
    failed: ["The login browser is not running", detail || "Click Log in, or submit a fresh MFA code to try again."],
    connected: ["Login complete", "The temporary login browser closes after authentication. Use Renew when another login is needed."],
    reconnecting: ["VPN is reconnecting", "There is no login browser to display while the tunnel is retrying."],
    unknown: ["Control service unavailable", "The panel cannot read /status right now; the VNC canvas is paused."],
  };
  const copy = messages[state] || ["Starting the login browser", detail || "The VNC view will appear as soon as Chromium is ready."];
  const clickHint = fillMode === "auto" && state === "awaiting-login";
  overlay.hidden = showFrame;
  $("novnc-message-title").textContent = copy[0];
  $("novnc-message").textContent = copy[1];
  iframe.style.visibility = showFrame ? "visible" : "hidden";
  iframe.setAttribute("aria-hidden", showFrame ? "false" : "true");
  frame.classList.toggle("empty", !showFrame);
  if (sub){
    sub.textContent = showFrame
      ? (clickHint
        ? "Click once inside the login page to start automatic credential filling."
        : "The login browser is fitted to the largest area that preserves the VNC screen ratio.")
      : copy[1];
  }
  if (open){
    const openable = hasUrl && browserExpected && vncBrowserReady;
    open.classList.toggle("disabled", !openable);
    open.setAttribute("aria-disabled", openable ? "false" : "true");
    open.tabIndex = openable ? 0 : -1;
  }
  scheduleVncFit();
}

// Refit on layout changes only — never on scroll, which must not resize the
// frame (fitVnc's formula is scroll-independent for the same reason).
window.addEventListener("resize", scheduleVncFit);
if (window.ResizeObserver){
  const ro = new ResizeObserver(scheduleVncFit);
  ro.observe($("p-browser"));
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
  const sessionActive = connected || s.state === "reconnecting";

  const card = $("status");
  card.className = "status " + s.state;
  card.dataset.s = s.state;
  $("o-state").textContent  = s.state.replace("-", " ");
  $("o-detail").textContent = s.detail || " ";

  // Only the actions that make sense for this state.
  $("b-cancel").style.display = inLogin ? "" : "none";
  $("b-renew").style.display  = sessionActive ? "" : "none";
  $("b-logout").style.display = sessionActive ? "" : "none";
  $("signin").style.display   = inLogin || sessionActive ? "none" : "";
  $("session").style.display  = sessionActive ? "" : "none";

  renderFlow(s);

  // The moment a login starts waiting, park the caret in the code field so the
  // code can be typed straight away — but never steal focus from a field that
  // is being edited.
  if (awaiting && lastState !== "awaiting-login" && pane === "overview" &&
      document.activeElement === document.body)
    $("mfa-code").focus();
  lastState = s.state;

  $("o-ip").textContent     = s.tunnel_ip || "—";
  $("o-socks").textContent  = "127.0.0.1:" + s.socks_port;
  $("o-choice").textContent = s.vpn_choice || "—";
  $("o-uptime").textContent = fmtDur(s.seconds_in_state);

  // Prefer the server-computed epoch: openconnect's string is a bare local
  // time in the container's zone (UTC), so parsing it in the browser assumed
  // the wrong zone. Fall back to the string only for an older container.
  const exp = sessionActive
    ? (s.session_expires_epoch ? new Date(s.session_expires_epoch * 1000)
                               : parseExpiry(s.session_expires))
    : null;
  // Show it in the container's timezone (set from the egress IP), with the
  // zone label so it is unambiguous. An unknown zone falls back to the
  // viewer's own; toLocaleString throws on a bad IANA name, hence the catch.
  let expText = "—";
  if (exp){
    const fmt = {timeZoneName: "short"};
    if (s.timezone) fmt.timeZone = s.timezone;
    try { expText = exp.toLocaleString(undefined, fmt); }
    catch(e){ expText = exp.toLocaleString(undefined, {timeZoneName: "short"}); }
  } else expText = s.session_expires || "—";
  $("o-exp").textContent = expText;
  if (exp){
    const left = (exp.getTime() - Date.now()) / 1000;
    $("o-left").textContent = left > 0 ? fmtDur(left) + " left"
                                       : "expired — renew to keep the tunnel";
    $("o-bar").style.width = Math.max(0, Math.min(100, left / 864)) + "%"; // of ~24h
  }

  if (pane !== "logs") renderLogs(s.logs || []);   // the pane pulls the full buffer itself

  // Built here rather than server-side so the host matches however you reached
  // this page, and so the VNC password rides along instead of being retyped.
  const v = s.vnc || {};
  updateVncAspect(v);
  const vncPort = Number(v.port) || 6080;
  novncUrl = v.url || (location.protocol + "//" + location.hostname + ":" + vncPort +
    "/vnc.html?autoconnect=1&resize=scale&reconnect=1" +
    (v.password ? "&password=" + encodeURIComponent(v.password) : ""));
  $("novnc-open").href = novncUrl;
  if (pane === "browser" && novncUrl && (!framed || $("novnc").src !== novncUrl)) {
    $("novnc").src = novncUrl;
    framed = true;
  }
  updateVncView(s.state, s.detail, (s.settings || {}).fill_mode || "");

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
  const codeHint = "The Log in button and the MFA code box live in the flow above; " +
                   "a code submitted while idle starts a fresh login with it queued.";
  const credentialHint = st.netpass_set
    ? (st.fill_mode === "auto"
      ? "Saved credentials will be filled after you click once inside Browser."
      : "Password stored — leave it empty to keep it.")
    : "No password stored; it is typed into the browser instead.";
  $("signin-foot").textContent = codeHint + " " + credentialHint;
  const pp = st.netpass_set ? "stored" : "not set";
  $("f-netpass").placeholder = pp;
  $("s-netpass").placeholder = pp;

  // The Fill button only acts on a login page that is currently open.
  $("b-fill").hidden = !(awaiting && st.fill_mode === "manual");
  $("b-fill").textContent = m.fill_pending ? "Filling…" : "Fill & log in";
  $("mfa-hint").textContent =
    m.pending ? "queued — typed in as soon as the field appears" :
    m.prompt  ? "the page asks: " + m.prompt :
    inLogin   ? "typed into the page as soon as it asks" :
    sessionActive ? "not needed while connected" :
    "sending now starts a login with the code queued";

  // VPN service suggestions: the option texts the login pages actually showed.
  vpnOpts = [...new Set([...(st.vpn_options || []), st.vpn_choice, "research"])].filter(Boolean);

  for (const el of document.querySelectorAll("[data-key]")){
    const val = st[el.dataset.key];
    if (val === undefined || el === document.activeElement || dirty.has(el)) continue;
    fset(el, val);
  }

  setControlsDisabled(busy);
  // Flow inputs are always visible, so availability is expressed by disabling:
  // Log in restarts from rest, a code is useful up to the MFA step and (as the
  // code-first path) before a login exists at all.
  $("b-login").disabled = busy || !(s.state === "idle" || s.state === "failed");
  $("b-login").textContent = s.state === "failed" ? "Retry login" : "Log in";
  const codeUsable = awaiting || s.state === "idle" || s.state === "failed";
  $("b-code").disabled = busy || !codeUsable;
  $("mfa-code").disabled = !codeUsable;
}

// The flow strip: which station the login is at, what is finished, and what
// each station currently needs.
const FLOW_STEPS = ["fs-start","fs-netid","fs-code","fs-tunnel","fs-done"];
function renderFlow(s){
  const m = s.mfa || {}, st = s.settings || {};
  // awaiting-login spans two stations: the browser is on the credential pages
  // until the login page shows a code field (prompt) or a code is queued.
  const codeStep = s.state === "awaiting-login" && Boolean(m.prompt || m.pending);
  const at = {"idle": 0, "failed": 0,
              "awaiting-login": codeStep ? 2 : 1,
              "connecting": 3, "connected": 4, "reconnecting": 4}[s.state];
  const idx = at === undefined ? -1 : at;   // -1: status unknown, all grey
  const mood = s.state === "failed" ? " error" :
               s.state === "reconnecting" ? " warn" :
               s.state === "connected" ? " ok" : "";
  FLOW_STEPS.forEach((id, i) => {
    const el = $(id), dot = el.querySelector(".fdot");
    const done = idx >= 0 && (i < idx || (i === idx && s.state === "connected"));
    el.className = "fstep " + (i === idx ? "active" + mood : done ? "done" : "todo");
    dot.textContent = done ? "✓" : String(i + 1);
  });
  document.querySelectorAll(".fjoin").forEach((el, i) => {
    el.className = "fjoin" + (idx >= 0 && i < idx ? " done" : "");
  });
  $("fs-start-sub").textContent = s.state === "failed"
    ? (s.detail || "login failed — try again")
    : "Opens a fresh SAML login in the container browser.";
  $("fs-netid-sub").textContent =
    st.fill_mode === "auto"   ? "Credentials are filled after one click in Browser." :
    st.fill_mode === "manual" ? "Click Fill & log in once the page is open." :
    "Type your NetID and password in Browser.";
  $("fs-tunnel-sub").textContent = s.state === "connecting" && s.detail
    ? s.detail : "openconnect brings the VPN up.";
  $("fs-done-sub").textContent =
    s.state === "connected"    ? "Tunnel IP " + (s.tunnel_ip || "up") + " — SOCKS5 ready." :
    s.state === "reconnecting" ? "Tunnel interrupted — reconnecting…" :
    "SOCKS5 proxy ready.";
}

function setControlsDisabled(disabled){
  for (const id of ["b-login","b-renew","b-logout","b-cancel","b-reload","b-save","b-code","b-fill"])
    $(id).disabled = disabled;
  for (const b of document.querySelectorAll(".seg button")) b.disabled = disabled;
  for (const b of document.querySelectorAll(".combo-btn")) b.disabled = disabled;
}

function renderUnavailable(){
  const pill = $("pill"), card = $("status");
  pill.textContent = "unknown";
  pill.className = "pill unknown";
  pill.dataset.s = "unknown";
  card.className = "status unknown";
  card.dataset.s = "unknown";
  $("o-state").textContent = "status unavailable";
  $("o-detail").textContent = "cannot reach the local /status endpoint";
  for (const id of ["b-cancel", "b-renew", "b-logout"])
    $(id).style.display = "none";
  if (!statusSeen){
    $("signin").style.display = "none";
    $("session").style.display = "none";
  }
  renderFlow({state: "unknown"});
  $("mfa-code").disabled = true;
  updateVncView("unknown", "The panel cannot reach the local /status endpoint.");
  setControlsDisabled(true);
  lastState = "unknown";
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

// Search hits are marked by splitting text nodes, never by building markup
// from the line, so a log line that happens to contain HTML stays inert.
function markHits(root, q){
  if (!q) return;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  for (const node of nodes){
    const text = node.nodeValue, lower = text.toLowerCase();
    let i = lower.indexOf(q);
    if (i < 0) continue;
    const frag = document.createDocumentFragment();
    let pos = 0;
    while (i >= 0){
      frag.append(text.slice(pos, i));
      const mark = document.createElement("mark");
      mark.className = "hit";
      mark.textContent = text.slice(i, i + q.length);
      frag.append(mark);
      pos = i + q.length;
      i = lower.indexOf(q, pos);
    }
    frag.append(text.slice(pos));
    node.parentNode.replaceChild(frag, node);
  }
}

function logLine(text, no, q){
  const div = document.createElement("div");
  div.className = "ln" + severity(text);
  const num = document.createElement("span");
  num.className = "no";
  num.textContent = no;
  const tx = document.createElement("span");
  tx.className = "tx";
  let rest = text;
  const tag = /^\[(control|gp)\]\s*/.exec(text);
  if (tag){
    const el = document.createElement("span");
    el.className = "tag";
    el.textContent = tag[0].trimEnd();
    tx.append(el, " ");
    rest = text.slice(tag[0].length);
  }
  for (const part of rest.split(TOKENS)){
    if (!part) continue;
    if (IS_TOKEN.test(part)){
      const el = document.createElement("span");
      el.className = "tok";
      el.textContent = part;
      tx.append(el);
    } else tx.append(part);
  }
  markHits(tx, q);
  div.append(num, tx);
  return div;
}

// The raw buffer as last received, and the view filters over it. Line numbers
// are positions in that buffer, so a filtered view keeps its real numbering.
let logLines = [], logVisible = [];
const logLv  = {err: true, warn: true, ok: true, info: true};
const logSrc = {control: true, gp: true, oc: true};

function logMeta(t){
  const m = /^\[(control|gp)\]/.exec(t);
  return {sev: severity(t).trim() || "info", src: m ? m[1] : "oc"};
}

function renderLogs(lines){
  logLines = lines;
  applyLogView(false);
}

function applyLogView(filtersChanged){
  const box = $("logs");
  const q = $("log-q").value.trim().toLowerCase();
  const key = [logLines.length, logLines[logLines.length - 1] || "", q,
               JSON.stringify(logLv), JSON.stringify(logSrc)].join("|");
  if (box.dataset.have === key) return;
  box.dataset.have = key;
  // Follow the tail only when already parked at it, so scrolling back to read
  // something does not get yanked away by the next poll. A filter change
  // jumps to the tail: the newest matches are the interesting ones.
  const atEnd = filtersChanged ||
                box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  box.textContent = "";
  logVisible = [];
  const frag = document.createDocumentFragment();
  logLines.forEach((l, i) => {
    const meta = logMeta(l);
    if (!logLv[meta.sev] || !logSrc[meta.src]) return;
    if (q && !l.toLowerCase().includes(q)) return;
    logVisible.push(l);
    frag.append(logLine(l, i + 1, q));
  });
  $("log-count").textContent = logVisible.length + " / " + logLines.length;
  if (!logVisible.length){
    const e = document.createElement("div");
    e.className = "empty";
    e.textContent = logLines.length
      ? "No lines match the search or filters."
      : "No output yet.";
    box.append(e);
    return;
  }
  box.append(frag);
  if (atEnd) box.scrollTop = box.scrollHeight;
}

async function poll(){
  try{
    const r = await fetch("/status" + Q, {cache:"no-store"});
    if (!r.ok) throw new Error("status HTTP " + r.status);
    render(await r.json());
    statusSeen = true;
    missedPolls = 0;
  }catch(e){
    missedPolls += 1;
    if (missedPolls >= 2) renderUnavailable();
  }
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

// One code box serves both moments: during a login it feeds the waiting page;
// while idle or failed it is the code-first path, which starts a fresh login
// with the code queued.
async function sendCode(){
  const v = $("mfa-code").value.trim();
  if (!v) return;
  // Code-first must stay equivalent to clicking Log in: credentials and the
  // service choice edited in the Sign in card are applied before the fresh
  // SAML request is created.  Only edited fields force the save — if the
  // first status poll has not populated the fields yet, blank values must
  // not overwrite credentials already present in the service environment.
  if (lastState === "idle" || lastState === "failed"){
    const edited = [...$("signin").querySelectorAll("[data-key]")]
      .some(el => dirty.has(el));
    if (edited && !(await save("signin"))) return;
  }
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

// Logs toolbar. The chips toggle independently, so any mix of severities and
// sources can be shown; search is a plain case-insensitive substring.
$("log-q").addEventListener("input", () => applyLogView(true));
for (const b of $("log-lv").children) b.onclick = () => {
  logLv[b.dataset.lv] = !logLv[b.dataset.lv];
  b.classList.toggle("on", logLv[b.dataset.lv]);
  applyLogView(true);
};
for (const b of $("log-src").children) b.onclick = () => {
  logSrc[b.dataset.src] = !logSrc[b.dataset.src];
  b.classList.toggle("on", logSrc[b.dataset.src]);
  applyLogView(true);
};
$("log-top").onclick = () => { $("logs").scrollTop = 0; };
$("log-end").onclick = () => { const b = $("logs"); b.scrollTop = b.scrollHeight; };
$("log-copy").onclick = async () => {
  if (!logVisible.length) return toast("nothing to copy");
  const text = logVisible.join("\n");
  try{
    // clipboard API needs a secure context; the panel is often reached over
    // plain http on a LAN address, so fall back to the selection route.
    if (navigator.clipboard && window.isSecureContext){
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.append(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    toast("copied " + logVisible.length + " lines");
  }catch(e){ toast("copy failed: " + e); }
};

// Enter in the credential fields logs in, like a native form.  The flow's MFA
// field has its own handler above so Enter there must not also start a
// second, code-less login request.
for (const el of $("signin").querySelectorAll("input[data-key]"))
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

    # Do not mint a SAML request during container boot.  The request has a
    # server-side lifetime, and users often need time to open noVNC/get a fresh
    # MFA code.  /login (or /code while idle) starts it explicitly instead.
    if env("AUTO_LOGIN", "0") == "1":
        Handler.tunnel.start()

    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[control] listening on :{port}", file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        Handler.tunnel.stop()


if __name__ == "__main__":
    main()
