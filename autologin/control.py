#!/usr/bin/env python3
"""HTTP control plane for the PolyGP container.

Turns the one-shot script into a long-lived service. Without it the container is
a single connection attempt that dies with the session; with it the tunnel is
something you start, stop and inspect from one page:

    GET  /            the control panel; every action is a button on it
    GET  /status      JSON: state, tunnel IP, session expiry, socks port
    POST /login       begin a SAML login; drive the browser via noVNC
    POST /renew       drop the session and start a fresh login right away
    POST /code        type the MFA code (only while the page shows the field)
    POST /fill        fill + submit the credential form (manual fill mode)
    POST /set         change one option (key/value), applied at the next login
    POST /save        change several options at once (form fields by name)
    POST /logout      disconnect and go back to idle
    POST /reload      re-read the mounted .env, applied at the next login
    GET  /logs        recent openconnect output

The action endpoints answer GET too, redirecting back to the panel, so they can
be poked from a URL bar. The login itself still happens in the browser on the
container's virtual display: /login creates a fresh SAML request only when you
ask for a login, then you finish NetID + MFA over noVNC. /code is accepted only
while the login page is actually showing a code field — anything earlier is
refused, so what the panel takes always matches where the page is. With
credentials configured, the form is filled after the first click in the login
page, and POLYGP_VPN_CHOICE picks the service option that follows.

The login's durable product — the GP session cookie openconnect authenticates
with — is saved to $POLYGP_SESSION_FILE (a volume in the container), so a
restarted container resumes the session without a fresh SAML/MFA round.
Stopping the container therefore only hangs the tunnel up (SIGHUP: openconnect
disconnects without logging off); /logout and /renew are the paths that log
the session off, and they delete the file. POLYGP_RESUME=off picks the strict
trade instead: the cookie is never written (and a leftover one is deleted at
boot), at the price of a fresh login after every restart.

Set $CONTROL_TOKEN to require ?token=... on every request — worth doing once the
port is reachable by anyone but you, since these endpoints control the VPN and
can log in with stored credentials.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gp_saml_login as gp
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "hip"))
import hip_identity

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

# The saved GP session: the durable cookie `openconnect --authenticate`
# printed, kept on a volume so a restarted container can rebuild the tunnel
# without a fresh SAML/MFA round (POLYGP_RESUME=off disables that). The file
# exists while a session is believed alive on the gateway; /logout and /renew
# log the session off and delete it, while stopping the container only hangs
# the tunnel up (SIGHUP — openconnect's disconnect-without-logoff).
SESSION_FILE = Path(os.environ.get("POLYGP_SESSION_FILE",
                                   "/opt/polygp/session/session.json"))


def save_session(data: dict) -> None:
    """Write the session record 0600 and atomically: the cookie *is* VPN
    access for whoever holds it, and a crash must not leave half a file."""
    try:
        SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = SESSION_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        tmp.chmod(0o600)
        tmp.replace(SESSION_FILE)
    except OSError as e:
        print(f"[control] could not save the session file: {e}",
              file=sys.stderr, flush=True)


def load_session() -> dict | None:
    try:
        data = json.loads(SESSION_FILE.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("cookie") else None


def clear_session() -> None:
    try:
        SESSION_FILE.unlink(missing_ok=True)
    except OSError:
        pass


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
        # Keep the session cookie on disk and resume it after a restart. Off
        # means the strict trade: nothing MFA-bypassing at rest, a fresh
        # SAML/MFA login after every container restart.
        "resume": env("POLYGP_RESUME", "on").strip().lower() != "off",
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
        self.hip_active: dict | None = None
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
        # Non-secret service names share the persistent volume, but are kept
        # separately from the session cookie and scoped to the login profile.
        self._vpn_profile = None
        self.vpn_options: list[str] = []
        self._load_vpn_options()

    def _service_profile(self) -> dict:
        return {"host": self.opts.get("host", "").lower(),
                "gateway": bool(self.opts.get("gateway", True)),
                "netid": os.environ.get("POLYGP_NETID", "")}

    def _load_vpn_options(self) -> None:
        profile = self._service_profile()
        if profile == self._vpn_profile:
            return
        self._vpn_profile = profile
        self.vpn_options = []
        try:
            saved = json.loads(SESSION_FILE.with_name("services.json").read_text())
            if isinstance(saved, dict) and saved.get("profile") == profile:
                options = saved.get("options")
                if isinstance(options, list):
                    self.vpn_options = list(dict.fromkeys(
                        x.strip() for x in options
                        if isinstance(x, str) and 0 < len(x.strip()) <= 60))[:32]
        except (OSError, ValueError):
            pass

    def _remember_vpn_options(self, choices: list[str], profile: dict, generation: int) -> None:
        with self.lock:
            if generation != self.generation or profile != self._service_profile():
                return
            self._load_vpn_options()
            options = list(dict.fromkeys([*self.vpn_options, *choices]))[:32]
            if options == self.vpn_options:
                return
            self.vpn_options = options
            path = SESSION_FILE.with_name("services.json")
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                tmp = path.with_suffix(".tmp")
                tmp.write_text(json.dumps({"profile": profile, "options": options}))
                tmp.chmod(0o600)
                tmp.replace(path)
            except OSError as e:
                self.log(f"[control] could not save service options: {e}")

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

    def start(self) -> tuple[bool, str]:
        """Start a fresh login. ``start`` replaces the feed on every attempt
        so input from an abandoned attempt cannot leak into the next one."""
        with self.lock:
            if self.busy():
                return False, f"already {self.state}"
            self.generation += 1
            gen = self.generation
            self._set("awaiting-login", "opening the browser")
            self.browser_ready = False
            self.hip_active = None
            self.ip = self.expiry = ""
            self.expiry_epoch = None
            profile = self._service_profile()
            self.feed = gp.LoginFeed(on_service_options=lambda options:
                self._remember_vpn_options(options, profile, gen))
            self.feed.set_choice(self.opts["choice"] or "")
            threading.Thread(target=self._run, args=(gen, self.feed),
                             daemon=True).start()
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
            # SIGTERM makes openconnect log the session off on the gateway, so
            # the saved cookie is dead the moment this returns — forget it.
            # (Stopping the *container* goes through hangup() instead, which
            # keeps both the session and the file.)
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            clear_session()
            # Set synchronously (rather than leaving it to the tunnel tail,
            # which only notices once the closed stdout pipe unblocks it) so a
            # stop() immediately followed by start() — as renew() does — does
            # not find a stale "connected" and refuse.
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
            clear_session()
            self._set("idle", "disconnected")
            return True, "disconnected"
        return False, "not connected"

    def hangup(self) -> None:
        """Container shutdown: disconnect WITHOUT logging off.

        SIGHUP is openconnect's disconnect-that-keeps-the-session (SIGINT and
        SIGTERM both log off on the gateway), so after this the saved cookie
        is still valid and the next container start can resume the session.
        """
        with self.lock:
            self.generation += 1
            proc, self.proc = self.proc, None
        if proc and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGHUP)
                proc.wait(timeout=8)
            except (OSError, subprocess.TimeoutExpired):
                proc.kill()
            self.log("[control] tunnel hung up — session kept for resume")

    def resume(self) -> tuple[bool, str]:
        """Rebuild the tunnel from the saved session cookie — no SAML, no MFA.

        Runs at container start (unless POLYGP_RESUME=off). The record is only
        trusted for the portal it was minted at and not past its known expiry;
        the gateway stays the final judge, and a rejected cookie ends in
        `failed` with the file cleared rather than in a surprise login.
        """
        session = load_session()
        if session is None:
            return False, "no saved session"
        o = self.opts
        if (session.get("host") != o["host"]
                or bool(session.get("gateway")) != o["gateway"]):
            return False, "saved session is for a different portal"
        expiry = session.get("expiry_epoch")
        if expiry and expiry <= time.time() + 60:
            clear_session()
            return False, "saved session already expired"
        with self.lock:
            if self.busy():
                return False, f"already {self.state}"
            self.generation += 1
            gen = self.generation
            self._set("connecting", "resuming the saved VPN session — no new login")
            self.browser_ready = False
            self.hip_active = None
            self.ip = self.expiry = ""
            self.expiry_epoch = None
            self.feed = gp.LoginFeed()
            threading.Thread(target=self._tunnel, args=(gen, session, True),
                             daemon=True).start()
        return True, "resuming the saved session"

    def renew(self) -> tuple[bool, str]:
        """Disconnect (if connected) and start a fresh login — for a session near expiry."""
        self.stop()
        return self.start()

    def submit_code(self, code: str) -> tuple[bool, str]:
        """Type an MFA code into the login page — accepted only while the
        page is actually showing a code field.

        The gate is deliberate: a code accepted early looks like progress the
        login has not made (and MFA codes age out), so the panel refuses it
        server-side rather than merely greying a button out. This replaces
        the old code-first path that started a login from idle.
        """
        code = (code or "").strip()
        if not code:
            return False, "empty code"
        if len(code) > 32:
            return False, "that does not look like a verification code"

        with self.lock:
            if self.state != "awaiting-login":
                return False, f"no login waiting for input (state: {self.state})"
            if self.feed.stage() != "code":
                return False, ("the login page is not asking for a code yet — "
                               "it is typed in only at the MFA step")
            if self.feed.code_busy():
                return False, ("a code is already on its way — wait for the "
                               "page's answer")
            self.feed.offer(code)
        self.log("[control] verification code received from the panel")
        return True, "code sent — it is typed into the page"

    def request_fill(self) -> tuple[bool, str]:
        """Trigger the credential prefill from the panel.

        Accepted in auto mode as well as manual: the button is an explicit
        human action arriving through the control plane, which is the same
        authorization auto mode's trusted click provides. The click gate
        exists so that a *page* cannot make the browser type stored
        credentials at it, and a panel button is not a page. Offering both
        means the NetID step can be finished from here or from the browser,
        whichever is at hand.
        """
        if self.state != "awaiting-login":
            return False, f"no login waiting for input (state: {self.state})"
        fill_mode = self.opts.get("fill_mode", "off")
        if fill_mode == "off":
            return False, "credential fill is switched off in the settings"
        netid, netpass = gp.credentials()
        if not (netid and netpass):
            return False, "no credentials stored — type them in the browser"
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
        if "vpn_choice" in cleaned:
            # The one setting a login in progress can still use: the picker
            # step is clicked from the feed's live value.
            self.feed.set_choice(self.opts["choice"] or "")
            if self.state == "awaiting-login":
                note = (f"saved {what} — picked when the service page shows"
                        if self.opts["choice"] else
                        f"saved {what} — pick the service on the page yourself")
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

    def hip_status(self) -> dict:
        with self.lock:
            try:
                result = hip_identity.snapshot()
            except (OSError, ValueError) as error:
                return {"identity": {}, "revision": "", "problem": f"Cannot read HIP identity: {error}",
                        "read_error": True, "active_identity": self.hip_active if self.busy() else None}
            result["active_identity"] = self.hip_active if self.busy() else None
            result["pending"] = bool(result["active_identity"] and
                                     result["identity"] != result["active_identity"])
            return result

    def save_hip(self, values: dict, revision: str) -> dict:
        with self.lock:
            result = hip_identity.save(values, revision)
        self.log("[control] HIP identity saved for the next VPN session")
        return result

    def _hip_environment(self, session: dict) -> dict:
        """Freeze four identity fields for this session, including resumes and
        periodic HIP checks. Updating the defaults cannot alter a live session."""
        values = session.get("hip_identity")
        if values is None:
            values = hip_identity.parse_conf(hip_identity.read_config()[0])
        # Existing deployments can retain their old values until the user
        # chooses to replace them; new saved/imported values are stricter.
        values = hip_identity.validate(values, allow_legacy=True)
        session["hip_identity"] = values
        self.hip_active = values
        self._remember(session)
        environment = gp.openconnect_env()
        environment.update({"POLYGP_SESSION_" + key: value for key, value in values.items()})
        return environment

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
                                   cancelled=lambda: gen != self.generation,
                                   log=lambda message: self.log(f"[gp] {message}"))
        except gp.LoginTimeout as e:
            # Nobody finished the sign-in in time — an unattended automatic
            # login after a session expiry ends here as a matter of course.
            # Nothing broke, so the panel goes back to rest with a sentence
            # on where the page stood; the page dump goes to the log only.
            self._set_browser_ready(False, gen)
            if gen == self.generation:
                feed.discard_pending()
                for line in e.diagnostics():
                    self.log(f"[control] {line}")
                self._set("idle", f"{e.summary()}. Click Log in to start a fresh one.")
            return
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
        self._set("connecting", f"authenticated as {user or 'unknown'} — "
                                "exchanging the login for a session cookie")

        session = self._authenticate(gen, user, got[gp.H_COOKIE])
        if session is None or gen != self.generation:
            return
        self._remember(session)
        if self.opts["resume"]:
            self.log("[control] session cookie saved — a container restart can "
                     "resume this session without a new login")
        self._tunnel(gen, session, resumed=False)

    def _remember(self, session: dict) -> None:
        """Persist the session for a later resume — unless the resume knob is
        off, which has to mean "keep no MFA-bypassing credential on disk at
        all", not merely "do not use it at boot"."""
        if self.opts.get("resume", True):
            save_session(session)

    def _authenticate(self, gen: int, user: str,
                      prelogin_cookie: str) -> dict | None:
        """Exchange the one-shot prelogin-cookie for the durable session
        cookie (openconnect --authenticate). The cookie is what makes the
        session survive this process: openconnect's own reconnects reuse it,
        and so can a whole new openconnect after a container restart.
        Returns the session record, or None after publishing the failure."""
        o = self.opts
        cmd = gp.build_openconnect_auth(o["host"], user, o["gateway"])
        try:
            done = subprocess.run(cmd, input=prelogin_cookie + "\n",
                                  capture_output=True, text=True, timeout=120,
                                  env=gp.openconnect_env())
        except (OSError, subprocess.TimeoutExpired) as e:
            if gen == self.generation:
                self._set("failed", f"could not run openconnect --authenticate: {e}")
            return None
        for line in (done.stderr or "").splitlines():
            self.log(line)
        auth = gp.parse_authenticate(done.stdout or "")
        if done.returncode != 0 or not auth.get("COOKIE"):
            if gen == self.generation:
                self._set("failed",
                          f"session-cookie exchange failed ({done.returncode})")
            return None
        return {
            "host": o["host"], "gateway": o["gateway"], "user": user,
            "cookie": auth["COOKIE"],
            "target": auth.get("CONNECT_URL") or auth.get("HOST") or o["host"],
            "fingerprint": auth.get("FINGERPRINT", ""),
            "resolve": auth.get("RESOLVE", ""),
            "expiry_epoch": None,     # filled in once openconnect reports it
            "saved_at": time.time(),
        }

    def _tunnel(self, gen: int, session: dict, resumed: bool) -> None:
        """Build the tunnel from a session cookie — the shared tail of a fresh
        login and of a resume after restart."""
        o = self.opts
        cmd = gp.build_openconnect_tunnel(session["target"], session["fingerprint"],
                                          session["resolve"], o["hip"], "socks",
                                          o["socks_port"], o["reconnect_timeout"],
                                          o["socks_bind"])
        try:
            with self.lock:
                if gen != self.generation:
                    return
                environment = self._hip_environment(session)
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1, env=environment)
        except (OSError, ValueError) as e:
            if gen == self.generation:
                self._set("failed", f"could not start VPN; check HIP identity in Settings: {e}")
            return

        with self.lock:
            if gen != self.generation:
                proc.terminate()  # superseded before we even got to hand off the cookie
                return
            self.proc = proc
        assert proc.stdin is not None
        proc.stdin.write(session["cookie"] + "\n")
        proc.stdin.flush()

        ever_connected = False
        assert proc.stdout is not None
        for line in proc.stdout:
            self.log(line)
            if gen != self.generation:
                continue  # keep draining the pipe, but a newer run now owns state
            self._consume_openconnect_line(line)
            if self.session_active():
                ever_connected = True
            # Keep the saved record's expiry current, so a later boot can tell
            # a resumable session from one the gateway has already expired.
            if self.expiry_epoch and session.get("expiry_epoch") != self.expiry_epoch:
                session["expiry_epoch"] = self.expiry_epoch
                self._remember(session)

        rc = proc.wait()
        if gen == self.generation:
            with self.lock:
                self.proc = None
            # A terminate() from /logout or /renew is an intended stop, not a failure.
            clean = rc in (0, -15, 143)
            had_session = self.session_active()
            if resumed and not ever_connected:
                # The gateway would not take the saved cookie (expired, or
                # logged off elsewhere). Forget it — and do not chain into a
                # SAML login by itself: a surprise MFA push at container boot
                # is worse than waiting for the user.
                clear_session()
                self._set("failed", "saved session rejected — log in afresh")
                return
            self._set("idle" if clean else "failed", f"openconnect exited ({rc})")
            # A session that dies underneath us is gone for good: openconnect
            # logs it out on the way down (a failed HIP recheck ends here), so
            # only a fresh SAML login brings the tunnel back. Start one now so
            # the panel is already waiting on MFA instead of sitting failed
            # until someone notices. One attempt only — if that login fails or
            # times out, it stays failed rather than paging the phone forever.
            if not clean and had_session:
                clear_session()   # that logout invalidated the saved cookie
                if self.opts["auto_relogin"]:
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
        # Only service-page options belong in this list; Sign in / Verify
        # buttons from other pages must never replace it.
        mfa.pop("choices", None)
        mfa.pop("service_options", None)
        with self.lock:
            self._load_vpn_options()
            vpn_options = list(self.vpn_options)
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
                "vpn_options": vpn_options,
                "login_timeout": str(o["timeout"]),
                "reconnect_timeout": str(o["reconnect_timeout"]),
            },
            "hip": self.hip_status(),
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
                # Whether a restart could resume the session without a login.
                "saved session": "kept for resume" if load_session() else "none",
            },
        }


# Read the panel for each request so UI updates need no tunnel restart.
PANEL_FILE = Path(__file__).with_name("panel.html")


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
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _authed(self) -> bool:
        if not self.token:
            return True
        q = parse_qs(urlparse(self.path).query, keep_blank_values=True).get("token") or [""]
        return q[0] == self.token or self.headers.get("X-Token") == self.token

    def _wants_json(self) -> bool:
        return "application/json" in (self.headers.get("Accept") or "")

    def _param(self, name: str) -> str:
        """A request parameter, from the query string or the form body."""
        if not hasattr(self, "_params"):
            self._params = parse_qs(urlparse(self.path).query, keep_blank_values=True)
            if self.command == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
                for k, v in parse_qs(body, keep_blank_values=True).items():
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
        self.send_header("Location", "/" + ("?" + urlencode({"token": self.token}) if self.token else ""))
        self.end_headers()

    def _route(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        if not self._authed():
            return self._send(403, "forbidden: bad or missing token", "text/plain")

        t = self.tunnel
        if path == "/hip" or path.startswith("/hip/"):
            return self._hip_route(path)
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
            page = (PANEL_FILE.read_text().replace("__NOVNC__", self.novnc)
                        .replace("__TOKEN_QUERY__", "?" + urlencode({"token": self.token}) if self.token else ""))
            return self._send(200, page)
        self._send(404, "not found", "text/plain")

    def _hip_route(self, path: str) -> None:
        def respond(code, data):
            return self._send(code, json.dumps(data), "application/json; charset=utf-8")
        if path == "/hip" and self.command == "GET":
            return respond(200, {"ok": True, **self.tunnel.hip_status()})
        if path not in ("/hip/save", "/hip/validate", "/hip/generate"):
            return respond(404, {"ok": False, "message": "Unknown HIP action."})
        if self.command != "POST":
            return respond(405, {"ok": False, "message": "Use POST for HIP actions."})
        # Also protects tokenless localhost deployments from cross-origin
        # forms. Cross-origin fetch would require a preflight we do not allow.
        if self.headers.get("X-PolyGP-HIP") != "1":
            return respond(403, {"ok": False, "message": "Use the HIP controls in Settings."})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 0 or size > 4 * hip_identity.MAX_IMPORT_BYTES:
                return respond(413, {"ok": False, "message": "Import files must be 64 KB or smaller."})
            if path == "/hip/generate":
                # Consume any submitted body before returning a candidate.
                self._param("")
                return respond(200, {"ok": True, "identity": hip_identity.random_identity()})
            values = hip_identity.import_identity(self._param("content"))
            if path == "/hip/save":
                result = self.tunnel.save_hip(values, self._param("revision"))
                return respond(200, {"ok": True, **result})
            return respond(200, {"ok": True, "identity": values})
        except (ValueError, OSError) as error:
            return respond(409 if path == "/hip/save" else 400,
                           {"ok": False, "message": str(error)})


def main() -> None:
    env = os.environ.get
    Handler.tunnel = Tunnel(build_opts())
    Handler.token = env("CONTROL_TOKEN", "")
    Handler.novnc = env("NOVNC_URL", f"http://{env('PUBLIC_HOST', 'localhost')}:"
                                     f"{env('VNC_PORT', '6080')}/vnc.html")
    port = int(env("CONTROL_PORT", "11936"))

    # Do not mint a SAML request during container boot.  The request has a
    # server-side lifetime, and users often need time to open noVNC/get a fresh
    # MFA code. /login starts it explicitly; /code only answers an MFA prompt.
    # A session saved by the previous run needs no request at all: resume it.
    if not Handler.tunnel.opts["resume"]:
        # The knob means "keep nothing on disk", so a cookie left behind by an
        # earlier run with the knob on must go too.
        clear_session()
    if env("AUTO_LOGIN", "0") == "1":
        Handler.tunnel.start()
    elif Handler.tunnel.opts["resume"]:
        ok, msg = Handler.tunnel.resume()
        if ok or msg != "no saved session":
            Handler.tunnel.log(f"[control] resume: {msg}")

    # Stopping the container must not log the VPN session off — that is what
    # makes the saved cookie above worth keeping.  /logout is the way to end
    # the session; SIGTERM (docker stop, forwarded by the entrypoint) and
    # Ctrl+C only hang the tunnel up, via the finally below.
    def graceful_exit(_sig, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, graceful_exit)

    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[control] listening on :{port}", file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        Handler.tunnel.hangup()


if __name__ == "__main__":
    main()
