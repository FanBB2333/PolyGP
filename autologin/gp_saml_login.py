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

The login itself is done by you, in the browser, so no TOTP seed is needed and
MFA stays a real second factor. Storing your NetID and NetPassword is optional;
when present they are typed into the ADFS form for you, leaving only the phone
prompt to approve:

    security add-generic-password -U -s polygp-netid   -a polygp -w '<NetID>'
    security add-generic-password -U -s polygp-netpass -a polygp -w '<NetPassword>'

($POLYGP_NETID / $POLYGP_NETPASS take precedence; --no-fill disables this.)

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
import errno
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

DEFAULT_HOST = "researchvpn.polyu.edu.hk"
HIP_SCRIPT = Path(__file__).resolve().parent.parent / "hip" / "polyu-hipreport.sh"

# The Xvfb display and the browser need to agree on their native size.  Keep
# the parser here (rather than duplicating it in the control panel) so a custom
# VNC_SCREEN value is reflected both in Chromium and in /status.  Xvfb accepts
# an optional depth suffix, e.g. 1280x900x24.
DEFAULT_VNC_SCREEN = (1600, 900)


def vnc_screen_size(value: str | None = None) -> tuple[int, int]:
    """Return the width and height from a ``VNC_SCREEN``-style value.

    A malformed or unreasonably small value falls back to the known-good
    default.  The depth is intentionally ignored: it does not affect browser
    layout or noVNC scaling.
    """
    raw = os.environ.get("VNC_SCREEN", "1600x900x24") if value is None else value
    match = re.fullmatch(r"\s*(\d+)[xX](\d+)(?:x\d+)?\s*", str(raw or ""))
    if not match:
        return DEFAULT_VNC_SCREEN
    width, height = (int(part) for part in match.groups())
    if width < 320 or height < 200:
        return DEFAULT_VNC_SCREEN
    return width, height

# Docker Desktop's DNS forwarder can briefly return EAI_AGAIN while the host
# changes network or a local proxy reloads.  A login used to fail immediately
# in that case, even though repeating the same request a moment later worked.
# Retry only errors that are plausibly temporary; bad hostnames and ordinary
# HTTP client errors still fail without delay.
PRELOGIN_ATTEMPTS = 5
PRELOGIN_RETRY_DELAY = 1.0
PRELOGIN_MAX_RETRY_DELAY = 8.0
RETRYABLE_HTTP_STATUS = {408, 425, 429, 500, 502, 503, 504}
RETRYABLE_ERRNOS = {
    code for name in (
        "EAGAIN", "ECONNABORTED", "ECONNREFUSED", "ECONNRESET",
        "EHOSTDOWN", "EHOSTUNREACH", "ENETDOWN", "ENETRESET",
        "ENETUNREACH", "EPIPE", "ETIMEDOUT",
    )
    if (code := getattr(errno, name, None)) is not None
}

# openconnect must report the same OS/version the HIP report claims, or PolyU's
# HIP policy rejects the (Windows Defender) anti-malware block as inconsistent.
GP_OS = "win"
GP_CLIENT_VERSION = "6.2.8-243"

# What GlobalProtect sends back once SAML succeeds.
H_STATUS = "saml-auth-status"
H_COOKIE = "prelogin-cookie"
H_USER = "saml-username"

# PolyU's IdP is a classic ADFS form (not Microsoft AAD), verified against the
# live page: NetID and NetPassword inputs plus a <span> acting as the button.
SEL_USER = "#userNameInput"
SEL_PASS = "#passwordInput"
SEL_SUBMIT = "#submitButton"

KEYCHAIN_ACCOUNT = "polygp"


def _retryable_prelogin_error(error: BaseException) -> bool:
    """Whether another identical prelogin request may reasonably succeed."""
    if isinstance(error, urllib.error.HTTPError):
        return error.code in RETRYABLE_HTTP_STATUS

    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, socket.gaierror):
        # EAI_AGAIN is explicitly a temporary resolver failure. EAI_NONAME and
        # the other resolver errors usually mean a bad PORTAL value.
        return reason.errno == socket.EAI_AGAIN
    if isinstance(reason, (TimeoutError, ConnectionError, ssl.SSLError)):
        return True
    return isinstance(reason, OSError) and reason.errno in RETRYABLE_ERRNOS


def _wait_before_prelogin_retry(delay: float, cancelled) -> bool:
    """Wait for a retry, returning early when the control request was cancelled."""
    if cancelled is None:
        time.sleep(delay)
        return False

    deadline = time.monotonic() + delay
    while True:
        if cancelled():
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return cancelled()
        time.sleep(min(0.2, remaining))


def prelogin(host: str, gateway: bool, *, attempts: int = PRELOGIN_ATTEMPTS,
             retry_delay: float = PRELOGIN_RETRY_DELAY, log=None,
             cancelled=None) -> tuple[str, str]:
    """Run GP prelogin; return (saml_method, decoded_saml_request)."""
    path = "/ssl-vpn/prelogin.esp" if gateway else "/global-protect/prelogin.esp"
    url = f"https://{host}{path}?tmp=tmp&clientVer=4100&clientos=Windows"

    # PolyU's portal is an old TLS stack; be permissive here (this request carries
    # no secrets, and openconnect verifies the certificate on the real connection).
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # The portal is an old TLS server that needs legacy renegotiation, which
    # OpenSSL 3.x refuses by default (UNSAFE_LEGACY_RENEGOTIATION_DISABLED, seen
    # on Debian trixie but not bookworm). Same concession gpclient makes with
    # --fix-openssl. OP_LEGACY_SERVER_CONNECT is only named from Python 3.12.
    ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)

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
    attempts = max(1, int(attempts))
    retry_delay = max(0.0, float(retry_delay))
    for attempt in range(1, attempts + 1):
        if cancelled is not None and cancelled():
            raise SystemExit("prelogin cancelled")
        try:
            with opener.open(req, timeout=20) as r:
                xml = r.read().decode("utf-8", "replace")
            break
        except (urllib.error.URLError, OSError) as e:
            if attempt < attempts and _retryable_prelogin_error(e):
                delay = min(retry_delay * (2 ** (attempt - 1)),
                            PRELOGIN_MAX_RETRY_DELAY)
                message = (f"prelogin attempt {attempt}/{attempts} failed temporarily: "
                           f"{e}; retrying in {delay:g}s")
                if log is None:
                    print(f"[gp] {message}", file=sys.stderr, flush=True)
                else:
                    log(message)
                if _wait_before_prelogin_retry(delay, cancelled):
                    raise SystemExit("prelogin cancelled")
                continue
            attempt_note = f" after {attempt} attempts" if attempt > 1 else ""
            raise SystemExit(f"could not reach {host}{attempt_note}: {e}\n"
                             f"Check the portal is reachable: "
                             f"curl -sk https://{host}{path}")

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


def _keychain(service: str) -> str | None:
    """Read a secret from the macOS login Keychain, or None if absent."""
    if sys.platform != "darwin":
        return None
    try:
        r = subprocess.run(
            ["security", "find-generic-password", "-s", service,
             "-a", KEYCHAIN_ACCOUNT, "-w"],
            capture_output=True, text=True, check=True)
        return r.stdout.strip() or None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def credentials() -> tuple[str | None, str | None]:
    """NetID and NetPassword from the environment, else the Keychain."""
    netid = os.environ.get("POLYGP_NETID") or _keychain("polygp-netid")
    netpass = os.environ.get("POLYGP_NETPASS") or _keychain("polygp-netpass")
    return netid, netpass


def _prefill(page, log) -> None:
    """Fill the ADFS form and submit, leaving only the MFA step to the user."""
    netid, netpass = credentials()
    if not (netid and netpass):
        log("no stored credentials — type them in the browser "
            "(see --help to store them in the Keychain)")
        return
    try:
        page.wait_for_selector(SEL_USER, state="visible", timeout=15000)
        page.fill(SEL_USER, netid)
        page.fill(SEL_PASS, netpass)
        page.click(SEL_SUBMIT)
        log(f"submitted NetID {netid} — now approve the MFA prompt on your phone")
    except Exception as e:
        # Not fatal: the window is open, so fall back to typing it by hand.
        log(f"auto-fill skipped ({type(e).__name__}) — log in manually")


def _auto_choose(page, choice: str, log) -> bool:
    """Pick the service option matching `choice` once that step appears.

    PolyU asks which VPN to use after the credential form. The markup of that
    step is not known here, so match on visible text rather than a selector: a
    <select> option, or any radio/button/link carrying the text.
    """
    pat = re.compile(re.escape(choice), re.I)
    try:
        sel = page.locator("select").first
        if sel.count() and sel.is_visible():
            for opt in sel.locator("option").all():
                label = (opt.inner_text() or "").strip()
                if label and pat.search(label):
                    sel.select_option(label=label)
                    log(f"chose {label!r} from the dropdown")
                    for submit in (SEL_SUBMIT, "input[type=submit]", "button[type=submit]"):
                        b = page.locator(submit).first
                        if b.count() and b.is_visible():
                            b.click()
                            break
                    return True
    except Exception:
        pass
    for role in ("radio", "button", "link"):
        try:
            loc = page.get_by_role(role, name=pat).first
            if loc.count() and loc.is_visible():
                loc.click()
                log(f"clicked the {role} matching {choice!r}")
                return True
        except Exception:
            continue
    return False


class LoginFeed:
    """Thread-safe mailbox between the login thread and an outside controller.

    Playwright's sync API is single-threaded: only the login thread may touch
    the page. A control panel that wants to type an MFA code for the user
    therefore cannot reach into the browser itself — it offer()s the text here,
    and the login loop types it in at its next tick. The loop also publishes
    what code input the page is currently showing, so the panel can tell the
    user a code is being asked for. A code offered before the field exists is
    kept until the field appears (you can type it the moment your phone shows
    it, ahead of the page).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: str | None = None
        self._prompt = ""
        self._fill = False
        self._choices: list[str] = []

    def offer(self, text: str) -> None:
        with self._lock:
            self._pending = text

    def take(self) -> str | None:
        with self._lock:
            text, self._pending = self._pending, None
            return text

    def has_pending(self) -> bool:
        with self._lock:
            return self._pending is not None

    def set_prompt(self, prompt: str) -> None:
        with self._lock:
            self._prompt = prompt

    def request_fill(self) -> None:
        """Ask the login thread to run the credential prefill (manual mode)."""
        with self._lock:
            self._fill = True

    def take_fill_request(self) -> bool:
        with self._lock:
            v, self._fill = self._fill, False
            return v

    def set_choices(self, choices: list[str]) -> bool:
        """Publish the clickable options currently on the page; True if changed."""
        with self._lock:
            changed = choices != self._choices
            self._choices = choices
            return changed

    def snapshot(self) -> dict:
        with self._lock:
            return {"prompt": self._prompt, "pending": self._pending is not None,
                    "fill_pending": self._fill, "choices": list(self._choices)}


# Attribute text that marks an input as asking for a one-time code, matched
# against id/name/placeholder/aria-label/autocomplete. Deliberately broad: the
# exact markup of PolyU's MFA step is not pinned down here.
CODE_HINTS = re.compile(
    r"(one-?time|otp|verif|code|token|mfa|pin\b|challenge|passcode|answer)", re.I)


def _find_code_input(page):
    """Locate a visible one-time-code input; searches child frames too.

    Returns (frame, locator, description) or (None, None, "").
    """
    for frame in page.frames:
        try:
            candidates = frame.locator(
                "input[type=text], input[type=tel], input[type=number], "
                "input[type=password], input:not([type])").all()
        except Exception:
            continue
        for loc in candidates:
            try:
                if not loc.is_visible() or not loc.is_enabled():
                    continue
                ident = {
                    a: (loc.get_attribute(a) or "")
                    for a in ("id", "name", "placeholder", "aria-label", "autocomplete")
                }
                # Never touch the ADFS credential fields.
                if "#" + ident["id"] in (SEL_USER, SEL_PASS):
                    continue
                if CODE_HINTS.search(" ".join(ident.values())):
                    desc = (ident["placeholder"] or ident["aria-label"]
                            or ident["name"] or ident["id"])
                    return frame, loc, desc
            except Exception:
                continue
    return None, None, ""


def _scan_choices(page) -> list[str]:
    """Texts of the clickable options currently on the page (buttons, radios,
    links, select options). PolyU's service-selection step is one of these —
    its exact texts are not known here, so they are captured live and become
    the panel's suggestions for the VPN service field."""
    seen: list[str] = []
    for frame in page.frames:
        try:
            for role in ("button", "radio", "link"):
                for el in frame.get_by_role(role).all()[:20]:
                    try:
                        if not el.is_visible():
                            continue
                        text = (el.inner_text() or "").strip() \
                            or (el.get_attribute("aria-label") or "").strip() \
                            or (el.get_attribute("value") or "").strip()
                        if text and len(text) <= 60 and text not in seen:
                            seen.append(text)
                    except Exception:
                        continue
            for el in frame.locator("select option").all()[:20]:
                try:
                    text = (el.inner_text() or "").strip()
                    if text and len(text) <= 60 and text not in seen:
                        seen.append(text)
                except Exception:
                    continue
        except Exception:
            continue
    return seen[:12]


def _pump_feed(page, feed: LoginFeed, log) -> None:
    """One tick of panel-driven input: publish what the page is asking, and
    type a pending code into it. Runs on the login thread — the only thread
    allowed to touch the page."""
    frame, loc, desc = _find_code_input(page)
    feed.set_prompt(desc)
    choices = _scan_choices(page)
    if feed.set_choices(choices) and choices:
        log("options in view: " + " | ".join(choices))
    if loc is None or not feed.has_pending():
        return
    code = feed.take()
    if not code:
        return
    try:
        loc.fill(code)
    except Exception as e:
        log(f"could not type the panel's code ({type(e).__name__}) — "
            "enter it in the browser view instead")
        return
    # Submit: prefer a real control in the same frame — ADFS renders its
    # button as a <span id=submitButton>, which an Enter keypress does not
    # reach unless the page bound its own key handler. Enter is the fallback.
    for sel in (SEL_SUBMIT, "input[type=submit]", "button[type=submit]"):
        try:
            b = frame.locator(sel).first
            if b.count() and b.is_visible():
                b.click()
                log(f"typed the panel's code into {desc!r} and submitted")
                return
        except Exception:
            continue
    try:
        loc.press("Enter")
        log(f"typed the panel's code into {desc!r} (submitted with Enter)")
    except Exception:
        log(f"typed the panel's code into {desc!r} — submit it in the browser view")


def browser_login(entry: str, method: str, timeout: int, keep_open: bool,
                  channel: str | None, fill, choice: str | None = None,
                  feed: LoginFeed | None = None, on_ready=None) -> dict[str, str]:
    """Open a browser for the user to log in; capture the GP response headers.

    `fill` is a mode string — "auto" (fill and submit the credential form as
    soon as it appears), "manual" (only when the feed receives a fill request,
    i.e. a button on the control panel), or "off" (never touch it). A bool is
    accepted for backward compatibility: True = auto, False = off.
    ``on_ready`` is an optional callback notified after the visible Chromium
    page has been created and just before the browser is closed.
    """
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
        screen_width, screen_height = vnc_screen_size()
        args = [
            f"--window-size={screen_width},{screen_height}",
            "--window-position=0,0",
            # A fresh container has no Chromium profile.  Suppress the first
            # run/terms surfaces so the VNC canvas immediately shows the SAML
            # page instead of an uninteractive startup dialog.
            "--no-first-run",
            "--no-default-browser-check",
        ]
        # In a container the browser is Debian's chromium on a virtual display,
        # and it needs the usual sandbox/shm concessions.
        args += shlex.split(os.environ.get("POLYGP_BROWSER_ARGS", ""))
        launch = {"headless": False, "args": args}
        if channel:
            launch["channel"] = channel  # e.g. your installed Chrome / Edge
        elif os.environ.get("POLYGP_CHROMIUM"):
            # Use a system browser instead of a Playwright-downloaded one.
            launch["executable_path"] = os.environ["POLYGP_CHROMIUM"]
        browser = p.chromium.launch(**launch)
        # Playwright's default emulated 1280x720 viewport is independent of
        # the Xvfb size and leaves an unused strip of desktop below the page.
        # Native sizing makes the browser occupy the VNC display we advertise.
        ctx = browser.new_context(ignore_https_errors=True, no_viewport=True)
        page = ctx.new_page()
        page.on("response", on_response)
        if on_ready is not None:
            try:
                on_ready(True)
            except Exception:
                pass

        log = lambda m: print(f"[gp] {m}", file=sys.stderr)
        log("browser opening")
        if method.upper() == "REDIRECT":
            # Chromium's network-change detection trips over a container's
            # virtual interfaces and aborts the first navigation with
            # ERR_NETWORK_CHANGED; retrying rides it out.
            for attempt in range(3):
                try:
                    page.goto(entry, wait_until="domcontentloaded")
                    break
                except Exception as e:
                    if attempt == 2:
                        raise
                    log(f"navigation retry after {type(e).__name__}: "
                        f"{str(e).splitlines()[0][:80]}")
                    page.wait_for_timeout(1500)
        else:  # POST: saml-request is a full HTML page that self-submits
            page.set_content(entry)

        fill_mode = fill if isinstance(fill, str) else ("auto" if fill else "off")
        if fill_mode == "auto":
            _prefill(page, log)
        elif fill_mode == "manual":
            log("manual fill mode — press the panel's Fill & log in button "
                "(or type the credentials in the browser)")

        deadline = time.time() + timeout
        chosen = not choice
        ticks = 0
        while time.time() < deadline and not got.get(H_COOKIE):
            page.wait_for_timeout(500)
            ticks += 1
            if ticks % 4 == 0:
                # The service-selection step can appear either side of MFA, so
                # keep looking for it rather than assuming a point in the
                # sequence.
                if not chosen:
                    chosen = _auto_choose(page, choice, log)
                if feed is not None:
                    try:
                        if feed.take_fill_request() and fill_mode != "off":
                            _prefill(page, log)
                        _pump_feed(page, feed, log)
                    except Exception:
                        pass  # a mid-navigation page throws; next tick retries

        if feed is not None:
            feed.set_prompt("")

        if not got.get(H_COOKIE):
            # Log where it stalled: the remaining unknown in this flow is what
            # PolyU shows between the password form and the assertion.
            try:
                got["_where"] = page.url
                body = page.inner_text("body")
                got["_text"] = " / ".join(
                    ln.strip() for ln in body.splitlines() if ln.strip())[:600]
            except Exception:
                pass

        if got.get(H_COOKIE) and keep_open:
            print("[gp] captured — press Enter to close the browser", file=sys.stderr)
            input()
        if on_ready is not None:
            try:
                on_ready(False)
            except Exception:
                pass
        browser.close()

    if not got.get(H_COOKIE):
        msg = [f"timed out after {timeout}s without seeing a {H_COOKIE} header."]
        if got.get("_where"):
            msg.append(f"stalled at: {got['_where']}")
        if got.get("_text"):
            msg.append(f"page said: {got['_text']}")
        msg.append("If the browser did reach \"Login Successful!\", the server may "
                   "put the value elsewhere — rerun with --keep-open and check the "
                   "Network tab.")
        raise SystemExit("\n".join(msg))
    return got


def build_openconnect(host: str, user: str, gateway: bool, hip: Path,
                      mode: str, socks_port: int, reconnect_timeout: int,
                      socks_bind: str | None = None) -> list[str]:
    usergroup = "gateway:prelogin-cookie" if gateway else "portal:prelogin-cookie"
    cmd = [
        "openconnect",
        "--protocol=gp",
        f"--os={GP_OS}",
        f"--version-string={GP_CLIENT_VERSION}",
        f"--usergroup={usergroup}",
        "--passwd-on-stdin",
        f"--csd-wrapper={hip}",
        # Keep retrying this long after a drop before giving up. The default is
        # only 300s, so a laptop that sleeps past that wakes to a dead client;
        # a large window lets openconnect re-establish with the still-valid
        # session cookie instead (no fresh SAML/MFA), up to the gateway's own
        # session-auth expiry (~24h).
        f"--reconnect-timeout={reconnect_timeout}",
    ]
    if user:
        cmd.append(f"--user={user}")

    if mode == "socks":
        # Userspace TCP/IP: openconnect hands the tunnel to ocproxy over a pipe
        # instead of a tun device, so nothing about the system's networking moves.
        # -k: keepalive, so an idle session survives the gateway and any stateful
        # firewall between here and it (the connection may cross a proxy hop).
        # ocproxy binds loopback unless told otherwise; inside a container the
        # SOCKS port has to listen on all interfaces for Docker to publish it.
        ocp = "ocproxy -k 30"
        if socks_bind in ("0.0.0.0", "*"):
            ocp += f" -g -D {socks_port}"
        elif socks_bind:
            ocp += f" -D {socks_bind}:{socks_port}"
        else:
            ocp += f" -D {socks_port}"
        cmd += ["--script-tun", "--script", ocp]
    else:
        cmd.insert(0, "sudo")  # a real tun device and system routes need root

    cmd.append(host)
    return cmd


def openconnect_env() -> dict[str, str]:
    """The environment to run openconnect in, minus any proxy settings.

    openconnect honours https_proxy/http_proxy, and prelogin deliberately does
    not, so leaving them in would authenticate over one path and build the
    tunnel over another. A shell exporting https_proxy=https://... would also
    abort it outright with "Only http or socks(5) proxies supported". A sudo'd
    run gets this for free; socks mode has no sudo to sanitise anything.
    """
    return {k: v for k, v in os.environ.items()
            if k.lower() not in ("http_proxy", "https_proxy", "all_proxy", "ftp_proxy")}


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
    ap.add_argument("--vpn-choice", default=os.environ.get("POLYGP_VPN_CHOICE") or None,
                    help="text of the VPN/service option to pick after the login "
                         "form, e.g. 'research' (env POLYGP_VPN_CHOICE)")
    ap.add_argument("--socks-bind", default=None,
                    help="address the SOCKS port listens on (default loopback; use "
                         "0.0.0.0 in a container so the port can be published)")
    ap.add_argument("--reconnect-timeout", type=int, default=86400,
                    help="seconds openconnect keeps retrying after a drop before "
                         "giving up (default 86400, so sleep/wake auto-recovers)")
    ap.add_argument("--print-only", action="store_true",
                    help="print the captured cookie and the openconnect command; do not connect")
    ap.add_argument("--keep-open", action="store_true",
                    help="keep the browser open after capture (for inspection)")
    ap.add_argument("--no-fill", dest="fill", action="store_false",
                    help="do not pre-fill the login form even if credentials are stored")
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
    got = browser_login(entry, method, a.timeout, a.keep_open, channel, a.fill,
                        a.vpn_choice)
    user = got.get(H_USER, "")
    print(f"[gp] captured {H_COOKIE} for user={user or '(unknown)'}", file=sys.stderr)

    cmd = build_openconnect(a.host, user, a.gateway, a.hip, a.mode, a.socks_port,
                            a.reconnect_timeout, a.socks_bind)

    if a.print_only:
        print(f"\n{H_COOKIE}: {got[H_COOKIE]}")
        print(f"{H_USER}: {user}\n")
        print("echo <cookie> | " + " ".join(shlex.quote(c) for c in cmd))
        return

    if a.mode == "socks":
        print(f"[gp] SOCKS5 will listen on 127.0.0.1:{a.socks_port} — "
              "no routes or DNS are touched; Ctrl+C to disconnect", file=sys.stderr)
    print(f"[gp] connecting: {' '.join(shlex.quote(c) for c in cmd)}", file=sys.stderr)
    # sudo prompts on the tty, so it does not clash with the cookie on stdin.
    sys.exit(subprocess.run(cmd, input=got[H_COOKIE] + "\n", text=True,
                            env=openconnect_env()).returncode)


if __name__ == "__main__":
    main()
