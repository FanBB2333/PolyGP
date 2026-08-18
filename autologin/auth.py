#!/usr/bin/env python3
"""Headless SAML login for PolyU GlobalProtect.

Drives the auth URL that `gpclient --browser remote` prints: fills NetID +
NetPassword, chooses the "use a verification code" path, enters an oathtool-
generated Microsoft MFA code, and captures the `globalprotectcallback:...`
string that gpclient expects pasted back.

  auth URL in  -> (arg, or stdin)
  callback out -> printed to stdout (logs go to stderr)

Credentials, in priority order:
  NetID     : $POLYGP_NETID    | Keychain service=polygp-netid  account=polygp
  NetPass   : $POLYGP_NETPASS  | Keychain service=polygp-netpass account=polygp
  TOTP seed : see mfa.py

NOTE: the selectors in SEL below are Microsoft-AAD defaults. If PolyU's ADFS
page differs, capture the real ones once with:
    python3 -m playwright codegen "<the auth URL>"
and adjust SEL. Run with --headful the first few times to watch it.
"""
import argparse
import re
import subprocess
import sys
import time

from mfa import gen_code

# --- Selectors (Microsoft AAD defaults; confirm against the real login) -------
SEL = {
    # username / NetID step
    "user_input": "input[type=email], input[name=loginfmt], #i0116",
    "user_next":  "#idSIButton0, input[type=submit]",
    # password step (AAD or ADFS)
    "pass_input": "input[type=password], #i0118, #passwordInput",
    "pass_next":  "#idSIButton0, #submitButton, input[type=submit]",
    # MFA: switch to code entry, then the code field + verify
    "use_code":   "text=/use a verification code/i, #idA_PWD_SwitchToRemoteNGC, "
                  "#signInAnotherWay",
    "code_input": "#idTxtBx_SAOTCC_OTC, input[name=otc], "
                  "input[autocomplete=one-time-code]",
    "code_next":  "#idSubmit_SAOTCC_Continue, #idSIButton0, input[type=submit]",
    # "Stay signed in?" interstitial
    "stay_no":    "#idBtn_Back",
    "stay_yes":   "#idSIButton0",
}
CALLBACK_SCHEME = "globalprotectcallback:"


def _keychain(service: str) -> str | None:
    if sys.platform != "darwin":
        return None
    try:
        r = subprocess.run(
            ["security", "find-generic-password", "-s", service,
             "-a", "polygp", "-w"],
            capture_output=True, text=True, check=True)
        return r.stdout.strip() or None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _cred(env: str, service: str, what: str) -> str:
    import os
    val = os.environ.get(env) or _keychain(service)
    if not val:
        raise SystemExit(f"missing {what}: set ${env} or store in Keychain "
                         f"(service={service}, account=polygp)")
    return val


def _click_any(page, selector: str, timeout: int = 8000) -> bool:
    """Click the first matching locator; return False if none appears."""
    try:
        loc = page.locator(selector).first
        loc.wait_for(state="visible", timeout=timeout)
        loc.click()
        return True
    except Exception:
        return False


def _fill_any(page, selector: str, value: str, timeout: int = 15000) -> None:
    loc = page.locator(selector).first
    loc.wait_for(state="visible", timeout=timeout)
    loc.fill(value)


def run(auth_url: str, headful: bool, debug_dir: str | None) -> str:
    from playwright.sync_api import sync_playwright

    netid = _cred("POLYGP_NETID", "polygp-netid", "NetID")
    netpass = _cred("POLYGP_NETPASS", "polygp-netpass", "NetPassword")

    captured: dict[str, str] = {}

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not headful)
        ctx = browser.new_context()
        page = ctx.new_page()

        # The final hop is a redirect to globalprotectcallback:<data>, a custom
        # scheme the browser can't load; catch it from navigation attempts.
        def on_nav(frame):
            url = frame.url or ""
            if url.startswith(CALLBACK_SCHEME):
                captured["cb"] = url
        page.on("framenavigated", on_nav)

        def on_req(req):
            if req.url.startswith(CALLBACK_SCHEME):
                captured["cb"] = req.url
        ctx.on("request", on_req)

        log = lambda m: print(f"[auth] {m}", file=sys.stderr)
        try:
            log(f"opening auth url")
            page.goto(auth_url, wait_until="domcontentloaded")

            log("entering NetID")
            _fill_any(page, SEL["user_input"], netid)
            _click_any(page, SEL["user_next"])

            log("entering NetPassword")
            _fill_any(page, SEL["pass_input"], netpass)
            _click_any(page, SEL["pass_next"])

            # MFA: prefer the code path over push/number-matching
            log("switching to verification-code method")
            _click_any(page, SEL["use_code"], timeout=12000)

            log("entering TOTP code")
            _fill_any(page, SEL["code_input"], gen_code())
            _click_any(page, SEL["code_next"])

            # optional "Stay signed in?" -> No
            _click_any(page, SEL["stay_no"], timeout=6000)

            # wait for the callback to be captured
            for _ in range(60):
                if "cb" in captured:
                    break
                time.sleep(0.5)
        except Exception as e:
            if debug_dir:
                shot = f"{debug_dir}/auth-fail-{int(time.time())}.png"
                try:
                    page.screenshot(path=shot, full_page=True)
                    log(f"screenshot: {shot}")
                except Exception:
                    pass
            log(f"error at url={page.url}")
            raise
        finally:
            browser.close()

    cb = captured.get("cb")
    if not cb:
        raise SystemExit("did not capture globalprotectcallback (login may have "
                         "stalled or the MFA method was rejected)")
    return cb


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("auth_url", nargs="?", help="gpclient auth URL (or via stdin)")
    ap.add_argument("--headful", action="store_true", help="show the browser")
    ap.add_argument("--debug-dir", help="dir for failure screenshots")
    a = ap.parse_args()
    url = a.auth_url or sys.stdin.readline().strip()
    if not re.match(r"https?://", url):
        raise SystemExit("expected an http(s) auth URL as arg or on stdin")
    print(run(url, a.headful, a.debug_dir))


if __name__ == "__main__":
    main()
