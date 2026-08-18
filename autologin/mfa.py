#!/usr/bin/env python3
"""Generate the Microsoft MFA 6-digit TOTP code from a stored seed.

The Microsoft Authenticator "verification code" is a standard RFC 6238 TOTP
(SHA1, 30s, 6 digits). Once you hold the enrollment seed you can generate the
exact same codes here — no phone needed.

Seed source, in priority order:
  1. env  POLYGP_TOTP_SEED           (base32 secret; spaces/newlines ignored)
  2. macOS Keychain                  (service=polygp-totp-seed, account=polygp)

Requires `oathtool` (brew install oath-toolkit) on PATH.

Usage:
  python3 mfa.py code       # print the current 6-digit code (default)
  python3 mfa.py store      # read a seed from stdin and save to macOS Keychain
  python3 mfa.py check      # verify a seed is reachable and oathtool works
"""
import os
import re
import subprocess
import sys

KEYCHAIN_SERVICE = "polygp-totp-seed"
KEYCHAIN_ACCOUNT = "polygp"


def _from_keychain() -> str | None:
    """Return the seed from the macOS login Keychain, or None."""
    if sys.platform != "darwin":
        return None
    try:
        out = subprocess.run(
            ["security", "find-generic-password",
             "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"],
            capture_output=True, text=True, check=True,
        )
        return out.stdout.strip() or None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def get_seed() -> str:
    """Resolve the TOTP seed (base32, no spaces). Raises if not found."""
    seed = os.environ.get("POLYGP_TOTP_SEED") or _from_keychain()
    if not seed:
        raise SystemExit(
            "no TOTP seed found: set $POLYGP_TOTP_SEED or run `mfa.py store`")
    # base32 secrets are printed with spaces in QR fallbacks; oathtool wants none
    return re.sub(r"\s+", "", seed).upper()


def gen_code(seed: str | None = None) -> str:
    """Return the current 6-digit TOTP code for the seed."""
    seed = seed or get_seed()
    try:
        out = subprocess.run(
            ["oathtool", "--totp", "-b", seed],
            capture_output=True, text=True, check=True,
        )
    except FileNotFoundError:
        raise SystemExit("oathtool not found — `brew install oath-toolkit`")
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"oathtool failed: {e.stderr.strip()}")
    code = out.stdout.strip()
    if not re.fullmatch(r"\d{6}", code):
        raise SystemExit(f"unexpected oathtool output: {code!r}")
    return code


def _store() -> None:
    """Read a seed from stdin and write it to the macOS Keychain."""
    if sys.platform != "darwin":
        raise SystemExit("`store` uses the macOS Keychain; on Linux set "
                         "$POLYGP_TOTP_SEED (e.g. from ~/.secrets) instead")
    print("Paste the Microsoft authenticator secret key (base32), then Enter:",
          file=sys.stderr)
    seed = re.sub(r"\s+", "", sys.stdin.readline()).upper()
    if not seed:
        raise SystemExit("empty seed; nothing stored")
    # -U updates if it already exists
    subprocess.run(
        ["security", "add-generic-password",
         "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w", seed, "-U"],
        check=True,
    )
    # sanity: generate one code so a bad paste fails loudly here, not at login
    print(f"stored. current code: {gen_code(seed)}", file=sys.stderr)


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "code"
    if cmd == "code":
        print(gen_code())
    elif cmd == "store":
        _store()
    elif cmd == "check":
        seed = get_seed()
        print(f"seed reachable ({len(seed)} chars); current code: {gen_code(seed)}",
              file=sys.stderr)
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
