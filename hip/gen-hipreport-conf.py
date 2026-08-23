#!/usr/bin/env python3
"""Generate a per-machine PolyU HIP config (hip/hipreport.conf).

The HIP report carries a Windows machine's identity: computer name, machine
GUID, the PANGP virtual adapter's GUID/MAC. Shipping one fixed set means
everyone who uses this project reports the *same* machine — and, if the repo's
own hipreport.conf were shared, the maintainer's real one. This mints a fresh,
plausible Windows identity instead, so each user (or container) looks like its
own machine.

Only the identity fields are randomised. The anti-malware / OS-pretence block —
the part PolyU actually validates — is copied verbatim from the reference file
(hipreport.conf.example), so it stays correct and single-sourced.

    python3 hip/gen-hipreport-conf.py            # write hip/hipreport.conf
    python3 hip/gen-hipreport-conf.py --force    # overwrite an existing one
    python3 hip/gen-hipreport-conf.py --print    # just print it
    python3 hip/gen-hipreport-conf.py --netid 12345678d --out /path/conf

The values are not validated by PolyU, so regenerating is harmless; but the
file is meant to be made once and kept, so the machine identity stays stable.
"""
from __future__ import annotations

import argparse
import re
import secrets
import string
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Identity keys this tool regenerates; everything else in the reference file
# (anti-malware block, OS pretence, domain, user fallback) is passed through.
IDENTITY_KEYS = ("HOST_NAME", "HOST_ID", "NIC_GUID", "NIC_MAC", "CLIENT_IP")


def windows_computer_name() -> str:
    """A default-style Windows name: DESKTOP- + 7 upper-alnum chars (15 total,
    the NetBIOS limit — exactly how Windows Setup names an unattended install)."""
    alphabet = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(alphabet) for _ in range(7))
    return f"DESKTOP-{suffix}"


def machine_guid() -> str:
    """HKLM\\...\\Cryptography\\MachineGuid: a lowercase UUID, no braces."""
    return str(uuid.uuid4())


def nic_guid() -> str:
    """A network adapter's registry GUID: uppercase, in braces."""
    return "{" + str(uuid.uuid4()).upper() + "}"


def pangp_mac() -> str:
    """A MAC for the PANGP virtual adapter. Keeps its 02-50-41 prefix (locally
    administered; 50 41 = 'PA') and randomises the last three octets."""
    tail = [secrets.randbelow(256) for _ in range(3)]
    return "02-50-41-" + "-".join(f"{b:02X}" for b in tail)


def client_ip() -> str:
    """A fallback tunnel IP in PolyU's 10.8/16 pool (openconnect overrides it)."""
    return f"10.8.{secrets.randbelow(256)}.{secrets.randbelow(254) + 1}"


def generate(reference: str, netid: str | None = None) -> str:
    """Return the reference conf with its identity lines replaced."""
    values = {
        "HOST_NAME": windows_computer_name(),
        "HOST_ID": machine_guid(),
        "NIC_GUID": nic_guid(),
        "NIC_MAC": pangp_mac(),
        "CLIENT_IP": client_ip(),
    }
    if netid:
        values["USER_NAME"] = netid

    seen: set[str] = set()
    out = []
    for line in reference.splitlines(keepends=True):
        m = re.match(r'^(\w+)=', line)
        if m and m.group(1) in values:
            key = m.group(1)
            out.append(f'{key}="{values[key]}"\n')
            seen.add(key)
        else:
            out.append(line)

    # A key present in `values` but absent from the reference would silently be
    # dropped; append it so the result is always complete.
    for key in values:
        if key not in seen:
            out.append(f'{key}="{values[key]}"\n')
    return "".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=HERE / "hipreport.conf",
                    help="where to write (default hip/hipreport.conf)")
    ap.add_argument("--from", dest="ref", type=Path, default=HERE / "hipreport.conf.example",
                    help="reference conf to copy the non-identity block from")
    ap.add_argument("--netid", help="also set USER_NAME (the fallback NetID)")
    ap.add_argument("--force", action="store_true", help="overwrite an existing --out")
    ap.add_argument("--print", dest="to_stdout", action="store_true",
                    help="print to stdout instead of writing --out")
    a = ap.parse_args()

    if not a.ref.is_file():
        raise SystemExit(f"reference conf not found: {a.ref}")
    conf = generate(a.ref.read_text(), a.netid)

    if a.to_stdout:
        sys.stdout.write(conf)
        return
    if a.out.exists() and not a.force:
        raise SystemExit(
            f"{a.out} already exists — keeping your machine identity stable.\n"
            f"Pass --force to mint a new one, or --print to preview.")
    a.out.write_text(conf)
    ident = {}
    for line in conf.splitlines():
        m = re.match(r'^(HOST_NAME|HOST_ID)="(.*)"$', line)
        if m:
            ident[m.group(1)] = m.group(2)
    print(f"wrote {a.out}")
    print(f"  computer name: {ident.get('HOST_NAME', '?')}")
    print(f"  machine GUID:  {ident.get('HOST_ID', '?')}")


if __name__ == "__main__":
    main()
