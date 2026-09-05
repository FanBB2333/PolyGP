"""Read and update HIP identity data without executing configuration or imports."""
from __future__ import annotations

import json
import os
import re
import secrets
import string
import tempfile
import uuid
from pathlib import Path

KEYS = ("HOST_NAME", "HOST_ID", "NIC_GUID", "NIC_MAC")
FORMAT = "polygp-hip-identity"
MAX_IMPORT_BYTES = 64 * 1024
HERE = Path(__file__).resolve().parent


def config_path() -> Path:
    return Path(os.environ.get("POLYGP_HIP_CONF", str(HERE / "hipreport.conf")))


def random_identity() -> dict[str, str]:
    # Five random MAC octets; keep the local/unicast bits, avoid the old shared
    # adapter prefix and the small 24-bit suffix space.
    return {
        "HOST_NAME": "DESKTOP-" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(7)),
        "HOST_ID": str(uuid.uuid4()),
        "NIC_GUID": "{" + str(uuid.uuid4()).upper() + "}",
        "NIC_MAC": "02-" + "-".join(f"{secrets.randbelow(256):02X}" for _ in range(5)),
    }


def validate(values: dict, *, allow_legacy: bool = False) -> dict[str, str]:
    if not isinstance(values, dict) or set(values) != set(KEYS):
        raise ValueError("Include exactly HOST_NAME, HOST_ID, NIC_GUID and NIC_MAC.")
    if any(not isinstance(v, str) for v in values.values()):
        raise ValueError("Identity fields must be text.")
    out = {k: values[k].strip() for k in KEYS}
    name = out["HOST_NAME"]
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?", name) or name.isdigit():
        raise ValueError("Computer name: use 1–15 letters, numbers or hyphens; start and end with a letter or number.")
    out["HOST_NAME"] = name.upper()
    for key in ("HOST_ID", "NIC_GUID"):
        raw = out[key]
        if raw.startswith("{") and raw.endswith("}"):
            raw = raw[1:-1]
        if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", raw):
            raise ValueError(f"{key}: enter a UUID such as 12345678-1234-4234-8234-123456789abc.")
        value = uuid.UUID(raw)
        if not value.int and not allow_legacy:
            raise ValueError(f"{key}: the all-zero example UUID cannot be used.")
        out[key] = str(value) if key == "HOST_ID" else "{" + str(value).upper() + "}"
    mac = out["NIC_MAC"].replace(":", "-").upper()
    if not re.fullmatch(r"[0-9A-F]{2}(?:-[0-9A-F]{2}){5}", mac) or int(mac[:2], 16) & 1 or mac == "00-00-00-00-00-00":
        raise ValueError("Adapter MAC: enter six hexadecimal pairs for a unicast address.")
    out["NIC_MAC"] = mac
    return out


def parse_conf(content: str) -> dict[str, str]:
    values = {}
    for line in content.splitlines():
        match = re.match(r"^\s*(?:export\s+)?(HOST_NAME|HOST_ID|NIC_GUID|NIC_MAC)\s*=\s*(.*?)\s*$", line)
        if not match:
            continue
        key, raw = match.groups()
        if key in values:
            raise ValueError(f"Duplicate identity field: {key}.")
        # No shell evaluation, interpolation or command substitution. Quoted
        # values may have trailing comments; validation restricts their contents.
        quoted = re.fullmatch(r'''(["'])(.*?)\1\s*(?:#.*)?''', raw)
        values[key] = quoted.group(2) if quoted else raw.split(" #", 1)[0].strip()
    return values


def import_identity(content: str) -> dict[str, str]:
    if len(content.encode("utf-8")) > MAX_IMPORT_BYTES:
        raise ValueError("Import files must be 64 KB or smaller.")
    content = content.lstrip("\ufeff").strip()
    if content.startswith("{"):
        def unique(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError(f"Duplicate JSON field: {key}.")
                result[key] = value
            return result
        data = json.loads(content, object_pairs_hook=unique)
        if not isinstance(data, dict):
            raise ValueError("Import a PolyGP identity JSON object or hipreport.conf.")
        if "format" in data:
            if data.get("format") != FORMAT or type(data.get("version")) is not int or data["version"] != 1:
                raise ValueError("Unsupported identity file format or version.")
            if set(data) != {"format", "version", "identity"}:
                raise ValueError("Unexpected fields in identity file.")
            data = data["identity"]
    else:
        data = parse_conf(content)
    return validate(data)


def document(identity: dict) -> dict:
    # Export legacy identities too, so a user can back up before repairing.
    return {"format": FORMAT, "version": 1, "identity": {k: identity.get(k, "") for k in KEYS}}


def read_config(path: Path | None = None) -> tuple[str, str]:
    path = path or config_path()
    try:
        with path.open() as source:
            info = os.fstat(source.fileno())
            return source.read(), f"{info.st_ino}:{info.st_mtime_ns}:{info.st_size}"
    except FileNotFoundError:
        return "", "missing"


def snapshot() -> dict:
    content, revision = read_config()
    values = parse_conf(content)
    problem = ""
    try:
        validate(values)
    except ValueError as error:
        problem = str(error)
    return {"identity": {k: values.get(k, "") for k in KEYS}, "revision": revision,
            "problem": problem}


def replace_identity(content: str, values: dict) -> str:
    # Remove every old assignment before appending the four validated values.
    lines = [line for line in content.splitlines()
             if not re.match(r"^\s*(?:export\s+)?(?:HOST_NAME|HOST_ID|NIC_GUID|NIC_MAC)\s*=", line)]
    return "\n".join(lines).rstrip() + "\n" + "".join(f'{key}="{values[key]}"\n' for key in KEYS)


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".hip-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def save(values: dict, revision: str) -> dict:
    values = validate(values)
    path = config_path()
    content, current = read_config(path)
    if revision != current:
        raise ValueError("HIP identity changed elsewhere. Export your draft, then discard it and review the latest values before saving again.")
    if not content:
        content = (HERE / "hipreport.conf.example").read_text()
    atomic_write(path, replace_identity(content, values))
    return snapshot()
