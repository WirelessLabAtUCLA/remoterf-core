# Copyright (C) 2026 RemoteRF
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""`schema browse` / `schema download`: RemoteRF Global's registry of the device
driver schemas the Wireless Lab approved, for a lab on Global.

A schema is the interface a driver serves (what clients generate their code
from), not the driver: serving one for a device still needs the driver code
that implements it, a `<type>_schema.py` in the drivers folder, and code is not
part of the registry. A download is checked against its approved hash and
kept under `<drivers folder>/registry/`, where the Server never loads it.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import global_onboarding

_ME = "/v2/broker/deployments/me"
_NEEDS_GLOBAL = "The schema registry is part of RemoteRF Global: put this lab on Global first (global join)."


def digest(schema: dict) -> str:
    """A schema's hash as a Server computes it (DeviceSchema.get_idl, idl.v2)."""
    body = {key: value for key, value in schema.items() if key != "schema_hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def registry_dir() -> Path:
    from ..common.utils import get_drivers_dir

    return get_drivers_dir() / "registry"


def _ask(payload: dict) -> dict:
    import requests

    try:
        return global_onboarding.call("POST", _ME, payload)
    except global_onboarding.GlobalError as exc:
        if exc.code in ("http_404", "http_405"):
            raise RuntimeError("This RemoteRF Global has no schema registry yet.") from None
        raise RuntimeError(f"RemoteRF Global refused that: {exc.code}") from None
    except requests.RequestException:
        raise RuntimeError("RemoteRF Global is unreachable right now; try again later.") from None


def _approved() -> list[dict]:
    return list(_ask({"registry": "browse"}).get("schemas") or [])


def _text(value, limit: int = 64) -> str:
    """Text from Global (a lab chose it) on one printable line: no escape sequences reach the terminal."""
    return "".join(c for c in str(value) if c.isprintable())[:limit]


def _row(item: dict) -> tuple[str, ...]:
    import time

    when = item.get("approved_at")
    return (_text(item.get("device_type") or "?"), _text(item.get("driver_version") or "-", 32),
            _text(item.get("deployment_name") or "-"),
            time.strftime("%Y-%m-%d", time.gmtime(when)) if isinstance(when, int) else "-",
            str(item.get("schema_hash", ""))[7:19])


def _print_rows(items: list[dict]) -> None:
    rows = [("NAME", "VERSION", "LAB", "APPROVED", "HASH"), *(_row(item) for item in items)]
    widths = [max(len(row[i]) for row in rows) for i in range(5)]
    for row in rows:
        print("  " + "  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip())


def _words(argv) -> list[str]:
    return [word for word in argv if not word.startswith("-")]


def cmd_browse(argv: list[str]) -> int:
    """schema browse [text]: the approved schemas, optionally only those whose name or lab has <text>."""
    if global_onboarding.state() != "active":
        print(_NEEDS_GLOBAL)
        return 2
    text = " ".join(_words(argv)).lower()
    try:
        items = [item for item in _approved()
                 if text in f"{item.get('device_type', '')} {item.get('deployment_name', '')}".lower()]
    except RuntimeError as exc:
        print(exc)
        return 1
    if not items:
        print("No approved schemas" + (f" match {text!r}." if text else " yet."))
        return 0
    _print_rows(items)
    print("  Save one with: schema download <name|hash>")
    return 0


def _pick(items: list[dict], ref: str) -> list[dict]:
    digits = ref.lower().removeprefix("sha256:")
    if re.fullmatch(r"[0-9a-f]{8,64}", digits):
        by_hash = [item for item in items if str(item.get("schema_hash", "")).startswith("sha256:" + digits)]
        if by_hash:
            return by_hash
    return [item for item in items if str(item.get("device_type", "")).casefold() == ref.casefold()]


def cmd_download(argv: list[str]) -> int:
    """schema download <name|hash> [-y]: save an approved schema, its hash checked, to the drivers folder."""
    from ..common.utils.panel import confirm

    if global_onboarding.state() != "active":
        print(_NEEDS_GLOBAL)
        return 2
    words = _words(argv)
    if len(words) != 1:
        print("Usage: schema download <name|hash> [-y]   (schema browse lists them)")
        return 2
    try:
        matches = _pick(_approved(), words[0])
        if len(matches) != 1:
            if matches:
                _print_rows(matches)
                print("  More than one approved schema has that name: download one by its hash.")
            else:
                print(f"No approved schema is called or hashed {words[0]!r}; schema browse lists them.")
            return 2
        schema_hash = matches[0]["schema_hash"]
        entry = _ask({"registry": "download", "schema_hash": schema_hash})
    except RuntimeError as exc:
        print(exc)
        return 1
    schema = entry.get("schema")
    if not isinstance(schema, dict) or digest(schema) != schema_hash or schema.get("schema_hash") != schema_hash:
        print("RemoteRF Global sent a schema that does not match its approved hash; nothing was saved.")
        return 1
    device_type = _text(schema.get("device_type") or "device")
    target = registry_dir() / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', device_type)[:64]}-{schema_hash[7:19]}.json"
    text = json.dumps(schema, indent=1, sort_keys=True) + "\n"
    if target.exists() and target.read_text(encoding="utf-8") == text:
        print(f"Already saved: {target}")
    else:
        if target.exists() and "-y" not in argv and "--yes" not in argv and not confirm(
                f"{target.name} is there and differs; replace it?", default=False):
            print("Kept the file that was there.")
            return 1
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        print(f"Saved {target}")
    lab = _text(entry.get("deployment_name") or "the lab that published it")
    print(f"  The approved {device_type!r} schema (driver {_text(schema.get('driver_version') or '?', 32)!r}, "
          f"{schema_hash[:19]}…) from {lab}.")
    print(f"  This is the interface only: a device needs driver code that implements it, a {device_type}_schema.py"
          f" in {registry_dir().parent}. Code is not part of the registry; ask {lab} for theirs.")
    print("  Global users get the schema your driver serves, once its hash is approved.")
    return 0
