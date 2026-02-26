# remoteRF_server/host/host_auth_token.py

from __future__ import annotations

import os
import re
import sys
import time
import threading
from pathlib import Path
from typing import Dict, Tuple, List
from datetime import datetime, timezone
import hashlib

from ..common.utils import *  

_HOST_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

def _validate_host_id(raw: str) -> str:
    hid = (raw or "").strip()
    if not hid:
        raise ValueError("Missing host_id")
    if hid == "unknown-host":
        raise ValueError("host_id cannot be 'unknown-host'")
    if not _HOST_ID_RE.fullmatch(hid):
        raise ValueError("Invalid host_id (allowed: 1..64 chars of [A-Za-z0-9_.-])")
    return hid

def _hosts_auth_path() -> Path:
    return get_db_dir() / "hosts_auth.env"

def _utc_now_s() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _host_key(host_id: str) -> str:
    return hashlib.sha256(host_id.encode("utf-8")).hexdigest()[:16]

# Minimal env read/write

def _read_env_kv(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out

def _write_env_kv(path: Path, kv: Dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # deterministic output makes diffs/debugging easier
    lines: List[str] = []
    for k in sorted(kv.keys()):
        v = str(kv[k])
        if any(c.isspace() for c in v) or any(c in v for c in ['"', "'"]):
            v = v.replace('"', '\\"')
            lines.append(f'{k}="{v}"')
        else:
            lines.append(f"{k}={v}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

# Cached DB load (thread-safe)

_DB_LOCK = threading.RLock()
_DB_CACHE_MTIME: float = 0.0
_DB_CACHE: Dict[str, str] = {}

def _load_db_kv() -> Dict[str, str]:
    global _DB_CACHE_MTIME, _DB_CACHE
    p = _hosts_auth_path()

    try:
        st = p.stat()
        mtime = float(st.st_mtime)
    except FileNotFoundError:
        with _DB_LOCK:
            _DB_CACHE_MTIME = 0.0
            _DB_CACHE = {}
            return {}
    except Exception:
        # if stat fails oddly, fall back to best-effort read
        mtime = -1.0

    with _DB_LOCK:
        if mtime > 0 and _DB_CACHE and _DB_CACHE_MTIME == mtime:
            return dict(_DB_CACHE)

        kv = _read_env_kv(p)
        _DB_CACHE = dict(kv)
        _DB_CACHE_MTIME = mtime if mtime > 0 else time.time()
        return dict(kv)

def _save_db_kv(kv: Dict[str, str]) -> None:
    global _DB_CACHE_MTIME, _DB_CACHE
    p = _hosts_auth_path()
    _write_env_kv(p, kv)
    # refresh cache immediately
    try:
        mtime = float(p.stat().st_mtime)
    except Exception:
        mtime = time.time()
    with _DB_LOCK:
        _DB_CACHE = dict(kv)
        _DB_CACHE_MTIME = mtime

# Public API

def create_host_token(
    host_id: str,
    *,
    length: int = 8,
    status: str = "approved",
    overwrite: bool = True,
) -> str:
    hid = _validate_host_id(host_id)
    hk = _host_key(hid)

    salt, hashed, token = generate_token(length=length)
    now = _utc_now_s()

    kv = _load_db_kv()

    # If not overwriting and host exists, refuse
    if not overwrite and kv.get(f"HOST_{hk}_ID", "").strip():
        raise ValueError(f"Host token already exists for host_id={hid!r} (use --force to overwrite)")

    kv[f"HOST_{hk}_ID"] = hid
    kv[f"HOST_{hk}_SALT"] = salt
    kv[f"HOST_{hk}_HASH"] = hashed
    kv[f"HOST_{hk}_STATUS"] = (status or "approved").strip().lower()
    kv[f"HOST_{hk}_UPDATED_UTC"] = now
    if f"HOST_{hk}_CREATED_UTC" not in kv:
        kv[f"HOST_{hk}_CREATED_UTC"] = now

    _save_db_kv(kv)
    return token

def set_host_status(host_id: str, status: str) -> None:
    hid = _validate_host_id(host_id)
    hk = _host_key(hid)

    kv = _load_db_kv()
    if kv.get(f"HOST_{hk}_ID", "").strip() != hid:
        raise ValueError(f"Unknown host_id={hid!r} (no record)")

    kv[f"HOST_{hk}_STATUS"] = (status or "").strip().lower()
    kv[f"HOST_{hk}_UPDATED_UTC"] = _utc_now_s()
    _save_db_kv(kv)

def is_host_token_valid(host_id: str, token: str, *, require_status: str = "approved") -> bool:
    try:
        hid = _validate_host_id(host_id)
    except Exception:
        return False

    tok = (token or "").strip()
    if not tok:
        return False

    hk = _host_key(hid)
    kv = _load_db_kv()

    rid = (kv.get(f"HOST_{hk}_ID", "") or "").strip()
    if rid != hid:
        return False

    status = (kv.get(f"HOST_{hk}_STATUS", "") or "").strip().lower()
    if require_status and status != require_status.strip().lower():
        return False

    salt = (kv.get(f"HOST_{hk}_SALT", "") or "").strip()
    hashed = (kv.get(f"HOST_{hk}_HASH", "") or "").strip()
    if not salt or not hashed:
        return False

    try:
        return bool(validate_token(salt, hashed, tok))
    except Exception:
        return False

def list_hosts() -> List[Tuple[str, str]]:
    kv = _load_db_kv()
    out: List[Tuple[str, str]] = []
    # Scan by HOST_<hk>_ID keys
    for k, v in kv.items():
        if not k.startswith("HOST_") or not k.endswith("_ID"):
            continue
        hk = k[len("HOST_") : -len("_ID")]
        hid = (v or "").strip()
        st = (kv.get(f"HOST_{hk}_STATUS", "") or "").strip().lower()
        if hid:
            out.append((hid, st or ""))
    out.sort(key=lambda t: t[0])
    return out

def _host_record_keys(hk: str) -> list[str]:
    # all keys stored for this host_key
    return [
        f"HOST_{hk}_ID",
        f"HOST_{hk}_SALT",
        f"HOST_{hk}_HASH",
        f"HOST_{hk}_STATUS",
        f"HOST_{hk}_CREATED_UTC",
        f"HOST_{hk}_UPDATED_UTC",
    ]

def list_host_token_records(*, include_secrets: bool = False) -> list[dict[str, str]]:
    kv = _load_db_kv()
    out: list[dict[str, str]] = []

    # Find all host keys by scanning HOST_<hk>_ID
    for k, v in kv.items():
        if not k.startswith("HOST_") or not k.endswith("_ID"):
            continue

        hk = k[len("HOST_") : -len("_ID")]
        host_id = (v or "").strip()
        if not host_id:
            continue

        rec: dict[str, str] = {
            "host_id": host_id,
            "status": (kv.get(f"HOST_{hk}_STATUS", "") or "").strip().lower(),
            "created_utc": (kv.get(f"HOST_{hk}_CREATED_UTC", "") or "").strip(),
            "updated_utc": (kv.get(f"HOST_{hk}_UPDATED_UTC", "") or "").strip(),
        }

        if include_secrets:
            rec["salt"] = (kv.get(f"HOST_{hk}_SALT", "") or "").strip()
            rec["hash"] = (kv.get(f"HOST_{hk}_HASH", "") or "").strip()

        out.append(rec)

    out.sort(key=lambda r: r.get("host_id", ""))
    return out

def delete_host_token(host_id: str) -> bool:
    hid = _validate_host_id(host_id)
    hk = _host_key(hid)

    kv = _load_db_kv()
    rid = (kv.get(f"HOST_{hk}_ID", "") or "").strip()
    if rid != hid:
        return False

    removed = False
    for k in _host_record_keys(hk):
        if k in kv:
            kv.pop(k, None)
            removed = True

    if removed:
        _save_db_kv(kv)
    return removed

def wipe_all_host_tokens() -> int:
    kv = _load_db_kv()

    # Count how many hosts are present
    host_keys: list[str] = []
    for k in kv.keys():
        if k.startswith("HOST_") and k.endswith("_ID"):
            hk = k[len("HOST_") : -len("_ID")]
            host_keys.append(hk)

    # Remove all per-host keys
    for hk in host_keys:
        for kk in _host_record_keys(hk):
            kv.pop(kk, None)

    _save_db_kv(kv)
    return len(host_keys)

def show_host_tokens(*, include_secrets: bool = False, file=sys.stdout) -> None:
    recs = list_host_token_records(include_secrets=include_secrets)
    if not recs:
        print(f"No host tokens found ({_hosts_auth_path()}).", file=file)
        return

    print(f"Host tokens ({_hosts_auth_path()}):", file=file)
    for r in recs:
        host_id = r.get("host_id", "")
        status = r.get("status", "")
        created = r.get("created_utc", "")
        updated = r.get("updated_utc", "")
        print(f"  - {host_id}  status={status}  created={created}  updated={updated}", file=file)
        if include_secrets:
            print(f"      salt={r.get('salt','')}", file=file)
            print(f"      hash={r.get('hash','')}", file=file)