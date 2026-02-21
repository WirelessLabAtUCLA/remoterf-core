# device_manager.py (host)

from __future__ import annotations

import adi
import os
import re
import subprocess
import threading
from pathlib import Path
from typing import Dict, Tuple, Optional, Any

# -----------------------------
# Pluto helpers
# -----------------------------

def connect_pluto(*, ip: str = "", usb: str = ""):
    try:
        if ip:
            dev = adi.Pluto(f"ip:{ip}")
            print(f"Connected to Pluto ip:{ip}")
        else:
            dev = adi.Pluto(f"usb:{usb}")
            print(f"Connected to Pluto usb:{usb}")
        return dev
    except Exception as e:
        print(f"Pluto {ip or usb}: {e}")
        return None


def get_usb_port_from_serial(serial: str) -> Optional[str]:
    serial = (serial or "").strip()
    if not serial:
        return None
    try:
        out = subprocess.check_output(["iio_info", "-s"], text=True, stderr=subprocess.STDOUT)
    except Exception as e:
        print(f"Error running iio_info: {e}")
        return None

    # Be tolerant: iio_info varies; match either serial= or hw_serial=
    for line in out.splitlines():
        if (f"serial={serial}" in line) or (f"hw_serial={serial}" in line):
            m = re.search(r"\[usb:([^\]]+)\]", line)
            if m:
                return m.group(1).strip()

    print(f"No device found with serial {serial}")
    return None


# -----------------------------
# repo-local config paths
# -----------------------------

def _repo_root() -> Path:
    """
    Robustly find the repo root by locating the 'src' directory in parents.
    Works for paths like:
      <repo>/src/remoteRF_host/host/device_manager.py
    """
    p = Path(__file__).resolve()
    for parent in p.parents:
        if parent.name == "src":
            return parent.parent
    # fallback: best-effort
    if len(p.parents) >= 4:
        return p.parents[3]
    return p.parent


def _devices_env_candidates() -> list[Path]:
    """
    Prefer the new canonical location used by tunnel_agent.py:
      <repo>/.config/devices.env

    But keep backwards-compat with your older layout:
      <repo>/config/remoteRF_host/devices.env
    """
    root = _repo_root()
    return [
        root / ".config" / "devices.env",
        root / "config" / "remoteRF_host" / "devices.env",
    ]


def _devices_env_path() -> Path:
    # Allow override
    override = (os.getenv("REMOTERF_DEVICES_ENV", "") or "").strip()
    if override:
        return Path(override).expanduser().resolve()

    for p in _devices_env_candidates():
        if p.exists():
            return p

    # default to canonical path even if missing
    return _repo_root() / ".config" / "devices.env"


# -----------------------------
# .env parsing
# -----------------------------

_ENV_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
_DEVICE_KEY_RE = re.compile(r"^DEVICE_(\d+)_(.+)$", re.IGNORECASE)

def _strip_quotes(v: str) -> str:
    v = (v or "").strip()
    if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
        return v[1:-1]
    return v


def _read_env_file(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not path.exists():
        return out
    try:
        txt = path.read_text(encoding="utf-8")
    except Exception:
        return out

    for raw in txt.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _ENV_LINE.match(line)
        if not m:
            continue
        k = m.group(1).strip()
        v = _strip_quotes(m.group(2))
        out[k] = v
    return out


def _load_device_records() -> Dict[int, Dict[str, str]]:
    """
    Returns:
      { gid: { "TYPE":..., "NAME":..., "IDENT_KIND":..., "IDENT":..., ... } }
    """
    kv = _read_env_file(_devices_env_path())
    recs: Dict[int, Dict[str, str]] = {}

    # New format: DEVICE_<gid>_<FIELD>
    for k, v in kv.items():
        m = _DEVICE_KEY_RE.match(k.strip())
        if not m:
            continue
        try:
            gid = int(m.group(1))
        except Exception:
            continue
        field = m.group(2).strip().upper()
        recs.setdefault(gid, {})[field] = str(v).strip()

    # Back-compat: DEVICE_<gid>_ID treated as IDENT (iio_serial)
    for k, v in kv.items():
        kk = k.strip().upper()
        if not kk.startswith("DEVICE_") or not kk.endswith("_ID"):
            continue
        mid = kk[7:-3]
        try:
            gid = int(mid)
        except Exception:
            continue
        recs.setdefault(gid, {})
        recs[gid].setdefault("TYPE", "pluto")
        recs[gid].setdefault("NAME", f"device-{gid}")
        recs[gid].setdefault("IDENT_KIND", "iio_serial")
        recs[gid].setdefault("IDENT", str(v).strip())

    return recs


def _connect_from_record(rec: Dict[str, str]) -> Tuple[object | None, str, str]:
    """
    Returns (device_obj, ident, dtype).
    """
    dtype = (rec.get("TYPE") or "").strip().lower()
    ident_kind = (rec.get("IDENT_KIND") or "").strip().lower()
    ident = (rec.get("IDENT") or "").strip()

    if dtype != "pluto":
        return (None, ident, dtype)

    if ident_kind in ("iio_serial", "serial", "iio"):
        if not ident:
            return (None, ident, dtype)
        usb_port = get_usb_port_from_serial(ident)
        if not usb_port:
            return (None, ident, dtype)
        return (connect_pluto(usb=usb_port), ident, dtype)

    if ident_kind == "usb":
        if not ident:
            return (None, ident, dtype)
        return (connect_pluto(usb=ident), ident, dtype)

    if ident_kind == "ip":
        if not ident:
            return (None, ident, dtype)
        return (connect_pluto(ip=ident), ident, dtype)

    return (None, ident, dtype)


# -----------------------------
# Runtime state + API
# -----------------------------

_state_lock = threading.RLock()

# legacy maps
device_serialization: Dict[int, str] = {}
devices_info: Dict[int, str] = {}

# gid -> (dev, ident, dtype)
devices: Dict[int, Tuple[object | None, str, str]] = {}

master_token = "***REMOVED***"  # (host can have one; but host RPC should NOT need it)

def reload_devices() -> None:
    """
    Reload devices.env and reconnect devices.
    Safe to call at startup and optionally on MetaRequest / refresh flows.
    """
    global devices, devices_info, device_serialization

    records = _load_device_records()

    tmp_devices: Dict[int, Tuple[object | None, str, str]] = {}
    tmp_info: Dict[int, str] = {}
    tmp_ser: Dict[int, str] = {}

    for gid, rec in sorted(records.items()):
        name = (rec.get("NAME") or f"device-{gid}").strip()
        ident = (rec.get("IDENT") or "").strip()

        dev, ident2, dtype2 = _connect_from_record(rec)

        tmp_devices[int(gid)] = (dev, ident2, dtype2)
        tmp_info[int(gid)] = name
        if ident:
            tmp_ser[int(gid)] = ident

    with _state_lock:
        devices = tmp_devices
        devices_info = tmp_info
        device_serialization = tmp_ser


# initialize on import
reload_devices()


def get_all_devices() -> Dict[int, Tuple[object | None, str, str]]:
    with _state_lock:
        return {k: v for k, v in devices.items() if v and v[0] is not None}


def get_all_devices_str() -> Dict[int, str]:
    with _state_lock:
        return dict(devices_info)


def device_exists(device_id: int | str) -> bool:
    try:
        did = int(device_id)
    except Exception:
        return False
    with _state_lock:
        if did not in devices:
            return False
        dev, _, _ = devices[did]
        return dev is not None


def get_device(*, id: int | str):
    """
    Accepts 10 or "10". Returns the live device object, or None if missing/offline.
    """
    try:
        did = int(id)
    except Exception:
        return None
    with _state_lock:
        tup = devices.get(did)
        if not tup:
            return None
        return tup[0]