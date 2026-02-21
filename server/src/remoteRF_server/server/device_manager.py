# src/remoteRF_server/server/device_manager.py

from __future__ import annotations

import hashlib
from typing import Dict, Tuple, Optional, Any

import os
import re
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple, List, Iterator
from contextlib import contextmanager

import adi

from ..common.utils import validate_token  # your salt/hash validator
from ..host import host_tunnel_server as hts  # gives access to hts.TUNNEL_REGISTRY

# -----------------------------
# Config paths (server-side)
# -----------------------------

def _xdg_config_home() -> Path:
    return Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config"))

def _cfg_dir() -> Path:
    # default: ~/.config/remoterf
    return Path(os.getenv("REMOTERF_CONFIG_DIR", _xdg_config_home() / "remoterf"))

def _devices_env_path() -> Path:
    return _cfg_dir() / "devices.env"

# -----------------------------
# Host stuff
# -----------------------------

def _get_host_registry():
    # host_tunnel_server sets this when the tunnel server starts
    return getattr(hts, "TUNNEL_REGISTRY", None)


def _host_devices_str_snapshot() -> Dict[int, str]:
    """
    Pull a FRESH host-device directory snapshot every call.
    Assumes host device_ids are numeric strings that should be treated as gids.
    """
    reg = _get_host_registry()
    if reg is None:
        return {}

    # ttl_ms=0 => force refresh (no caching)
    snap = reg.device_directory_cached(ttl_ms=0)  # device_id -> (host_id, info_obj, is_active)

    out: Dict[int, str] = {}
    for device_id, (host_id, info_obj, is_active) in snap.items():
        # You said host device IDs are already globally unique => treat as gid.
        try:
            gid = int(str(device_id))
        except Exception:
            # If something non-numeric ever sneaks in, just skip it.
            continue

        local_id = int(getattr(info_obj, "local_id", 0) or 0)
        label = str(getattr(info_obj, "label", "") or "").strip()
        serial = str(getattr(info_obj, "serial", "") or "").strip()
        kind = str(getattr(info_obj, "kind", "") or "").strip()

        status = "online" if bool(is_active) else "offline"
        name = label or f"host-device-{gid}"

        # keep it human-readable for CLI/UI
        out[gid] = (
            f"{name} "
            f"[host={host_id}, local_id={local_id}"
            f"{', kind=' + kind if kind else ''}"
            f"{', serial=' + serial if serial else ''}"
            f"] ({status})"
        )

    return out

# -----------------------------
# Pluto helpers
# -----------------------------

def connect_pluto(*, ip: str = "", usb: str = ""):
    try:
        if ip == "":
            dev = adi.Pluto(f"usb:{usb}")
            print(f"Connected to Pluto usb:{usb}")
        else:
            dev = adi.Pluto(f"ip:{ip}")
            print(f"Connected to Pluto ip:{ip}")
        return dev
    except Exception as e:
        print(f"Pluto {ip}: {e}")
        return None
    
def get_usb_port_from_serial(serial: str) -> str | None:
    serial = (serial or "").strip()
    if not serial:
        return None

    try:
        out = subprocess.check_output(["iio_info", "-s"], text=True, stderr=subprocess.STDOUT)
    except Exception as e:
        print(f"Error running iio_info: {e}")
        return None

    # match either serial= or hw_serial= and extract usb context anywhere on the line
    for line in out.splitlines():
        if (f"serial={serial}" in line) or (f"hw_serial={serial}" in line):
            m = re.search(r"\[usb:([^\]]+)\]", line)
            if m:
                return m.group(1).strip()

    print(f"No device found with serial {serial}")
    return None


# -----------------------------
# Parse devices.env
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

    # Back-compat: DEVICE_<gid>_ID treated as IDENT
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

def _connect_from_record(rec: Dict[str, str]):
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
# Thread-safe runtime state
# -----------------------------

_state_lock = threading.RLock()

@dataclass
class _DeviceState:
    dev: object
    salt: str
    hsh: str
    name: str
    ident: str
    dtype: str
    io_lock: threading.RLock

# gid -> state
_devices: Dict[int, _DeviceState] = {}

# legacy maps (kept for your existing server calls/UI)
devices_info: Dict[int, str] = {}
device_serialization: Dict[int, str] = {}

# master token (overrideable)
master_token = os.getenv("REMOTERF_MASTER_TOKEN", "***REMOVED***")


def _init_from_env() -> None:
    records = _load_device_records()

    tmp_devices: Dict[int, _DeviceState] = {}
    tmp_info: Dict[int, str] = {}
    tmp_ser: Dict[int, str] = {}

    # Build + connect (do the expensive work without holding the global lock)
    for gid, rec in sorted(records.items()):
        name = (rec.get("NAME") or f"device-{gid}").strip()
        ident = (rec.get("IDENT") or "").strip()
        dtype = (rec.get("TYPE") or "").strip().lower()

        dev, ident2, dtype2 = _connect_from_record(rec)

        tmp_info[int(gid)] = name
        if ident:
            tmp_ser[int(gid)] = ident

        tmp_devices[int(gid)] = _DeviceState(
            dev=dev,
            salt="",
            hsh="",
            name=name,
            ident=ident2,
            dtype=dtype2 or dtype,
            io_lock=threading.RLock(),
        )

    # Swap atomically
    with _state_lock:
        _devices.clear()
        _devices.update(tmp_devices)

        devices_info.clear()
        devices_info.update(tmp_info)

        device_serialization.clear()
        device_serialization.update(tmp_ser)

# initialize on import
_init_from_env()


# -----------------------------
# Legacy reservation helpers (master token parsing)
# -----------------------------

def parse_mastertoken(token: str):
    """
    Matches:
      {master_token}_0
      {master_token}-1
      {master_token}_0_force

    Returns (device_id:int, force:bool) or None.
    """
    if not token:
        return None
    prefix = re.escape(master_token)
    pattern = re.compile(rf"^{prefix}[_-](\d+)(?:_force)?$")
    m = pattern.match(token)
    if not m:
        return None
    device_id = int(m.group(1))
    force = token.endswith("_force")
    return (device_id, force)


# -----------------------------
# Transmitter stubs (legacy)
# -----------------------------

_transmitter = None

def start_transmitter():
    pass

def terminate_transmitter():
    pass

def get_transmitter_state() -> bool:
    return False


# -----------------------------
# Legacy API (state-safe)
# -----------------------------

def get_all_devices() -> Dict[int, Tuple[object, str, str]]:
    # snapshot: connected devices only
    with _state_lock:
        out: Dict[int, Tuple[object, str, str]] = {}
        for gid, st in _devices.items():
            if st.dev is not None:
                out[gid] = (st.dev, st.salt, st.hsh)
        return out

def get_all_devices_str() -> Dict[int, str]:
    # local snapshot (fast)
    with _state_lock:
        out = dict(devices_info)

    # host snapshot (fresh pull each call)
    out.update(_host_devices_str_snapshot())
    return out

def set_device(device_id: int, salt: str, hash: str):
    # update ONLY reservation/auth state
    with _state_lock:
        st = _devices.get(int(device_id))
        if not st:
            return
        st.salt = str(salt or "")
        st.hsh = str(hash or "")

def device_exists(device_id: int) -> bool:
    did = int(device_id)

    # local
    with _state_lock:
        st = _devices.get(did)
        if st and st.dev is not None:
            return True

    # host
    reg = _get_host_registry()
    if reg is None:
        return False
    return bool(reg.is_host_device(str(did)))

def device_is_available(device_id: int) -> bool:
    with _state_lock:
        st = _devices.get(int(device_id))
        if not st or st.dev is None:
            return False
        return (st.salt == "") and (st.hsh == "")

def get_device_by_id(device_id: int):
    # legacy: returns (dev, salt, hash) tuple
    with _state_lock:
        st = _devices.get(int(device_id))
        if not st:
            return None
        return (st.dev, st.salt, st.hsh)

def get_device(*, api_token: str):
    """
    Legacy behavior:
      - master_token returns first available device object
      - master_token_<id>[_force] selects a specific device
      - otherwise validate against per-device salt/hash (set via reservations)
    Returns the connected device object or None.

    NOTE: This does NOT serialize hardware I/O; use acquire_device() for that.
    """
    if not api_token:
        return None

    # Take a snapshot of state for validation without holding the global lock
    with _state_lock:
        snapshot: List[Tuple[int, object, str, str]] = [
            (gid, st.dev, st.salt, st.hsh)
            for gid, st in _devices.items()
            if st.dev is not None
        ]

    if api_token == master_token:
        for _, dev, salt, hsh in snapshot:
            if dev is not None and salt == "" and hsh == "":
                return dev
        return None

    parsed = parse_mastertoken(api_token)
    if parsed:
        device_id, force = parsed
        with _state_lock:
            st = _devices.get(int(device_id))
            if not st or st.dev is None:
                return None
            if force:
                return st.dev
            return st.dev if (st.salt == "" and st.hsh == "") else None

    for _, dev, salt, hsh in snapshot:
        if dev is None:
            continue
        if salt and hsh and validate_token(salt, hsh, api_token):
            return dev

    return None


# -----------------------------
# NEW: Per-device I/O locking (true concurrency support)
# -----------------------------

@contextmanager
def acquire_device(api_token: str) -> Iterator[Tuple[int, object]]:
    """
    Thread-safe way to use a device:
      with acquire_device(token) as (gid, dev):
          # safe: only one thread at a time per device
          ...

    - Selects the device using the SAME logic as get_device()
    - Then acquires that device's io_lock
    - Yields (gid, dev)
    """
    if not api_token:
        raise RuntimeError("missing api_token")

    # resolve gid first (snapshot-based)
    gid: Optional[int] = None

    if api_token == master_token:
        with _state_lock:
            for k, st in _devices.items():
                if st.dev is not None and st.salt == "" and st.hsh == "":
                    gid = k
                    break
    else:
        parsed = parse_mastertoken(api_token)
        if parsed:
            cand, force = parsed
            with _state_lock:
                st = _devices.get(int(cand))
                if st and st.dev is not None:
                    if force or (st.salt == "" and st.hsh == ""):
                        gid = int(cand)
        else:
            # validate token against per-device salt/hash
            with _state_lock:
                snapshot = [(k, st.dev, st.salt, st.hsh) for k, st in _devices.items() if st.dev is not None]
            for k, dev, salt, hsh in snapshot:
                if salt and hsh and validate_token(salt, hsh, api_token):
                    gid = k
                    break

    if gid is None:
        raise RuntimeError("no device available / invalid token")

    # lock the selected device for I/O
    with _state_lock:
        st = _devices.get(int(gid))
        if not st or st.dev is None:
            raise RuntimeError("device disappeared / not connected")
        lock = st.io_lock
        dev = st.dev

    lock.acquire()
    try:
        yield int(gid), dev
    finally:
        lock.release()


# -----------------------------
# Optional: reload device definitions (atomic swap)
# -----------------------------

def reload_devices() -> None:
    """
    Reload devices.env and reconnect devices.
    Preserves existing salt/hash for devices that remain (same gid).
    """
    records = _load_device_records()

    # snapshot current salt/hash so we can carry it over
    with _state_lock:
        prev_auth = {gid: (st.salt, st.hsh) for gid, st in _devices.items()}

    tmp_devices: Dict[int, _DeviceState] = {}
    tmp_info: Dict[int, str] = {}
    tmp_ser: Dict[int, str] = {}

    for gid, rec in sorted(records.items()):
        name = (rec.get("NAME") or f"device-{gid}").strip()
        ident = (rec.get("IDENT") or "").strip()

        dev, ident2, dtype2 = _connect_from_record(rec)

        tmp_info[int(gid)] = name
        if ident:
            tmp_ser[int(gid)] = ident

        salt, hsh = prev_auth.get(int(gid), ("", ""))
        tmp_devices[int(gid)] = _DeviceState(
            dev=dev,
            salt=salt,
            hsh=hsh,
            name=name,
            ident=ident2,
            dtype=dtype2,
            io_lock=threading.RLock(),
        )

    with _state_lock:
        _devices.clear()
        _devices.update(tmp_devices)

        devices_info.clear()
        devices_info.update(tmp_info)

        device_serialization.clear()
        device_serialization.update(tmp_ser)


def set_pluto(ip: str = "192.168.2.1"):
    # kept for compatibility (no-op)
    pass
