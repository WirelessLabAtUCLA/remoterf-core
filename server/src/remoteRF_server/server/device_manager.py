# src/remoteRF_server/server/device_manager.py

from __future__ import annotations

import os
import re
import time
import adi
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Tuple, Optional, Any, List, Iterator
from contextlib import contextmanager

from ..common.utils import validate_token  # your salt/hash validator
from ..host import host_tunnel_server as hts  # gives access to hts.TUNNEL_REGISTRY

_state_lock = threading.RLock()


# ============================================================
# Virtual device (server-side proxy for host-managed hardware)
# ============================================================

@dataclass(frozen=True)
class VirtualDevice:
    """
    Server-side proxy for a host-managed device.

    IMPORTANT:
      - This is NOT an adi device.
      - It only carries routing metadata so your pipeline can forward later.
    """
    gid: int
    host_id: str
    device_id: str  # whatever key the host directory uses (stringified)
    label: str = ""
    serial: str = ""
    kind: str = ""

    def __repr__(self) -> str:
        return f"<VirtualDevice gid={self.gid} host={self.host_id} device_id={self.device_id}>"


def is_virtual(dev: object) -> bool:
    return isinstance(dev, VirtualDevice)


@dataclass
class _DeviceState:
    dev: object | None
    origin: str            # "local" or "host"
    online: bool           # for host devices; for local can mirror (dev is not None)
    salt: str
    hsh: str
    name: str
    ident: str
    dtype: str
    io_lock: threading.RLock = field(default_factory=threading.RLock)


# gid -> state
_devices: Dict[int, _DeviceState] = {}


def _is_connected(st: _DeviceState) -> bool:
    if st.origin == "local":
        return st.dev is not None
    # host
    return bool(st.online)


# ============================================================
# Host device pulling/grabbing
# ============================================================

def _get_host_registry():
    return hts.get_tunnel_registry()


_host_sync_lock = threading.RLock()
_host_sync_last_ms = 0
_HOST_SYNC_TTL_MS = 500  # tune later


def _sync_host_devices(*, force: bool = False) -> None:
    """
    Pull host directory and upsert host devices into _devices using their GID.

    - Does NOT touch local devices (origin="local")
    - Preserves salt/hsh/io_lock for existing entries
    - Marks missing host devices offline (keeps their proxy for reservations)
    - Updates devices_info/device_serialization for host devices (best-effort)
    """
    global _host_sync_last_ms

    now_ms = int(time.time() * 1000)
    with _host_sync_lock:
        if not force and (now_ms - _host_sync_last_ms) < _HOST_SYNC_TTL_MS:
            return
        _host_sync_last_ms = now_ms

    reg = _get_host_registry()
    if reg is None:
        return

    # Do registry calls without holding _state_lock
    snap = reg.device_directory_cached(ttl_ms=0)  # device_id -> (host_id, info_obj, is_active)

    updates: Dict[int, Dict[str, object]] = {}
    for device_id, (host_id, info_obj, is_active) in snap.items():
        # You said device_id is assumed to be the GID
        try:
            gid = int(str(device_id))
        except Exception:
            continue

        label = str(getattr(info_obj, "label", "") or "").strip()
        serial = str(getattr(info_obj, "serial", "") or "").strip()
        kind = str(getattr(info_obj, "kind", "") or "").strip()

        updates[gid] = {
            "host_id": str(host_id),
            "device_id": str(device_id),
            "label": label,
            "serial": serial,
            "kind": kind,
            "online": bool(is_active),
        }

    with _state_lock:
        # Upsert / refresh host entries
        for gid, u in updates.items():
            prev = _devices.get(int(gid))

            # Collision policy: do not overwrite local devices
            if prev is not None and prev.origin == "local":
                # collision shouldn't happen; keep local stable
                continue

            salt = prev.salt if prev else ""
            hsh = prev.hsh if prev else ""
            lock = prev.io_lock if prev else threading.RLock()

            label = str(u["label"] or "")
            serial = str(u["serial"] or "")
            kind = str(u["kind"] or "")
            host_id = str(u["host_id"] or "")
            device_id = str(u["device_id"] or "")

            name = label or (prev.name if prev else f"host-device-{gid}")
            dtype = (kind or (prev.dtype if prev else "")).strip().lower()
            ident = serial or (prev.ident if prev else device_id)

            _devices[int(gid)] = _DeviceState(
                dev=VirtualDevice(
                    gid=int(gid),
                    host_id=host_id,
                    device_id=device_id,
                    label=label,
                    serial=serial,
                    kind=kind,
                ),
                origin="host",
                online=bool(u["online"]),
                salt=salt,
                hsh=hsh,
                name=name,
                ident=ident,
                dtype=dtype,
                io_lock=lock,
            )

            # Keep legacy maps coherent for host devices too (best-effort)
            devices_info[int(gid)] = name
            if ident:
                device_serialization[int(gid)] = ident

        # Mark host entries not present in current snap as offline (but keep proxy + auth)
        present = set(updates.keys())
        for gid, st in _devices.items():
            if st.origin == "host" and gid not in present:
                st.online = False


def _local_devices_str_snapshot() -> Dict[int, str]:
    """
    Local devices from devices.env (whether connected or not).
    """
    out: Dict[int, str] = {}
    with _state_lock:
        for gid, st in _devices.items():
            if st.origin != "local":
                continue

            name = (st.name or f"device-{gid}").strip()
            status = "online" if _is_connected(st) else "offline"

            dtype = (st.dtype or "").strip()
            ident = (st.ident or "").strip()

            meta_parts: List[str] = ["local"]
            if dtype:
                meta_parts.append(f"type={dtype}")
            if ident:
                meta_parts.append(f"ident={ident}")

            if st.salt or st.hsh:
                status = status + ", reserved"

            out[int(gid)] = f"{name} [{', '.join(meta_parts)}] ({status})"
    return out

def _host_devices_str_snapshot() -> Dict[int, str]:
    _sync_host_devices()  # ensure host devices are up-to-date before snapshot
    reg = _get_host_registry()
    if reg is None:
        return {}

    snap = reg.device_directory_cached(ttl_ms=0)  # device_id -> (host_id, info_obj, is_active)

    try:
        status_map = reg.list_devices()  # device_id -> DeviceStatus
    except Exception:
        status_map = {}

    now_ms = int(time.time() * 1000)

    out: Dict[int, str] = {}
    for device_id, (host_id, info_obj, is_active) in snap.items():
        # Prefer numeric device_id (old world), otherwise fall back to local_id (compat/UI key).
        try:
            gid = int(str(device_id))
        except Exception:
            try:
                gid = int(getattr(info_obj, "local_id", 0) or 0)
            except Exception:
                continue
            if gid <= 0:
                continue

        local_id = int(getattr(info_obj, "local_id", 0) or 0)
        label = str(getattr(info_obj, "label", "") or "").strip()
        serial = str(getattr(info_obj, "serial", "") or "").strip()
        kind = str(getattr(info_obj, "kind", "") or "").strip()

        status = "online" if bool(is_active) else "offline"
        name = label or f"host-device-{gid}"

        last_seen = ""
        ds = status_map.get(str(device_id))
        if ds is not None:
            try:
                ls = int(getattr(ds, "last_seen_ms", 0) or 0)
                if ls > 0:
                    age_s = max(0, (now_ms - ls) // 1000)
                    last_seen = f", seen={age_s}s ago"
            except Exception:
                pass

        out[gid] = (
            f"{name} "
            f"({status})"
        )

    return out

# ============================================================
# Config paths (server-side)
# ============================================================

def _xdg_config_home() -> Path:
    return Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config"))


def _cfg_dir() -> Path:
    # default: ~/.config/remoterf
    return Path(os.getenv("REMOTERF_CONFIG_DIR", _xdg_config_home() / "remoterf"))


def _devices_env_path() -> Path:
    return _cfg_dir() / "devices.env"


# ============================================================
# Pluto helpers
# ============================================================

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

    for line in out.splitlines():
        if (f"serial={serial}" in line) or (f"hw_serial={serial}" in line):
            m = re.search(r"\[usb:([^\]]+)\]", line)
            if m:
                return m.group(1).strip()

    print(f"No device found with serial {serial}")
    return None


# ============================================================
# Parse devices.env
# ============================================================

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


# ============================================================
# Thread-safe runtime state
# ============================================================

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
            origin="local",
            online=(dev is not None),
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


# ============================================================
# Legacy reservation helpers (master token parsing)
# ============================================================

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


# ============================================================
# Transmitter stubs (legacy)
# ============================================================

_transmitter = None

def start_transmitter():
    pass

def terminate_transmitter():
    pass

def get_transmitter_state() -> bool:
    return False


# ============================================================
# Legacy API (state-safe)
# ============================================================

def get_all_devices() -> Dict[int, Tuple[object, str, str]]:
    _sync_host_devices()

    with _state_lock:
        out: Dict[int, Tuple[object, str, str]] = {}
        for gid, st in _devices.items():
            if _is_connected(st):
                out[gid] = (st.dev, st.salt, st.hsh)  # dev may be VirtualDevice for host
        return out


def get_all_devices_str() -> Dict[int, str]:
    _sync_host_devices()

    out = _local_devices_str_snapshot()
    host_out = _host_devices_str_snapshot()

    # merge with collision handling (shouldn't happen; keeps UI stable if it does)
    for gid, s in host_out.items():
        if gid in out:
            alt = -int(gid) - 1
            out[alt] = s + " [gid-collision]"
        else:
            out[gid] = s

    return out


def set_device(device_id: int, salt: str, hash: str):
    # ensure host devices are upserted so reservations can apply to them too
    _sync_host_devices()

    with _state_lock:
        st = _devices.get(int(device_id))

    if not st:
        _sync_host_devices(force=True)
        with _state_lock:
            st = _devices.get(int(device_id))
        if not st:
            return

    with _state_lock:
        st = _devices.get(int(device_id))
        if not st:
            return
        st.salt = str(salt or "")
        st.hsh = str(hash or "")


def device_exists(device_id: int) -> bool:
    did = int(device_id)

    _sync_host_devices()

    # local: connected only (unchanged semantics)
    with _state_lock:
        st = _devices.get(did)
        if st and st.origin == "local" and st.dev is not None:
            return True

    # host: existence as known by registry (unchanged)
    reg = _get_host_registry()
    if reg is None:
        return False
    return bool(reg.is_host_device(str(did)))


def device_is_available(device_id: int) -> bool:
    _sync_host_devices()

    with _state_lock:
        st = _devices.get(int(device_id))
        if not st or not _is_connected(st):
            return False
        return (st.salt == "") and (st.hsh == "")


def get_device_by_id(device_id: int):
    _sync_host_devices()

    with _state_lock:
        st = _devices.get(int(device_id))
        if not st:
            return None
        return (st.dev, st.salt, st.hsh)


def get_device(*, api_token: str):
    """
    Legacy behavior preserved:
      - master_token returns first available device object
      - master_token_<id>[_force] selects a specific device
      - otherwise validate against per-device salt/hash (set via reservations)
    Returns the connected device object or None.

    NOTE: This does NOT serialize hardware I/O; use acquire_device() for that.
    """
    if not api_token:
        return None

    _sync_host_devices()

    with _state_lock:
        snapshot: List[Tuple[int, object, str, str, str]] = [
            (gid, st.dev, st.salt, st.hsh, st.origin)
            for gid, st in _devices.items()
            if _is_connected(st)
        ]

    # Preserve "master prefers local" behavior
    if api_token == master_token:
        # local first
        for _, dev, salt, hsh, origin in snapshot:
            if origin == "local" and dev is not None and salt == "" and hsh == "":
                return dev
        # then host
        for _, dev, salt, hsh, origin in snapshot:
            if origin == "host" and dev is not None and salt == "" and hsh == "":
                return dev
        return None

    parsed = parse_mastertoken(api_token)
    if parsed:
        device_id, force = parsed
        with _state_lock:
            st = _devices.get(int(device_id))
            if not st or not _is_connected(st):
                return None
            if force:
                return st.dev
            return st.dev if (st.salt == "" and st.hsh == "") else None

    for _, dev, salt, hsh, _origin in snapshot:
        if dev is None:
            continue
        if salt and hsh and validate_token(salt, hsh, api_token):
            return dev

    return None


# ============================================================
# Per-device I/O locking (true concurrency support)
# ============================================================

@contextmanager
def acquire_device(api_token: str) -> Iterator[Tuple[int, object]]:
    """
    Thread-safe way to use a device:
      with acquire_device(token) as (gid, dev):
          ...

    - Selects the device using the SAME logic as get_device()
    - Then acquires that device's io_lock
    - Yields (gid, dev)

    NOTE:
      dev can be an adi device (local) OR a VirtualDevice (host).
    """
    if not api_token:
        raise RuntimeError("missing api_token")

    _sync_host_devices()

    gid: Optional[int] = None

    if api_token == master_token:
        with _state_lock:
            # prefer local first
            for k, st in _devices.items():
                if st.origin == "local" and _is_connected(st) and st.salt == "" and st.hsh == "":
                    gid = k
                    break
            if gid is None:
                for k, st in _devices.items():
                    if st.origin == "host" and _is_connected(st) and st.salt == "" and st.hsh == "":
                        gid = k
                        break
    else:
        parsed = parse_mastertoken(api_token)
        if parsed:
            cand, force = parsed
            with _state_lock:
                st = _devices.get(int(cand))
                if st and _is_connected(st):
                    if force or (st.salt == "" and st.hsh == ""):
                        gid = int(cand)
        else:
            with _state_lock:
                snapshot = [(k, st.dev, st.salt, st.hsh) for k, st in _devices.items() if _is_connected(st)]
            for k, dev, salt, hsh in snapshot:
                if salt and hsh and validate_token(salt, hsh, api_token):
                    gid = k
                    break

    if gid is None:
        raise RuntimeError("no device available / invalid token")

    with _state_lock:
        st = _devices.get(int(gid))
        if not st or not _is_connected(st) or st.dev is None:
            raise RuntimeError("device disappeared / not connected")
        lock = st.io_lock
        dev = st.dev

    lock.acquire()
    try:
        yield int(gid), dev
    finally:
        lock.release()


# ============================================================
# Optional: reload device definitions (atomic swap)
# ============================================================

def reload_devices() -> None:
    """
    Reload devices.env and reconnect local devices.
    Preserves existing salt/hash for devices that remain (same gid),
    and preserves host virtual devices + their auth state.
    """
    records = _load_device_records()

    _sync_host_devices()  # ensure host entries exist before snapshot

    with _state_lock:
        prev_auth = {gid: (st.salt, st.hsh) for gid, st in _devices.items()}
        prev_host = {gid: st for gid, st in _devices.items() if st.origin == "host"}

    tmp_local: Dict[int, _DeviceState] = {}
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
        tmp_local[int(gid)] = _DeviceState(
            dev=dev,
            origin="local",
            online=(dev is not None),
            salt=salt,
            hsh=hsh,
            name=name,
            ident=ident2,
            dtype=dtype2,
            io_lock=threading.RLock(),
        )

    with _state_lock:
        _devices.clear()

        # restore host entries (but do not overwrite locals if collision)
        for gid, st in prev_host.items():
            if gid not in tmp_local:
                _devices[gid] = st

        # add locals
        _devices.update(tmp_local)

        devices_info.clear()
        devices_info.update(tmp_info)

        device_serialization.clear()
        device_serialization.update(tmp_ser)

    # refresh host online/offline status after reload (best-effort)
    _sync_host_devices(force=True)


def set_pluto(ip: str = "192.168.2.1"):
    # kept for compatibility (no-op)
    pass