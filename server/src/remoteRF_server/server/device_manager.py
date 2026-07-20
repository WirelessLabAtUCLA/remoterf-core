# src/remoteRF_server/server/device_manager.py

from __future__ import annotations

import os
import re
import shutil
import time
import yaml
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Tuple, Optional, Any, List, Iterator
from contextlib import contextmanager

from ..common.utils import validate_token, get_remoterf_root, get_drivers_dir
from ..common.idl.schema import get_driver_class, load_drivers
from ..host import host_tunnel_server as hts

_state_lock = threading.RLock()
_reservation_end_callbacks: list = []

@dataclass(frozen=True)
class VirtualDevice:
    gid: int
    host_id: str
    device_id: str  
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

# Host device pulling/grabbing

def _get_host_registry():
    return hts.get_tunnel_registry()

_host_sync_lock = threading.RLock()
_host_sync_last_ms = 0
_HOST_SYNC_TTL_MS = 500  # tune later

def _sync_host_devices(*, force: bool = False) -> None:
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
    out: Dict[int, str] = {}
    with _state_lock:
        for gid, st in _devices.items():
            if st.origin != "local":
                continue

            name = (st.name or f"device-{gid}").strip()

            status = "online" if _is_connected(st) else "offline"
            if st.salt or st.hsh:
                status = f"{status}, reserved"

            out[int(gid)] = f"{name} ({status})"
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

# Config paths (server-side)

def _cfg_dir() -> Path:
    return Path(os.getenv("REMOTERF_CONFIG_DIR", get_remoterf_root()))

def _super_token_path() -> Path:
    path = _cfg_dir() / "super_token.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    return path

def _get_master_token() -> str:
    """Read the configured super token; blank file means the override is disabled."""
    path = _super_token_path()
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as e:
        print(f"Warning: could not read super token file {path}: {e}")
        return ""

def _devices_yaml_path() -> Path:
    cfg_dir = _cfg_dir()
    p1 = cfg_dir / "devices.yml"
    if p1.exists():
        return p1
    p2 = cfg_dir / "devices.yaml"
    if p2.exists():
        return p2
    try:
        cfg_dir.mkdir(parents=True, exist_ok=True)
        p1.touch(exist_ok=True)
    except OSError as e:
        print(f"Warning: could not create empty devices config {p1}: {e}")
    return p1

def _load_device_records() -> Dict[int, Dict[str, str]]:
    path = _devices_yaml_path()
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"Error reading YAML config {path}: {e}")
        return {}

    devices = data.get("devices") or []
    if not isinstance(devices, list):
        print(f"Invalid YAML config {path}: 'devices' must be a list")
        return {}

    recs: Dict[int, Dict[str, str]] = {}

    for item in devices:
        if not isinstance(item, dict):
            continue

        try:
            gid = int(item["device_id"])
        except Exception:
            print(f"Skipping device entry with invalid/missing device_id: {item}")
            continue

        dtype = str(item.get("device_type") or "").strip().lower()
        if not dtype:
            print(f"Skipping device gid={gid}: missing device_type")
            continue

        name = str(item.get("name") or f"device-{gid}").strip()
        init = item.get("init") or {}
        if not isinstance(init, dict):
            init = {}

        serial = str(init.get("serial") or "").strip()

        recs[gid] = {
            "TYPE": dtype,
            "NAME": name,
            "IDENT": serial,
            "INIT": init,
        }

    return recs

def _connect_from_record(rec: Dict[str, Any]):
    """Returns (schema_instance_or_None, ident, dtype)."""
    dtype = (rec.get("TYPE") or "").strip().lower()
    ident = (rec.get("IDENT") or "").strip()
    init_kwargs = rec.get("INIT") or {}

    try:
        schema_cls = get_driver_class(dtype)
    except KeyError:
        print(f"No driver registered for device_type={dtype!r} — skipping")
        return (None, ident, dtype)

    if bool(getattr(schema_cls, "session_scoped", False)):
        try:
            schema = schema_cls()
            schema.bind_inventory(init_kwargs)
            return (schema, ident, dtype)
        except Exception as e:
            print(f"inventory binding failed for {dtype}: {e}")
            return (None, ident, dtype)

    try:
        raw_dev = schema_cls.make_device(**init_kwargs)
    except Exception as e:
        print(f"make_device() failed for {dtype}: {e}")
        return (None, ident, dtype)

    if raw_dev is None:
        return (None, ident, dtype)

    schema = schema_cls()
    schema.bind(raw_dev)
    return (schema, ident, dtype)

# Thread-safe runtime state

# legacy maps (kept for your existing server calls/UI)
devices_info: Dict[int, str] = {}
device_serialization: Dict[int, str] = {}

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


# Load built-in drivers, then any user-supplied drivers from the config dir.
# Importing the module triggers @idl_register, which adds the class to the registry.
def _packaged_driver_schema_path(filename: str) -> Path:
    drivers_root = Path(__file__).resolve().parents[1] / "drivers"
    direct = drivers_root / filename
    if direct.exists():
        return direct
    for candidate in sorted(drivers_root.glob(f"*/{filename}")):
        if candidate.exists():
            return candidate
    return drivers_root / "adalm_pluto" / filename

def _driver_registers_type(path: Path, device_type: str) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    pattern = rf"(?:idl_register|register_driver)\(\s*['\"]{re.escape(device_type)}['\"]\s*\)"
    return re.search(pattern, text) is not None

def _seed_default_driver(filename: str, *device_types: str) -> None:
    drivers_dir = get_drivers_dir()
    target = drivers_dir / filename
    if target.exists() or target.is_symlink():
        return

    try:
        drivers_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"Warning: could not create drivers directory {drivers_dir}: {e}")
        return

    for driver_file in drivers_dir.glob("*.py"):
        if driver_file.name.startswith("_"):
            continue
        if any(_driver_registers_type(driver_file, device_type) for device_type in device_types):
            return

    source = _packaged_driver_schema_path(filename)
    if not source.exists():
        print(f"Warning: default driver schema source is missing: {source}")
        return

    try:
        shutil.copy2(source, target)
        print(f"Created default driver config at {target}")
    except OSError as e:
        print(f"Warning: could not create default driver config {target}: {e}")

def _seed_default_pluto_drivers() -> None:
    _seed_default_driver("pluto_schema.py", "adalm_pluto")
    _seed_default_driver("pluto_mimo_schema.py", "adalm_pluto_mimo")

def _seed_default_usrp_driver() -> None:
    _seed_default_driver("usrp_schema.py", "usrp")

def _load_all_drivers() -> None:
    _seed_default_pluto_drivers()
    _seed_default_usrp_driver()

    try:
        from ..common.idl import pluto_schema as _  # noqa: F401
    except Exception as e:
        print(f"Warning: could not load built-in pluto driver: {e}")

    try:
        from ..common.idl import pluto_mimo_schema as _  # noqa: F401
    except Exception as e:
        print(f"Warning: could not load built-in pluto mimo driver: {e}")

    try:
        from ..drivers.usrp import usrp_schema as _  # noqa: F401
    except Exception as e:
        print(f"Warning: could not load built-in usrp driver: {e}")

    results = load_drivers()
    for fname, status in results.items():
        if status != "ok":
            print(f"Driver load {fname}: {status}")


_load_all_drivers()
_init_from_env()
_super_token_path()

# Legacy reservation helpers (master token parsing)

def parse_mastertoken(token: str, configured_token: Optional[str] = None):
    configured_token = _get_master_token() if configured_token is None else configured_token
    if not token or not configured_token:
        return None
    prefix = re.escape(configured_token)
    pattern = re.compile(rf"^{prefix}[_-](\d+)(?:_force)?$")
    m = pattern.match(token)
    if not m:
        return None
    device_id = int(m.group(1))
    force = token.endswith("_force")
    return (device_id, force)

# Transmitter stubs (legacy)

_transmitter = None

def start_transmitter():
    pass

def terminate_transmitter():
    pass

def get_transmitter_state() -> bool:
    return False

# Legacy API (state-safe)

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

    return dict(sorted(out.items(), key=lambda kv: int(kv[0])))

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

    notify_end = False
    with _state_lock:
        st = _devices.get(int(device_id))
        if not st:
            return
        was_reserved = bool(st.salt or st.hsh)
        st.salt = str(salt or "")
        st.hsh = str(hash or "")
        notify_end = was_reserved and not (st.salt or st.hsh)

    if notify_end:
        for callback in tuple(_reservation_end_callbacks):
            try:
                callback(int(device_id))
            except Exception as exc:
                print(f"Warning: reservation cleanup callback failed for {device_id}: {exc}")


def register_reservation_end_callback(callback) -> None:
    """Register an in-process local-device cleanup hook."""
    if not callable(callback):
        raise TypeError("reservation callback must be callable")
    with _state_lock:
        if callback not in _reservation_end_callbacks:
            _reservation_end_callbacks.append(callback)


def get_local_device_context(device_id: int) -> dict[str, Any] | None:
    """Return a read-only local inventory/session view for Dynamic v2."""
    with _state_lock:
        st = _devices.get(int(device_id))
        if st is None or st.origin != "local" or st.dev is None:
            return None
        return {
            "gid": int(device_id),
            "schema": st.dev,
            "dtype": st.dtype,
            "ident": st.ident,
            "name": st.name,
            "reserved": bool(st.salt or st.hsh),
        }


def token_matches_device(api_token: str, device_id: int) -> bool:
    return resolve_gid_for_token(api_token) == int(device_id)

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

def get_device_schema(device_id: int):
    """
    Return a DeviceSchema instance for this device, or None if unavailable.

    For local devices: returns the live bound schema instance.
    For host devices: instantiates an unbound schema from the driver registry
    using the device's dtype — sufficient for IDL/hash purposes since the
    schema structure is defined by the class, not the live device.
    """
    with _state_lock:
        st = _devices.get(int(device_id))
        if st is None:
            return None

        if st.origin == "local" and st.dev is not None:
            return st.dev

        if st.origin == "host" and st.dtype:
            try:
                return get_driver_class(st.dtype)()
            except KeyError:
                return None

    return None

def get_schema_by_token(api_token: str):
    """
    Resolve an API token to its DeviceSchema without acquiring the I/O lock.

    Returns the DeviceSchema for the device this token grants access to,
    or None if the token is invalid, the device is a host device, or the
    device has no schema loaded.
    """
    if not api_token:
        return None

    _sync_host_devices()
    gid: Optional[int] = None
    configured_token = _get_master_token()

    if configured_token and api_token == configured_token:
        with _state_lock:
            for k, st in _devices.items():
                if st.origin == "local" and _is_connected(st) and st.salt == "" and st.hsh == "":
                    gid = k
                    break
    else:
        parsed = parse_mastertoken(api_token, configured_token=configured_token)
        if parsed:
            cand, _ = parsed
            with _state_lock:
                st = _devices.get(int(cand))
                if st and _is_connected(st):
                    gid = int(cand)
        else:
            with _state_lock:
                snapshot = [
                    (k, st.salt, st.hsh)
                    for k, st in _devices.items()
                    if _is_connected(st)
                ]
            for k, salt, hsh in snapshot:
                if salt and hsh and validate_token(salt, hsh, api_token):
                    gid = k
                    break

    if gid is None:
        return None
    return get_device_schema(gid)

def resolve_gid_for_token(api_token: str) -> Optional[int]:
    """
    Resolve an API token to its device gid regardless of device origin
    (local or host/VirtualDevice).

    Unlike get_schema_by_token — which returns None for host devices because
    they have no salt/hash — this function also covers:
      • parsed master-tokens  ('{gid}:secret')  → any device by gid
      • raw master_token                         → first connected device
      • regular per-device tokens (salt/hsh)     → local devices

    Used by IDL queries that need a schema even for host devices.
    Does NOT acquire any device I/O lock.
    """
    if not api_token:
        return None

    _sync_host_devices()
    configured_token = _get_master_token()

    # Parsed master-token: resolves any device directly by gid (local or host).
    parsed = parse_mastertoken(api_token, configured_token=configured_token)
    if parsed:
        cand, _ = parsed
        with _state_lock:
            st = _devices.get(int(cand))
            if st and _is_connected(st):
                return int(cand)
        return None

    # Raw master token — prefer local, fall back to any connected device.
    if configured_token and api_token == configured_token:
        with _state_lock:
            # local first
            for k, st in _devices.items():
                if st.origin == "local" and _is_connected(st) and st.salt == "" and st.hsh == "":
                    return k
            # then host
            for k, st in _devices.items():
                if _is_connected(st) and st.salt == "" and st.hsh == "":
                    return k
        return None

    # Regular per-device token (salt/hsh).  Host devices have empty salt/hsh
    # so they won't match here — but this covers local devices correctly.
    with _state_lock:
        snapshot = [
            (k, st.salt, st.hsh)
            for k, st in _devices.items()
            if _is_connected(st)
        ]
    for k, salt, hsh in snapshot:
        if salt and hsh and validate_token(salt, hsh, api_token):
            return k

    return None


def find_device_id_by_name(name: str) -> Optional[int]:
    """Return the gid of the first device whose name matches (case-insensitive), or None."""
    name_lower = name.strip().lower()
    with _state_lock:
        for gid, st in _devices.items():
            if st.name.strip().lower() == name_lower:
                return gid
    return None

def get_device(*, api_token: str):
    if not api_token:
        return None

    _sync_host_devices()
    configured_token = _get_master_token()

    with _state_lock:
        snapshot: List[Tuple[int, object, str, str, str]] = [
            (gid, st.dev, st.salt, st.hsh, st.origin)
            for gid, st in _devices.items()
            if _is_connected(st)
        ]

    # Preserve "master prefers local" behavior
    if configured_token and api_token == configured_token:
        # local first
        for _, dev, salt, hsh, origin in snapshot:
            if origin == "local" and dev is not None and salt == "" and hsh == "":
                return dev
        # then host
        for _, dev, salt, hsh, origin in snapshot:
            if origin == "host" and dev is not None and salt == "" and hsh == "":
                return dev
        return None

    parsed = parse_mastertoken(api_token, configured_token=configured_token)
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

# Per-device I/O locking (true concurrency support)

@contextmanager
def acquire_device(api_token: str) -> Iterator[Tuple[int, object]]:
    if not api_token:
        raise RuntimeError("missing api_token")

    _sync_host_devices()

    gid: Optional[int] = None
    configured_token = _get_master_token()

    if configured_token and api_token == configured_token:
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
        parsed = parse_mastertoken(api_token, configured_token=configured_token)
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

# Optional: reload device definitions (atomic swap)

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
