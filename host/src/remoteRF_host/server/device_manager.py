from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from ..common.idl.schema import ensure_default_driver_files, get_driver_class, load_drivers
from ..common.utils import get_devices_config_path, get_drivers_dir
from ..common.utils.host_logging import error, warn

_state_lock = threading.RLock()


@dataclass
class _DeviceState:
    schema: object | None
    name: str
    ident: str
    dtype: str
    init: Dict[str, Any]


_devices: Dict[int, _DeviceState] = {}
_loaded_signature: tuple | None = None

device_serialization: Dict[int, str] = {}
devices_info: Dict[int, str] = {}


def _devices_yaml_path() -> Path:
    return get_devices_config_path(create=True)


def _path_signature(path: Path) -> tuple:
    try:
        st = path.stat()
        return (str(path.resolve()), st.st_mtime_ns, st.st_size)
    except FileNotFoundError:
        return (str(path.resolve()), None, None)


def _drivers_signature() -> tuple:
    ensure_default_driver_files()
    drivers_dir = get_drivers_dir()
    try:
        files = sorted(
            f for f in drivers_dir.glob("*.py")
            if not f.name.startswith("_")
        )
    except Exception:
        files = []

    return tuple(_path_signature(f) for f in files)


def _reload_signature() -> tuple:
    return (
        _path_signature(_devices_yaml_path()),
        _drivers_signature(),
    )


def _infer_ident(init: Dict[str, Any]) -> str:
    for key in ("serial", "usb", "ip", "uri", "address"):
        value = str(init.get(key) or "").strip()
        if value:
            return value
    return ""


def _load_device_records() -> Dict[int, Dict[str, Any]]:
    path = _devices_yaml_path()
    if not path.exists():
        return {}

    try:
        text = path.read_text(encoding="utf-8")
        try:
            data = json.loads(text) or {}
        except json.JSONDecodeError:
            try:
                import yaml  # type: ignore
            except ImportError:
                error(
                    f"Error reading device config {path}: install PyYAML or rewrite devices.yml as JSON.",
                    component="hostrf.device_manager",
                )
                return {}
            data = yaml.safe_load(text) or {}
    except Exception as e:
        error(f"Error reading device config {path}: {e}", component="hostrf.device_manager")
        return {}

    devices = data.get("devices") or []
    if not isinstance(devices, list):
        error(f"Invalid device config {path}: 'devices' must be a list", component="hostrf.device_manager")
        return {}

    recs: Dict[int, Dict[str, Any]] = {}
    for item in devices:
        if not isinstance(item, dict):
            continue

        try:
            gid = int(item["device_id"])
        except Exception:
            warn(f"Skipping device entry with invalid/missing device_id: {item}", component="hostrf.device_manager")
            continue

        dtype = str(item.get("device_type") or "").strip().lower()
        if not dtype:
            warn(f"Skipping device gid={gid}: missing device_type", component="hostrf.device_manager")
            continue

        name = str(item.get("name") or f"device-{gid}").strip()
        init = item.get("init") or {}
        if not isinstance(init, dict):
            init = {}

        recs[gid] = {
            "TYPE": dtype,
            "NAME": name,
            "IDENT": _infer_ident(init),
            "INIT": dict(init),
        }

    return recs


def _connect_from_record(rec: Dict[str, Any]):
    dtype = (rec.get("TYPE") or "").strip().lower()
    ident = (rec.get("IDENT") or "").strip()
    init_kwargs = rec.get("INIT") or {}

    try:
        schema_cls = get_driver_class(dtype)
    except KeyError:
        warn(f"No driver registered for device_type={dtype!r} - skipping", component="hostrf.device_manager")
        return (None, ident, dtype)

    try:
        raw_dev = schema_cls.make_device(**init_kwargs)
    except Exception as e:
        warn(f"make_device() failed for {dtype}: {e}", component="hostrf.device_manager")
        return (None, ident, dtype)

    if raw_dev is None:
        return (None, ident, dtype)

    schema = schema_cls()
    schema.bind(raw_dev)
    return (schema, ident, dtype)


def _load_all_drivers(required_types: set[str]) -> None:
    if {"adalm_pluto", "pluto"} & required_types:
        try:
            from ..common.idl import pluto_schema as _  # noqa: F401
        except Exception as e:
            warn(f"Could not load built-in pluto driver: {e}", component="hostrf.device_manager")

    if {"adalm_pluto_mimo"} & required_types:
        try:
            from ..common.idl import pluto_mimo_schema as _  # noqa: F401
        except Exception as e:
            warn(f"Could not load built-in pluto mimo driver: {e}", component="hostrf.device_manager")

    results = load_drivers()
    for fname, status in results.items():
        if status != "ok":
            warn(f"Driver load {fname}: {status}", component="hostrf.device_manager")


def reload_devices(*, force: bool = False) -> bool:
    global _loaded_signature

    sig = _reload_signature()
    with _state_lock:
        if not force and _loaded_signature == sig:
            return False

    records = _load_device_records()
    required_types = {str(rec.get("TYPE") or "").strip().lower() for rec in records.values()}
    _load_all_drivers(required_types)

    tmp_devices: Dict[int, _DeviceState] = {}
    tmp_info: Dict[int, str] = {}
    tmp_ser: Dict[int, str] = {}

    for gid, rec in sorted(records.items()):
        name = (rec.get("NAME") or f"device-{gid}").strip()
        ident = (rec.get("IDENT") or "").strip()
        dtype = (rec.get("TYPE") or "").strip().lower()

        schema, ident2, dtype2 = _connect_from_record(rec)

        tmp_devices[int(gid)] = _DeviceState(
            schema=schema,
            name=name,
            ident=ident2 or ident,
            dtype=dtype2 or dtype,
            init=dict(rec.get("INIT") or {}),
        )
        tmp_info[int(gid)] = name
        if ident:
            tmp_ser[int(gid)] = ident

    with _state_lock:
        _devices.clear()
        _devices.update(tmp_devices)

        devices_info.clear()
        devices_info.update(tmp_info)

        device_serialization.clear()
        device_serialization.update(tmp_ser)
        _loaded_signature = sig

    return True


reload_devices(force=True)


def get_all_devices() -> Dict[int, object]:
    with _state_lock:
        return {
            gid: st.schema
            for gid, st in _devices.items()
            if st.schema is not None
        }


def get_all_devices_str() -> Dict[int, str]:
    with _state_lock:
        return dict(devices_info)


def get_configured_devices() -> Dict[int, Dict[str, Any]]:
    with _state_lock:
        return {
            gid: {
                "device_id": int(gid),
                "type": st.dtype,
                "kind": st.dtype,
                "name": st.name,
                "label": st.name or f"Device {gid}",
                "serial": str(st.init.get("serial") or st.ident or ""),
                "ident": st.ident,
                "init": dict(st.init),
                "connected": st.schema is not None,
            }
            for gid, st in _devices.items()
        }


def device_exists(device_id: int | str) -> bool:
    try:
        did = int(device_id)
    except Exception:
        return False

    with _state_lock:
        st = _devices.get(did)
        return bool(st and st.schema is not None)


def get_device(*, id: int | str):
    try:
        did = int(id)
    except Exception:
        return None

    with _state_lock:
        st = _devices.get(did)
        if not st:
            return None
        return st.schema


def get_device_schema(device_id: int | str):
    try:
        did = int(device_id)
    except Exception:
        return None

    with _state_lock:
        st = _devices.get(did)
        if st is None:
            return None
        if st.schema is not None:
            return st.schema
        dtype = st.dtype

    if not dtype:
        return None

    try:
        return get_driver_class(dtype)()
    except KeyError:
        return None


def find_device_id_by_name(name: str):
    name_lower = str(name or "").strip().lower()
    if not name_lower:
        return None

    with _state_lock:
        for gid, st in _devices.items():
            if str(st.name or "").strip().lower() == name_lower:
                return int(gid)
    return None
