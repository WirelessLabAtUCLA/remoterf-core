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

from __future__ import annotations

import json
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from ..common.idl import ensure_default_driver_files, get_driver_class, load_drivers
from ..common.idl.host_drivers import _packaged_schema_path, _seed_default_driver
from ..common.utils import get_devices_config_path, get_drivers_dir
from ..common.utils.host_logging import error, warn

_state_lock = threading.RLock()
_reservation_end_callbacks: list = []
_reservation_hooks: Dict[int, ThreadPoolExecutor] = {}
_HOST_BRIDGE_TOKEN_PREFIX = "__remoterf_host_v2_gid__:"


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
    for key in (
        "serial",
        "addr",
        "address",
        "device_index",
        "args",
        "usb",
        "ip",
        "uri",
    ):
        if key not in init or init.get(key) is None:
            continue
        value = str(init.get(key)).strip()
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

    if bool(getattr(schema_cls, "session_scoped", False)):
        try:
            schema = schema_cls()
            schema.bind_inventory(init_kwargs)
            return (schema, ident, dtype)
        except Exception as e:
            warn(f"inventory binding failed for {dtype}: {e}", component="hostrf.device_manager")
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


def _seed_default_usrp_driver() -> None:
    _seed_default_driver(
        "usrp_schema.py",
        "usrp",
        _packaged_schema_path("usrp", "usrp_schema.py"),
    )


def _seed_default_rtl_sdr_driver() -> None:
    _seed_default_driver(
        "rtl_sdr_schema.py",
        "rtl_sdr",
        _packaged_schema_path("rtl_sdr", "rtl_sdr_schema.py"),
    )


def _seed_default_hackrf_driver() -> None:
    _seed_default_driver(
        "hackrf_schema.py",
        "hackrf",
        _packaged_schema_path("hackrf", "hackrf_schema.py"),
        legacy_hashes=(
            "65c4ef33f530fd43ed88aa445f7088e92a6c0eb662007a2a05bc7d2395fde64c",
        ),
    )


def _seed_default_ti_mmwave_driver() -> None:
    _seed_default_driver(
        "ti_mmwave_schema.py",
        "ti_mmwave",
        _packaged_schema_path("ti_mmwave", "ti_mmwave_schema.py"),
    )


def _seed_default_usrp_phaser_driver() -> None:
    _seed_default_driver(
        "usrp_phaser_schema.py",
        "usrp_phaser",
        _packaged_schema_path("usrp_phaser", "usrp_phaser_schema.py"),
    )


def _load_all_drivers(required_types: set[str]) -> None:
    if "usrp" in required_types:
        _seed_default_usrp_driver()
    if "usrp_phaser" in required_types:
        _seed_default_usrp_phaser_driver()
    if "rtl_sdr" in required_types:
        _seed_default_rtl_sdr_driver()
    if "hackrf" in required_types:
        _seed_default_hackrf_driver()
    if "ti_mmwave" in required_types:
        _seed_default_ti_mmwave_driver()

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

    if "usrp" in required_types:
        try:
            from ..drivers.usrp import usrp_schema as _  # noqa: F401
        except Exception as e:
            warn(f"Could not load built-in USRP driver: {e}", component="hostrf.device_manager")

    if "rtl_sdr" in required_types:
        try:
            from ..drivers.rtl_sdr import rtl_sdr_schema as _  # noqa: F401
        except Exception as e:
            warn(f"Could not load built-in RTL-SDR driver: {e}", component="hostrf.device_manager")

    if "hackrf" in required_types:
        try:
            from ..drivers.hackrf import hackrf_schema as _  # noqa: F401
        except Exception as e:
            warn(f"Could not load built-in HackRF driver: {e}", component="hostrf.device_manager")

    if "ti_mmwave" in required_types:
        try:
            from ..drivers.ti_mmwave import ti_mmwave_schema as _  # noqa: F401
        except Exception as e:
            warn(f"Could not load built-in TI mmWave driver: {e}", component="hostrf.device_manager")

    if "usrp_phaser" in required_types:
        try:
            from ..drivers.usrp_phaser import usrp_phaser_schema as _  # noqa: F401
        except Exception as e:
            warn(f"Could not load built-in USRP Phaser driver: {e}", component="hostrf.device_manager")

    results = load_drivers()
    for fname, status in results.items():
        if status != "ok":
            warn(f"Driver load {fname}: {status}", component="hostrf.device_manager")


_reload_lock = threading.Lock()


def reload_devices(*, force: bool = False) -> bool:
    # MetaRequests each run on their own thread; two reloads at once would
    # each make every device and leave one set open.
    with _reload_lock:
        return _reload_devices_locked(force=force)


def _reload_devices_locked(*, force: bool) -> bool:
    global _loaded_signature

    sig = _reload_signature()
    with _state_lock:
        if not force and _loaded_signature == sig:
            return False

    records = _load_device_records()
    required_types = {str(rec.get("TYPE") or "").strip().lower() for rec in records.values()}
    _load_all_drivers(required_types)
    # Seeding a newly required packaged driver changes the driver-directory
    # signature. Cache the post-seed state so the tunnel agent does not
    # immediately reload and attempt to open the same USB radio twice.
    sig = _reload_signature()

    # Let go of serial ports and USB handles before make_device opens them again.
    with _state_lock:
        old_schemas = [st.schema for st in _devices.values() if st.schema is not None]
    for schema in old_schemas:
        native = getattr(schema, "device", None)
        if native is None:
            continue
        try:
            close_native = getattr(schema, "close_native_device", None)
            if callable(close_native):
                close_native()
            else:
                close = getattr(native, "close", None)
                if callable(close):
                    close()
                schema.bind(None)
        except Exception as e:
            warn(f"could not close a device before reloading: {e}", component="hostrf.device_manager")

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


def get_local_device_context(device_id: int) -> dict[str, Any] | None:
    """Return the local inventory context consumed by Dynamic v2 sessions."""
    try:
        did = int(device_id)
    except Exception:
        return None

    with _state_lock:
        st = _devices.get(did)
        if st is None or st.schema is None:
            return None
        return {
            "gid": did,
            "schema": st.schema,
            "dtype": st.dtype,
            "ident": st.ident,
            "name": st.name,
            "reserved": True,
        }


def register_reservation_end_callback(callback) -> None:
    """Register cleanup invoked when the server closes a tunneled reservation."""
    if not callable(callback):
        raise TypeError("reservation callback must be callable")
    with _state_lock:
        if callback not in _reservation_end_callbacks:
            _reservation_end_callbacks.append(callback)


def _run_hook(gid: int, name: str, failed: str) -> Optional[Future]:
    """Queue a device's reservation hook on its own worker: hooks for one device
    run in arrival order, and a boot that takes seconds never holds up the tunnel."""
    with _state_lock:
        st = _devices.get(gid)
        hook = getattr(st.schema if st else None, name, None)
        if not callable(hook):
            return None
        worker = _reservation_hooks.get(gid)
        if worker is None:
            worker = _reservation_hooks[gid] = ThreadPoolExecutor(1, thread_name_prefix=f"hostrf-gid{gid}")

    def run() -> None:
        try:
            hook()
        except Exception as e:
            warn(f"{failed} gid={gid} failed: {e}", component="hostrf.device_manager")

    return worker.submit(run)


def prepare_reservation(device_id: int | str) -> Optional[Future]:
    """The lab started a reservation on this device: ready it (a switched Pluto boots) for the holder."""
    return _run_hook(int(device_id), "prepare_for_holder", "preparing")


def end_reservation(device_id: int | str) -> Optional[Future]:
    """The lab ended this device's reservation: close its sessions, then reset it for the next holder."""
    gid = int(device_id)
    with _state_lock:
        callbacks = tuple(_reservation_end_callbacks)
    for callback in callbacks:
        try:
            callback(gid)
        except Exception as e:
            warn(f"reservation cleanup failed for gid={gid}: {e}", component="hostrf.device_manager")
    return _run_hook(gid, "reset_for_next_holder", "resetting")


def make_host_bridge_token(device_id: int | str) -> str:
    """Create a tunnel-internal token; it is accepted only inside the host agent."""
    return f"{_HOST_BRIDGE_TOKEN_PREFIX}{int(device_id)}"


def resolve_gid_for_token(token: str):
    value = str(token or "")
    if not value.startswith(_HOST_BRIDGE_TOKEN_PREFIX):
        return None
    try:
        gid = int(value[len(_HOST_BRIDGE_TOKEN_PREFIX):])
    except (TypeError, ValueError):
        return None
    return gid if device_exists(gid) else None


def token_matches_device(token: str, device_id: int) -> bool:
    return resolve_gid_for_token(token) == int(device_id)
