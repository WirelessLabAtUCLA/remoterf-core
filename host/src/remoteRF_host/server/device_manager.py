from __future__ import annotations

import adi
import os
import re
import yaml
import subprocess
import threading
from pathlib import Path
from typing import Dict, Tuple, Optional, Any

# Use the same helper the other device manager uses.
# Adjust this import path only if your host package layout differs.
from ..common.utils import get_remoterf_root


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

    for line in out.splitlines():
        if (f"serial={serial}" in line) or (f"hw_serial={serial}" in line):
            m = re.search(r"\[usb:([^\]]+)\]", line)
            if m:
                return m.group(1).strip()

    print(f"No device found with serial {serial}")
    return None


# -----------------------------
# same YAML config loading as server device_manager
# -----------------------------

def _cfg_dir() -> Path:
    p = Path(os.getenv("REMOTERF_CONFIG_DIR", get_remoterf_root()))
    p.mkdir(parents=True, exist_ok=True)
    return p

def _devices_yaml_path() -> Path:
    p1 = _cfg_dir() / "devices.yml"
    if p1.exists():
        return p1
    return _cfg_dir() / "devices.yaml"


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

        dtype = str(item.get("device_type") or "pluto").strip().lower()
        if dtype != "pluto":
            print(f"Skipping unsupported device_type={dtype!r} for gid={gid}")
            continue

        name = str(item.get("name") or f"device-{gid}").strip()
        init = item.get("init") or {}
        if not isinstance(init, dict):
            init = {}

        serial = str(init.get("serial") or "").strip()
        if not serial:
            print(f"Skipping Pluto gid={gid}: missing init.serial")
            continue

        recs[gid] = {
            "TYPE": "pluto",
            "NAME": name,
            "IDENT_KIND": "iio_serial",
            "IDENT": serial,
        }

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

device_serialization: Dict[int, str] = {}
devices_info: Dict[int, str] = {}
devices: Dict[int, Tuple[object | None, str, str]] = {}

master_token = os.getenv("REMOTERF_MASTER_TOKEN", "***REMOVED***")

def reload_devices() -> None:
    """
    Reload devices.yaml/devices.yml and reconnect devices.
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
    try:
        did = int(id)
    except Exception:
        return None
    with _state_lock:
        tup = devices.get(did)
        if not tup:
            return None
        return tup[0]