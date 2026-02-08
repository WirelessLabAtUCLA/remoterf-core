# device_manager.py

import adi
# import uhd
# from hackrf import *
from ..common.utils import *
import subprocess

import time
import gc

#* Device manager *
'''
Responsible for starting and managing queues for devices.
'''

# TODO: Implement multiple device support
#region PlutoSDR

def connect_pluto(*, ip='', usb=''):
    try:
        if ip == '':
            device = adi.Pluto(f'usb:{usb}')
            print(f"Connected to Pluto usb:{usb}")
        else:
            device = adi.Pluto(f'ip:{ip}')
            print(f"Connected to Pluto ip:{ip}")
        return device
    except Exception as e:
        print(f"Pluto {ip}: {e}")
        return None

import subprocess
import re
from pathlib import Path

def get_usb_port_from_serial(serial):
    try:
        # Run iio_info -s and get the output
        output = subprocess.check_output(["iio_info", "-s"]).decode("utf-8")
    except Exception as e:
        print(f"Error running iio_info: {e}")
        return None

    # Regex to find the USB port associated with the given serial number
    pattern = re.compile(rf"\d+:.*serial={re.escape(str(serial))}\s+\[usb:(\S+)\]")

    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            return match.group(1)  # Return the USB port

    print(f"No device found with serial {serial}")
    return None

# def connect_hackrf(device_index):
#     try:
#         device = HackRF(device_index=device_index)
#         print(f"Connected to HackRF {device_index}")
#         return device
#     except Exception as e:
#         print(f"HackRF {device_index}: {e}")
#         return None
#
# def connect_usrp2901():
#     usrp = uhd.usrp.MultiUSRP()
#     print(f"Connected to USRP 2901")
#     return usrp


# -----------------------------
# NEW: load devices from env
#   <repo>/config/remoteRF_host/devices.env
#
# Expected keys per device (future-friendly):
#   DEVICE_<gid>_TYPE=pluto
#   DEVICE_<gid>_NAME=pluto_aaa
#   DEVICE_<gid>_IDENT_KIND=iio_serial
#   DEVICE_<gid>_IDENT=<serial>
#
# (Optional backwards compat):
#   DEVICE_<gid>_ID=<serial>   # treated as IDENT_KIND=iio_serial, NAME="device-<gid>"
# -----------------------------

_ENV_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
_DEVICE_KEY_RE = re.compile(r"^DEVICE_(\d+)_(.+)$", re.IGNORECASE)

def _strip_quotes(v: str) -> str:
    v = (v or "").strip()
    if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
        return v[1:-1]
    return v

def _read_env_file(path: Path) -> dict:
    out = {}
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

def _repo_root() -> Path:
    # For: <repo>/src/remoteRF_host/device_manager.py
    # parents[0]=remoteRF_host, [1]=src, [2]=<repo>
    return Path(__file__).resolve().parents[2]

def _devices_env_path() -> Path:
    return _repo_root() / "config" / "remoteRF_host" / "devices.env"

def _load_device_records() -> dict[int, dict[str, str]]:
    """
    Returns:
      { gid: { "TYPE":..., "NAME":..., "IDENT_KIND":..., "IDENT":... , ... } }
    """
    kv = _read_env_file(_devices_env_path())
    recs: dict[int, dict[str, str]] = {}

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

def _connect_from_record(rec: dict[str, str]):
    """
    Returns (device_obj, ident, dtype).
    Keeps tuple structure so existing helper functions keep working.
    """
    dtype = (rec.get("TYPE") or "").strip().lower()
    ident_kind = (rec.get("IDENT_KIND") or "").strip().lower()
    ident = (rec.get("IDENT") or "").strip()

    if dtype == "pluto":
        if ident_kind in ("iio_serial", "serial", "iio"):
            if not ident:
                return (None, ident, dtype)
            usb_port = get_usb_port_from_serial(ident)
            if not usb_port:
                return (None, ident, dtype)
            dev = connect_pluto(usb=usb_port)
            return (dev, ident, dtype)

        if ident_kind == "usb":
            if not ident:
                return (None, ident, dtype)
            dev = connect_pluto(usb=ident)
            return (dev, ident, dtype)

        if ident_kind == "ip":
            if not ident:
                return (None, ident, dtype)
            dev = connect_pluto(ip=ident)
            return (dev, ident, dtype)

        # Unknown ident_kind for pluto
        return (None, ident, dtype)

    # Unknown/unsupported device type (future extension point)
    return (None, ident, dtype)


# -----------------------------
# Build runtime maps from env
# -----------------------------

_records = _load_device_records()

# global_id -> serial (or IDENT) for convenience / debug
device_serialization = {}

# global_id -> name/info string
devices_info = {}

for gid, rec in sorted(_records.items()):
    name = (rec.get("NAME") or f"device-{gid}").strip()
    ident = (rec.get("IDENT") or "").strip()
    devices_info[int(gid)] = name
    if ident:
        device_serialization[int(gid)] = ident


master_token = '***REMOVED***'

# print("New Version")

devices = {  # global_id -> (device_obj, ident, dtype)
    gid: _connect_from_record(rec)
    for gid, rec in sorted(_records.items())
}

# transmitter = subprocess.Popen(['python3', 'transmitter.py'])
# transmitter.terminate()

def get_all_devices() -> dict:
    # Only return entries with a connected device object
    return {k: v for k, v in devices.items() if v is not None and isinstance(v, tuple) and len(v) >= 1 and v[0] is not None}

def get_all_devices_str() -> dict:
    # "name is the info"
    return devices_info

def device_exists(device_id: int) -> bool:
    if device_id not in devices:
        return False
    dev, _, _ = devices[device_id]
    return dev is not None

def get_device(*, id):
    if id not in devices:
        return None
    return devices[id][0]
