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

"""
RemoteRF Custom Device Schema for USB Wi-Fi Dongle (Realtek RTL8811CU / RTL8821CU).

Follows the RemoteRF Custom Device Specification:
https://remoterf.net/docs/server/device-setup/custom/

This schema bridges physical USB Wi-Fi dongles to RemoteRF clients for RF signal monitoring,
spectrum sensing, and RSSI tracking. It guarantees that wired Ethernet connections and default
routes remain completely unaffected.

Exposes:
  - Readable device properties: interface name, driver info, USB IDs, health, default route safety
  - Runtime setters: auto-rescan mode, scan history buffer size
  - Actions/Calls:
      * scan(): List all nearby Wi-Fi APs with RSSI (dBm), quality, channel, band, and security
      * get_rssi(): Quick scalar query for a target SSID or BSSID (returns float dBm)
      * get_rssi_burst(): High-rate batch sampling with linear-power averaging (mW & dBm)
      * get_ap(): Full dictionary metadata for a target access point
      * get_ap_details(): Deep PHY & vendor telemetry (WPS manufacturer, model, TSF, capabilities)
      * scan_summary(): Environment RF overview (AP counts, band distribution, strongest signals)
      * get_channel_distribution(): AP counts and signal metrics grouped by Wi-Fi channel
      * get_history(): Buffered RSSI tracking samples over time
"""

from __future__ import annotations

import hashlib
import inspect
import json
import math
import os
import re
import sys
import time
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

# Ensure parent directory is in sys.path so rssi package can be imported
_CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
_PARENT_DIR = os.path.dirname(_CURRENT_DIR)
if _PARENT_DIR not in sys.path:
    sys.path.insert(0, _PARENT_DIR)

from rssi.scanner import RSSIScanner, AccessPoint, freq_to_channel, dbm_to_quality_percent
from rssi.dongle import find_usb_wifi_dongles, get_default_usb_dongle, USBWiFiDevice
from rssi.safety import verify_network_safety, get_default_route_info

# -----------------------------------------------------------------------------
# RemoteRF IDL Framework Import with Standalone Fallback
# -----------------------------------------------------------------------------
try:
    from remoteRF_server.common.idl import DeviceSchema, idl_expose, idl_register
    _SERVER_IDL_LOADED = True
except ImportError:
    _SERVER_IDL_LOADED = False

    _REGISTERED_SCHEMAS: Dict[str, type] = {}

    def idl_register(device_type: str):
        """Class decorator registering device type in RemoteRF driver registry."""
        def decorator(cls):
            cls.device_type = device_type
            _REGISTERED_SCHEMAS[device_type] = cls
            return cls
        return decorator

    def idl_expose(func=None, *, kind: str = "call", doc: Optional[str] = None):
        """Method decorator exposing getter, setter, or call in RemoteRF IDL."""
        def decorator(fn):
            fn._idl_exposed = True
            fn._idl_kind = kind
            fn._idl_doc = doc or (inspect.getdoc(fn) or "")
            return fn

        if func is not None:
            return decorator(func)
        return decorator

    class DeviceSchema:
        """Base class providing RemoteRF introspection and RPC dispatch."""
        device_type: str = "custom"
        driver_version: str = "0.1.0"
        client_class: str = "CustomDevice"
        client_modules: Dict[str, str] = {}

        def __init__(self):
            self.device: Any = None

        def bind(self, device: Any) -> None:
            self.device = device

        def list_exposed(self) -> Dict[str, Dict[str, Any]]:
            """Returns exposed getters, setters, and calls with metadata."""
            getters: Dict[str, Any] = {}
            setters: Dict[str, Any] = {}
            calls: Dict[str, Any] = {}

            for name, member in inspect.getmembers(self.__class__):
                if not getattr(member, "_idl_exposed", False):
                    continue
                kind = getattr(member, "_idl_kind", "call")
                doc = getattr(member, "_idl_doc", "")
                sig = inspect.signature(member)
                params: List[Dict[str, Any]] = []

                for p_name, param in sig.parameters.items():
                    if p_name == "self":
                        continue
                    p_info: Dict[str, Any] = {
                        "name": p_name,
                        "required": param.default is inspect.Parameter.empty,
                        "kind": param.kind.name.lower(),
                    }
                    if param.default is not inspect.Parameter.empty:
                        p_info["default"] = param.default
                    if param.annotation is not inspect.Parameter.empty:
                        p_info["type"] = getattr(param.annotation, "__name__", str(param.annotation))
                    params.append(p_info)

                entry = {"doc": doc, "args": params}
                if kind == "get":
                    getters[name] = {"doc": doc}
                elif kind == "set":
                    setters[name] = entry
                elif kind == "call":
                    calls[name] = entry

            return {"getters": getters, "setters": setters, "calls": calls}

        def get_idl_json(self, pretty: bool = False) -> str:
            """Generates JSON Interface Description Language document."""
            exposed = self.list_exposed()
            meta = {
                "schema_version": "1.0",
                "device_type": getattr(self, "device_type", "custom"),
                "driver_version": getattr(self, "driver_version", "0.1.0"),
                "client_class": getattr(self, "client_class", "CustomDevice"),
                "client_modules": getattr(self, "client_modules", {}),
                "getters": exposed["getters"],
                "setters": exposed["setters"],
                "calls": exposed["calls"],
            }
            digest = hashlib.sha256(json.dumps(meta, sort_keys=True).encode("utf-8")).hexdigest()
            meta["schema_hash"] = f"sha256:{digest}"
            return json.dumps(meta, indent=2 if pretty else None)

        def dispatch(self, method_name: str, kwargs: Optional[Dict[str, Any]] = None) -> Any:
            """Dispatches incoming RPC call to local schema method."""
            kwargs = kwargs or {}
            method = getattr(self, method_name, None)
            if not method or not getattr(method, "_idl_exposed", False):
                raise AttributeError(f"Method '{method_name}' is not exposed in schema.")
            return method(**kwargs)


# -----------------------------------------------------------------------------
# Linear Power Math Utilities
# -----------------------------------------------------------------------------

def dbm_to_mw(dbm: float) -> float:
    """Convert power from logarithmic dBm to linear milliwatts (mW)."""
    return 10.0 ** (dbm / 10.0)


def mw_to_dbm(mw: float) -> float:
    """Convert power from linear milliwatts (mW) to logarithmic dBm."""
    if mw <= 0.0:
        return -120.0
    return 10.0 * math.log10(mw)


def compute_linear_stats(dbm_values: List[float]) -> Dict[str, float]:
    """
    Compute rigorous physical statistics in the linear power domain (mW),
    and convert the resulting mean back to dBm.

    Note: An arithmetic average of decibels [e.g. (-60 + -80)/2 = -70 dBm] is physically
    inaccurate because decibels are logarithmic (it gives the geometric mean of power).
    True average received power requires averaging in linear milliwatts:
      P_avg_mW = (1/N) * sum(10^(dBm_i / 10))
      mean_dbm = 10 * log10(P_avg_mW)
    """
    if not dbm_values:
        return {
            "count": 0,
            "mean_dbm": float("nan"),
            "mean_mw": 0.0,
            "min_dbm": float("nan"),
            "max_dbm": float("nan"),
            "std_dbm": 0.0,
            "median_dbm": float("nan"),
        }

    # Convert to linear power (mW)
    mw_array = np.array([dbm_to_mw(v) for v in dbm_values], dtype=np.float64)
    mean_mw = float(np.mean(mw_array))
    mean_dbm = mw_to_dbm(mean_mw)

    dbm_array = np.array(dbm_values, dtype=np.float64)
    return {
        "count": len(dbm_values),
        "mean_dbm": round(mean_dbm, 2),
        "mean_mw": float(mean_mw),
        "min_dbm": round(float(np.min(dbm_array)), 1),
        "max_dbm": round(float(np.max(dbm_array)), 1),
        "std_dbm": round(float(np.std(dbm_array)), 2),
        "median_dbm": round(float(np.median(dbm_array)), 1),
    }


# -----------------------------------------------------------------------------
# Device Controller Implementation
# -----------------------------------------------------------------------------

class WifiDongleDevice:
    """
    Hardware controller managing the USB Wi-Fi dongle for RemoteRF.

    Wraps low-level scanning, dBm kernel dumps, network safety assertions,
    burst sampling, and detailed 802.11 information element parsing.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        auto_rescan: bool = True,
        max_history: int = 100,
    ) -> None:
        self.scanner = RSSIScanner(interface=interface)
        self.interface = self.scanner.interface
        self.auto_rescan = auto_rescan
        self.max_history = max_history

        self._scan_count = 0
        self._last_scan_time = 0.0
        self._last_results: List[AccessPoint] = []
        self._history: deque = deque(maxlen=max_history)

    @property
    def is_available(self) -> bool:
        return os.path.exists(f"/sys/class/net/{self.interface}")

    @property
    def scan_count(self) -> int:
        return self._scan_count

    @property
    def last_scan_time(self) -> float:
        return self._last_scan_time

    @property
    def default_route_safe(self) -> bool:
        """Verify that default gateway is active and is NOT this Wi-Fi interface."""
        route = get_default_route_info()
        default_iface = route.get("interface")
        return bool(default_iface and default_iface != self.interface)

    def get_device_info(self) -> Dict[str, Any]:
        """Hardware identity, driver, and sysfs information."""
        info = {
            "interface": self.interface,
            "vendor_id": "unknown",
            "product_id": "unknown",
            "product_name": "USB Wi-Fi Dongle",
            "driver": "unknown",
            "sysfs_path": "",
        }
        if self.scanner.device_info:
            d = self.scanner.device_info
            info.update({
                "vendor_id": d.vendor_id,
                "product_id": d.product_id,
                "product_name": f"{d.manufacturer} {d.product_name}".strip(),
                "driver": d.driver,
                "sysfs_path": d.sysfs_path,
            })
        return info

    def scan(
        self,
        rescan: bool = True,
        band: str = "",
        min_rssi: float = -120.0
    ) -> List[Dict[str, Any]]:
        """
        Perform a Wi-Fi scan and return all detected Access Points.
        """
        do_rescan = rescan if rescan is not None else self.auto_rescan
        aps = self.scanner.scan(rescan=do_rescan)
        self._last_results = aps
        self._scan_count += 1
        self._last_scan_time = time.time()

        # Append to history
        for ap in aps:
            self._history.append({
                "timestamp": ap.timestamp,
                "bssid": ap.bssid,
                "ssid": ap.ssid,
                "signal_dbm": ap.signal_dbm,
                "channel": ap.channel,
                "freq_mhz": ap.freq_mhz,
            })

        # Apply filtering
        filtered = aps
        if band:
            filtered = [ap for ap in filtered if band in ap.band]
        if min_rssi > -120.0:
            filtered = [ap for ap in filtered if ap.signal_dbm >= min_rssi]

        return [ap.to_dict() for ap in filtered]

    def get_rssi(self, target: str, rescan: bool = True) -> Optional[float]:
        """
        Get the latest signal strength (in dBm) for a target SSID or BSSID.
        Returns float dBm value, or None if target is not found.
        """
        if not target:
            return None

        # If rescan is requested or no previous results, run scan
        if rescan or not self._last_results:
            self.scan(rescan=True)

        target_clean = target.strip().lower()
        for ap in self._last_results:
            if ap.bssid.lower() == target_clean or ap.ssid.lower() == target_clean:
                return float(ap.signal_dbm)

        return None

    def get_ap(self, target: str, rescan: bool = True) -> Optional[Dict[str, Any]]:
        """Get full AccessPoint dictionary for a target SSID or BSSID."""
        if not target:
            return None

        if rescan or not self._last_results:
            self.scan(rescan=True)

        target_clean = target.strip().lower()
        for ap in self._last_results:
            if ap.bssid.lower() == target_clean or ap.ssid.lower() == target_clean:
                return ap.to_dict()

        return None

    def get_rssi_burst(
        self,
        target: str,
        count: int = 10,
        max_time: float = 5.0,
        rescan: bool = True
    ) -> Dict[str, Any]:
        """
        Collect a burst of multiple RSSI measurements for a target network,
        computing rigorous physical statistics in the linear power domain (mW & dBm).
        """
        target_clean = target.strip().lower()
        rssi_list: List[float] = []
        timestamps: List[float] = []
        matched_bssid: Optional[str] = None
        matched_ssid: Optional[str] = None
        channel: Optional[int] = None
        band: Optional[str] = None

        t0 = time.time()
        iterations = 0
        max_samples = max(1, min(count, 100))

        while len(rssi_list) < max_samples and (time.time() - t0) < max_time:
            iterations += 1
            # Execute scan
            aps = self.scanner.scan(rescan=rescan)
            self._scan_count += 1
            self._last_scan_time = time.time()

            found_in_scan = False
            for ap in aps:
                if ap.bssid.lower() == target_clean or ap.ssid.lower() == target_clean:
                    rssi_list.append(ap.signal_dbm)
                    timestamps.append(ap.timestamp)
                    matched_bssid = ap.bssid
                    matched_ssid = ap.ssid
                    channel = ap.channel
                    band = ap.band
                    found_in_scan = True
                    break

            # Small dwell before next scan
            time.sleep(0.1)

        stats = compute_linear_stats(rssi_list)
        return {
            "target": target,
            "matched_ssid": matched_ssid or target,
            "matched_bssid": matched_bssid or "",
            "channel": channel,
            "band": band or "Unknown",
            "samples_collected": len(rssi_list),
            "requested_count": max_samples,
            "elapsed_seconds": round(time.time() - t0, 3),
            "rssi_values_dbm": rssi_list,
            "timestamps": timestamps,
            "linear_stats": stats,
        }

    def get_ap_details(self, target: str) -> Dict[str, Any]:
        """
        Extract deep hardware and protocol information from raw kernel scan dump
        for a target network (WPS manufacturer, model, TSF microsecond clock,
        beamforming, channel widths, and supported modulation rates).
        """
        import subprocess

        target_clean = target.strip().lower()
        try:
            out = subprocess.check_output(
                ["iw", "dev", self.interface, "scan", "dump"],
                text=True,
                errors="replace"
            )
        except Exception as e:
            return {"error": str(e), "target": target}

        for block in out.split("BSS "):
            if not block.strip():
                continue
            first_line = block.splitlines()[0]
            m = re.match(r"([0-9a-fA-F:]{17})", first_line)
            if not m:
                continue
            bssid = m.group(1).lower()

            ssid_m = re.search(r"^[ \t]*SSID:[ \t]*(.*)$", block, re.MULTILINE)
            ssid = ssid_m.group(1).strip() if ssid_m else ""

            if bssid == target_clean or (ssid and ssid.lower() == target_clean):
                # Found target! Parse deep telemetry
                tsf_m = re.search(r"\bTSF:\s*(\d+)", block)
                freq_m = re.search(r"\bfreq:\s*(\d+)", block)
                sig_m = re.search(r"\bsignal:\s*([-\d\.]+)\s*dBm", block)
                beacon_int_m = re.search(r"\bbeacon interval:\s*(\d+)", block)

                # WPS info
                wps_manuf_m = re.search(r"\bManufacturer:\s*(.*)$", block, re.MULTILINE)
                wps_model_m = re.search(r"\bModel:\s*(.*)$", block, re.MULTILINE)
                wps_model_num_m = re.search(r"\bModel Number:\s*(.*)$", block, re.MULTILINE)
                wps_uuid_m = re.search(r"\bUUID:\s*([0-9a-fA-F\-]+)", block)
                wps_devname_m = re.search(r"\bDevice name:\s*(.*)$", block, re.MULTILINE)

                # Capabilities
                has_beamformer = "SU Beamformer" in block or "MU Beamformer" in block
                has_beamformee = "SU Beamformee" in block or "MU Beamformee" in block
                is_80211ax = "HE capabilities:" in block
                is_80211ac = "VHT capabilities:" in block
                is_80211n = "HT capabilities:" in block

                freq = int(freq_m.group(1)) if freq_m else None
                chan = freq_to_channel(freq) if freq else None

                return {
                    "bssid": bssid,
                    "ssid": ssid or "<hidden>",
                    "signal_dbm": float(sig_m.group(1)) if sig_m else None,
                    "freq_mhz": freq,
                    "channel": chan,
                    "tsf_usec": int(tsf_m.group(1)) if tsf_m else None,
                    "beacon_interval_tu": int(beacon_int_m.group(1)) if beacon_int_m else None,
                    "wps": {
                        "manufacturer": wps_manuf_m.group(1).strip() if wps_manuf_m else None,
                        "model": wps_model_m.group(1).strip() if wps_model_m else None,
                        "model_number": wps_model_num_m.group(1).strip() if wps_model_num_m else None,
                        "device_name": wps_devname_m.group(1).strip() if wps_devname_m else None,
                        "uuid": wps_uuid_m.group(1).strip() if wps_uuid_m else None,
                    },
                    "phy_features": {
                        "wifi_generation": "Wi-Fi 6 (802.11ax)" if is_80211ax else ("Wi-Fi 5 (802.11ac)" if is_80211ac else ("Wi-Fi 4 (802.11n)" if is_80211n else "Legacy 802.11a/b/g")),
                        "supports_beamforming": has_beamformer or has_beamformee,
                        "beamformer": has_beamformer,
                        "beamformee": has_beamformee,
                        "short_gi_80mhz": "short GI (80 MHz)" in block,
                    }
                }

        return {"error": "Target not found in scan dump", "target": target}

    def scan_summary(self) -> Dict[str, Any]:
        """High-level summary of the surrounding RF environment."""
        if not self._last_results:
            self.scan(rescan=True)

        aps = self._last_results
        total = len(aps)
        count_24 = sum(1 for ap in aps if ap.band == "2.4 GHz")
        count_50 = sum(1 for ap in aps if ap.band == "5 GHz")

        dbm_vals = [ap.signal_dbm for ap in aps]
        stats = compute_linear_stats(dbm_vals)
        strongest = aps[0].to_dict() if aps else None

        return {
            "total_access_points": total,
            "band_distribution": {
                "2.4_ghz_count": count_24,
                "5.0_ghz_count": count_50,
            },
            "strongest_ap": strongest,
            "overall_power_stats": stats,
            "interface": self.interface,
            "timestamp": self._last_scan_time,
        }

    def get_channel_distribution(self) -> Dict[str, Any]:
        """AP counts and average signal metrics grouped by Wi-Fi channel."""
        if not self._last_results:
            self.scan(rescan=True)

        channels: Dict[int, List[float]] = {}
        for ap in self._last_results:
            ch = ap.channel or 0
            if ch not in channels:
                channels[ch] = []
            channels[ch].append(ap.signal_dbm)

        summary = {}
        for ch, vals in sorted(channels.items()):
            summary[ch] = {
                "ap_count": len(vals),
                "linear_mean_dbm": compute_linear_stats(vals)["mean_dbm"],
                "max_dbm": max(vals),
                "min_dbm": min(vals),
            }
        return summary

    def get_history(self, target: str = "") -> List[Dict[str, Any]]:
        """Return rolling history buffer of collected RSSI readings."""
        hist = list(self._history)
        if not target:
            return hist
        t_clean = target.strip().lower()
        return [
            entry for entry in hist
            if entry["bssid"].lower() == t_clean or entry["ssid"].lower() == t_clean
        ]


# -----------------------------------------------------------------------------
# RemoteRF Device Schema Class
# -----------------------------------------------------------------------------

@idl_register("wifi_dongle")
class WifiDongleSchema(DeviceSchema):
    """
    RemoteRF Device Schema for USB Wi-Fi Dongles (RSSI Collector & RF Monitor).

    Exposes live wireless telemetry, accurate linear-power RSSI statistics,
    batch burst sampling, and deep 802.11 physical layer diagnostics to remote Python clients.
    """
    device_type = "wifi_dongle"
    client_class = "WifiDongle"
    driver_version = "0.1.0"

    client_modules = {"wifi_dongle": "remoteRF.drivers.support.wifi_dongle"}

    @staticmethod
    def make_device(**kwargs) -> Optional[WifiDongleDevice]:
        """
        Factory method called by RemoteRF server/host when initializing device inventory.

        Parameters from devices.yml 'init' dictionary:
            interface (str, optional): Wireless interface name (e.g. 'wlx90de800a82c4').
                                       If omitted or None, auto-detects USB Wi-Fi dongle.
            auto_rescan (bool, optional): Trigger fresh active scan on calls (default: True).
            max_history (int, optional): Size of rolling RSSI history buffer (default: 100).

        Returns:
            WifiDongleDevice instance if hardware is available, or None.
        """
        interface = kwargs.get("interface")
        auto_rescan = bool(kwargs.get("auto_rescan", True))
        max_history = int(kwargs.get("max_history", 100))

        try:
            print(f"[wifi_dongle] Initializing USB Wi-Fi dongle (interface={interface or 'auto'})...")
            dev = WifiDongleDevice(
                interface=interface,
                auto_rescan=auto_rescan,
                max_history=max_history
            )
            print(f"[wifi_dongle] Bound to interface '{dev.interface}'. Default route protected.")
            return dev
        except Exception as exc:
            raise RuntimeError(f"Wi-Fi dongle initialization failed: {exc}") from exc

    # -------------------------------------------------------------------------
    # Exposed Getters
    # -------------------------------------------------------------------------

    @idl_expose(kind="get", doc="Wireless interface name used by this dongle.")
    def get_interface(self) -> str:
        return self.device.interface

    @idl_expose(kind="get", doc="Hardware vendor ID, product ID, driver, and model.")
    def get_device_info(self) -> Dict[str, Any]:
        return self.device.get_device_info()

    @idl_expose(kind="get", doc="Whether the USB dongle interface is present and active.")
    def get_is_available(self) -> bool:
        return self.device.is_available

    @idl_expose(kind="get", doc="Total number of scans executed since device initialization.")
    def get_scan_count(self) -> int:
        return self.device.scan_count

    @idl_expose(kind="get", doc="UNIX timestamp of the most recent scan.")
    def get_last_scan_time(self) -> float:
        return self.device.last_scan_time

    @idl_expose(kind="get", doc="Verification that default Ethernet gateway routing is intact.")
    def get_default_route_safe(self) -> bool:
        return self.device.default_route_safe

    # -------------------------------------------------------------------------
    # Exposed Setters
    # -------------------------------------------------------------------------

    @idl_expose(kind="get", doc="Whether active rescan is automatically triggered on scan calls.")
    def get_auto_rescan(self) -> bool:
        return self.device.auto_rescan

    @idl_expose(kind="set", doc="Enable or disable automatic active rescanning.")
    def set_auto_rescan(self, value: bool) -> None:
        self.device.auto_rescan = bool(value)

    # -------------------------------------------------------------------------
    # Exposed Calls
    # -------------------------------------------------------------------------

    @idl_expose(kind="call", doc="Scan nearby Wi-Fi APs. Returns list of access point dictionaries.")
    def call_scan(
        self,
        rescan: bool = True,
        *,
        band: str = "",
        min_rssi: float = -120.0,
    ) -> List[Dict[str, Any]]:
        """
        Scan nearby Wi-Fi access points.
        Returns list of AP dicts sorted by signal strength.
        """
        return self.device.scan(
            rescan=bool(rescan),
            band=str(band),
            min_rssi=float(min_rssi)
        )

    @idl_expose(kind="call", doc="Get the RSSI value (in dBm) for a target SSID or BSSID.")
    def call_get_rssi(self, target: str, *, rescan: bool = True) -> Optional[float]:
        """Returns float signal strength in dBm, or None if target is not detected."""
        return self.device.get_rssi(target=str(target), rescan=bool(rescan))

    @idl_expose(kind="call", doc="Collect burst of RSSI measurements with linear-power averaging.")
    def call_get_rssi_burst(
        self,
        target: str,
        *,
        count: int = 10,
        max_time: float = 5.0,
        rescan: bool = True,
    ) -> Dict[str, Any]:
        """
        Takes multiple RSSI samples in rapid succession.
        Calculates physical average power in linear milliwatts and converts to dBm.
        """
        return self.device.get_rssi_burst(
            target=str(target),
            count=int(count),
            max_time=float(max_time),
            rescan=bool(rescan)
        )

    @idl_expose(kind="call", doc="Get full AccessPoint metadata dictionary for a target.")
    def call_get_ap(self, target: str, *, rescan: bool = True) -> Optional[Dict[str, Any]]:
        """Returns full AP dictionary (SSID, BSSID, RSSI, channel, freq, security)."""
        return self.device.get_ap(target=str(target), rescan=bool(rescan))

    @idl_expose(kind="call", doc="Extract deep hardware & WPS telemetry (manufacturer, model, TSF clock).")
    def call_get_ap_details(self, target: str) -> Dict[str, Any]:
        """Returns WPS vendor identity, TSF microsecond timestamp, and 802.11ac/ax capabilities."""
        return self.device.get_ap_details(target=str(target))

    @idl_expose(kind="call", doc="High-level RF environment summary (AP counts, band stats, strongest AP).")
    def call_scan_summary(self) -> Dict[str, Any]:
        return self.device.scan_summary()

    @idl_expose(kind="call", doc="Channel distribution map showing AP density and signal by channel.")
    def call_get_channel_distribution(self) -> Dict[str, Any]:
        return self.device.get_channel_distribution()

    @idl_expose(kind="call", doc="Get buffered history of RSSI measurements over time.")
    def call_get_history(self, target: str = "") -> List[Dict[str, Any]]:
        return self.device.get_history(target=str(target))
