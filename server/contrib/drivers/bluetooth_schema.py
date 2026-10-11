#!/usr/bin/env python3
"""
RemoteRF Schema for Bluetooth Devices (e.g. ZEXMTE CSR8510 USB Bluetooth Dongle).
Provides remote discovery, device inspection, and adapter control over RemoteRF RPC.

Client usage example:
    from remoterf.drivers.bluetooth import BluetoothModule

    bluetooth = BluetoothModule(token)
    print(f"Adapter: {bluetooth.adapter} ({bluetooth.chipset})")
    print(f"MAC: {bluetooth.address}, Spec: {bluetooth.version}")

    devices = bluetooth.scan(timeout=5.0)
    for dev in devices:
        print(f"  {dev['address']} | {dev['rssi']} dBm | {dev['name'] or dev['vendor']}")
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import math
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional
from uuid import UUID

# Ensure parent directory is in sys.path when running from schema directory
_current_dir = Path(__file__).resolve().parent
_parent_dir = _current_dir.parent
for d in (_current_dir, _parent_dir):
    d_str = str(d)
    if d_str not in sys.path:
        sys.path.insert(0, d_str)

from remoteRF_server.common.idl import DeviceSchema, idl_expose, idl_register

# Optional imports for hardware control
try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
except ImportError:
    BleakScanner = None

try:
    import bluetooth_numbers
except ImportError:
    bluetooth_numbers = None

from dbus_fast import Message, Variant
from dbus_fast.aio import MessageBus
from dbus_fast.constants import BusType, MessageType

# A replugged dongle comes back as another hciN; its old object path is gone.
_GONE_ERRORS = {"org.freedesktop.DBus.Error.UnknownObject", "org.freedesktop.DBus.Error.UnknownMethod"}
_SYSFS_BLUETOOTH = Path("/sys/class/bluetooth")

BT_CORE_VERSIONS = {
    0: "Bluetooth 1.0b",
    1: "Bluetooth 1.1",
    2: "Bluetooth 1.2",
    3: "Bluetooth 2.0 + EDR",
    4: "Bluetooth 2.1 + EDR",
    5: "Bluetooth 3.0 + HS",
    6: "Bluetooth 4.0",
    7: "Bluetooth 4.1",
    8: "Bluetooth 4.2",
    9: "Bluetooth 5.0",
    10: "Bluetooth 5.1",
    11: "Bluetooth 5.2",
    12: "Bluetooth 5.3",
    13: "Bluetooth 5.4",
}


def _run_coroutine_sync(coro_fn, *args, **kwargs) -> Any:
    """Execute an asyncio coroutine safely from sync RemoteRF RPC dispatch."""
    try:
        asyncio.get_running_loop()
        # A loop is already running in this thread, execute in a worker thread
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(lambda: asyncio.run(coro_fn(*args, **kwargs))).result()
    except RuntimeError:
        # No loop in current thread
        return asyncio.run(coro_fn(*args, **kwargs))


class _JsonList(list):
    """A list of dicts for the wire. remoteRF-server 1.3.0 and older map_arg turns
    a plain list into a numpy array and refuses the object-dtype one dicts make;
    refusing numpy conversion sends it as JSON, which the client decodes back to
    a list. 1.3.1+ servers send such lists as JSON themselves; kept for older ones."""

    def __array__(self, *args, **kwargs):
        raise TypeError("encode as JSON")


class _BluetoothDevice:
    """Represents a live physical Bluetooth adapter instance on the host machine."""

    def __init__(
        self,
        adapter_name: str,
        sysfs_path: str,
        usb_vendor: str,
        usb_product: str,
        product_name: str,
        bd_address: str,
        version_str: str,
        is_zexmte: bool,
        requested: Optional[str] = None,
        allow_fallback: bool = False,
    ):
        self.requested = requested
        self.allow_fallback = allow_fallback
        self.adapter_name = adapter_name
        self.sysfs_path = sysfs_path
        self.usb_vendor = usb_vendor
        self.usb_product = usb_product
        self.product_name = product_name
        self.bd_address = bd_address
        self.version_str = version_str
        self.is_zexmte = is_zexmte
        self.device_cache: Dict[str, dict] = {}
        self.last_scan_time: float = 0.0

    def _reresolve(self) -> bool:
        """Find the adapter again after a replug renumbered it; True if it moved."""
        info = _find_adapter_sysfs(target_name=self.requested, allow_fallback=self.allow_fallback)
        if not info or info["name"] == self.adapter_name:
            return False
        print(f"Bluetooth: {self.adapter_name} is now {info['name']}")
        self.adapter_name = info["name"]
        self.sysfs_path = info["sysfs_path"]
        self.usb_vendor = info["vendor"]
        self.usb_product = info["product"]
        self.product_name = info["product_name"]
        self.is_zexmte = info["is_zexmte"]
        return True

    async def _properties(self, member: str, signature: str, body: list):
        """One org.freedesktop.DBus.Properties call on this adapter. If its object
        is gone, look the adapter up again and retry once."""
        for retry in (True, False):
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            try:
                reply = await bus.call(
                    Message(
                        destination="org.bluez",
                        path=f"/org/bluez/{self.adapter_name}",
                        interface="org.freedesktop.DBus.Properties",
                        member=member,
                        signature=signature,
                        body=body,
                    )
                )
            finally:
                bus.disconnect()
            if reply.message_type != MessageType.ERROR:
                return reply
            if not (retry and reply.error_name in _GONE_ERRORS and self._reresolve()):
                raise RuntimeError(f"{self.adapter_name}: {reply.error_name}")

    async def get_powered_async(self) -> bool:
        try:
            reply = await self._properties("Get", "ss", ["org.bluez.Adapter1", "Powered"])
            return bool(reply.body[0].value)
        except Exception:
            return False

    async def set_powered_async(self, powered: bool) -> bool:
        try:
            await self._properties(
                "Set", "ssv", ["org.bluez.Adapter1", "Powered", Variant("b", bool(powered))]
            )
            return True
        except Exception:
            return False

    async def get_discovering_async(self) -> bool:
        try:
            reply = await self._properties("Get", "ss", ["org.bluez.Adapter1", "Discovering"])
            return bool(reply.body[0].value)
        except Exception:
            return False

    async def scan_async(self, duration: float) -> List[dict]:
        """Perform a BLE discovery scan using Bleak on the target adapter."""
        if BleakScanner is None:
            raise RuntimeError("bleak library is required on the host machine to scan")

        # Ensure adapter is powered (this also finds a renumbered adapter)
        is_on = await self.get_powered_async()
        if not is_on:
            await self.set_powered_async(True)
            await asyncio.sleep(0.5)

        discovered: Dict[str, dict] = {}

        def _callback(dev: BLEDevice, adv: AdvertisementData):
            addr = dev.address
            name = adv.local_name or dev.name

            # Decode companies and beacon hints
            companies = []
            hints = []
            for cid, data in adv.manufacturer_data.items():
                cname = f"0x{cid:04x}"
                if bluetooth_numbers:
                    cname = bluetooth_numbers.company.get(cid, cname)
                companies.append(cname)

                if cid == 0x004C and len(data) >= 2:
                    t = data[0]
                    if t == 0x02:
                        hints.append("iBeacon")
                    elif t == 0x10:
                        hints.append("Nearby/AirDrop")
                    elif t == 0x07:
                        hints.append("AirPods")
                    elif t == 0x12:
                        hints.append("Find My/AirTag")
                    elif t == 0x09:
                        hints.append("AirPlay")
                elif cid == 0x0006:
                    hints.append("Swift Pair")
                elif cid == 0x00E0:
                    hints.append("Fast Pair")

            services = []
            for s in adv.service_uuids:
                s_name = s
                if bluetooth_numbers:
                    try:
                        s_name = bluetooth_numbers.service[UUID(s)]
                    except Exception:
                        s_name = s[:8] + "…"
                services.append(s_name)

            # Signal quality
            rssi = adv.rssi
            if rssi >= -60:
                qual, bar = "Strong", "●●●●"
            elif rssi >= -72:
                qual, bar = "Good", "●●●○"
            elif rssi >= -82:
                qual, bar = "Fair", "●●○○"
            elif rssi >= -92:
                qual, bar = "Weak", "●○○○"
            else:
                qual, bar = "Faint", "○○○○"

            # Distance estimation (-59 dBm calibrated at 1m with indoor exponent 2.2)
            ratio = (-59.0 - rssi) / (10.0 * 2.2)
            dist_m = round(10.0**ratio, 2)
            if dist_m < 1.0:
                dist_str = "< 1 m"
            elif dist_m < 10.0:
                dist_str = f"~{dist_m:.1f} m"
            elif dist_m < 20.0:
                dist_str = f"~{int(dist_m)} m"
            else:
                dist_str = "> 20 m"

            comp_str = ", ".join(companies) if companies else "Unknown Vendor"
            proto_str = ", ".join(hints) if hints else ""

            if addr in discovered:
                rec = discovered[addr]
                rec["rssi"] = rssi
                rec["signal_quality"] = qual
                rec["signal_bar"] = bar
                rec["estimated_distance_m"] = dist_m
                rec["distance_str"] = dist_str
                rec["packet_count"] += 1
                rec["last_seen"] = time.time()
                if name and not rec["name"]:
                    rec["name"] = name
                if comp_str != "Unknown Vendor":
                    rec["vendor"] = comp_str
                if proto_str:
                    rec["protocol"] = proto_str
                for s in services:
                    if s not in rec["services"]:
                        rec["services"].append(s)
            else:
                discovered[addr] = {
                    "address": addr,
                    "name": name,
                    "rssi": rssi,
                    "signal_quality": qual,
                    "signal_bar": bar,
                    "estimated_distance_m": dist_m,
                    "distance_str": dist_str,
                    "vendor": comp_str,
                    "protocol": proto_str,
                    "services": services,
                    "packet_count": 1,
                    "first_seen": time.time(),
                    "last_seen": time.time(),
                }

        scanner = BleakScanner(
            detection_callback=_callback,
            bluez={"adapter": self.adapter_name},
        )
        await scanner.start()
        try:
            await asyncio.sleep(duration)
        finally:
            await scanner.stop()

        self.device_cache = discovered
        self.last_scan_time = time.time()
        return list(discovered.values())


def _find_adapter_sysfs(target_name: Optional[str] = None, allow_fallback: bool = False) -> Optional[dict]:
    """Inspect /sys/class/bluetooth to find the target adapter or auto-detect ZEXMTE CSR8510.

    Auto-detection never settles for another adapter (a built-in one, say)
    unless allow_fallback: the device is offline until the CSR is plugged in."""
    base = _SYSFS_BLUETOOTH
    if not base.exists():
        return None

    candidates = []
    for entry in sorted(base.glob("hci*")):
        name = entry.name
        if target_name and target_name.lower() != name.lower():
            continue

        resolved = entry.resolve()
        vendor, product, prod_name = "", "", ""
        curr = resolved
        while curr != curr.parent:
            if (curr / "idVendor").exists() and not vendor:
                try:
                    vendor = (curr / "idVendor").read_text().strip()
                    product = (curr / "idProduct").read_text().strip()
                except OSError:
                    pass
            if (curr / "product").exists() and not prod_name:
                try:
                    prod_name = (curr / "product").read_text().strip()
                except OSError:
                    pass
            curr = curr.parent

        is_zexmte = (
            (vendor.lower() == "0a12" and product.lower() == "0001")
            or "csr8510" in prod_name.lower()
            or "csr" in prod_name.lower()
        )

        candidates.append({
            "name": name,
            "sysfs_path": str(resolved),
            "vendor": vendor,
            "product": product,
            "product_name": prod_name or "USB Bluetooth Adapter",
            "is_zexmte": is_zexmte,
        })

    if not candidates:
        return None

    # If user specified a name, return it
    if target_name:
        return candidates[0]

    # Otherwise prefer ZEXMTE dongle
    for c in candidates:
        if c["is_zexmte"]:
            return c

    return candidates[0] if allow_fallback else None


async def _query_bluez_props(adapter_name: str) -> dict:
    """Retrieve address and version info from BlueZ D-Bus."""
    props = {}
    try:
        bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
        msg = Message(
            destination="org.bluez",
            path=f"/org/bluez/{adapter_name}",
            interface="org.freedesktop.DBus.Properties",
            member="GetAll",
            signature="s",
            body=["org.bluez.Adapter1"],
        )
        reply = await bus.call(msg)
        bus.disconnect()
        if reply.body:
            for k, v in reply.body[0].items():
                props[k] = v.value
    except Exception:
        pass
    return props


def _connect_bluetooth_device(
    *, adapter: Optional[str] = None, allow_fallback: bool = False
) -> Optional[_BluetoothDevice]:
    """Factory helper to detect and open the Bluetooth controller."""
    info = _find_adapter_sysfs(target_name=adapter, allow_fallback=allow_fallback)
    if not info:
        hint = "" if adapter or allow_fallback else " (no CSR8510; set allow_fallback: true to use another)"
        print(f"Bluetooth: No adapter found matching {adapter or 'default'}{hint}")
        return None

    dbus_props = _run_coroutine_sync(_query_bluez_props, info["name"])
    bd_address = dbus_props.get("Address", "00:00:00:00:00:00")
    version_id = dbus_props.get("Version")
    version_str = BT_CORE_VERSIONS.get(version_id, f"HCI Version {version_id}")

    return _BluetoothDevice(
        adapter_name=info["name"],
        sysfs_path=info["sysfs_path"],
        usb_vendor=info["vendor"],
        usb_product=info["product"],
        product_name=info["product_name"],
        bd_address=bd_address,
        version_str=version_str,
        is_zexmte=info["is_zexmte"],
        requested=adapter,
        allow_fallback=allow_fallback,
    )


@idl_register("bluetooth")
class BluetoothSchema(DeviceSchema):
    """RemoteRF schema wrapper for Bluetooth HCI devices (e.g. ZEXMTE CSR8510)."""

    device_type = "bluetooth"
    client_class = "BluetoothModule"
    driver_version = "0.1.2"

    @staticmethod
    def make_device(**kwargs) -> Optional[_BluetoothDevice]:
        """Open the physical Bluetooth device based on devices.yml init block.
        Without 'adapter' the CSR's current hciN is looked up on every call."""
        adapter = kwargs.get("adapter")
        return _connect_bluetooth_device(
            adapter=adapter, allow_fallback=bool(kwargs.get("allow_fallback", False))
        )

    # -------------------------------------------------------------------------
    # Getters: Readable device properties
    # -------------------------------------------------------------------------

    @idl_expose(kind="get", doc="HCI adapter name (e.g. 'hci1').")
    def get_adapter(self) -> str:
        return self.device.adapter_name

    @idl_expose(kind="get", doc="Bluetooth hardware BD_ADDR (MAC address).")
    def get_address(self) -> str:
        return self.device.bd_address

    @idl_expose(kind="get", doc="Bluetooth hardware BD_ADDR alias.")
    def get_bd_address(self) -> str:
        return self.device.bd_address

    @idl_expose(kind="get", doc="Chipset or device model name.")
    def get_chipset(self) -> str:
        return self.device.product_name

    @idl_expose(kind="get", doc="Bluetooth Core specification version string.")
    def get_version(self) -> str:
        return self.device.version_str

    @idl_expose(kind="get", doc="Whether the adapter is a ZEXMTE CSR8510 module.")
    def get_is_zexmte(self) -> bool:
        return self.device.is_zexmte

    @idl_expose(kind="get", doc="RF power state of the Bluetooth controller (True=ON, False=OFF).")
    def get_powered(self) -> bool:
        return bool(_run_coroutine_sync(self.device.get_powered_async))

    @idl_expose(kind="set", doc="Set the RF power state (True=ON, False=OFF).")
    def set_powered(self, value: bool) -> bool:
        return bool(_run_coroutine_sync(self.device.set_powered_async, bool(value)))

    @idl_expose(kind="get", doc="Whether the adapter is actively discovering.")
    def get_discovering(self) -> bool:
        return bool(_run_coroutine_sync(self.device.get_discovering_async))

    @idl_expose(kind="get", doc="Number of devices currently cached from recent scans.")
    def get_device_count(self) -> int:
        return len(self.device.device_cache)

    # -------------------------------------------------------------------------
    # Calls: Actions and commands
    # -------------------------------------------------------------------------

    @idl_expose(kind="call", doc="Scan for Bluetooth devices in the vicinity.")
    def call_scan(
        self,
        timeout: float = 5.0,
        *,
        named_only: bool = False,
        min_rssi: int = None,
        limit: int = None,
    ) -> List[dict]:
        """
        Scan for nearby devices for timeout seconds.
        Filters by named_only (True/False) or min_rssi (dBm).
        Returns a list of device dictionaries sorted by signal strength.
        """
        duration = max(1.0, min(float(timeout), 30.0))
        results = _run_coroutine_sync(self.device.scan_async, duration)

        if named_only:
            results = [d for d in results if d.get("name")]

        if min_rssi is not None:
            results = [d for d in results if d.get("rssi", -100) >= int(min_rssi)]

        results.sort(key=lambda d: d.get("rssi", -100), reverse=True)

        if limit is not None and int(limit) > 0:
            results = results[: int(limit)]

        return _JsonList(results)

    @idl_expose(kind="call", doc="Perform a scan and return high-level vicinity statistics.")
    def call_scan_summary(self, timeout: float = 5.0) -> dict:
        """Scan and return a statistical overview of nearby devices and vendor distribution."""
        devices = self.call_scan(timeout=timeout)
        named_count = sum(1 for d in devices if d.get("name"))

        vendors: Dict[str, int] = {}
        for d in devices:
            v = d.get("vendor")
            if v and v != "Unknown Vendor":
                vendors[v] = vendors.get(v, 0) + 1

        strongest = devices[0] if devices else None

        return {
            "total_devices": len(devices),
            "named_devices": named_count,
            "anonymous_beacons": len(devices) - named_count,
            "vendors": vendors,
            "strongest_device": strongest,
            "scan_duration_sec": float(timeout),
            "timestamp": time.time(),
        }

    @idl_expose(kind="call", doc="Retrieve cached information for a specific MAC address.")
    def call_get_device(self, address: str) -> Optional[dict]:
        """Look up a specific device by MAC address from the recent scan cache."""
        addr_clean = str(address).strip().upper()
        for k, v in self.device.device_cache.items():
            if k.upper() == addr_clean:
                return v
        return None

    @idl_expose(kind="call", doc="Retrieve all currently cached devices without scanning.")
    def call_get_devices(
        self,
        *,
        named_only: bool = False,
        min_rssi: int = None,
        limit: int = None,
    ) -> List[dict]:
        """Return all devices currently in the local cache."""
        results = list(self.device.device_cache.values())

        if named_only:
            results = [d for d in results if d.get("name")]

        if min_rssi is not None:
            results = [d for d in results if d.get("rssi", -100) >= int(min_rssi)]

        results.sort(key=lambda d: d.get("rssi", -100), reverse=True)

        if limit is not None and int(limit) > 0:
            results = results[: int(limit)]

        return _JsonList(results)

    @idl_expose(kind="call", doc="Get full adapter hardware and driver metadata.")
    def call_info(self) -> dict:
        """Return adapter hardware descriptors, USB IDs, and Bluetooth specification."""
        return {
            "adapter": self.device.adapter_name,
            "address": self.device.bd_address,
            "chipset": self.device.product_name,
            "usb_id": f"{self.device.usb_vendor}:{self.device.usb_product}",
            "bluetooth_version": self.device.version_str,
            "is_zexmte": self.device.is_zexmte,
            "sysfs_path": self.device.sysfs_path,
            "powered": self.get_powered(),
            "discovering": self.get_discovering(),
            "cached_devices": len(self.device.device_cache),
        }

    @idl_expose(kind="call", doc="Reset Bluetooth adapter discovery state and clear cache.")
    def call_reset(self) -> dict:
        """Reset the adapter state, clear cache, and ensure power is enabled."""
        self.device.device_cache.clear()
        _run_coroutine_sync(self.device.set_powered_async, True)
        return {
            "status": "reset_complete",
            "powered": True,
            "cached_devices": 0,
        }

    def reset_for_next_holder(self):
        """Called by the server (not exposed) when a reservation ends: the next
        holder must not read this holder's scan results (nearby people's addresses
        and names) or find the adapter left powered off."""
        if self.device is None:
            return
        self.device.device_cache.clear()
        self.device.last_scan_time = 0.0
        # Bounded: this runs under the device's io_lock, and a D-Bus call that
        # never gets a reply would otherwise lock the device until a restart.
        try:
            ok = _run_coroutine_sync(lambda: asyncio.wait_for(self.device.set_powered_async(True), 10.0))
        except asyncio.TimeoutError:
            ok = False
        if not ok:
            raise RuntimeError(f"could not power {self.device.adapter_name} on")


if __name__ == "__main__":
    print("Testing RemoteRF BluetoothSchema...\n")
    schema = BluetoothSchema()
    print("Exposed Methods:")
    for method in schema.list_exposed():
        print(f"  - {method}")

    print("\nValidating IDL Generation:")
    idl_json = schema.get_idl_json(pretty=True)
    print(idl_json[:400] + "...\n")

    print("Opening local hardware via make_device()...")
    device = schema.make_device()
    if device is None:
        print("[!] No physical Bluetooth adapter found.")
    else:
        schema.bind(device)
        print(f"Bound device: {device.adapter_name} ({device.product_name}) - MAC: {device.bd_address}")
        print(f"Powered: {schema.dispatch('get_powered', {})}")
        print(f"Chipset: {schema.dispatch('get_chipset', {})}")
        print(f"Version: {schema.dispatch('get_version', {})}")
        print("\nTesting local dispatch call_scan(timeout=2.0, limit=3):")
        scan_res = schema.dispatch("call_scan", {"timeout": 2.0, "limit": 3})
        print(f"Discovered {len(scan_res)} device(s):")
        for d in scan_res:
            print(f"  {d['address']} | {d['rssi']} dBm | {d['name'] or d['vendor']} ({d['distance_str']})")
