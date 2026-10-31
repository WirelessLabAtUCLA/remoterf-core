"""
USB Wi-Fi Dongle detection and management.
"""

import os
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class USBWiFiDevice:
    interface: str
    vendor_id: str
    product_id: str
    product_name: str
    manufacturer: str
    driver: str
    sysfs_path: str

    def __str__(self) -> str:
        return f"{self.interface} ({self.manufacturer} {self.product_name} [{self.vendor_id}:{self.product_id}], driver: {self.driver})"


def find_usb_wifi_dongles() -> List[USBWiFiDevice]:
    """
    Search sysfs for all wireless network interfaces connected via USB.
    """
    devices: List[USBWiFiDevice] = []
    net_path = Path("/sys/class/net")
    if not net_path.exists():
        return devices

    for iface_dir in net_path.iterdir():
        # Check if interface is wireless
        is_wireless = (iface_dir / "wireless").exists() or (iface_dir / "phy80211").exists()
        dev_link = iface_dir / "device"

        if not is_wireless or not dev_link.exists():
            continue

        target = os.path.realpath(dev_link)
        # Check if USB bus in path
        if "/usb" not in target:
            continue

        # Find driver
        driver = "unknown"
        driver_link = iface_dir / "device" / "driver"
        if driver_link.exists():
            driver = os.path.realpath(driver_link).split(os.sep)[-1]

        # Walk up to find USB device attributes
        usb_dir = Path(target)
        vendor_id = "unknown"
        product_id = "unknown"
        product_name = "USB Wi-Fi Adapter"
        manufacturer = ""

        curr = usb_dir
        while curr != Path("/") and curr.name != "":
            if (curr / "idVendor").exists():
                try:
                    vendor_id = (curr / "idVendor").read_text().strip()
                except Exception:
                    pass
            if (curr / "idProduct").exists():
                try:
                    product_id = (curr / "idProduct").read_text().strip()
                except Exception:
                    pass
            if (curr / "product").exists():
                try:
                    product_name = (curr / "product").read_text().strip()
                except Exception:
                    pass
            if (curr / "manufacturer").exists():
                try:
                    manufacturer = (curr / "manufacturer").read_text().strip()
                except Exception:
                    pass
            if vendor_id != "unknown" and product_id != "unknown":
                break
            curr = curr.parent

        devices.append(
            USBWiFiDevice(
                interface=iface_dir.name,
                vendor_id=vendor_id,
                product_id=product_id,
                product_name=product_name,
                manufacturer=manufacturer or "Generic",
                driver=driver,
                sysfs_path=target
            )
        )

    return devices


def get_default_usb_dongle(preferred_interface: Optional[str] = None) -> USBWiFiDevice:
    """
    Get the preferred or first available USB Wi-Fi dongle.
    """
    dongles = find_usb_wifi_dongles()
    if not dongles:
        raise RuntimeError(
            "No USB Wi-Fi dongle detected! Please check that the USB dongle is plugged in "
            "and recognized by the kernel (e.g., check 'lsusb' or 'dmesg')."
        )

    if preferred_interface:
        for d in dongles:
            if d.interface == preferred_interface:
                return d
        raise ValueError(
            f"Specified interface '{preferred_interface}' is not an active USB Wi-Fi device. "
            f"Detected USB Wi-Fi interfaces: {[d.interface for d in dongles]}"
        )

    # If Realtek 0bda:c811 (the user's dongle) is present, prefer it
    for d in dongles:
        if d.vendor_id.lower() == "0bda" and d.product_id.lower() == "c811":
            return d

    return dongles[0]
