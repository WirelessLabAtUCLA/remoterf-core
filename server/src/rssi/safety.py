"""
Safety checks to ensure network configuration and Ethernet connections are never disturbed.
"""

import os
import subprocess
import re
from pathlib import Path
from typing import Dict, Any, Optional, List


def get_default_route_info() -> Dict[str, Any]:
    """
    Get the current default route interface and gateway from the kernel routing table.
    """
    try:
        output = subprocess.check_output(["ip", "route", "show", "default"], text=True).strip()
        # Example: "default via 128.97.88.1 dev enp86s0 proto static metric 100"
        match = re.search(r"default via ([\d\.]+) dev (\w+)", output)
        if match:
            return {
                "gateway": match.group(1),
                "interface": match.group(2),
                "raw": output
            }
    except Exception as e:
        return {"error": str(e), "interface": None, "gateway": None}
    return {"interface": None, "gateway": None, "raw": ""}


def ensure_wifi_autoconnect_disabled(interfaces: Optional[List[str]] = None) -> None:
    """
    Ensure NetworkManager autoconnect is set to 'no' for the given wireless interfaces
    (or all wifi interfaces if None provided). This prevents NetworkManager from
    automatically connecting to any Wi-Fi AP and changing the default route or DNS.
    """
    if interfaces is None:
        try:
            out = subprocess.check_output(
                ["nmcli", "-t", "-f", "DEVICE,TYPE", "device"],
                text=True,
                stderr=subprocess.DEVNULL
            )
            interfaces = []
            for line in out.splitlines():
                parts = line.strip().split(":")
                if len(parts) >= 2 and parts[1] == "wifi":
                    interfaces.append(parts[0])
        except Exception:
            interfaces = []

    for iface in interfaces:
        try:
            subprocess.run(
                ["nmcli", "device", "set", iface, "autoconnect", "no"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
        except Exception:
            pass


def ensure_wifi_unblocked() -> bool:
    """
    Ensure Wi-Fi radio is not blocked by rfkill and NetworkManager radio is on.
    """
    # 1. rfkill unblock wifi
    try:
        subprocess.run(["rfkill", "unblock", "wifi"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass

    # 2. nmcli radio wifi on
    try:
        subprocess.run(["nmcli", "radio", "wifi", "on"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except Exception:
        pass

    try:
        state = subprocess.check_output(
            ["nmcli", "radio", "wifi"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip().lower()
    except (OSError, subprocess.SubprocessError):
        # Systems that scan with iw may not have NetworkManager. In that case
        # the scanner itself remains the authority on whether the radio works.
        return True
    return state == "enabled"


def verify_network_safety(target_interface: str) -> Dict[str, Any]:
    """
    Verify that the target interface is not the primary Ethernet / default gateway device,
    and configure safe parameters so that Ethernet traffic remains completely unaffected.
    """
    route_info = get_default_route_info()
    default_iface = route_info.get("interface")

    if default_iface and target_interface == default_iface:
        raise RuntimeError(
            f"SAFETY ABORT: Target interface '{target_interface}' is the default route interface! "
            f"Refusing to operate on Ethernet or default gateway connection."
        )

    # Disable autoconnect on wireless interfaces to keep Ethernet active as primary
    ensure_wifi_autoconnect_disabled([target_interface])
    if not ensure_wifi_unblocked():
        raise RuntimeError(
            "Wi-Fi radio is disabled or soft-blocked. Run once as an administrator: "
            "sudo rfkill unblock wifi && sudo nmcli radio wifi on"
        )

    return {
        "status": "safe",
        "default_route_interface": default_iface,
        "default_gateway": route_info.get("gateway"),
        "target_interface": target_interface
    }
