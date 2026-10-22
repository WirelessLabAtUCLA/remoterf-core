"""
Core RSSI Scanner implementation for Linux wireless interfaces.
"""

import time
import subprocess
import re
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Optional, Callable, Dict, Any

from .dongle import get_default_usb_dongle, USBWiFiDevice
from .safety import verify_network_safety


def freq_to_channel(freq_mhz: int) -> Optional[int]:
    """Convert radio frequency in MHz to 802.11 channel number."""
    if freq_mhz == 2484:
        return 14
    elif 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    elif 5180 <= freq_mhz <= 5885:
        return (freq_mhz - 5000) // 5
    elif 5955 <= freq_mhz <= 7115:
        return (freq_mhz - 5950) // 5
    return None


def dbm_to_quality_percent(signal_dbm: float) -> int:
    """
    Standard Wi-Fi signal quality formula:
    -50 dBm or higher = 100%
    -100 dBm or lower = 0%
    Linear scaling in between.
    """
    if signal_dbm >= -50.0:
        return 100
    elif signal_dbm <= -100.0:
        return 0
    else:
        return int(2 * (signal_dbm + 100.0))


@dataclass
class AccessPoint:
    bssid: str
    ssid: str
    signal_dbm: float
    quality_pct: int
    freq_mhz: Optional[int]
    channel: Optional[int]
    band: str
    security: str
    last_seen_ms: Optional[int]
    timestamp: float

    @property
    def iso_timestamp(self) -> str:
        return datetime.fromtimestamp(self.timestamp).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["iso_timestamp"] = self.iso_timestamp
        return d


class RSSIScanner:
    """
    Wi-Fi RSSI Scanner designed for USB Wi-Fi dongles on Linux.
    Safely operates without disrupting wired Ethernet or default routing.
    """

    def __init__(self, interface: Optional[str] = None):
        if interface:
            self.interface = interface
            self.device_info: Optional[USBWiFiDevice] = None
        else:
            dongle = get_default_usb_dongle()
            self.interface = dongle.interface
            self.device_info = dongle

        # Run safety verification
        self.safety_status = verify_network_safety(self.interface)

    def _trigger_rescan(self) -> None:
        """
        Trigger NetworkManager to perform an active Wi-Fi scan using standard user permissions.
        """
        try:
            subprocess.run(
                ["nmcli", "dev", "wifi", "list", "ifname", self.interface, "--rescan", "yes"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False
            )
        except Exception:
            pass

    def _parse_iw_dump(self) -> List[AccessPoint]:
        """
        Read the Linux kernel cfg80211 BSS dump cache via 'iw dev <interface> scan dump'.
        This returns exact signal strength in dBm without requiring root privileges.
        """
        try:
            out = subprocess.check_output(
                ["iw", "dev", self.interface, "scan", "dump"],
                text=True,
                errors="replace"
            )
        except Exception as e:
            return []

        now = time.time()
        bss_blocks = out.split("BSS ")
        records: List[AccessPoint] = []

        for block in bss_blocks:
            if not block.strip():
                continue
            first_line = block.splitlines()[0]
            m = re.match(r"([0-9a-fA-F:]{17})", first_line)
            if not m:
                continue
            bssid = m.group(1).lower()

            freq_m = re.search(r"\bfreq:\s*(\d+)", block)
            freq = int(freq_m.group(1)) if freq_m else None

            sig_m = re.search(r"\bsignal:\s*([-\d\.]+)\s*dBm", block)
            signal_dbm = float(sig_m.group(1)) if sig_m else -100.0

            seen_m = re.search(r"\blast seen:\s*(\d+)\s*ms ago", block)
            last_seen = int(seen_m.group(1)) if seen_m else None

            ssid_m = re.search(r"^[ \t]*SSID:[ \t]*(.*)$", block, re.MULTILINE)
            if ssid_m:
                raw_ssid = ssid_m.group(1).strip()
                if not raw_ssid or all(c in "\x00 \t" for c in raw_ssid):
                    ssid = "<hidden>"
                else:
                    ssid = raw_ssid.replace("\x00", "")
            else:
                ssid = "<hidden>"

            security: List[str] = []
            if "SAE" in block or "WPA3" in block:
                security.append("WPA3")
            if "RSN:" in block:
                security.append("WPA2")
            if "WPA:" in block:
                security.append("WPA")
            if "capability: ESS Privacy" in block and not security:
                security.append("WEP")
            if not security:
                security.append("Open")

            chan = freq_to_channel(freq) if freq else None
            band = "2.4 GHz" if freq and freq < 3000 else "5 GHz" if freq and freq < 6000 else "6 GHz" if freq else "Unknown"
            quality = dbm_to_quality_percent(signal_dbm)

            records.append(
                AccessPoint(
                    bssid=bssid,
                    ssid=ssid,
                    signal_dbm=signal_dbm,
                    quality_pct=quality,
                    freq_mhz=freq,
                    channel=chan,
                    band=band,
                    security="/".join(dict.fromkeys(security)),
                    last_seen_ms=last_seen,
                    timestamp=now
                )
            )

        return records

    def _parse_nmcli_fallback(self) -> List[AccessPoint]:
        """
        Fallback parser using nmcli output directly if iw scan dump returns empty.
        """
        try:
            out = subprocess.check_output(
                ["nmcli", "-t", "-f", "BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY", "dev", "wifi", "list", "ifname", self.interface],
                text=True,
                errors="replace"
            )
        except Exception:
            return []

        now = time.time()
        records: List[AccessPoint] = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            # nmcli escapes colons in BSSID as \:
            # Format: BSSID:SSID:CHAN:FREQ:SIGNAL:SECURITY
            parts = re.split(r"(?<!\\):", line)
            if len(parts) < 6:
                continue
            bssid = parts[0].replace(r"\:", ":").lower()
            ssid = parts[1].replace(r"\:", ":") or "<hidden>"
            chan = int(parts[2]) if parts[2].isdigit() else None
            freq_str = parts[3].replace("MHz", "").strip()
            freq = int(freq_str) if freq_str.isdigit() else None
            signal_pct = int(parts[4]) if parts[4].isdigit() else 0
            # convert signal % back to approx dBm
            signal_dbm = round((signal_pct / 2.0) - 100.0, 1)
            sec = parts[5].strip() or "Open"
            band = "2.4 GHz" if freq and freq < 3000 else "5 GHz" if freq and freq < 6000 else "Unknown"

            records.append(
                AccessPoint(
                    bssid=bssid,
                    ssid=ssid,
                    signal_dbm=signal_dbm,
                    quality_pct=signal_pct,
                    freq_mhz=freq,
                    channel=chan,
                    band=band,
                    security=sec,
                    last_seen_ms=None,
                    timestamp=now
                )
            )
        return records

    def scan(self, rescan: bool = True) -> List[AccessPoint]:
        """
        Perform a Wi-Fi scan and return all detected Access Points.
        Results are sorted by signal strength (highest/strongest dBm first).
        """
        if rescan:
            self._trigger_rescan()

        results = self._parse_iw_dump()
        if not results:
            results = self._parse_nmcli_fallback()

        # Sort by signal strength descending
        results.sort(key=lambda ap: ap.signal_dbm, reverse=True)
        return results

    def get_target_rssi(
        self,
        ssid: Optional[str] = None,
        bssid: Optional[str] = None,
        rescan: bool = True
    ) -> List[AccessPoint]:
        """
        Get RSSI reading specifically for a target SSID or BSSID.
        """
        all_aps = self.scan(rescan=rescan)
        matches = []
        target_bssid = bssid.lower() if bssid else None
        target_ssid = ssid.lower() if ssid else None

        for ap in all_aps:
            if target_bssid and ap.bssid.lower() == target_bssid:
                matches.append(ap)
            elif target_ssid and ap.ssid.lower() == target_ssid:
                matches.append(ap)

        return matches

    def monitor(
        self,
        interval: float = 1.0,
        callback: Optional[Callable[[List[AccessPoint]], None]] = None,
        target_ssid: Optional[str] = None,
        target_bssid: Optional[str] = None,
        count: Optional[int] = None
    ):
        """
        Continuous RSSI monitoring generator.
        Yields scan results on every interval.
        """
        iterations = 0
        while count is None or iterations < count:
            if target_ssid or target_bssid:
                results = self.get_target_rssi(ssid=target_ssid, bssid=target_bssid, rescan=True)
            else:
                results = self.scan(rescan=True)

            if callback:
                callback(results)
            yield results

            iterations += 1
            if count is None or iterations < count:
                time.sleep(interval)
