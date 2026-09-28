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

# SAMPLE schema for ADI Pluto SDR in AD9361 MIMO / 2R2T mode.
# Place into -> ~/.config/remoterf/drivers and restart server to utilize!

from remoteRF_server.common.idl import idl_register, idl_expose
from remoteRF_server.common.idl.pluto_schema import PlutoSchema

import subprocess
import re
from pathlib import Path

import adi


def _normalize_channels(value, default):
    if value is None:
        return list(default)
    if isinstance(value, str):
        if not value.strip():
            return list(default)
        return [int(part.strip()) for part in value.split(",") if part.strip()]
    return [int(ch) for ch in value]


def _get_attr(device, *names):
    for name in names:
        if hasattr(device, name):
            return getattr(device, name)
    raise AttributeError(f"{device!r} has none of: {', '.join(names)}")


def _set_attr(device, value, *names):
    for name in names:
        if hasattr(device, name):
            setattr(device, name, value)
            return
    raise AttributeError(f"{device!r} has none of: {', '.join(names)}")


def _apply_initial_settings(device, settings):
    int_attrs = (
        "sample_rate",
        "rx_lo",
        "tx_lo",
        "rx_rf_bandwidth",
        "tx_rf_bandwidth",
        "rx_buffer_size",
    )
    for attr in int_attrs:
        value = settings.get(attr)
        if value is not None:
            setattr(device, attr, int(value))


# == PLUTO MIMO Connection Logic ==

def _usb_address_for_port(port):
    """The libiio usb address (bus.address.interface) now behind a physical
    USB port path such as "1-2.3" (Linux sysfs)."""
    base = Path("/sys/bus/usb/devices") / port
    try:
        prefix = f"{int((base / 'busnum').read_text())}.{int((base / 'devnum').read_text())}."
    except (OSError, ValueError):
        return ""
    out = subprocess.check_output(["iio_info", "-s"], text=True, stderr=subprocess.STDOUT)
    for address in re.findall(r"\[usb:([^\]]+)\]", out):
        if address.startswith(prefix):
            return address.strip()
    return ""


def connect_pluto_mimo(
    *,
    serial="",
    usb="",
    usb_port="",
    rx_enabled_channels=None,
    tx_enabled_channels=None,
    initial_settings=None,
):
    serial = (serial or "").strip()
    usb = (usb or "").strip()
    usb_port = (usb_port or "").strip()
    if not serial and not usb and not usb_port:
        print("An adalm_pluto_mimo serial, usb bus address or usb_port must be provided")
        return None

    try:
        if usb_port:
            # A board without a serial keeps its port across re-enumeration;
            # its bus address does not.
            usb = _usb_address_for_port(usb_port)
            if not usb:
                print(f"No adalm_pluto_mimo device found on USB port {usb_port}")
                return None

        if not usb:
            out = subprocess.check_output(
                ["iio_info", "-s"],
                text=True,
                stderr=subprocess.STDOUT,
            )

            for line in out.splitlines():
                if (f"serial={serial}" in line) or (f"hw_serial={serial}" in line):
                    m = re.search(r"\[usb:([^\]]+)\]", line)
                    if m:
                        usb = m.group(1).strip()
                        break

            if not usb:
                print(f"No adalm_pluto_mimo device found with serial {serial}")
                return None

        dev = adi.ad9361(f"usb:{usb}")
        dev.rx_enabled_channels = _normalize_channels(rx_enabled_channels, [0, 1])
        dev.tx_enabled_channels = _normalize_channels(tx_enabled_channels, [0, 1])
        _apply_initial_settings(dev, initial_settings or {})
        from remoteRF_server.common.utils.ansi_codes import Sty, printf

        printf(f"Connected to adalm_pluto_mimo serial={serial} via usb:{usb}", Sty.GRAY)
        return dev

    except Exception as e:
        from remoteRF_server.common.utils.ansi_codes import Sty, printf

        printf(f"Failed to connect to adalm_pluto_mimo serial={serial}: {e}", Sty.GRAY)
        return None


# ========================= PLUTO MIMO Schema =========================

@idl_register("adalm_pluto_mimo")
class PlutoMIMOSchema(PlutoSchema):

    device_type = "adalm_pluto_mimo"
    client_class = "PlutoMIMO"
    driver_version = "0.0.1"

    @staticmethod
    def make_device(**kwargs):
        return connect_pluto_mimo(
            serial=kwargs.get("serial"),
            usb=kwargs.get("usb"),
            usb_port=kwargs.get("usb_port"),
            rx_enabled_channels=kwargs.get("rx_enabled_channels"),
            tx_enabled_channels=kwargs.get("tx_enabled_channels"),
            initial_settings=kwargs,
        )

    # region MIMO channel selection

    @idl_expose(kind="get")
    def get_mode(self):
        return "mimo"

    @idl_expose(kind="get")
    def get_rx_enabled_channels(self):
        return list(self.device.rx_enabled_channels)

    @idl_expose(kind="set")
    def set_rx_enabled_channels(self, value):
        self.device.rx_enabled_channels = _normalize_channels(value, [0, 1])

    @idl_expose(kind="get")
    def get_tx_enabled_channels(self):
        return list(self.device.tx_enabled_channels)

    @idl_expose(kind="set")
    def set_tx_enabled_channels(self, value):
        self.device.tx_enabled_channels = _normalize_channels(value, [0, 1])

    # endregion

    # region channel 1 controls

    @idl_expose(kind="get")
    def get_gain_control_mode_chan1(self):
        return self.device.gain_control_mode_chan1

    @idl_expose(kind="set")
    def set_gain_control_mode_chan1(self, value):
        self.device.gain_control_mode_chan1 = value

    @idl_expose(kind="get")
    def get_rx_hardwaregain_chan1(self):
        """RX channel 1 hardware gain (dB)."""
        return _get_attr(self.device, "rx_hardwaregain_chan1", "hardwaregain_chan1")

    @idl_expose(kind="set")
    def set_rx_hardwaregain_chan1(self, value):
        """RX channel 1 hardware gain (dB)."""
        _set_attr(self.device, value, "rx_hardwaregain_chan1", "hardwaregain_chan1")

    @idl_expose(kind="get")
    def get_tx_hardwaregain_chan1(self):
        return self.device.tx_hardwaregain_chan1

    @idl_expose(kind="set")
    def set_tx_hardwaregain_chan1(self, value):
        self.device.tx_hardwaregain_chan1 = value

    # endregion

    # region AD9361 gain compatibility

    @idl_expose(kind="get")
    def get_rx_hardwaregain_chan0(self):
        """RX channel 0 hardware gain (dB)."""
        return _get_attr(self.device, "rx_hardwaregain_chan0", "hardwaregain_chan0")

    @idl_expose(kind="set")
    def set_rx_hardwaregain_chan0(self, value):
        """RX channel 0 hardware gain (dB)."""
        _set_attr(self.device, value, "rx_hardwaregain_chan0", "hardwaregain_chan0")

    # endregion
