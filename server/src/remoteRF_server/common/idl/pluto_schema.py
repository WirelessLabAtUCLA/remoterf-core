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

# SAMPLE schema for ADI Pluto SDR.
# Place into -> ~/.config/remoterf/drivers and restart server to utilize!


from remoteRF_server.common.idl import DeviceSchema, idl_register, idl_expose
from remoteRF_server.drivers.adalm_pluto.poe import PoePluto, is_poe, poe_pluto_from_init

import subprocess
import re
import adi


def _normalize_channels(value):
    """Restore channel lists after numeric lists cross the legacy RPC codec."""
    if hasattr(value, "tolist"):
        value = value.tolist()
    if isinstance(value, tuple):
        value = list(value)
    if not isinstance(value, list):
        return value

    channels = []
    for channel in value:
        if not isinstance(channel, str):
            integer = int(channel)
            if channel == integer:
                channel = integer
        channels.append(channel)
    return channels


# == PLUTO Connection Logic ==

def connect_pluto(*, serial: str, ip: str = ""):
    serial = (serial or "").strip()
    ip = (ip or "").strip()
    if ip:
        # An always-powered Pluto on the network (its static ipaddr_eth).
        try:
            dev = adi.Pluto(f"ip:{ip}")
            found = str(dev._ctx.attrs.get("hw_serial", "")).strip()
            if serial and found.lower() != serial.lower():
                print(f"ip:{ip} is Pluto {found}, expected {serial}")
                return None
            from remoteRF_server.common.utils.ansi_codes import Sty, printf

            printf(f"Connected to Pluto via ip:{ip}", Sty.GRAY)
            return dev
        except Exception as e:
            print(f"Failed to connect to Pluto ip:{ip}: {e}")
            return None
    if not serial:
        print("A Pluto serial must be provided")
        return None

    try:
        out = subprocess.check_output(
            ["iio_info", "-s"],
            text=True,
            stderr=subprocess.STDOUT
        )

        usb = None
        for line in out.splitlines():
            if (f"serial={serial}" in line) or (f"hw_serial={serial}" in line):
                m = re.search(r"\[usb:([^\]]+)\]", line)
                if m:
                    usb = m.group(1).strip()
                    break

        if not usb:
            print(f"No device found with serial {serial}")
            return None

        dev = adi.Pluto(f"usb:{usb}")
        from remoteRF_server.common.utils.ansi_codes import Sty, printf

        printf(f"Connected to Pluto serial={serial} via usb:{usb}", Sty.GRAY)
        return dev

    except Exception as e:
        print(f"Failed to connect to Pluto serial={serial}: {e}")
        return None

# ========================= PLUTO Schema =========================

@idl_register("adalm_pluto")
class PlutoSchema(DeviceSchema):

    device_type = "adalm_pluto"
    client_class = "Pluto"
    driver_version = "0.0.4"
    _fir_rate = None  # the rate whose pyadi FIR this schema last loaded

    @staticmethod
    def make_device(**kwargs):
        # init.poe: true -> the Pluto is powered from a PoE switch port and starts off.
        if is_poe(kwargs):
            return poe_pluto_from_init(kwargs)
        return connect_pluto(serial=kwargs.get("serial"), ip=kwargs.get("ip"))

    # region ad9364

    @idl_expose(kind="get")
    def get_filter(self):
        return self.device.filter

    @idl_expose(kind="set")
    def set_filter(self, value):
        self._fir_rate = None
        self.device.filter = value

    @idl_expose(kind="get")
    def get_loopback(self):
        return self.device.loopback

    @idl_expose(kind="set")
    def set_loopback(self, value):
        self.device.loopback = value

    @idl_expose(kind="get")
    def get_gain_control_mode_chan0(self):
        return self.device.gain_control_mode_chan0

    @idl_expose(kind="set")
    def set_gain_control_mode_chan0(self, value):
        self.device.gain_control_mode_chan0 = value

    @idl_expose(kind="get")
    def get_rx_hardwaregain_chan0(self):
        """RX hardware gain (dB). pyadi-iio attribute: rx_hardwaregain_chan0"""
        return self.device.rx_hardwaregain_chan0

    @idl_expose(kind="set")
    def set_rx_hardwaregain_chan0(self, value):
        """RX hardware gain (dB). pyadi-iio attribute: rx_hardwaregain_chan0"""
        self.device.rx_hardwaregain_chan0 = value

    @idl_expose(kind="get")
    def get_tx_hardwaregain_chan0(self):
        return self.device.tx_hardwaregain_chan0

    @idl_expose(kind="set")
    def set_tx_hardwaregain_chan0(self, value):
        self.device.tx_hardwaregain_chan0 = value

    @idl_expose(kind="get")
    def get_rx_rf_bandwidth(self):
        return self.device.rx_rf_bandwidth

    @idl_expose(kind="set")
    def set_rx_rf_bandwidth(self, value):
        self.device.rx_rf_bandwidth = value

    @idl_expose(kind="get")
    def get_tx_rf_bandwidth(self):
        return self.device.tx_rf_bandwidth

    @idl_expose(kind="set")
    def set_tx_rf_bandwidth(self, value):
        self.device.tx_rf_bandwidth = value

    @idl_expose(kind="get")
    def get_sample_rate(self):
        return self.device.sample_rate

    @idl_expose(kind="set")
    def set_sample_rate(self, value):
        # pyadi reloads its FIR and re-runs the AD9361 rate chain (~0.8 s) even
        # for an unchanged rate: skip only what our own last set left in place.
        if value == self._fir_rate:
            try:
                if (
                    self.device.sample_rate == value
                    and self.device._get_iio_attr("out", "voltage_filter_fir_en", False) == 1
                ):
                    return
            except Exception:
                pass
        self._fir_rate = None
        self.device.sample_rate = value
        self._fir_rate = value

    @idl_expose(kind="get")
    def get_rx_lo(self):
        return self.device.rx_lo

    @idl_expose(kind="set")
    def set_rx_lo(self, value):
        self.device.rx_lo = value

    @idl_expose(kind="get")
    def get_tx_lo(self):
        return self.device.tx_lo

    @idl_expose(kind="set")
    def set_tx_lo(self, value):
        self.device.tx_lo = value

    @idl_expose(kind="get")
    def get_tx_cyclic_buffer(self):
        return self.device.tx_cyclic_buffer

    @idl_expose(kind="set")
    def set_tx_cyclic_buffer(self, value):
        self.device.tx_cyclic_buffer = value

    # region RX/TX

    @idl_expose(kind="call")
    def call_rx(self):
        return self.device.rx()

    @idl_expose(kind="get")
    def get_rx_buffer_size(self):
        return self.device.rx_buffer_size

    @idl_expose(kind="set")
    def set_rx_buffer_size(self, value):
        # pyadi reads rx_buffer_size only when it (re)creates the RX buffer.
        if value != self.device.rx_buffer_size:
            self.device.rx_destroy_buffer()
        self.device.rx_buffer_size = value

    @idl_expose(kind="call")
    def call_rx_destroy_buffer(self):
        self.device.rx_destroy_buffer()

    @idl_expose(kind="call")
    def call_tx(self, value):
        self.device.tx(value)

    @idl_expose(kind="call")
    def call_tx_destroy_buffer(self):
        self.device.tx_destroy_buffer()

    def reset_for_next_holder(self):
        """A reservation ended: a PoE Pluto powers off. Otherwise stop its cyclic
        transmission, and drop its RX buffer so the next holder's rx_buffer_size takes effect."""
        self._fir_rate = None
        if isinstance(self.device, PoePluto):
            self.device.power_down()
        elif self.device is not None:
            self.device.tx_destroy_buffer()
            self.device.rx_destroy_buffer()

    def prepare_for_holder(self):
        """A reservation started: a PoE Pluto boots now, not at the holder's first command."""
        if isinstance(self.device, PoePluto):
            self.device.power_up()

    @idl_expose(kind="call")
    def call_disable_dds(self):
        """Disable the internal DDS tone generator."""
        self.device.disable_dds()

    # region power (PoE Plutos; a no-op on any other Pluto)

    @idl_expose(kind="call")
    def call_power_up(self):
        """PoE Plutos: power on and wait for boot (any command does this when needed). No-op on other Plutos."""
        if isinstance(self.device, PoePluto):
            self.device.power_up()

    @idl_expose(kind="call")
    def call_power_down(self):
        """PoE Plutos: cut power; the next command powers it back up. No-op on other Plutos."""
        self._fir_rate = None
        if isinstance(self.device, PoePluto):
            self.device.power_down()

    @idl_expose(kind="call")
    def call_power_cycle(self):
        """PoE Plutos: power off, then on, and wait for boot. No-op on other Plutos."""
        self._fir_rate = None
        if isinstance(self.device, PoePluto):
            self.device.power_cycle()

    # endregion

    # region DDS

    @idl_expose(kind="call")
    def call_dds_single_tone(self, frequency, scale, channel=0):
        """Generate one complex DDS tone on the selected TX channel."""
        self.device.dds_single_tone(frequency, scale, channel)

    @idl_expose(kind="call")
    def call_dds_dual_tone(
        self,
        frequency1,
        scale1,
        frequency2,
        scale2,
        channel=0,
    ):
        """Generate two complex DDS tones on the selected TX channel."""
        self.device.dds_dual_tone(
            frequency1,
            scale1,
            frequency2,
            scale2,
            channel,
        )

    @idl_expose(kind="get")
    def get_dds_frequencies(self):
        return self.device.dds_frequencies

    @idl_expose(kind="set")
    def set_dds_frequencies(self, value):
        self.device.dds_frequencies = value

    @idl_expose(kind="get")
    def get_dds_scales(self):
        return self.device.dds_scales

    @idl_expose(kind="set")
    def set_dds_scales(self, value):
        self.device.dds_scales = value

    @idl_expose(kind="get")
    def get_dds_phases(self):
        return self.device.dds_phases

    @idl_expose(kind="set")
    def set_dds_phases(self, value):
        self.device.dds_phases = value

    @idl_expose(kind="get")
    def get_dds_enabled(self):
        return self.device.dds_enabled

    @idl_expose(kind="set")
    def set_dds_enabled(self, value):
        self.device.dds_enabled = value

    # endregion

    # region channel configuration

    @idl_expose(kind="get")
    def get_rx_enabled_channels(self):
        return self.device.rx_enabled_channels

    @idl_expose(kind="set")
    def set_rx_enabled_channels(self, value):
        self.device.rx_enabled_channels = _normalize_channels(value)

    @idl_expose(kind="get")
    def get_tx_enabled_channels(self):
        return self.device.tx_enabled_channels

    @idl_expose(kind="set")
    def set_tx_enabled_channels(self, value):
        self.device.tx_enabled_channels = _normalize_channels(value)

    @idl_expose(kind="get")
    def get_rx_annotated(self):
        return self.device.rx_annotated

    @idl_expose(kind="set")
    def set_rx_annotated(self, value):
        self.device.rx_annotated = value

    @idl_expose(kind="get")
    def get_rx_output_type(self):
        return self.device.rx_output_type

    @idl_expose(kind="set")
    def set_rx_output_type(self, value):
        self.device.rx_output_type = value

    @idl_expose(kind="get")
    def get_rx_channel_names(self):
        return self.device.rx_channel_names

    @idl_expose(kind="get")
    def get_tx_channel_names(self):
        return self.device.tx_channel_names

    # endregion

    # endregion

    # region ip / repr

    @idl_expose(kind="call")
    def call_ip(self):
        """Return a connection identifier for this device (ping / verify)."""
        try:
            return str(self.device.uri)
        except AttributeError:
            return str(self.device._uri_auto)

    @idl_expose(kind="get")
    def get_repr(self):
        """Return repr() of the underlying device object."""
        return repr(self.device)

    # endregion

    # region _dec_int_fpga_filter

    @idl_expose(kind="get")
    def get_rx_dec8_filter_en(self):
        """rx_dec8_filter_en: Enable decimate-by-8 filter in FPGA"""
        return bool(self.device.rx_dec8_filter_en)

    @idl_expose(kind="set")
    def set_rx_dec8_filter_en(self, value):
        """rx_dec8_filter_en: Enable decimate-by-8 filter in FPGA"""
        self.device.rx_dec8_filter_en = value

    @idl_expose(kind="get")
    def get_tx_int8_filter_en(self):
        """tx_int8_filter_en: Enable interpolate-by-8 filter in FPGA"""
        return bool(self.device.tx_int8_filter_en)

    @idl_expose(kind="set")
    def set_tx_int8_filter_en(self, value):
        """tx_int8_filter_en: Enable interpolate-by-8 filter in FPGA"""
        self.device.tx_int8_filter_en = value

    @idl_expose(kind="get")
    def get_rates(self):
        """Get decimation/interpolation rates from the FPGA filter block."""
        return self.device._get_rates(self.device._rxadc, False)

    # endregion
