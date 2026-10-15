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

"""KrakenSDR: five R820T2 RTL-SDR tuners on one clock, used as one device.

Each tuner opens through the built-in rtl_sdr driver by its USB serial (a
KrakenSDR ships as 1000-1004). Settings apply to all five; a read starts all
five together and returns one array per channel.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import numpy as np

from remoteRF_server.common.idl import DeviceSchema, idl_expose, idl_register
from remoteRF_server.drivers.rtl_sdr.rtl_sdr_schema import (
    _MAX_COMPLEX64_SAMPLES,
    _bounded_count,
    _connect_rtl_sdr,
    _whole_packets,
)

DEFAULT_SERIALS = ("1000", "1001", "1002", "1003", "1004")


class KrakenDevice:
    def __init__(self, serials):
        self.channels = []
        try:
            for serial in serials:
                self.channels.append(_connect_rtl_sdr(serial=serial))
        except Exception:
            self.close()
            raise
        self.serials = [str(s) for s in serials]

    def close(self) -> None:
        channels, self.channels = self.channels, []
        for channel in channels:
            channel.close()


@idl_register("kraken_sdr")
class KrakenSdrSchema(DeviceSchema):
    """Receive-only, five channels. ponytail: the five reads start together but are
    neither sample-aligned nor phase-calibrated (each tune gives each R820T2 its own
    phase); coherent direction finding needs the KrakenSDR Heimdall DAQ firmware."""

    device_type = "kraken_sdr"
    client_class = "KrakenSDR"
    driver_version = "0.0.1"

    @staticmethod
    def make_device(**kwargs):
        return KrakenDevice([str(s) for s in kwargs.get("serials") or DEFAULT_SERIALS])

    def _natives(self):
        natives = [channel.native for channel in self.device.channels]
        if not natives or any(n is None or getattr(n, "device_opened", True) is False for n in natives):
            raise RuntimeError("KrakenSDR is closed")
        return natives

    def _set_all(self, name, value):
        for native in self._natives():
            setattr(native, name, value)

    @idl_expose(kind="get")
    def get_num_channels(self):
        return len(self.device.channels)

    @idl_expose(kind="get")
    def get_serials(self):
        return list(self.device.serials)

    @idl_expose(kind="get")
    def get_center_freq(self):
        """Center frequency in Hz (channel 0; every channel is tuned together)."""
        return float(self._natives()[0].center_freq)

    @idl_expose(kind="set")
    def set_center_freq(self, value):
        self._set_all("center_freq", float(value))

    @idl_expose(kind="get")
    def get_sample_rate(self):
        return float(self._natives()[0].sample_rate)

    @idl_expose(kind="set")
    def set_sample_rate(self, value):
        self._set_all("sample_rate", float(value))

    @idl_expose(kind="get")
    def get_gain(self):
        """Tuner gain in dB per channel."""
        return [native.gain for native in self._natives()]

    @idl_expose(kind="set")
    def set_gain(self, value):
        """One gain in dB (or "auto") for every channel."""
        self._set_all("gain", value if str(value).lower() == "auto" else float(value))

    @idl_expose(kind="get")
    def get_valid_gains_db(self):
        return [float(g) for g in self._natives()[0].valid_gains_db]

    @idl_expose(kind="get")
    def get_tuner_type(self):
        return self._natives()[0].get_tuner_type()

    @idl_expose(kind="call")
    def call_read_samples(self, num_samples=1024):
        """Read normalized complex64 IQ from all five channels: a list of five arrays."""
        natives = self._natives()
        count = _bounded_count(num_samples, label="num_samples", maximum=_MAX_COMPLEX64_SAMPLES // len(natives))
        read = _whole_packets(2 * count) // 2
        for native in natives:
            reset = getattr(native, "reset_buffer", None)  # absent from some pyrtlsdr builds (0.5.0 RtlSdrAio)
            if callable(reset):
                reset()
        with ThreadPoolExecutor(len(natives)) as pool:
            reads = list(pool.map(lambda n: np.asarray(n.read_samples(read), dtype=np.complex64)[:count], natives))
        for index, samples in enumerate(reads):
            if samples.size != count:
                raise RuntimeError(f"short read on channel {index}: requested {count}, received {samples.size}")
        return [np.ascontiguousarray(samples) for samples in reads]
