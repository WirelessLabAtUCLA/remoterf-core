"""Simulated SDR: no hardware. rx() returns a complex tone at sample_rate/8 plus
a little noise, so a test can check length, dtype and the FFT peak (bin n/8).

No docstrings on the exposed methods: they are part of the schema hash, and
without them it matches the SimSDR client bundled with `remoterf`
(sha256:3e5daa54...)."""
from __future__ import annotations

import numpy as np
from remoteRF_server.common.idl import DeviceSchema, idl_expose, idl_register

_MAX_SAMPLES = 1 << 19  # 4 MiB of complex64, the remote payload limit


class SimDevice:
    def __init__(self):
        self.rx_lo = 2_400_000_000
        self.sample_rate = 1_000_000
        self.rx_buffer_size = 1024

    def rx(self) -> np.ndarray:
        n = int(self.rx_buffer_size)
        tone = np.exp(2j * np.pi * np.arange(n) / 8).astype(np.complex64)
        noise = (np.random.standard_normal(n) + 1j * np.random.standard_normal(n)) * 0.01
        return (tone + noise).astype(np.complex64)


@idl_register("sim_sdr")
class SimSdrSchema(DeviceSchema):
    """Simulated receive-only SDR for test labs."""

    device_type = "sim_sdr"
    client_class = "SimSDR"
    driver_version = "0.1.0"

    @staticmethod
    def make_device(**kwargs):
        return SimDevice()

    @idl_expose(kind="get")
    def get_rx_lo(self):
        return self.device.rx_lo

    @idl_expose(kind="set")
    def set_rx_lo(self, value):
        self.device.rx_lo = int(value)

    @idl_expose(kind="get")
    def get_sample_rate(self):
        return self.device.sample_rate

    @idl_expose(kind="set")
    def set_sample_rate(self, value):
        self.device.sample_rate = int(value)

    @idl_expose(kind="get")
    def get_rx_buffer_size(self):
        return self.device.rx_buffer_size

    @idl_expose(kind="set")
    def set_rx_buffer_size(self, value):
        value = int(value)
        if not 0 < value <= _MAX_SAMPLES:
            raise ValueError(f"rx_buffer_size must be 1..{_MAX_SAMPLES}")
        self.device.rx_buffer_size = value

    @idl_expose(kind="call")
    def call_ip(self):
        return "sim"

    @idl_expose(kind="call")
    def call_rx(self):
        return self.device.rx()
