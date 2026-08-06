"""Native HackRF controls exposed through the RemoteRF schema system."""
from __future__ import annotations

import json
from typing import Any

import numpy as np

from remoteRF_server.common.idl import DeviceSchema, idl_expose, idl_register

_MAX_REMOTE_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_COMPLEX64_SAMPLES = _MAX_REMOTE_PAYLOAD_BYTES // np.dtype(np.complex64).itemsize

VALID_FILTER_BANDWIDTHS = (
    1_750_000,
    2_500_000,
    3_500_000,
    5_000_000,
    5_500_000,
    6_000_000,
    7_000_000,
    8_000_000,
    9_000_000,
    10_000_000,
    12_000_000,
    14_000_000,
    15_000_000,
    20_000_000,
    24_000_000,
    28_000_000,
)


def _require_hackrf():
    try:
        from pyhackrf2 import HackRF
    except Exception as exc:
        raise RuntimeError(
            "HackRF support requires pyhackrf2 and the native libhackrf library "
            "on the machine that owns the radio"
        ) from exc
    return HackRF


def enumerate_hackrf_serials() -> list[str]:
    """Return attached HackRF serial numbers in device-index order."""
    HackRF = _require_hackrf()
    return [str(serial) for serial in (HackRF.enumerate() or [])]


def _resolve_device_index(
    *,
    serial: str | None,
    device_index: int | None,
    serials: list[str] | None = None,
) -> int:
    serial = str(serial or "").strip()
    if serial and device_index is not None:
        raise ValueError("configure either serial or device_index, not both")

    if serial:
        attached = enumerate_hackrf_serials() if serials is None else serials
        try:
            return attached.index(serial)
        except ValueError as exc:
            raise RuntimeError(
                f"no HackRF found with serial {serial!r}; attached serials: "
                f"{attached or ['(none)']}"
            ) from exc

    index = int(0 if device_index is None else device_index)
    if index < 0:
        raise ValueError("device_index must be >= 0")
    return index


def connect_hackrf(*, serial: str | None = None, device_index: int | None = None):
    """Open one HackRF by stable serial or zero-based device index."""
    HackRF = _require_hackrf()
    attached = [str(value) for value in (HackRF.enumerate() or [])] if serial else None
    index = _resolve_device_index(
        serial=serial,
        device_index=device_index,
        serials=attached,
    )
    return HackRF(device_index=index)


def _nearest_filter_bandwidth(value: Any) -> int:
    target = int(float(value))
    return min(VALID_FILTER_BANDWIDTHS, key=lambda item: abs(item - target))


def _coerce_bool(value: Any, *, label: str) -> bool:
    if isinstance(value, (bool, np.bool_)):
        return bool(value)
    if isinstance(value, (int, np.integer)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "on", "1"}:
            return True
        if normalized in {"false", "no", "off", "0"}:
            return False
    raise ValueError(f"{label} must be a boolean")


def _bounded_sample_count(value: Any) -> int:
    count = int(value)
    if count <= 0:
        raise ValueError("num_samples must be greater than zero")
    if count > _MAX_COMPLEX64_SAMPLES:
        raise ValueError(
            "num_samples exceeds the RemoteRF limit of "
            f"{_MAX_COMPLEX64_SAMPLES}"
        )
    return count


def _complex_to_iq_bytes(value: Any) -> bytearray:
    arr = np.asarray(value)
    if arr.size == 0:
        return bytearray()

    if not np.iscomplexobj(arr):
        if arr.ndim == 2 and arr.shape[-1] == 2:
            arr = arr[:, 0].astype(np.float32) + 1j * arr[:, 1].astype(np.float32)
        else:
            raise ValueError("TX IQ input must be a complex array or an Nx2 I/Q array")

    arr = np.asarray(arr, dtype=np.complex64).reshape(-1)
    if arr.size > _MAX_COMPLEX64_SAMPLES:
        raise ValueError(
            "TX IQ input exceeds the RemoteRF limit of "
            f"{_MAX_COMPLEX64_SAMPLES} samples"
        )
    if not np.all(np.isfinite(arr)):
        raise ValueError("TX IQ input must contain only finite samples")

    i = np.clip(np.real(arr), -1.0, 1.0)
    q = np.clip(np.imag(arr), -1.0, 1.0)
    out = np.empty(arr.size * 2, dtype=np.int8)
    out[0::2] = np.round(i * 127.0).astype(np.int8)
    out[1::2] = np.round(q * 127.0).astype(np.int8)
    return bytearray(out.tobytes())


def _tracked_property(device, public_name: str, private_name: str):
    """Read pyhackrf2's tracked value, including its broken 1.0.3 LNA getter."""
    if hasattr(device, private_name):
        return getattr(device, private_name)
    return getattr(device, public_name)


@idl_register("hackrf")
class HackRFSchema(DeviceSchema):
    """PyHackRF2-compatible tuning, gain, power, and bounded IQ controls."""

    device_type = "hackrf"
    client_class = "HackRF"
    driver_version = "0.1.0"

    @staticmethod
    def make_device(**kwargs):
        return connect_hackrf(
            serial=kwargs.get("serial"),
            device_index=kwargs.get("device_index"),
        )

    @idl_expose(kind="get")
    def get_center_freq(self):
        """Center frequency in Hz."""
        return int(self.device.center_freq)

    @idl_expose(kind="set")
    def set_center_freq(self, value):
        self.device.center_freq = int(float(value))

    @idl_expose(kind="get")
    def get_sample_rate(self):
        """Complex sample rate in samples per second."""
        return int(self.device.sample_rate)

    @idl_expose(kind="set")
    def set_sample_rate(self, value):
        self.device.sample_rate = int(float(value))

    @idl_expose(kind="get")
    def get_filter_bandwidth(self):
        """Baseband filter bandwidth in Hz."""
        return int(self.device.filter_bandwidth)

    @idl_expose(kind="set")
    def set_filter_bandwidth(self, value):
        self.device.filter_bandwidth = _nearest_filter_bandwidth(value)

    @idl_expose(kind="get")
    def get_lna_gain(self):
        """Receive IF LNA gain in dB (0 to 40, in 8 dB steps)."""
        return int(_tracked_property(self.device, "lna_gain", "_lna_gain"))

    @idl_expose(kind="set")
    def set_lna_gain(self, value):
        self.device.lna_gain = int(float(value))

    @idl_expose(kind="get")
    def get_vga_gain(self):
        """Receive baseband VGA gain in dB (0 to 62, in 2 dB steps)."""
        return int(self.device.vga_gain)

    @idl_expose(kind="set")
    def set_vga_gain(self, value):
        self.device.vga_gain = int(float(value))

    @idl_expose(kind="get")
    def get_txvga_gain(self):
        """Transmit VGA gain in dB (0 to 47)."""
        return int(self.device.txvga_gain)

    @idl_expose(kind="set")
    def set_txvga_gain(self, value):
        self.device.txvga_gain = int(float(value))

    @idl_expose(kind="get")
    def get_amplifier_on(self):
        """Whether the 14 dB RF front-end amplifier is enabled."""
        return bool(_tracked_property(self.device, "amplifier_on", "_amplifier_on"))

    @idl_expose(kind="set")
    def set_amplifier_on(self, value):
        enabled = _coerce_bool(value, label="amplifier_on")
        self.device.amplifier_on = enabled
        # pyhackrf2 1.0.3 does not update this tracked field in its setter.
        if hasattr(self.device, "_amplifier_on"):
            self.device._amplifier_on = enabled

    @idl_expose(kind="get")
    def get_bias_tee_on(self):
        """Whether 3.3 V antenna bias (50 mA maximum) is enabled."""
        return bool(_tracked_property(self.device, "bias_tee_on", "_bias_tee_on"))

    @idl_expose(kind="set")
    def set_bias_tee_on(self, value):
        self.device.bias_tee_on = _coerce_bool(value, label="bias_tee_on")

    @idl_expose(kind="get")
    def get_sample_count_limit(self):
        """Asynchronous receive limit in raw IQ bytes; zero means unlimited."""
        return int(self.device.sample_count_limit)

    @idl_expose(kind="set")
    def set_sample_count_limit(self, value):
        count = int(value)
        if count < 0:
            raise ValueError("sample_count_limit must be >= 0")
        self.device.sample_count_limit = count

    @idl_expose(kind="call")
    def call_read_samples(self, num_samples=131072):
        """Synchronously read a bounded complex64 IQ array."""
        count = _bounded_sample_count(num_samples)
        samples = np.asarray(self.device.read_samples(count), dtype=np.complex64)
        if samples.size != count:
            raise RuntimeError(
                f"short HackRF read: requested {count}, received {samples.size}"
            )
        return np.ascontiguousarray(samples.reshape(-1))

    @idl_expose(kind="call")
    def call_load_tx_iq(self, samples):
        """Convert normalized IQ samples and load the native transmit buffer."""
        payload = _complex_to_iq_bytes(samples)
        self.device.buffer = payload
        return len(payload)

    @idl_expose(kind="call")
    def call_enumerate(self):
        """Return attached serials as a JSON array for broad client compatibility."""
        return json.dumps(enumerate_hackrf_serials())

    @idl_expose(kind="call")
    def call_get_serial_no(self):
        """Read the serial number from the open device."""
        return str(self.device.get_serial_no())
