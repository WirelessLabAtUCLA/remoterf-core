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

"""Native HackRF controls exposed through the RemoteRF schema system."""
from __future__ import annotations

import ctypes
import json
from importlib.metadata import PackageNotFoundError, version
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


def _correct_pyhackrf2_iq(samples: Any) -> np.ndarray:
    """Undo pyhackrf2 1.0.3's erroneous post-conversion ``- (1+1j)``."""
    values = np.asarray(samples, dtype=np.complex64)
    try:
        affected = version("pyhackrf2") == "1.0.3"
    except PackageNotFoundError:
        affected = False
    if affected:
        values = values + np.complex64(1.0 + 1.0j)
    return values


def _complex_to_iq_bytes(value: Any) -> bytearray:
    arr = np.asarray(value)
    if arr.size == 0:
        return bytearray()

    if not np.iscomplexobj(arr):
        # Match the common libhackrf Python binding convention: a signed int8
        # array is already interleaved I/Q bytes and must not be normalized or
        # scaled again.  A two-column int8 array is the same representation in
        # a more convenient shape.
        if arr.dtype == np.dtype(np.int8):
            if arr.ndim == 2 and arr.shape[-1] == 2:
                arr = arr.reshape(-1)
            if arr.ndim == 1:
                if arr.size % 2:
                    raise ValueError("interleaved int8 TX IQ must contain I/Q pairs")
                if arr.nbytes > _MAX_REMOTE_PAYLOAD_BYTES:
                    raise ValueError(
                        "interleaved int8 TX IQ exceeds the RemoteRF limit of "
                        f"{_MAX_REMOTE_PAYLOAD_BYTES} bytes"
                    )
                return bytearray(np.ascontiguousarray(arr).tobytes())
        if arr.ndim == 2 and arr.shape[-1] == 2:
            arr = arr[:, 0].astype(np.float32) + 1j * arr[:, 1].astype(np.float32)
        else:
            raise ValueError(
                "TX IQ input must be normalized complex samples, an Nx2 I/Q array, "
                "or interleaved signed int8 I/Q bytes"
            )

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


def _install_safe_tx_callback(device: Any) -> None:
    """Replace pyhackrf2's unsafe TX callback with one that fills libhackrf memory.

    pyhackrf2 1.0.3 replaces ``transfer.buffer`` with a pointer to a temporary
    Python ``bytearray``.  libhackrf owns that buffer and continues using it
    after the callback returns, so replacing it permits a use-after-free and
    can crash the process.  This callback leaves the C-owned pointer intact,
    copies a retained cyclic payload into it, and keeps streaming until the
    caller explicitly invokes ``stop_tx``.
    """
    if getattr(device, "_remoterf_safe_tx_callback_installed", False):
        return

    existing_callback = getattr(device, "_cfunc_tx_callback", None)
    if existing_callback is None:
        # Non-pyhackrf2 test doubles and compatible implementations may offer
        # start_tx without exposing their private ctypes callback.
        return

    callback_type = type(existing_callback)

    def _tx_callback(transfer_pointer) -> int:
        try:
            transfer = transfer_pointer.contents
            payload = getattr(device, "_remoterf_tx_payload", b"")
            buffer_length = int(transfer.buffer_length)
            if not payload or buffer_length <= 0:
                transfer.valid_length = 0
                return 1

            # libhackrf supplies a C-owned buffer for every async USB
            # transfer. Fill it completely by repeating the user payload, so
            # it remains valid until the USB layer releases it.
            repeats = (buffer_length + len(payload) - 1) // len(payload)
            block = (payload * repeats)[:buffer_length]
            ctypes.memmove(transfer.buffer, block, buffer_length)
            transfer.valid_length = buffer_length
            return 0
        except BaseException:
            # Never let a Python exception unwind through a ctypes callback.
            return 1

    safe_callback = callback_type(_tx_callback)
    # Keep the ctypes function object strongly referenced for the lifetime of
    # the device; otherwise its callback trampoline could itself be collected.
    device._remoterf_safe_tx_callback = safe_callback
    device._remoterf_safe_tx_callback_installed = True
    device._cfunc_tx_callback = safe_callback


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
    driver_version = "0.1.1"

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
        samples = _correct_pyhackrf2_iq(self.device.read_samples(count))
        if samples.size != count:
            raise RuntimeError(
                f"short HackRF read: requested {count}, received {samples.size}"
            )
        return np.ascontiguousarray(samples.reshape(-1))

    @idl_expose(kind="call")
    def call_load_tx_iq(self, samples):
        """Load normalized complex or native interleaved signed-int8 TX IQ."""
        payload = _complex_to_iq_bytes(samples)
        if not payload:
            raise ValueError("TX IQ input must contain at least one sample")
        self.device.buffer = payload
        self.device._remoterf_tx_payload = bytes(payload)
        _install_safe_tx_callback(self.device)
        return len(payload)

    @idl_expose(kind="call")
    def call_setup(self):
        """Confirm the already-managed remote HackRF is ready for use."""
        # The RemoteRF server owns the physical device for its whole lifetime,
        # so there is no native setup action to repeat for each client.
        return None

    @idl_expose(kind="call")
    def call_set_freq(self, value):
        """Compatibility alias for setting the center frequency in Hz."""
        self.set_center_freq(value)

    @idl_expose(kind="call")
    def call_set_sample_rate(self, value):
        """Compatibility alias for setting the complex sample rate in Hz."""
        self.set_sample_rate(value)

    @idl_expose(kind="call")
    def call_start_tx(self):
        """Start transmitting the IQ bytes previously loaded with load_tx_iq()."""
        if getattr(self.device, "_remoterf_tx_active", False):
            raise RuntimeError("HackRF TX is already active; stop it before starting again")
        payload_bytes = len(self.device.buffer)
        if payload_bytes <= 0:
            raise RuntimeError("load TX IQ samples before starting transmission")
        self.device.start_tx()
        self.device._remoterf_tx_active = True
        return payload_bytes

    @idl_expose(kind="call")
    def call_stop_tx(self):
        """Stop an active HackRF transmission."""
        if not getattr(self.device, "_remoterf_tx_active", False):
            return
        try:
            self.device.stop_tx()
        finally:
            self.device._remoterf_tx_active = False

    @idl_expose(kind="call")
    def call_clear_buffer(self):
        """Clear any captured or queued IQ bytes while the radio is idle."""
        if getattr(self.device, "_remoterf_tx_active", False):
            raise RuntimeError("stop HackRF TX before clearing its buffer")
        self.device.buffer = bytearray()
        self.device._remoterf_tx_payload = b""
        return 0

    @idl_expose(kind="call")
    def call_close(self):
        """Safely end this remote TX use without closing the server-owned radio."""
        self.call_stop_tx()
        self.call_clear_buffer()
        # Calling pyhackrf2.close() here can tear down the shared production
        # device and has been observed to crash its native libhackrf path.
        return None

    @idl_expose(kind="call")
    def call_enumerate(self):
        """Return attached serials as a JSON array for broad client compatibility."""
        return json.dumps(enumerate_hackrf_serials())

    @idl_expose(kind="call")
    def call_get_serial_no(self):
        """Read the serial number from the open device."""
        return str(self.device.get_serial_no())
