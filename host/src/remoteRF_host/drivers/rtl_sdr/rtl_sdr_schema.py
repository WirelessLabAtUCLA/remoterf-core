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

"""Native receive-only RTL-SDR support through the RemoteRF schema system."""
from __future__ import annotations

import inspect
from typing import Any

import numpy as np

from remoteRF_host.common.idl import DeviceSchema, idl_expose, idl_register

_MAX_REMOTE_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_COMPLEX64_SAMPLES = _MAX_REMOTE_PAYLOAD_BYTES // np.dtype(np.complex64).itemsize

def _require_rtlsdr():
    try:
        from rtlsdr import RtlSdr
    except Exception as exc:
        raise RuntimeError(
            "RTL-SDR support requires pyrtlsdr and the native "
            "librtlsdr library on the machine that owns the radio"
        ) from exc
    return RtlSdr


def _bounded_count(value: Any, *, label: str, maximum: int) -> int:
    count = int(value)
    if count <= 0:
        raise ValueError(f"{label} must be greater than zero")
    if count > maximum:
        raise ValueError(f"{label} exceeds the RemoteRF limit of {maximum}")
    return count


class _RtlSdrAdapter:
    def __init__(
        self,
        native,
        *,
        device_index: int,
        serial_number: str,
        usb_strings: tuple[str, str, str],
        test_mode_enabled: bool,
        dithering_enabled: bool | None,
    ):
        self.native = native
        self.device_index = int(device_index)
        self.serial_number = str(serial_number or "")
        self.usb_strings = tuple(str(item or "") for item in usb_strings)
        self.test_mode_enabled = bool(test_mode_enabled)
        self.control_state = {
            "agc_mode": None,
            "bias_tee": None,
            "direct_sampling": None,
            "offset_tuning": None,
            "dithering": (
                None if dithering_enabled is None else bool(dithering_enabled)
            ),
        }

    def close(self) -> None:
        native, self.native = self.native, None
        close = getattr(native, "close", None)
        if callable(close):
            close()


def _connect_rtl_sdr(
    *,
    serial: str | None = None,
    device_index: int | None = None,
    test_mode_enabled: bool = False,
    dithering_enabled: bool = True,
):
    RtlSdr = _require_rtlsdr()
    serial = str(serial or "").strip()
    if serial and device_index is not None:
        raise ValueError("configure either serial or device_index, not both")

    if serial:
        resolved_index = int(RtlSdr.get_device_index_by_serial(serial))
        if resolved_index < 0:
            raise RuntimeError(f"no RTL-SDR found with serial {serial!r}")
    else:
        resolved_index = int(0 if device_index is None else device_index)
        if resolved_index < 0:
            raise ValueError("device_index must be >= 0")

    try:
        usb_strings = tuple(RtlSdr.get_device_usb_strings(resolved_index))
    except Exception:
        usb_strings = ("", "", serial)

    constructor_params = inspect.signature(RtlSdr).parameters
    accepts_kwargs = any(
        param.kind is inspect.Parameter.VAR_KEYWORD
        for param in constructor_params.values()
    )
    open_kwargs = {
        "device_index": resolved_index,
        "test_mode_enabled": bool(test_mode_enabled),
    }
    supports_dithering_at_open = (
        accepts_kwargs or "dithering_enabled" in constructor_params
    )
    if supports_dithering_at_open:
        open_kwargs["dithering_enabled"] = bool(dithering_enabled)
    native = RtlSdr(**open_kwargs)
    resolved_serial = serial or (usb_strings[2] if len(usb_strings) > 2 else "")
    return _RtlSdrAdapter(
        native,
        device_index=resolved_index,
        serial_number=resolved_serial,
        usb_strings=usb_strings if len(usb_strings) == 3 else ("", "", resolved_serial),
        test_mode_enabled=bool(test_mode_enabled),
        dithering_enabled=(
            bool(dithering_enabled)
            if supports_dithering_at_open
            or callable(getattr(native, "set_dithering", None))
            else None
        ),
    )


@idl_register("rtl_sdr")
class RtlSdrSchema(DeviceSchema):
    """PyRtlSdr-compatible receive controls and bounded sample acquisition."""

    device_type = "rtl_sdr"
    client_class = "RtlSdr"
    driver_version = "0.1.1"

    @staticmethod
    def make_device(**kwargs):
        return _connect_rtl_sdr(**kwargs)

    @property
    def _native(self):
        native = getattr(self.device, "native", None)
        if native is None:
            raise RuntimeError("RTL-SDR device is closed")
        return native

    def _require_native_method(self, name):
        method = getattr(self._native, name, None)
        if not callable(method):
            raise NotImplementedError(
                f"the installed PyRtlSdr/librtlsdr runtime does not support {name}"
            )
        return method

    @idl_expose(kind="get")
    def get_center_freq(self):
        """Tuner center frequency in Hz."""
        return float(self._native.center_freq)

    @idl_expose(kind="set")
    def set_center_freq(self, value):
        self._native.center_freq = float(value)

    @idl_expose(kind="get")
    def get_fc(self):
        """Alias for center_freq, matching PyRtlSdr."""
        return float(self._native.center_freq)

    @idl_expose(kind="set")
    def set_fc(self, value):
        self._native.center_freq = float(value)

    @idl_expose(kind="get")
    def get_sample_rate(self):
        """Complex sample rate in samples per second."""
        return float(self._native.sample_rate)

    @idl_expose(kind="set")
    def set_sample_rate(self, value):
        self._native.sample_rate = float(value)

    @idl_expose(kind="get")
    def get_rs(self):
        """Alias for sample_rate, matching PyRtlSdr."""
        return float(self._native.sample_rate)

    @idl_expose(kind="set")
    def set_rs(self, value):
        self._native.sample_rate = float(value)

    @idl_expose(kind="get")
    def get_gain(self):
        """Tuner gain in dB, or auto when automatic gain is enabled."""
        return self._native.gain

    @idl_expose(kind="set")
    def set_gain(self, value):
        self._native.gain = value if str(value).lower() == "auto" else float(value)

    @idl_expose(kind="get")
    def get_valid_gains_db(self):
        return [float(value) for value in self._native.valid_gains_db]

    @idl_expose(kind="get")
    def get_freq_correction(self):
        """Frequency correction in parts per million."""
        return int(self._native.freq_correction)

    @idl_expose(kind="set")
    def set_freq_correction(self, value):
        self._native.freq_correction = int(value)

    @idl_expose(kind="get")
    def get_bandwidth(self):
        """Tuner bandwidth in Hz; zero requests automatic selection."""
        return float(self._native.bandwidth)

    @idl_expose(kind="set")
    def set_bandwidth(self, value):
        self._native.bandwidth = float(value)

    @idl_expose(kind="get")
    def get_tuner_type(self):
        return self._native.get_tuner_type()

    @idl_expose(kind="get")
    def get_device_index(self):
        return int(self.device.device_index)

    @idl_expose(kind="get")
    def get_serial_number(self):
        return self.device.serial_number

    @idl_expose(kind="get")
    def get_usb_strings(self):
        manufacturer, product, serial = self.device.usb_strings
        return {
            "manufacturer": manufacturer,
            "product": product,
            "serial": serial,
        }

    @idl_expose(kind="get")
    def get_agc_mode(self):
        return self.device.control_state["agc_mode"]

    @idl_expose(kind="set")
    def set_agc_mode(self, value):
        enabled = bool(value)
        self._native.set_agc_mode(enabled)
        self.device.control_state["agc_mode"] = enabled

    @idl_expose(kind="get")
    def get_bias_tee(self):
        return self.device.control_state["bias_tee"]

    @idl_expose(kind="set")
    def set_bias_tee(self, value):
        enabled = bool(value)
        self._require_native_method("set_bias_tee")(enabled)
        self.device.control_state["bias_tee"] = enabled

    @idl_expose(kind="get")
    def get_direct_sampling(self):
        getter = getattr(self._native, "get_direct_sampling", None)
        if callable(getter):
            return getter()
        return self.device.control_state["direct_sampling"]

    @idl_expose(kind="set")
    def set_direct_sampling(self, value):
        self._require_native_method("set_direct_sampling")(value)
        self.device.control_state["direct_sampling"] = value

    @idl_expose(kind="get")
    def get_offset_tuning(self):
        getter = getattr(self._native, "get_offset_tuning", None)
        if callable(getter):
            return bool(getter())
        return self.device.control_state["offset_tuning"]

    @idl_expose(kind="set")
    def set_offset_tuning(self, value):
        enabled = bool(value)
        self._require_native_method("set_offset_tuning")(enabled)
        self.device.control_state["offset_tuning"] = enabled

    @idl_expose(kind="get")
    def get_dithering(self):
        return self.device.control_state["dithering"]

    @idl_expose(kind="set")
    def set_dithering(self, value):
        enabled = bool(value)
        self._require_native_method("set_dithering")(enabled)
        self.device.control_state["dithering"] = enabled

    @idl_expose(kind="call")
    def call_reset_buffer(self):
        """Discard pending USB samples before a new capture."""
        self._require_native_method("reset_buffer")()

    @idl_expose(kind="call")
    def call_read_samples(self, num_samples=1024):
        """Read normalized complex64 IQ samples."""
        count = _bounded_count(
            num_samples,
            label="num_samples",
            maximum=_MAX_COMPLEX64_SAMPLES,
        )
        samples = np.asarray(self._native.read_samples(count), dtype=np.complex64)
        if samples.size != count:
            raise RuntimeError(
                f"short RTL-SDR read: requested {count}, received {samples.size}"
            )
        return np.ascontiguousarray(samples)

    @idl_expose(kind="call")
    def call_read_bytes(self, num_bytes=1024):
        """Read packed unsigned 8-bit interleaved IQ bytes."""
        count = _bounded_count(
            num_bytes,
            label="num_bytes",
            maximum=_MAX_REMOTE_PAYLOAD_BYTES,
        )
        payload = bytes(self._native.read_bytes(count))
        if len(payload) != count:
            raise RuntimeError(
                f"short RTL-SDR byte read: requested {count}, received {len(payload)}"
            )
        return payload
