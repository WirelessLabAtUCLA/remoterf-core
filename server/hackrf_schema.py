from __future__ import annotations

from typing import Any

import numpy as np

from remoteRF_server.common.idl import DeviceSchema, idl_expose, idl_register


VALID_FILTER_BANDWIDTHS = [
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
]

DEFAULT_CENTER_FREQ = 433_200_000
DEFAULT_SAMPLE_RATE = 20_000_000
DEFAULT_FILTER_BANDWIDTH = 15_000_000
DEFAULT_LNA_GAIN = 16
DEFAULT_VGA_GAIN = 16
DEFAULT_TXVGA_GAIN = 10
DEFAULT_SAMPLE_COUNT_LIMIT = 0


def _import_hackrf_class():
    try:
        from pyhackrf2 import HackRF
    except Exception as exc:
        raise RuntimeError(
            "pyhackrf2 is required for the HackRF driver. "
            "Install it with: python -m pip install pyhackrf2"
        ) from exc
    return HackRF


def enumerate_hackrf_serials() -> list[str]:
    hackrf_cls = _import_hackrf_class()
    try:
        serials = hackrf_cls.enumerate() or []
    except Exception as exc:
        raise RuntimeError(f"HackRF enumeration failed: {exc}") from exc
    return [str(serial) for serial in serials]


def _resolve_device_index(*, serial: str | None, device_index: int | None) -> int:
    if serial:
        serials = enumerate_hackrf_serials()
        try:
            return serials.index(str(serial).strip())
        except ValueError as exc:
            raise ValueError(
                f"No HackRF found with serial {serial!r}. Attached serials: {serials or ['(none)']}"
            ) from exc

    if device_index is None:
        return 0
    return int(device_index)


def _nearest_filter_bandwidth(value: Any) -> int:
    target = int(float(value))
    return min(VALID_FILTER_BANDWIDTHS, key=lambda candidate: abs(candidate - target))


def _normalize_lna_gain(value: Any) -> int:
    n = max(0, min(40, int(float(value))))
    return (n // 8) * 8


def _normalize_vga_gain(value: Any) -> int:
    n = max(0, min(62, int(float(value))))
    return (n // 2) * 2


def _normalize_txvga_gain(value: Any) -> int:
    return max(0, min(47, int(float(value))))


def _complex_to_iq_bytes(value: Any) -> bytearray:
    arr = np.asarray(value)
    if arr.size == 0:
        return bytearray()

    if not np.iscomplexobj(arr):
        if arr.ndim == 2 and arr.shape[-1] == 2:
            arr = arr[:, 0].astype(np.float32) + 1j * arr[:, 1].astype(np.float32)
        else:
            raise ValueError("TX IQ input must be a complex array or an Nx2 I/Q array.")

    real = np.clip(np.real(arr), -1.0, 1.0)
    imag = np.clip(np.imag(arr), -1.0, 1.0)

    interleaved = np.empty(arr.size * 2, dtype=np.int8)
    interleaved[0::2] = np.round(real * 127.0).astype(np.int8)
    interleaved[1::2] = np.round(imag * 127.0).astype(np.int8)
    return bytearray(interleaved.tobytes())


def _iq_bytes_to_complex(data: bytes | bytearray) -> np.ndarray:
    raw = np.frombuffer(bytes(data), dtype=np.int8)
    if raw.size == 0:
        return np.array([], dtype=np.complex64)
    if raw.size % 2 == 1:
        raw = raw[:-1]

    i = raw[0::2].astype(np.float32) / 127.0
    q = raw[1::2].astype(np.float32) / 127.0
    return (i + 1j * q).astype(np.complex64)


class HackRFAdapter:
    def __init__(self, device, *, device_index: int, serial: str):
        self._device = device
        self._device_index = int(device_index)
        self._serial = serial
        self._is_open = True
        self._state = {
            "center_freq": DEFAULT_CENTER_FREQ,
            "sample_rate": DEFAULT_SAMPLE_RATE,
            "filter_bandwidth": DEFAULT_FILTER_BANDWIDTH,
            "lna_gain": DEFAULT_LNA_GAIN,
            "vga_gain": DEFAULT_VGA_GAIN,
            "amplifier_on": False,
            "bias_tee_on": False,
            "txvga_gain": DEFAULT_TXVGA_GAIN,
            "sample_count_limit": DEFAULT_SAMPLE_COUNT_LIMIT,
        }

    def __repr__(self) -> str:
        return (
            f"<HackRFAdapter serial={self._serial!r} "
            f"device_index={self._device_index} open={self._is_open}>"
        )

    @property
    def serial(self) -> str:
        return self._serial

    @property
    def device_index(self) -> int:
        return self._device_index

    @property
    def is_open(self) -> bool:
        return self._is_open

    @property
    def buffer(self) -> bytearray:
        return self._device.buffer

    @buffer.setter
    def buffer(self, value: bytes | bytearray) -> None:
        self._device.buffer = bytearray(value)

    @property
    def center_freq(self) -> int:
        return self._state["center_freq"]

    @center_freq.setter
    def center_freq(self, value: Any) -> None:
        normalized = int(float(value))
        self._device.center_freq = normalized
        self._state["center_freq"] = normalized

    @property
    def sample_rate(self) -> int:
        return self._state["sample_rate"]

    @sample_rate.setter
    def sample_rate(self, value: Any) -> None:
        normalized = int(float(value))
        self._device.sample_rate = normalized
        self._state["sample_rate"] = normalized

    @property
    def filter_bandwidth(self) -> int:
        return self._state["filter_bandwidth"]

    @filter_bandwidth.setter
    def filter_bandwidth(self, value: Any) -> None:
        normalized = _nearest_filter_bandwidth(value)
        self._device.filter_bandwidth = normalized
        self._state["filter_bandwidth"] = normalized

    @property
    def lna_gain(self) -> int:
        return self._state["lna_gain"]

    @lna_gain.setter
    def lna_gain(self, value: Any) -> None:
        normalized = _normalize_lna_gain(value)
        self._device.lna_gain = normalized
        self._state["lna_gain"] = normalized

    @property
    def vga_gain(self) -> int:
        return self._state["vga_gain"]

    @vga_gain.setter
    def vga_gain(self, value: Any) -> None:
        normalized = _normalize_vga_gain(value)
        self._device.vga_gain = normalized
        self._state["vga_gain"] = normalized

    @property
    def amplifier_on(self) -> bool:
        return self._state["amplifier_on"]

    @amplifier_on.setter
    def amplifier_on(self, value: Any) -> None:
        normalized = bool(value)
        self._device.amplifier_on = normalized
        self._state["amplifier_on"] = normalized

    @property
    def bias_tee_on(self) -> bool:
        return self._state["bias_tee_on"]

    @bias_tee_on.setter
    def bias_tee_on(self, value: Any) -> None:
        normalized = bool(value)
        self._device.bias_tee_on = normalized
        self._state["bias_tee_on"] = normalized

    @property
    def txvga_gain(self) -> int:
        return self._state["txvga_gain"]

    @txvga_gain.setter
    def txvga_gain(self, value: Any) -> None:
        normalized = _normalize_txvga_gain(value)
        self._device.txvga_gain = normalized
        self._state["txvga_gain"] = normalized

    @property
    def sample_count_limit(self) -> int:
        return self._state["sample_count_limit"]

    @sample_count_limit.setter
    def sample_count_limit(self, value: Any) -> None:
        normalized = max(0, int(float(value)))
        self._device.sample_count_limit = normalized
        self._state["sample_count_limit"] = normalized

    def get_serial_no(self) -> str:
        return str(self._device.get_serial_no())

    def read_samples(self, num_samples: int = 131072) -> np.ndarray:
        return np.asarray(self._device.read_samples(int(num_samples)), dtype=np.complex64)

    def start_rx(self) -> None:
        self._device.start_rx()

    def stop_rx(self) -> None:
        self._device.stop_rx()

    def start_tx(self) -> None:
        self._device.start_tx()

    def stop_tx(self) -> None:
        self._device.stop_tx()

    def clear_buffer(self) -> int:
        self._device.buffer = bytearray()
        return 0

    def get_buffer_iq(self) -> np.ndarray:
        return _iq_bytes_to_complex(self._device.buffer)

    def load_tx_iq(self, value: Any) -> int:
        payload = _complex_to_iq_bytes(value)
        self._device.buffer = payload
        return len(payload)

    def close(self) -> None:
        self._device.close()
        self._is_open = False


def connect_hackrf(*, serial: str | None = None, device_index: int | None = None, **_kwargs):
    hackrf_cls = _import_hackrf_class()
    index = _resolve_device_index(serial=serial, device_index=device_index)

    try:
        device = hackrf_cls(device_index=index)
    except Exception as exc:
        raise RuntimeError(f"Failed to open HackRF at index {index}: {exc}") from exc

    try:
        resolved_serial = str(device.get_serial_no())
    except Exception:
        resolved_serial = str(serial or "")

    return HackRFAdapter(device, device_index=index, serial=resolved_serial)


@idl_register("hackrf")
class HackRFSchema(DeviceSchema):
    device_type = "hackrf"
    driver_version = "0.1.1"

    @staticmethod
    def make_device(**kwargs):
        return connect_hackrf(**kwargs)

    @idl_expose(kind="get")
    def get_center_freq(self):
        """HackRF center frequency in Hz."""
        return self.device.center_freq

    @idl_expose(kind="set")
    def set_center_freq(self, value):
        """HackRF center frequency in Hz."""
        self.device.center_freq = value

    @idl_expose(kind="get")
    def get_sample_rate(self):
        """HackRF sample rate in Hz."""
        return self.device.sample_rate

    @idl_expose(kind="set")
    def set_sample_rate(self, value):
        """HackRF sample rate in Hz."""
        self.device.sample_rate = value

    @idl_expose(kind="get")
    def get_filter_bandwidth(self):
        """HackRF baseband filter bandwidth in Hz."""
        return self.device.filter_bandwidth

    @idl_expose(kind="set")
    def set_filter_bandwidth(self, value):
        """HackRF baseband filter bandwidth in Hz."""
        self.device.filter_bandwidth = value

    @idl_expose(kind="get")
    def get_lna_gain(self):
        """LNA gain in dB."""
        return self.device.lna_gain

    @idl_expose(kind="set")
    def set_lna_gain(self, value):
        """LNA gain in dB."""
        self.device.lna_gain = value

    @idl_expose(kind="get")
    def get_vga_gain(self):
        """RX VGA gain in dB."""
        return self.device.vga_gain

    @idl_expose(kind="set")
    def set_vga_gain(self, value):
        """RX VGA gain in dB."""
        self.device.vga_gain = value

    @idl_expose(kind="get")
    def get_amplifier_on(self):
        """Front-end amplifier enable state."""
        return self.device.amplifier_on

    @idl_expose(kind="set")
    def set_amplifier_on(self, value):
        """Front-end amplifier enable state."""
        self.device.amplifier_on = value

    @idl_expose(kind="get")
    def get_bias_tee_on(self):
        """Bias tee enable state."""
        return self.device.bias_tee_on

    @idl_expose(kind="set")
    def set_bias_tee_on(self, value):
        """Bias tee enable state."""
        self.device.bias_tee_on = value

    @idl_expose(kind="get")
    def get_txvga_gain(self):
        """TX VGA gain in dB."""
        return self.device.txvga_gain

    @idl_expose(kind="set")
    def set_txvga_gain(self, value):
        """TX VGA gain in dB."""
        self.device.txvga_gain = value

    @idl_expose(kind="get")
    def get_sample_count_limit(self):
        """Buffered RX stop threshold in bytes. Zero means run until stop_rx()."""
        return self.device.sample_count_limit

    @idl_expose(kind="set")
    def set_sample_count_limit(self, value):
        """Buffered RX stop threshold in bytes. Zero means run until stop_rx()."""
        self.device.sample_count_limit = value

    @idl_expose(kind="get")
    def get_repr(self):
        """Return a short debug representation of the bound HackRF adapter."""
        return repr(self.device)

    @idl_expose(kind="call")
    def call_enumerate(self):
        """Return attached HackRF serial numbers."""
        return enumerate_hackrf_serials()

    @idl_expose(kind="call")
    def call_get_serial_no(self):
        """Return the serial number of the bound HackRF."""
        return self.device.get_serial_no()

    @idl_expose(kind="call")
    def call_get_filter_bandwidth_options(self):
        """Return supported HackRF baseband filter bandwidths."""
        return VALID_FILTER_BANDWIDTHS

    @idl_expose(kind="call")
    def call_read_samples(self, num_samples=131072):
        """Read a fixed number of complex IQ samples."""
        return self.device.read_samples(num_samples)

    @idl_expose(kind="call")
    def call_start_rx_buffered(self, sample_count_limit=0):
        """Start asynchronous RX and append raw bytes into the internal buffer."""
        self.device.sample_count_limit = sample_count_limit
        self.device.start_rx()

    @idl_expose(kind="call")
    def call_stop_rx(self):
        """Stop an asynchronous RX session."""
        self.device.stop_rx()

    @idl_expose(kind="call")
    def call_get_buffer_iq(self):
        """Decode the current internal byte buffer into complex IQ samples."""
        return self.device.get_buffer_iq()

    @idl_expose(kind="call")
    def call_clear_buffer(self):
        """Clear the internal RX/TX byte buffer."""
        return self.device.clear_buffer()

    @idl_expose(kind="call")
    def call_load_tx_iq(self, value):
        """Convert complex IQ samples into HackRF int8 IQ bytes and load the TX buffer."""
        return self.device.load_tx_iq(value)

    @idl_expose(kind="call")
    def call_start_tx(self):
        """Start transmitting the current TX buffer."""
        self.device.start_tx()

    @idl_expose(kind="call")
    def call_stop_tx(self):
        """Stop an active TX session."""
        self.device.stop_tx()

    @idl_expose(kind="call")
    def call_close(self):
        """Close the bound HackRF handle."""
        self.device.close()
