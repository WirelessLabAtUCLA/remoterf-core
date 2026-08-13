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

"""TI mmWave dual-UART control and framed data acquisition.

The initial RemoteRF profile targets the xWR68xx out-of-box demo protocol:
an application/CLI UART at 115200 baud and a binary data UART at 921600
baud.  The transport deliberately returns complete raw packets.  Firmware-
specific TLV interpretation belongs to the client support module advertised
by this schema.
"""
from __future__ import annotations

import math
import queue
import struct
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterable

try:
    from remoteRF_server.common.idl import DeviceSchema, idl_expose, idl_register
except ImportError:
    from remoteRF_host.common.idl import DeviceSchema, idl_expose, idl_register

CP2105_VENDOR_ID = 0x10C4
CP2105_PRODUCT_ID = 0xEA70
DEFAULT_CLI_BAUD = 115_200
DEFAULT_DATA_BAUD = 921_600
DEFAULT_FIRMWARE_PROFILE = "xwr68xx_oob_sdk3"
TI_FRAME_MAGIC = b"\x02\x01\x04\x03\x06\x05\x08\x07"

_MIN_FRAME_BYTES = 40
_MAX_FRAME_BYTES = 4 * 1024 * 1024
_MAX_CONFIG_BYTES = 64 * 1024
_MAX_CONFIG_COMMANDS = 512
_MAX_COMMAND_BYTES = 1024
_MAX_COMMAND_TIMEOUT_SEC = 30.0
_DATA_READ_BYTES = 16 * 1024


def _require_pyserial():
    try:
        import serial
        from serial.tools import list_ports
    except Exception as exc:
        raise RuntimeError(
            "TI mmWave support requires pyserial on the machine that owns the "
            "radar. On macOS, the Silicon Labs CP210x VCP driver must also be "
            "installed so both UART device nodes are present."
        ) from exc
    return serial, list_ports


@dataclass(frozen=True)
class PortSelection:
    cli_port: str
    data_port: str
    bridge_serial: str
    cli_interface: str = "Enhanced Com Port"
    data_interface: str = "Standard Com Port"


def _port_text(port: Any) -> str:
    return " ".join(
        str(getattr(port, name, "") or "")
        for name in ("interface", "description", "product", "name", "device")
    ).lower()


def _port_summary(port: Any) -> str:
    return (
        f"{getattr(port, 'device', '?')} "
        f"serial={getattr(port, 'serial_number', None)!r} "
        f"interface={getattr(port, 'interface', None)!r}"
    )


def discover_ti_mmwave_ports(
    *,
    serial: str | None = None,
    cli_port: str | None = None,
    data_port: str | None = None,
    ports: Iterable[Any] | None = None,
    vendor_id: int = CP2105_VENDOR_ID,
    product_id: int = CP2105_PRODUCT_ID,
) -> PortSelection:
    """Resolve the Enhanced and Standard CP2105 interfaces for one radar."""
    bridge_serial = str(serial or "").strip()
    explicit_cli = str(cli_port or "").strip()
    explicit_data = str(data_port or "").strip()
    if explicit_cli and explicit_data:
        if explicit_cli == explicit_data:
            raise ValueError("cli_port and data_port must be different device nodes")
        return PortSelection(explicit_cli, explicit_data, bridge_serial)

    if ports is None:
        _serial, list_ports = _require_pyserial()
        ports = list_ports.comports()
    candidates = [
        port
        for port in ports
        if int(getattr(port, "vid", -1) or -1) == int(vendor_id)
        and int(getattr(port, "pid", -1) or -1) == int(product_id)
        and (
            not bridge_serial
            or str(getattr(port, "serial_number", "") or "").strip()
            == bridge_serial
        )
    ]

    if not bridge_serial:
        serials = {
            str(getattr(port, "serial_number", "") or "").strip()
            for port in candidates
            if str(getattr(port, "serial_number", "") or "").strip()
        }
        if len(serials) == 1:
            bridge_serial = next(iter(serials))
        elif len(serials) > 1:
            raise RuntimeError(
                "multiple CP2105 bridges are attached; configure the TI radar serial"
            )

    enhanced = [port for port in candidates if "enhanced" in _port_text(port)]
    standard = [port for port in candidates if "standard" in _port_text(port)]

    resolved_cli = explicit_cli or (
        str(getattr(enhanced[0], "device", "")) if len(enhanced) == 1 else ""
    )
    resolved_data = explicit_data or (
        str(getattr(standard[0], "device", "")) if len(standard) == 1 else ""
    )
    if not resolved_cli or not resolved_data or resolved_cli == resolved_data:
        attached = "; ".join(_port_summary(port) for port in candidates) or "none"
        raise RuntimeError(
            "could not uniquely resolve the TI mmWave Enhanced (CLI) and Standard "
            f"(data) UARTs; matching ports: {attached}. Configure cli_port and "
            "data_port explicitly if the OS does not publish interface names."
        )

    return PortSelection(
        cli_port=resolved_cli,
        data_port=resolved_data,
        bridge_serial=bridge_serial,
        cli_interface=str(getattr(enhanced[0], "interface", "") or "Enhanced Com Port")
        if enhanced
        else "Enhanced Com Port",
        data_interface=str(getattr(standard[0], "interface", "") or "Standard Com Port")
        if standard
        else "Standard Com Port",
    )


class TiFrameAccumulator:
    """Incrementally recover complete TI packets from an arbitrary byte stream."""

    def __init__(self, *, maximum_frame_bytes: int = _MAX_FRAME_BYTES):
        self.maximum_frame_bytes = int(maximum_frame_bytes)
        self.buffer = bytearray()
        self.discarded_bytes = 0
        self.invalid_headers = 0

    def clear(self) -> None:
        self.buffer.clear()

    def feed(self, data: bytes | bytearray | memoryview) -> list[bytes]:
        if data:
            self.buffer.extend(data)
        frames: list[bytes] = []
        while True:
            magic_at = self.buffer.find(TI_FRAME_MAGIC)
            if magic_at < 0:
                keep = min(len(self.buffer), len(TI_FRAME_MAGIC) - 1)
                discarded = len(self.buffer) - keep
                if discarded:
                    del self.buffer[:discarded]
                    self.discarded_bytes += discarded
                break
            if magic_at:
                del self.buffer[:magic_at]
                self.discarded_bytes += magic_at
            if len(self.buffer) < 16:
                break

            total_length = struct.unpack_from("<I", self.buffer, 12)[0]
            if not _MIN_FRAME_BYTES <= total_length <= self.maximum_frame_bytes:
                del self.buffer[0]
                self.invalid_headers += 1
                self.discarded_bytes += 1
                continue
            if len(self.buffer) < total_length:
                break

            frames.append(bytes(self.buffer[:total_length]))
            del self.buffer[:total_length]
        return frames


def _positive_baud(value: Any, *, label: str) -> int:
    baud = int(value)
    if baud <= 0 or baud > 10_000_000:
        raise ValueError(f"{label} must be between 1 and 10000000")
    return baud


def _bounded_timeout(value: Any, *, label: str) -> float:
    timeout = float(value)
    if (
        not math.isfinite(timeout)
        or timeout < 0
        or timeout > _MAX_COMMAND_TIMEOUT_SEC
    ):
        raise ValueError(
            f"{label} must be between 0 and {_MAX_COMMAND_TIMEOUT_SEC:g} seconds"
        )
    return timeout


def _open_serial(serial_module, *, port: str, baudrate: int):
    options = dict(
        port=port,
        baudrate=baudrate,
        bytesize=getattr(serial_module, "EIGHTBITS", 8),
        parity=getattr(serial_module, "PARITY_NONE", "N"),
        stopbits=getattr(serial_module, "STOPBITS_ONE", 1),
        timeout=0.1,
        write_timeout=2.0,
    )
    try:
        return serial_module.Serial(exclusive=True, **options)
    except TypeError:
        return serial_module.Serial(**options)


class TiMmWaveDevice:
    """Own both UARTs and buffer complete data packets in a bounded queue."""

    def __init__(
        self,
        selection: PortSelection,
        *,
        cli_baud: int = DEFAULT_CLI_BAUD,
        data_baud: int = DEFAULT_DATA_BAUD,
        firmware_profile: str = DEFAULT_FIRMWARE_PROFILE,
        frame_queue_depth: int = 8,
        serial_module=None,
        start_reader: bool = True,
    ):
        if serial_module is None:
            serial_module, _list_ports = _require_pyserial()
        depth = int(frame_queue_depth)
        if depth < 1 or depth > 1024:
            raise ValueError("frame_queue_depth must be between 1 and 1024")

        self.selection = selection
        self.cli_baud = _positive_baud(cli_baud, label="cli_baud")
        self.data_baud = _positive_baud(data_baud, label="data_baud")
        self.firmware_profile = str(firmware_profile or "").strip()
        if not self.firmware_profile:
            raise ValueError("firmware_profile must not be empty")

        self._cli_lock = threading.Lock()
        self._frame_lock = threading.Lock()
        self._frames: queue.Queue[bytes] = queue.Queue(maxsize=depth)
        self._accumulator = TiFrameAccumulator()
        self._stop_event = threading.Event()
        self._reader_error = ""
        self._reader_thread: threading.Thread | None = None
        self._frames_received = 0
        self._frames_dropped = 0
        self._bytes_received = 0
        self._commands_sent = 0
        self._running = False
        self._closed = False

        self.cli_serial = _open_serial(
            serial_module, port=selection.cli_port, baudrate=self.cli_baud
        )
        try:
            self.data_serial = _open_serial(
                serial_module, port=selection.data_port, baudrate=self.data_baud
            )
        except Exception:
            self.cli_serial.close()
            raise

        if start_reader:
            self._reader_thread = threading.Thread(
                target=self._reader_loop,
                name=f"ti-mmwave-{selection.bridge_serial or selection.data_port}",
                daemon=True,
            )
            self._reader_thread.start()

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def running(self) -> bool:
        return self._running

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("TI mmWave device is closed")

    def _reader_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                chunk = self.data_serial.read(_DATA_READ_BYTES)
            except Exception as exc:
                if not self._stop_event.is_set():
                    self._reader_error = f"{type(exc).__name__}: {exc}"
                return
            if chunk:
                self._ingest_data(chunk)

    def _ingest_data(self, data: bytes) -> int:
        """Feed transport bytes into the frame queue; also used by tests."""
        with self._frame_lock:
            self._bytes_received += len(data)
            frames = self._accumulator.feed(data)
            for frame in frames:
                if self._frames.full():
                    try:
                        self._frames.get_nowait()
                    except queue.Empty:
                        pass
                    self._frames_dropped += 1
                self._frames.put_nowait(frame)
                self._frames_received += 1
            return len(frames)

    def stream_stats(self) -> dict[str, Any]:
        with self._frame_lock:
            return {
                "frames_received": self._frames_received,
                "frames_dropped": self._frames_dropped,
                "frames_queued": self._frames.qsize(),
                "bytes_received": self._bytes_received,
                "discarded_bytes": self._accumulator.discarded_bytes,
                "invalid_headers": self._accumulator.invalid_headers,
                "reader_alive": bool(
                    self._reader_thread and self._reader_thread.is_alive()
                ),
                "reader_error": self._reader_error,
            }

    def device_info(self) -> dict[str, Any]:
        return {
            "bridge_serial": self.selection.bridge_serial,
            "usb_vendor_id": CP2105_VENDOR_ID,
            "usb_product_id": CP2105_PRODUCT_ID,
            "cli_port": self.selection.cli_port,
            "data_port": self.selection.data_port,
            "cli_interface": self.selection.cli_interface,
            "data_interface": self.selection.data_interface,
            "cli_baud": self.cli_baud,
            "data_baud": self.data_baud,
            "firmware_profile": self.firmware_profile,
            "running": self._running,
            "closed": self._closed,
            "stream": self.stream_stats(),
        }

    @staticmethod
    def _normalize_command(command: Any) -> str:
        text = str(command or "").strip()
        if not text:
            raise ValueError("command must not be empty")
        if "\r" in text or "\n" in text:
            raise ValueError("send_command accepts exactly one command line")
        if len(text.encode("utf-8")) > _MAX_COMMAND_BYTES:
            raise ValueError(f"command exceeds {_MAX_COMMAND_BYTES} bytes")
        return text

    @staticmethod
    def _response_failed(response: str) -> bool:
        lowered = response.lower()
        return any(
            marker in lowered
            for marker in (
                "not recognized as a cli command",
                "unrecognized command",
                "exception:",
                "error ",
                "error:",
            )
        )

    def send_command(self, command: Any, *, timeout: float = 2.0) -> str:
        self._ensure_open()
        text = self._normalize_command(command)
        timeout = _bounded_timeout(timeout, label="timeout")
        deadline = time.monotonic() + timeout
        prompt = b"mmwDemo:/>"

        with self._cli_lock:
            reset = getattr(self.cli_serial, "reset_input_buffer", None)
            if callable(reset):
                reset()
            self.cli_serial.write(text.encode("utf-8") + b"\n")
            flush = getattr(self.cli_serial, "flush", None)
            if callable(flush):
                flush()
            self._commands_sent += 1

            response = bytearray()
            while time.monotonic() <= deadline:
                chunk = self.cli_serial.read(512)
                if chunk:
                    response.extend(chunk)
                    if prompt in response:
                        break
                elif timeout == 0:
                    break
            if prompt not in response:
                raise TimeoutError(
                    "TI mmWave CLI did not return its prompt within "
                    f"{timeout:g} seconds"
                )

        decoded = response.decode("utf-8", errors="replace").replace("\r", "")
        decoded = decoded.replace("mmwDemo:/>", "").strip()
        lines = decoded.splitlines()
        if lines and lines[0].strip() == text:
            lines = lines[1:]
        return "\n".join(lines).strip()

    def apply_config(
        self,
        config_text: Any,
        *,
        start: bool = False,
        command_timeout: float = 2.0,
    ) -> dict[str, Any]:
        self._ensure_open()
        raw = str(config_text or "")
        if not raw.strip():
            raise ValueError("config_text must not be empty")
        if len(raw.encode("utf-8")) > _MAX_CONFIG_BYTES:
            raise ValueError(f"config_text exceeds {_MAX_CONFIG_BYTES} bytes")

        commands = [
            line.strip()
            for line in raw.splitlines()
            if line.strip()
            and not line.lstrip().startswith(("%", "#", "//"))
        ]
        if not commands:
            raise ValueError("config_text contains no commands")
        if len(commands) > _MAX_CONFIG_COMMANDS:
            raise ValueError(f"config_text exceeds {_MAX_CONFIG_COMMANDS} commands")

        last_response = ""
        for index, command in enumerate(commands, start=1):
            last_response = self.send_command(command, timeout=command_timeout)
            if self._response_failed(last_response):
                raise RuntimeError(
                    f"TI mmWave config command {index} failed: {command!r}: "
                    f"{last_response}"
                )
            verb = command.split(None, 1)[0].lower()
            if verb == "sensorstart":
                self._running = True
            elif verb == "sensorstop":
                self._running = False

        started_here = bool(start and not self._running)
        if started_here:
            last_response = self.start(timeout=command_timeout)
        return {
            "commands_sent": len(commands) + int(started_here),
            "running": self._running,
            "last_response": last_response,
        }

    def start(self, *, timeout: float = 2.0) -> str:
        response = self.send_command("sensorStart", timeout=timeout)
        if self._response_failed(response):
            raise RuntimeError(f"TI mmWave sensorStart failed: {response}")
        self._running = True
        return response

    def stop(self, *, timeout: float = 2.0) -> str:
        response = self.send_command("sensorStop", timeout=timeout)
        if self._response_failed(response):
            raise RuntimeError(f"TI mmWave sensorStop failed: {response}")
        self._running = False
        return response

    def query_version(self, *, timeout: float = 2.0) -> str:
        return self.send_command("version", timeout=timeout)

    def read_frame(self, *, timeout: float = 1.0) -> bytes:
        self._ensure_open()
        timeout = _bounded_timeout(timeout, label="timeout")
        try:
            return self._frames.get(timeout=timeout)
        except queue.Empty as exc:
            if self._reader_error:
                raise RuntimeError(
                    f"TI mmWave data reader stopped: {self._reader_error}"
                ) from exc
            raise TimeoutError(
                f"no complete TI mmWave frame received within {timeout:g} seconds"
            ) from exc

    def flush_frames(self) -> int:
        self._ensure_open()
        removed = 0
        with self._frame_lock:
            while True:
                try:
                    self._frames.get_nowait()
                    removed += 1
                except queue.Empty:
                    break
            self._accumulator.clear()
            reset = getattr(self.data_serial, "reset_input_buffer", None)
            if callable(reset):
                reset()
        return removed

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop_event.set()
        for handle in (self.data_serial, self.cli_serial):
            try:
                handle.close()
            except Exception:
                pass
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=1.0)


def connect_ti_mmwave(
    *,
    serial: str | None = None,
    bridge_serial: str | None = None,
    cli_port: str | None = None,
    data_port: str | None = None,
    cli_baud: int = DEFAULT_CLI_BAUD,
    data_baud: int = DEFAULT_DATA_BAUD,
    firmware_profile: str = DEFAULT_FIRMWARE_PROFILE,
    frame_queue_depth: int = 8,
    serial_module=None,
    ports: Iterable[Any] | None = None,
    start_reader: bool = True,
) -> TiMmWaveDevice:
    selection = discover_ti_mmwave_ports(
        serial=bridge_serial or serial,
        cli_port=cli_port,
        data_port=data_port,
        ports=ports,
    )
    return TiMmWaveDevice(
        selection,
        cli_baud=cli_baud,
        data_baud=data_baud,
        firmware_profile=firmware_profile,
        frame_queue_depth=frame_queue_depth,
        serial_module=serial_module,
        start_reader=start_reader,
    )


@idl_register("ti_mmwave")
class TiMmWaveSchema(DeviceSchema):
    """TI xWR mmWave CLI controls and bounded raw TLV frame reads."""

    device_type = "ti_mmwave"
    client_class = "TiMmWave"
    driver_version = "0.1.0"
    client_modules = {
        "ti_mmwave": "remoteRF.drivers.support.ti_mmwave",
    }

    @staticmethod
    def make_device(**kwargs):
        return connect_ti_mmwave(
            serial=kwargs.get("serial"),
            bridge_serial=kwargs.get("bridge_serial"),
            cli_port=kwargs.get("cli_port"),
            data_port=kwargs.get("data_port"),
            cli_baud=kwargs.get("cli_baud", DEFAULT_CLI_BAUD),
            data_baud=kwargs.get("data_baud", DEFAULT_DATA_BAUD),
            firmware_profile=kwargs.get(
                "firmware_profile", DEFAULT_FIRMWARE_PROFILE
            ),
            frame_queue_depth=kwargs.get("frame_queue_depth", 8),
        )

    @idl_expose(kind="get")
    def get_device_info(self):
        """USB/UART identity, firmware profile, and current stream state."""
        return self.device.device_info()

    @idl_expose(kind="get")
    def get_stream_stats(self):
        """Frame queue, resynchronization, and reader health counters."""
        return self.device.stream_stats()

    @idl_expose(kind="get")
    def get_firmware_profile(self):
        return self.device.firmware_profile

    @idl_expose(kind="get")
    def get_is_running(self):
        return self.device.running

    @idl_expose(kind="call")
    def call_send_command(self, command, timeout=2.0):
        """Send one runtime CLI command and return the textual response."""
        return self.device.send_command(command, timeout=timeout)

    @idl_expose(kind="call")
    def call_apply_config(self, config_text, start=False, command_timeout=2.0):
        """Apply newline-delimited TI CLI configuration commands in order."""
        return self.device.apply_config(
            config_text,
            start=start,
            command_timeout=command_timeout,
        )

    @idl_expose(kind="call")
    def call_start(self, timeout=2.0):
        return self.device.start(timeout=timeout)

    @idl_expose(kind="call")
    def call_stop(self, timeout=2.0):
        return self.device.stop(timeout=timeout)

    @idl_expose(kind="call")
    def call_query_version(self, timeout=2.0):
        return self.device.query_version(timeout=timeout)

    @idl_expose(kind="call")
    def call_read_frame(self, timeout=1.0):
        """Return one complete raw TI UART packet as bytes."""
        return self.device.read_frame(timeout=timeout)

    @idl_expose(kind="call")
    def call_flush_frames(self):
        """Discard queued and partially assembled data frames."""
        return self.device.flush_frames()

