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

"""RFbeam K-MD7 24 GHz radar on its UART (FTDI FT230X USB adapter).

RFbeam binary protocol: a 4-letter header, a uint32 little-endian payload
length, the payload; 115200 baud, 8E1. Every command is answered by RESP
(one error byte, 0 = OK) and then any data packets (VERS, RPST, PDAT, ...).
Payloads come back raw: the K-MD7 datasheet describes their layout.
"""
from __future__ import annotations

import re
import struct
import threading

import serial

from remoteRF_server.common.idl import DeviceSchema, idl_expose, idl_register

BAUD = 115200
IDLE_S = 0.2  # quiet this long after RESP: no more packets are coming
MAX_PAYLOAD = 256
HEADER = re.compile(r"[A-Z]{4}")
LINK_COMMANDS = {"INIT", "GBYE"}  # the driver owns the link: a baud change would strand it


class KMD7:
    def __init__(self, port, timeout=1.0):
        self.port = serial.Serial(port, BAUD, parity=serial.PARITY_EVEN, timeout=timeout)
        self.timeout = timeout
        self.lock = threading.Lock()
        try:
            packets = self.request("INIT", struct.pack("<I", 0))  # 0 = stay at 115200
        except Exception:
            self.port.close()
            raise
        self.version = packets.get("VERS", b"").rstrip(b"\0").decode(errors="replace")

    def _read(self, n):
        data = self.port.read(n)
        if len(data) != n:
            raise TimeoutError(f"K-MD7: read {len(data)} of {n} bytes")
        return data

    def request(self, header, payload=b""):
        """Send one command; return the packets after its RESP as {header: payload}."""
        with self.lock:
            self.port.reset_input_buffer()
            self.port.write(header.encode() + struct.pack("<I", len(payload)) + payload)
            head = self._read(8)
            body = self._read(struct.unpack("<I", head[4:])[0])
            if head[:4] != b"RESP" or not body:
                raise RuntimeError(f"K-MD7: expected RESP to {header}, got {head[:4]!r}")
            if body[0]:
                raise RuntimeError(f"K-MD7 rejected {header}: error {body[0]}")
            packets = {}
            try:
                while True:
                    self.port.timeout = IDLE_S
                    head = self.port.read(8)
                    self.port.timeout = self.timeout
                    if not head:
                        return packets
                    if len(head) != 8:
                        raise TimeoutError("K-MD7: truncated packet header")
                    packets[head[:4].decode(errors="replace")] = self._read(struct.unpack("<I", head[4:])[0])
            finally:
                self.port.timeout = self.timeout

    def close(self):
        try:
            self.request("GBYE")
        finally:
            self.port.close()


@idl_register("rfbeam_kmd7")
class KMD7Schema(DeviceSchema):
    device_type = "rfbeam_kmd7"
    client_class = "KMD7"
    driver_version = "0.0.1"

    @staticmethod
    def make_device(**kwargs):
        port = str(kwargs.get("port") or "").strip()
        if not port:
            raise ValueError("an rfbeam_kmd7 device needs init.port (a /dev/serial/by-id/... path)")
        return KMD7(port, timeout=float(kwargs.get("timeout", 1.0)))

    @idl_expose(kind="get")
    def get_version(self):
        """Firmware version string, e.g. K-MD7_APP-RFB-0205."""
        return self.device.version

    @idl_expose(kind="get")
    def get_parameters(self):
        """The raw RPST parameter structure (GRPS)."""
        return self.device.request("GRPS").get("RPST", b"")

    @idl_expose(kind="call")
    def call_frame(self, flags):
        """GNFD: the next frame's data packets for the requested flag bits, {header: bytes}."""
        return self.device.request("GNFD", struct.pack("<I", int(flags)))

    @idl_expose(kind="call")
    def call_command(self, header, value=None):
        """Any other command (parameter set, SRPS, RFSE, ...): value is an int32,
        raw bytes, or None for no payload. Returns the packets after RESP."""
        header = str(header)
        if not HEADER.fullmatch(header) or header in LINK_COMMANDS:
            raise ValueError(f"not an allowed K-MD7 command: {header!r}")
        if value is None:
            payload = b""
        elif isinstance(value, (bytes, bytearray)):
            payload = bytes(value)
        else:
            payload = struct.pack("<i", int(value))
        if len(payload) > MAX_PAYLOAD:
            raise ValueError(f"payload over {MAX_PAYLOAD} bytes")
        return self.device.request(header, payload)
