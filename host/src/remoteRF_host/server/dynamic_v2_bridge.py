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

"""Tunnel adapter for the additive Dynamic v2 and SampleData v1 protocols."""
from __future__ import annotations

import queue
import threading

from ..common.grpc import grpc_pb2
from ..common.utils import map_arg, unmap_arg
from .device_manager import make_host_bridge_token
from .dynamic_v2 import (
    DynamicControlV2Servicer,
    SampleDataV1Servicer,
    session_manager,
)
from .v2_errors import RemoteRFProtocolError


_CONTROL = DynamicControlV2Servicer()
_SAMPLES = SampleDataV1Servicer()


def _wire_arg(args: dict) -> bytes:
    value = args.get("wire")
    if value is None:
        raise RemoteRFProtocolError("tunneled Dynamic v2 request is missing wire data")
    wire = unmap_arg(value)
    if not isinstance(wire, bytes):
        raise RemoteRFProtocolError("tunneled Dynamic v2 wire data must be bytes")
    return wire


def _assert_session_gid(session_id: str, gid: int) -> None:
    session = session_manager.get(session_id)
    if session.gid != int(gid):
        raise RemoteRFProtocolError("Dynamic v2 session does not belong to this device")


class _FrameIterator:
    def __init__(self):
        self.frames: queue.Queue = queue.Queue()

    def __iter__(self):
        return self

    def __next__(self):
        return self.frames.get()


class _SampleOperation:
    def __init__(self):
        self.iterator = _FrameIterator()
        self.generator = _SAMPLES.SampleStream(self.iterator, None)
        self.lock = threading.RLock()

    def process(self, frame):
        with self.lock:
            self.iterator.frames.put(frame)
            try:
                return next(self.generator)
            except StopIteration as exc:
                raise RemoteRFProtocolError("sample operation is already closed") from exc

    def close(self):
        with self.lock:
            self.generator.close()


class SampleTunnelBridge:
    def __init__(self):
        self._lock = threading.RLock()
        self._operations: dict[tuple[str, str, str], _SampleOperation] = {}

    @staticmethod
    def _key(frame) -> tuple[str, str, str]:
        return (frame.session_id, frame.handle, frame.operation_id)

    def process(self, frame, *, gid: int):
        _assert_session_gid(frame.session_id, gid)
        key = self._key(frame)

        if frame.kind == grpc_pb2.SAMPLE_FRAME_OPEN:
            operation = _SampleOperation()
            with self._lock:
                if key in self._operations:
                    raise RemoteRFProtocolError("sample operation is already open")
                self._operations[key] = operation
        else:
            with self._lock:
                operation = self._operations.get(key)
            if operation is None:
                raise RemoteRFProtocolError("sample operation must begin with OPEN")

        response = operation.process(frame)
        terminal = bool(
            response.end_of_stream
            or response.kind == grpc_pb2.SAMPLE_FRAME_ERROR
            or (
                frame.direction == grpc_pb2.SAMPLE_DIRECTION_RX
                and frame.kind == grpc_pb2.SAMPLE_FRAME_REQUEST
                and response.kind == grpc_pb2.SAMPLE_FRAME_DATA
            )
            or (
                frame.direction == grpc_pb2.SAMPLE_DIRECTION_TX
                and frame.kind == grpc_pb2.SAMPLE_FRAME_DATA
                and response.kind == grpc_pb2.SAMPLE_FRAME_RESULT
            )
            or frame.kind in {
                grpc_pb2.SAMPLE_FRAME_CANCEL,
                grpc_pb2.SAMPLE_FRAME_CLOSE,
            }
        )
        if terminal:
            with self._lock:
                self._operations.pop(key, None)
            operation.close()
        return response

    def close_session(self, session_id: str) -> None:
        with self._lock:
            matches = [
                (key, operation)
                for key, operation in self._operations.items()
                if key[0] == session_id
            ]
            for key, _ in matches:
                self._operations.pop(key, None)
        for _, operation in matches:
            operation.close()

    def close_all(self) -> None:
        with self._lock:
            operations = list(self._operations.values())
            self._operations.clear()
        for operation in operations:
            operation.close()


_SAMPLE_BRIDGE = SampleTunnelBridge()


def close_all_bridge_sessions() -> int:
    """Release host hardware whenever the authenticated server tunnel ends."""
    _SAMPLE_BRIDGE.close_all()
    return session_manager.close_all()


def run_bridge(*, operation: str, args: dict, gid: int) -> dict:
    """Execute one serialized v2 protobuf request for a trusted server tunnel."""
    operation = str(operation or "")
    wire = _wire_arg(args)

    if operation == "Negotiate":
        request = grpc_pb2.NegotiateRequest.FromString(wire)
        response = _CONTROL.Negotiate(request, None)
    elif operation == "GetSchema":
        request = grpc_pb2.GetSchemaRequest.FromString(wire)
        request.token = make_host_bridge_token(gid)
        response = _CONTROL.GetSchema(request, None)
    elif operation == "OpenSession":
        request = grpc_pb2.OpenSessionRequest.FromString(wire)
        request.token = make_host_bridge_token(gid)
        response = _CONTROL.OpenSession(request, None)
    elif operation == "Invoke":
        request = grpc_pb2.InvokeRequest.FromString(wire)
        _assert_session_gid(request.session_id, gid)
        response = _CONTROL.Invoke(request, None)
    elif operation == "CloseHandle":
        request = grpc_pb2.CloseHandleRequest.FromString(wire)
        _assert_session_gid(request.session_id, gid)
        response = _CONTROL.CloseHandle(request, None)
    elif operation == "CloseSession":
        request = grpc_pb2.CloseSessionRequest.FromString(wire)
        _assert_session_gid(request.session_id, gid)
        _SAMPLE_BRIDGE.close_session(request.session_id)
        response = _CONTROL.CloseSession(request, None)
    elif operation == "SampleFrame":
        request = grpc_pb2.SampleFrame.FromString(wire)
        response = _SAMPLE_BRIDGE.process(request, gid=gid)
    else:
        raise RemoteRFProtocolError(f"unknown tunneled Dynamic v2 operation: {operation!r}")

    return {"wire": map_arg(response.SerializeToString())}
