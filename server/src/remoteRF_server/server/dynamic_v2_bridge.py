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

"""Dynamic v2 for a partner lab's caller, one serialized request per device RPC.

The federated device plane (the HOME relay and the direct path) carries
``DynamicV2:<Operation>:WIRE`` calls that it has already authorized and pinned
to one device; this runs each through the same servicers a native Client
reaches over gRPC. It mirrors RemoteRF-Host's tunnel bridge.
"""
from __future__ import annotations

import json
import queue
import threading

from ..common.grpc import grpc_pb2
from ..common.utils import map_arg, unmap_arg
from .device_manager import reservation_bridge_token
from .dynamic_v2 import DynamicControlV2Servicer, SampleDataV1Servicer, session_manager
from .host_dynamic_v2 import host_session_proxy
from .v2_errors import (
    RemoteRFError,
    RemoteRFProtocolError,
    RemoteRFReservationError,
    error_envelope,
)

# A TX DATA frame rides in the request, which the HOME relay caps at the
# decoded size of a device action (~192 KB); sessions opened here advertise a
# sample payload that fits, so the Client batches to it whichever route it takes.
FEDERATED_SAMPLE_PAYLOAD_BYTES = 128 * 1024

_CONTROL = DynamicControlV2Servicer()
_SAMPLES = SampleDataV1Servicer()
_RESPONSE_TYPES = {
    "Negotiate": grpc_pb2.NegotiateResponse,
    "GetSchema": grpc_pb2.GetSchemaResponse,
    "OpenSession": grpc_pb2.OpenSessionResponse,
    "Invoke": grpc_pb2.InvokeResponse,
    "CloseHandle": grpc_pb2.CloseResponse,
    "CloseSession": grpc_pb2.CloseResponse,
}


def _wire_arg(args: dict) -> bytes:
    value = args.get("wire")
    if value is None:
        raise RemoteRFProtocolError("tunneled Dynamic v2 request is missing wire data")
    wire = unmap_arg(value)
    if not isinstance(wire, bytes):
        raise RemoteRFProtocolError("tunneled Dynamic v2 wire data must be bytes")
    return wire


def _token(gid: int) -> str:
    try:
        return reservation_bridge_token(gid)
    except RuntimeError as exc:
        raise RemoteRFReservationError(str(exc)) from None


def _assert_session_gid(session_id: str, gid: int) -> None:
    if host_session_proxy.is_remote_session(session_id):
        owner = host_session_proxy.session_gid(session_id)
    else:
        owner = session_manager.get(session_id).gid
    if owner != int(gid):
        raise RemoteRFProtocolError("Dynamic v2 session does not belong to this device")


class _FrameIterator:
    def __init__(self):
        self.frames: queue.Queue = queue.Queue()

    def __iter__(self):
        return self

    def __next__(self):
        return self.frames.get()


class _SampleOperation:
    """One sample operation's SampleStream, fed a frame at a time."""

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


_SAMPLE_BRIDGE = SampleTunnelBridge()


def run_bridge(*, operation: str, args: dict, gid: int) -> dict:
    """Execute one serialized v2 protobuf request for an authorized federated caller."""
    operation = str(operation or "")
    wire = _wire_arg(args)
    try:
        response = _dispatch(operation, wire, gid)
    except RemoteRFError as exc:
        # A closed session or a mismatched device is the Client's to handle,
        # typed as the servicer would type it, not an opaque relay failure.
        if operation == "SampleFrame":
            response = _SAMPLES._error_frame(grpc_pb2.SampleFrame.FromString(wire), exc)
        elif operation in _RESPONSE_TYPES:
            response = _RESPONSE_TYPES[operation](error=error_envelope(exc))
        else:
            raise
    return {"wire": map_arg(response.SerializeToString())}


def _fit_sample_payload(response) -> None:
    if not response.capabilities_json:
        return
    capabilities = json.loads(response.capabilities_json)
    limits = capabilities.setdefault("remote_resource_limits", {})
    limits["maximum_sample_payload_bytes"] = min(
        int(limits.get("maximum_sample_payload_bytes") or FEDERATED_SAMPLE_PAYLOAD_BYTES),
        FEDERATED_SAMPLE_PAYLOAD_BYTES,
    )
    response.capabilities_json = json.dumps(capabilities, sort_keys=True, separators=(",", ":"))


def _dispatch(operation: str, wire: bytes, gid: int):
    if operation == "Negotiate":
        request = grpc_pb2.NegotiateRequest.FromString(wire)
        response = _CONTROL.Negotiate(request, None)
    elif operation == "GetSchema":
        request = grpc_pb2.GetSchemaRequest.FromString(wire)
        request.token = _token(gid)
        response = _CONTROL.GetSchema(request, None)
    elif operation == "OpenSession":
        request = grpc_pb2.OpenSessionRequest.FromString(wire)
        request.token = _token(gid)
        response = _CONTROL.OpenSession(request, None)
        _fit_sample_payload(response)
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
    return response
