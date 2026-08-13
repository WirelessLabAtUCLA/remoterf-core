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

"""Dynamic v2 local-device control, sessions, handles, and sample streaming."""
from __future__ import annotations

import json
import math
import numbers
import queue
import re
import secrets
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from ..common.grpc import grpc_pb2, grpc_pb2_grpc
from ..common.grpc.v2_codec import decode_value, encode_value
from ..common.idl.v2 import (
    CONTROL_PROTOCOL_VERSION,
    SCHEMA_VERSION,
    STREAMING_PROTOCOL_VERSION,
)
# Retained as a module attribute for integrations that patched the former
# policy loader. Runtime access is no longer gated by it.
from ..drivers.usrp.policy import USRPPolicy
from ..drivers.usrp.uhd_manifest import (
    HANDLE_METHOD_RETURN_TYPES,
    HANDLE_RETURN_METHODS,
    TARGET_UHD_VERSION,
    is_supported_uhd_version,
)
from .device_manager import (
    get_local_device_context,
    register_reservation_end_callback,
    resolve_gid_for_token,
    token_matches_device,
)
from .v2_errors import (
    RemoteRFNativeUHDError,
    RemoteRFOverloadError,
    RemoteRFProtocolError,
    RemoteRFReservationError,
    RemoteRFServerOverloadedError,
    RemoteRFSessionExpiredError,
    RemoteRFStaleHandleError,
    error_envelope,
)

_HANDLE_PREFIX_BYTES = 32
_MAX_ASYNC_EVENTS = 256
_MAX_SAMPLE_PAYLOAD_BYTES = 4 * 1024 * 1024
_MAX_SESSIONS = 64
_MAX_HANDLES_PER_SESSION = 64
_MAX_CREDITS = 64
_SAMPLE_DTYPES = {
    "<c8": np.dtype("<c8"),
    "<c16": np.dtype("<c16"),
    "<i2": np.dtype("<i2"),
    "<f4": np.dtype("<f4"),
    "<f8": np.dtype("<f8"),
}


def _opaque_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(_HANDLE_PREFIX_BYTES)}"


def _uhd_type_name(value: Any) -> str:
    cls = type(value)
    return f"{cls.__module__}.{cls.__name__}"


def _call_value(value: Any, name: str, default=None):
    target = getattr(value, name, None)
    if callable(target):
        try:
            return target()
        except Exception:
            return default
    return target if target is not None else default


def _sample_dtype(value: str) -> np.dtype:
    """Accept only the canonical scalar little-endian wire dtypes."""
    dtype = _SAMPLE_DTYPES.get(str(value))
    if dtype is None:
        raise RemoteRFProtocolError(
            f"unsupported or non-canonical sample dtype: {value!r}"
        )
    return dtype


def _sample_timeout(value: float) -> float:
    timeout = float(value)
    if not math.isfinite(timeout) or timeout < 0:
        raise RemoteRFProtocolError(
            "sample timeout must be finite and non-negative"
        )
    return timeout


def _matches_wire_type(value: Any, wire_type: str) -> bool:
    if value is None:
        return "None" in str(wire_type).split("|") or wire_type == "any"
    for choice in (part.strip() for part in str(wire_type or "any").split("|")):
        if choice == "any":
            return True
        if choice == "bool" and isinstance(value, (bool, np.bool_)):
            return True
        if (
            choice == "int"
            and isinstance(value, (numbers.Integral, np.integer))
            and not isinstance(value, bool)
        ):
            return True
        if (
            choice == "float"
            and isinstance(value, (numbers.Real, np.integer, np.floating))
            and not isinstance(value, bool)
        ):
            return True
        if choice == "str" and isinstance(value, str):
            return True
        if choice == "bytes" and isinstance(value, bytes):
            return True
        if choice == "complex" and isinstance(value, (complex, np.complexfloating)):
            return True
        if choice.startswith("list") and isinstance(value, (list, tuple)):
            if "[" not in choice:
                return True
            item_type = choice.partition("[")[2].rpartition("]")[0]
            return all(_matches_wire_type(item, item_type) for item in value)
        if choice.startswith("dict") and isinstance(value, dict):
            return True
        if choice == "ndarray" and isinstance(value, np.ndarray):
            return True
        if choice.startswith("uhd.") and isinstance(value, dict):
            return True
    return False


def _validate_overload(
    descriptor: dict,
    overload_id: str,
    args: dict[str, Any],
    positional_args: list[Any],
) -> str:
    candidates = list(descriptor.get("overloads") or ())
    if not overload_id:
        if len(candidates) != 1:
            raise RemoteRFOverloadError(
                f"{descriptor['name']} requires an explicit overload id"
            )
        selected = candidates[0]
    else:
        selected = next(
            (candidate for candidate in candidates if candidate.get("id") == overload_id),
            None,
        )
        if selected is None:
            raise RemoteRFOverloadError(
                f"unknown overload {overload_id!r} for {descriptor['name']}"
            )

    allowed: set[str] = set()
    accepts_positional = False
    accepts_keywords = False
    positional_index = 0
    for parameter in selected.get("parameters", ()):
        kind = parameter.get("kind", "positional_or_keyword")
        name = str(parameter["name"])
        if kind == "positional_only":
            accepts_positional = True
            if positional_index < len(positional_args):
                value = positional_args[positional_index]
                positional_index += 1
                if not _matches_wire_type(
                    value, str(parameter.get("type") or "any")
                ):
                    raise RemoteRFOverloadError(
                        f"argument {name!r} does not match "
                        f"{parameter.get('type', 'any')}"
                    )
            elif parameter.get("required", True):
                raise RemoteRFOverloadError(
                    f"missing required argument {name!r} for "
                    f"{descriptor['name']}"
                )
            continue
        if kind == "var_positional":
            accepts_positional = True
            positional_index = len(positional_args)
            continue
        if kind == "var_keyword":
            accepts_keywords = True
            continue
        allowed.add(name)
        if parameter.get("required", True) and name not in args:
            raise RemoteRFOverloadError(
                f"missing required argument {name!r} for {descriptor['name']}"
            )
        if name in args and not _matches_wire_type(
            args[name], str(parameter.get("type") or "any")
        ):
            raise RemoteRFOverloadError(
                f"argument {name!r} does not match {parameter.get('type', 'any')}"
            )

    unexpected = set(args) - allowed
    if unexpected and not accepts_keywords:
        raise RemoteRFOverloadError(
            f"unexpected arguments for {descriptor['name']}: {sorted(unexpected)}"
        )
    if len(positional_args) > positional_index:
        raise RemoteRFOverloadError(
            f"unexpected positional arguments for {descriptor['name']}"
        )
    if positional_args and not accepts_positional:
        raise RemoteRFOverloadError(
            f"unexpected positional arguments for {descriptor['name']}"
        )
    return str(selected.get("id") or "")


def snapshot_native(value: Any):
    """Convert UHD/pybind values into portable tagged value snapshots."""
    if value is None or isinstance(value, (str, bool, int, float, bytes, np.ndarray)):
        return value
    class_name = type(value).__name__.lower()
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, complex):
        return value
    if isinstance(value, Mapping) and "device_addr" not in class_name:
        return {str(key): snapshot_native(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [snapshot_native(item) for item in value]

    if "device_addr" in class_name:
        items = {}
        try:
            for key in value.keys():
                items[str(key)] = str(value[key])
        except Exception:
            raw = _call_value(value, "to_string", str(value))
            for item in str(raw or "").split(","):
                if "=" in item:
                    key, raw_value = item.split("=", 1)
                    items[key.strip()] = raw_value.strip()
        return {"__uhd_type__": "DeviceAddr", "items": items}

    if "time_spec" in class_name or (
        hasattr(value, "get_real_secs") and hasattr(value, "get_full_secs")
    ):
        return {
            "__uhd_type__": "TimeSpec",
            "secs": float(value.get_real_secs()),
        }

    if "meta_range" in class_name or "metarange" in class_name:
        ranges = []
        try:
            ranges = [snapshot_native(item) for item in value]
        except TypeError:
            pass
        start = snapshot_native(_call_value(value, "start"))
        stop = snapshot_native(_call_value(value, "stop"))
        step = snapshot_native(_call_value(value, "step"))
        if not ranges and start is not None and stop is not None:
            # UHD 4.10's Python MetaRange exposes aggregate methods but is not
            # iterable on every build. Preserve that interval as one Range so
            # clients do not decode a valid hardware range as an empty list.
            ranges = [
                {
                    "__uhd_type__": "Range",
                    "start": start,
                    "stop": stop,
                    "step": step,
                }
            ]
        return {
            "__uhd_type__": "MetaRange",
            "ranges": ranges,
            "start": start,
            "stop": stop,
            "step": step,
        }

    if class_name == "range" or class_name.endswith("_range"):
        return {
            "__uhd_type__": "Range",
            "start": snapshot_native(_call_value(value, "start")),
            "stop": snapshot_native(_call_value(value, "stop")),
            "step": snapshot_native(_call_value(value, "step")),
        }

    if "tune_result" in class_name:
        fields = (
            "clipped_rf_freq", "target_rf_freq", "actual_rf_freq",
            "target_dsp_freq", "actual_dsp_freq",
        )
        return {
            "__uhd_type__": "TuneResult",
            **{name: snapshot_native(getattr(value, name, None)) for name in fields},
        }

    if "tune_request" in class_name:
        fields = (
            "target_freq", "lo_offset", "rf_freq", "dsp_freq",
            "rf_freq_policy", "dsp_freq_policy", "args",
        )
        return {
            "__uhd_type__": "TuneRequest",
            **{name: snapshot_native(getattr(value, name, None)) for name in fields},
        }

    if "sensor_value" in class_name:
        fields = ("name", "value", "unit", "type")
        return {
            "__uhd_type__": "SensorValue",
            **{name: snapshot_native(getattr(value, name, None)) for name in fields},
            "pretty": str(value),
        }

    if "rx_metadata" in class_name:
        error = getattr(value, "error_code", None)
        return {
            "__uhd_type__": "RXMetadata",
            "error_code": str(error).split(".")[-1] if error is not None else "none",
            "error_code_repr": str(error) if error is not None else "none",
            "has_time_spec": getattr(value, "has_time_spec", None),
            "time_spec": snapshot_native(getattr(value, "time_spec", None)),
            "more_fragments": getattr(value, "more_fragments", None),
            "fragment_offset": getattr(value, "fragment_offset", None),
            "out_of_sequence": getattr(value, "out_of_sequence", None),
        }

    if "async_metadata" in class_name:
        event = getattr(value, "event_code", None)
        return {
            "__uhd_type__": "TXAsyncMetadata",
            "event_code": str(event).split(".")[-1] if event is not None else "",
            "event_code_repr": str(event) if event is not None else "",
            "has_time_spec": getattr(value, "has_time_spec", None),
            "time_spec": snapshot_native(getattr(value, "time_spec", None)),
            "channel": getattr(value, "channel", None),
            "user_payload": snapshot_native(getattr(value, "user_payload", None)),
        }

    if "subdev_spec_pair" in class_name:
        return {
            "__uhd_type__": "SubdevSpecPair",
            "db_name": str(getattr(value, "db_name", "")),
            "sd_name": str(getattr(value, "sd_name", "")),
        }

    if "subdev_spec" in class_name:
        return {"__uhd_type__": "SubdevSpec", "spec": str(value)}

    if "stream_args" in class_name:
        return {
            "__uhd_type__": "StreamArgs",
            "cpu_format": str(getattr(value, "cpu_format", "")),
            "otw_format": str(getattr(value, "otw_format", "")),
            "args": snapshot_native(getattr(value, "args", None)),
            "channels": snapshot_native(getattr(value, "channels", [])),
        }

    if "stream_cmd" in class_name:
        mode = getattr(value, "stream_mode", getattr(value, "mode", ""))
        return {
            "__uhd_type__": "StreamCMD",
            "mode": str(mode).split(".")[-1],
            "num_samps": getattr(value, "num_samps", 0),
            "stream_now": getattr(value, "stream_now", True),
            "time_spec": snapshot_native(getattr(value, "time_spec", None)),
        }

    if "tx_metadata" in class_name:
        return {
            "__uhd_type__": "TXMetadata",
            "has_time_spec": getattr(value, "has_time_spec", False),
            "time_spec": snapshot_native(getattr(value, "time_spec", None)),
            "start_of_burst": getattr(value, "start_of_burst", False),
            "end_of_burst": getattr(value, "end_of_burst", False),
        }

    if hasattr(value, "get_type") and hasattr(value, "is_bypassed"):
        pretty = str(value)

        def pretty_int(label, default=0):
            match = re.search(
                rf"^\s*{re.escape(label)}:\s*(\d+)\s*$",
                pretty,
                flags=re.MULTILINE,
            )
            return int(match.group(1)) if match else default

        fields = {
            "__uhd_type__": "FilterInfoBase",
            "native_class": class_name,
            "filter_type": str(value.get_type()).split(".")[-1],
            "bypassed": bool(value.is_bypassed()),
            "position": pretty_int("position index"),
            "pretty": pretty,
        }
        method_fields = {
            "get_analog_type": "analog_type",
            "get_cutoff": "cutoff",
            "get_rolloff": "rolloff",
            "get_output_rate": "output_rate",
            "get_input_rate": "input_rate",
            "get_interpolation": "interpolation",
            "get_decimation": "decimation",
            "get_tap_full_scale": "tap_full_scale",
            "get_taps": "taps",
        }
        for getter, field_name in method_fields.items():
            target = getattr(value, getter, None)
            if callable(target):
                fields[field_name] = snapshot_native(target())
        if "taps" in fields:
            fields["max_num_taps"] = pretty_int(
                "max num taps",
                len(fields["taps"]),
            )
        return fields

    enum_name = getattr(value, "name", None)
    if isinstance(enum_name, str):
        return enum_name

    public_fields = {}
    for name in dir(value):
        if name.startswith("_"):
            continue
        try:
            item = getattr(value, name)
        except Exception:
            continue
        if callable(item):
            continue
        if isinstance(item, (str, bool, int, float, complex, type(None))):
            public_fields[name] = snapshot_native(item)
    if public_fields:
        return {
            "__uhd_type__": type(value).__name__,
            "__native_path__": _uhd_type_name(value),
            **public_fields,
        }
    return str(value)


@dataclass
class HandleEntry:
    handle: str
    type_id: str
    value: Any
    parent: str | None
    generation: int
    lock: threading.RLock = field(default_factory=threading.RLock)
    closed: bool = False
    sequence: int = -1
    active_operation: str = ""
    async_events: queue.Queue = field(
        default_factory=lambda: queue.Queue(maxsize=_MAX_ASYNC_EVENTS)
    )
    stop_event: threading.Event = field(default_factory=threading.Event)
    worker: threading.Thread | None = None
    async_overflowed: bool = False
    stream_channels: list[int] = field(default_factory=list)
    cpu_format: str = ""


@dataclass
class DeviceSession:
    session_id: str
    token: str
    gid: int
    schema: Any
    schema_v2: dict
    root_handle: str
    capabilities: dict
    handles: dict[str, HandleEntry] = field(default_factory=dict)
    control_lock: threading.RLock = field(default_factory=threading.RLock)
    lifecycle_lock: threading.RLock = field(default_factory=threading.RLock)
    closed: bool = False
    created_monotonic: float = field(default_factory=time.monotonic)


class SessionManager:
    def __init__(self):
        self._lock = threading.RLock()
        self._sessions: dict[str, DeviceSession] = {}
        self._session_by_gid: dict[int, str] = {}
        self._opening_gids: set[int] = set()
        self._generation = 0

    def _next_generation(self) -> int:
        with self._lock:
            self._generation += 1
            return self._generation

    def metrics(self) -> dict[str, int]:
        """Return bounded-resource counters for server status/monitoring hooks."""
        with self._lock:
            sessions = list(self._sessions.values())
            opening = len(self._opening_gids)
        handles = []
        for session in sessions:
            with session.lifecycle_lock:
                handles.extend(session.handles.values())
        return {
            "sessions": len(sessions),
            "opening_sessions": opening,
            "handles": len(handles),
            "async_queue_depth": sum(entry.async_events.qsize() for entry in handles),
            "async_queue_overflows": sum(
                1 for entry in handles if entry.async_overflowed
            ),
        }

    def schema_for_token(self, token: str) -> dict:
        gid = resolve_gid_for_token(token)
        if gid is None:
            raise RemoteRFReservationError("invalid token or inactive reservation")
        context = get_local_device_context(gid)
        if context is None:
            raise RemoteRFReservationError(
                "Dynamic v2 currently supports local devices only"
            )
        schema = context["schema"]
        factory = getattr(schema, "get_idl_v2", None)
        if not callable(factory):
            raise RemoteRFProtocolError(
                f"device type {context['dtype']!r} does not publish schema v2"
            )
        return factory()

    def open(self, token: str, requested_schema_hash: str = "") -> DeviceSession:
        gid = resolve_gid_for_token(token)
        if gid is None:
            raise RemoteRFReservationError("invalid token or inactive reservation")
        context = get_local_device_context(gid)
        if context is None:
            raise RemoteRFReservationError(
                "Dynamic v2 currently supports local devices only"
            )
        inventory_schema = context["schema"]
        schema_v2 = self.schema_for_token(token)
        if requested_schema_hash and requested_schema_hash != schema_v2["schema_hash"]:
            raise RemoteRFProtocolError(
                "client schema hash is stale",
                details={
                    "requested": requested_schema_hash,
                    "current": schema_v2["schema_hash"],
                },
            )

        with self._lock:
            if len(self._sessions) + len(self._opening_gids) >= _MAX_SESSIONS:
                raise RemoteRFServerOverloadedError(
                    "the Dynamic v2 session limit has been reached",
                    details={"maximum_sessions": _MAX_SESSIONS},
                )
            existing = self._session_by_gid.get(gid)
            if (existing and existing in self._sessions) or gid in self._opening_gids:
                raise RemoteRFReservationError(
                    "the reserved USRP already has an active Dynamic v2 session"
                )
            self._opening_gids.add(gid)

        create = getattr(inventory_schema, "create_session_schema", None)
        if not callable(create):
            with self._lock:
                self._opening_gids.discard(gid)
            raise RemoteRFProtocolError("device driver is not session-scoped")
        try:
            if getattr(inventory_schema, "device", None) is not None:
                raise RemoteRFReservationError(
                    "the USRP is already open through a legacy v1 session"
                )
            live_schema = create()
            capabilities = live_schema.build_session_metadata_v2()
            capabilities["remote_resource_limits"] = {
                "maximum_sessions": _MAX_SESSIONS,
                "maximum_handles_per_session": _MAX_HANDLES_PER_SESSION,
                "maximum_async_events_per_streamer": _MAX_ASYNC_EVENTS,
                "maximum_sample_payload_bytes": _MAX_SAMPLE_PAYLOAD_BYTES,
                "maximum_stream_credits": _MAX_CREDITS,
            }
            version = str(capabilities.get("uhd_version") or "")
            if not is_supported_uhd_version(version):
                raise RemoteRFProtocolError(
                    f"UHD {TARGET_UHD_VERSION} is required; server reports {version or 'unknown'}",
                    details={"required": TARGET_UHD_VERSION, "actual": version},
                )
        except Exception:
            if "live_schema" in locals():
                live_schema.close_native_device()
            with self._lock:
                self._opening_gids.discard(gid)
            raise

        session_id = _opaque_id("sess")
        root_handle = _opaque_id("dev")
        session = DeviceSession(
            session_id=session_id,
            token=token,
            gid=gid,
            schema=live_schema,
            schema_v2=schema_v2,
            root_handle=root_handle,
            capabilities=capabilities,
        )
        session.handles[root_handle] = HandleEntry(
            handle=root_handle,
            type_id="uhd.usrp.MultiUSRP",
            value=live_schema.device,
            parent=None,
            generation=self._next_generation(),
        )
        with self._lock:
            self._opening_gids.discard(gid)
            self._sessions[session_id] = session
            self._session_by_gid[gid] = session_id
        return session

    def get(self, session_id: str, *, validate_reservation: bool = True) -> DeviceSession:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None or session.closed:
            raise RemoteRFSessionExpiredError("unknown or closed device session")
        if validate_reservation and not token_matches_device(session.token, session.gid):
            self.close(session_id)
            raise RemoteRFSessionExpiredError(
                "reservation ended; the device session and all handles are stale"
            )
        return session

    def get_handle(
        self,
        session: DeviceSession,
        handle: str,
        *,
        expected_type: str | None = None,
        generation: int | None = None,
    ) -> HandleEntry:
        with session.lifecycle_lock:
            entry = session.handles.get(handle)
            if entry is None or entry.closed:
                raise RemoteRFStaleHandleError("unknown or closed remote handle")
            if expected_type and entry.type_id != expected_type:
                raise RemoteRFStaleHandleError(
                    f"handle type mismatch: expected {expected_type}, got {entry.type_id}"
                )
            if generation is not None and int(generation) != entry.generation:
                raise RemoteRFStaleHandleError("stream generation does not match the handle")
            return entry

    def _resolve_handle_argument(self, session: DeviceSession, value: Any):
        if isinstance(value, Mapping):
            handle = value.get("__remoterf_handle_arg__")
            if handle is not None:
                entry = self.get_handle(
                    session,
                    str(handle),
                    expected_type=str(value.get("type_id") or "") or None,
                    generation=int(value.get("generation", 0)),
                )
                return entry.value
            if value.get("__uhd_type__") or value.get(
                "__remoterf_uhd_helper__"
            ):
                from ..drivers.usrp.usrp_schema import _construct
                return _construct(dict(value))
            return {
                str(key): self._resolve_handle_argument(session, item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [
                self._resolve_handle_argument(session, item)
                for item in value
            ]
        return value

    def register_handle(
        self,
        session: DeviceSession,
        value: Any,
        type_id: str,
        *,
        parent: str,
    ) -> HandleEntry:
        with session.lifecycle_lock:
            if session.closed:
                raise RemoteRFSessionExpiredError(
                    "cannot create a handle for a closed session"
                )
            if len(session.handles) >= _MAX_HANDLES_PER_SESSION:
                raise RemoteRFServerOverloadedError(
                    "the remote handle limit for this session has been reached",
                    details={"maximum_handles": _MAX_HANDLES_PER_SESSION},
                )
            prefix = "rx" if type_id.endswith("RXStreamer") else "tx" if type_id.endswith("TXStreamer") else "obj"
            handle = _opaque_id(prefix)
            entry = HandleEntry(
                handle=handle,
                type_id=type_id,
                value=value,
                parent=parent,
                generation=self._next_generation(),
            )
            session.handles[handle] = entry
        if type_id.endswith("TXStreamer"):
            self._start_async_worker(session, entry)
        return entry

    def _start_async_worker(self, session: DeviceSession, entry: HandleEntry) -> None:
        native_method = getattr(entry.value, "recv_async_msg", None)
        metadata_type = getattr(getattr(__import__("uhd"), "types", None), "TXAsyncMetadata", None)
        if not callable(native_method) or metadata_type is None:
            return

        def run():
            while not entry.stop_event.is_set() and not session.closed:
                metadata = metadata_type()
                try:
                    found = bool(native_method(metadata, 0.1))
                except Exception:
                    break
                if not found:
                    continue
                event = snapshot_native(metadata)
                try:
                    entry.async_events.put_nowait(event)
                except queue.Full:
                    entry.async_overflowed = True

        entry.worker = threading.Thread(
            target=run,
            name=f"remoterf-{entry.handle[:16]}-async",
            daemon=True,
        )
        entry.worker.start()

    @staticmethod
    def _stop_streamer(entry: HandleEntry) -> None:
        if not entry.type_id.endswith(("RXStreamer", "TXStreamer")):
            return
        acquired = entry.lock.acquire(timeout=0.01)
        if not acquired:
            return
        try:
            import uhd

            if entry.type_id.endswith("RXStreamer"):
                command = uhd.types.StreamCMD(uhd.types.StreamMode.stop_cont)
                entry.value.issue_stream_cmd(command)
                return
            metadata = uhd.types.TXMetadata()
            metadata.start_of_burst = False
            metadata.end_of_burst = True
            dtype = (
                np.complex128
                if entry.cpu_format.lower() == "fc64"
                else np.complex64
            )
            entry.value.send(np.empty(0, dtype=dtype), metadata, 0.1)
        except Exception:
            pass
        finally:
            entry.lock.release()

    def close_handle(self, session_id: str, handle: str) -> bool:
        session = self.get(session_id, validate_reservation=False)
        with session.lifecycle_lock:
            entry = session.handles.get(handle)
            if entry is None or entry.closed:
                return False
            if handle == session.root_handle:
                return self.close(session_id)
            entry.closed = True
            entry.stop_event.set()
            session.handles.pop(handle, None)
        self._stop_streamer(entry)
        close = getattr(entry.value, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass
        if entry.worker and entry.worker.is_alive():
            entry.worker.join(timeout=0.5)
        return True

    def close(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None or session.closed:
            return False
        with session.lifecycle_lock:
            session.closed = True
            entries = list(session.handles.values())
            session.handles.clear()
            for entry in entries:
                entry.closed = True
                entry.stop_event.set()
        for entry in entries:
            if entry.worker and entry.worker.is_alive():
                entry.worker.join(timeout=0.5)
            if entry.handle != session.root_handle:
                self._stop_streamer(entry)
                close = getattr(entry.value, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass
        try:
            session.schema.close_native_device()
        finally:
            with self._lock:
                if self._session_by_gid.get(session.gid) == session_id:
                    self._session_by_gid.pop(session.gid, None)
        return True

    def close_gid(self, gid: int) -> None:
        with self._lock:
            session_id = self._session_by_gid.get(int(gid))
        if session_id:
            self.close(session_id)

    def close_all(self) -> int:
        """Close every live session and native handle during server shutdown."""
        with self._lock:
            session_ids = list(self._sessions)
        closed = 0
        for session_id in session_ids:
            if self.close(session_id):
                closed += 1
        return closed

    def invoke(
        self,
        session_id: str,
        handle: str,
        method_name: str,
        args: dict[str, Any],
        *,
        positional_args: list[Any] | None = None,
        overload_id: str = "",
    ) -> tuple[Any, list[tuple[str, Any]]]:
        session = self.get(session_id)
        entry = self.get_handle(session, handle)
        mutations: list[tuple[str, Any]] = []
        positional_args = list(positional_args or ())

        if entry.type_id == "uhd.usrp.MultiUSRP":
            descriptor = next(
                (
                    item for item in session.schema_v2["methods"]
                    if item["owner"] == entry.type_id and item["name"] == method_name
                ),
                None,
            )
            if descriptor is None:
                raise RemoteRFProtocolError(f"method is not declared by schema v2: {method_name}")
            _validate_overload(
                descriptor,
                overload_id,
                args,
                positional_args,
            )
            native_args = {
                key: self._resolve_handle_argument(session, value)
                for key, value in args.items()
            }
            native_positional = [
                self._resolve_handle_argument(session, value)
                for value in positional_args
            ]
            with session.control_lock:
                try:
                    result = session.schema.invoke_native(
                        method_name,
                        native_args,
                        positional_args=native_positional,
                    )
                except RemoteRFProtocolError:
                    raise
                except Exception as exc:
                    raise RemoteRFNativeUHDError(
                        str(exc),
                        native_exception=_uhd_type_name(exc),
                        uhd_version=session.capabilities.get("uhd_version", ""),
                        method=method_name,
                    ) from exc
            self.get(session_id)
            type_id = HANDLE_RETURN_METHODS.get(method_name)
            if type_id and result is not None:
                child = self.register_handle(
                    session, result, type_id, parent=session.root_handle
                )
                stream_args = args.get("stream_args")
                if stream_args is None and positional_args:
                    stream_args = positional_args[0]
                if isinstance(stream_args, dict):
                    child.stream_channels = [
                        int(item) for item in stream_args.get("channels", ())
                    ]
                    child.cpu_format = str(stream_args.get("cpu_format") or "")
                return {
                    "__remoterf_handle__": child.handle,
                    "__remoterf_type__": child.type_id,
                    "generation": child.generation,
                }, mutations
            return snapshot_native(result), mutations

        descriptor = next(
            (
                item
                for item in session.schema_v2["methods"]
                if item["owner"] == entry.type_id and item["name"] == method_name
            ),
            None,
        )
        if descriptor is None:
            raise RemoteRFProtocolError(
                f"method is not declared by schema v2: "
                f"{entry.type_id}.{method_name}"
            )
        _validate_overload(
            descriptor,
            overload_id,
            args,
            positional_args,
        )

        if method_name in {"recv", "send"}:
            raise RemoteRFProtocolError(
                f"{method_name} must use the SampleDataV1.SampleStream RPC"
            )
        if entry.type_id.endswith("TXStreamer") and method_name == "recv_async_msg":
            timeout = float(args.get("timeout", 0.1))
            mutate_metadata = "async_metadata" in args
            try:
                event = entry.async_events.get(timeout=max(0.0, timeout))
                if entry.async_overflowed:
                    event["remoterf_queue_overflow"] = True
                    entry.async_overflowed = False
                if mutate_metadata:
                    mutations.append(("async_metadata", event))
                    return True, mutations
                return event, mutations
            except queue.Empty:
                return (False if mutate_metadata else None), mutations

        target = getattr(entry.value, method_name, None)
        if not callable(target):
            raise RemoteRFProtocolError(
                f"{entry.type_id} does not expose method {method_name!r}"
            )
        native_args = {
            key: self._resolve_handle_argument(session, value)
            for key, value in args.items()
        }
        native_positional = [
            self._resolve_handle_argument(session, value)
            for value in positional_args
        ]
        with entry.lock:
            try:
                result = target(*native_positional, **native_args)
            except Exception as exc:
                raise RemoteRFNativeUHDError(
                    str(exc),
                    native_exception=_uhd_type_name(exc),
                    uhd_version=session.capabilities.get("uhd_version", ""),
                    method=method_name,
                ) from exc
        self.get(session_id)
        snapshot = snapshot_native(result)
        return_type = HANDLE_METHOD_RETURN_TYPES.get(
            (entry.type_id, method_name)
        )
        if return_type and result is not None:
            child = self.register_handle(
                session,
                result,
                return_type,
                parent=entry.handle,
            )
            return {
                "__remoterf_handle__": child.handle,
                "__remoterf_type__": child.type_id,
                "generation": child.generation,
            }, mutations
        if (
            result is not None
            and not isinstance(result, (str, bool, int, float, complex, bytes, dict, list, tuple, np.ndarray, np.generic))
            and isinstance(snapshot, str)
        ):
            child = self.register_handle(
                session,
                result,
                f"{entry.type_id}.{method_name}",
                parent=entry.handle,
            )
            return {
                "__remoterf_handle__": child.handle,
                "__remoterf_type__": child.type_id,
                "generation": child.generation,
            }, mutations
        return snapshot, mutations


session_manager = SessionManager()
register_reservation_end_callback(session_manager.close_gid)


class DynamicControlV2Servicer(grpc_pb2_grpc.DynamicControlV2Servicer):
    def Negotiate(self, request, context):
        schema = SCHEMA_VERSION if SCHEMA_VERSION in request.schema_versions else ""
        control = (
            CONTROL_PROTOCOL_VERSION
            if CONTROL_PROTOCOL_VERSION in request.control_protocol_versions
            else ""
        )
        streaming = (
            STREAMING_PROTOCOL_VERSION
            if STREAMING_PROTOCOL_VERSION in request.streaming_protocol_versions
            else ""
        )
        if not schema or not control or not streaming:
            exc = RemoteRFProtocolError("no mutually supported Dynamic protocol version")
            return grpc_pb2.NegotiateResponse(error=error_envelope(exc))
        return grpc_pb2.NegotiateResponse(
            schema_version=schema,
            control_protocol_version=control,
            streaming_protocol_version=streaming,
        )

    def GetSchema(self, request, context):
        try:
            if SCHEMA_VERSION not in request.schema_versions:
                raise RemoteRFProtocolError("client did not advertise schema v2")
            schema = session_manager.schema_for_token(request.token)
            return grpc_pb2.GetSchemaResponse(
                schema_version=SCHEMA_VERSION,
                schema_json=json.dumps(schema, sort_keys=True, separators=(",", ":")),
                schema_hash=schema["schema_hash"],
            )
        except Exception as exc:
            return grpc_pb2.GetSchemaResponse(error=error_envelope(exc))

    def OpenSession(self, request, context):
        try:
            if request.control_protocol_version != CONTROL_PROTOCOL_VERSION:
                raise RemoteRFProtocolError("unsupported control protocol version")
            if request.streaming_protocol_version != STREAMING_PROTOCOL_VERSION:
                raise RemoteRFProtocolError("unsupported streaming protocol version")
            session = session_manager.open(
                request.token,
                requested_schema_hash=request.requested_schema_hash,
            )
            return grpc_pb2.OpenSessionResponse(
                session_id=session.session_id,
                device_handle=session.root_handle,
                schema_json=json.dumps(
                    session.schema_v2, sort_keys=True, separators=(",", ":")
                ),
                schema_hash=session.schema_v2["schema_hash"],
                capabilities_json=json.dumps(
                    snapshot_native(session.capabilities),
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                uhd_version=str(session.capabilities.get("uhd_version") or ""),
                uhd_abi=str(session.capabilities.get("uhd_abi") or ""),
                hardware_profile=str(
                    session.capabilities.get("hardware_profile") or "generic_usrp"
                ),
            )
        except Exception as exc:
            return grpc_pb2.OpenSessionResponse(error=error_envelope(exc))

    def Invoke(self, request, context):
        try:
            args = {}
            for item in request.args:
                if not item.name or item.name in args:
                    raise RemoteRFProtocolError(
                        "invoke arguments must have unique, non-empty names"
                    )
                args[item.name] = decode_value(item.value)
            positional = args.pop("__args__", [])
            extra_kwargs = args.pop("__kwargs__", {})
            if not isinstance(positional, (list, tuple)):
                raise RemoteRFProtocolError("__args__ must be a list")
            if not isinstance(extra_kwargs, dict):
                raise RemoteRFProtocolError("__kwargs__ must be a mapping")
            if extra_kwargs:
                overlap = set(args) & set(extra_kwargs)
                if overlap:
                    raise RemoteRFProtocolError(
                        f"duplicate invoke keywords: {sorted(overlap)}"
                    )
                args.update(extra_kwargs)
            result, mutations = session_manager.invoke(
                request.session_id,
                request.handle,
                request.method,
                args,
                positional_args=positional,
                overload_id=request.overload_id,
            )
            response = grpc_pb2.InvokeResponse(result=encode_value(result))
            for target, value in mutations:
                response.mutations.add(target=target, value=encode_value(value))
            return response
        except Exception as exc:
            return grpc_pb2.InvokeResponse(
                error=error_envelope(exc, method=request.method)
            )

    def CloseHandle(self, request, context):
        try:
            return grpc_pb2.CloseResponse(
                closed=session_manager.close_handle(request.session_id, request.handle)
            )
        except Exception as exc:
            return grpc_pb2.CloseResponse(error=error_envelope(exc))

    def CloseSession(self, request, context):
        try:
            return grpc_pb2.CloseResponse(
                closed=session_manager.close(request.session_id)
            )
        except Exception as exc:
            return grpc_pb2.CloseResponse(error=error_envelope(exc))


class SampleDataV1Servicer(grpc_pb2_grpc.SampleDataV1Servicer):
    def _error_frame(self, request, exc):
        return grpc_pb2.SampleFrame(
            session_id=request.session_id,
            handle=request.handle,
            generation=request.generation,
            operation_id=request.operation_id,
            sequence=request.sequence,
            direction=request.direction,
            kind=grpc_pb2.SAMPLE_FRAME_ERROR,
            error=error_envelope(exc),
            end_of_stream=True,
        )

    @staticmethod
    def _metadata_object(schema, tag: str, payload: str):
        try:
            value = json.loads(payload or "{}")
        except json.JSONDecodeError as exc:
            raise RemoteRFProtocolError("invalid sample metadata JSON") from exc
        value.setdefault("__uhd_type__", tag)
        # UsrpSchema's input codec owns construction against the installed UHD.
        from ..drivers.usrp.usrp_schema import _construct
        return _construct(value)

    @staticmethod
    def _finish_operation(entry: HandleEntry, operation_id: str) -> None:
        with entry.lock:
            if entry.active_operation == operation_id:
                entry.active_operation = ""

    def SampleStream(self, request_iterator, context):
        opened: tuple[DeviceSession, HandleEntry, str, int] | None = None
        try:
            for request in request_iterator:
                try:
                    session = session_manager.get(request.session_id)
                    entry = session_manager.get_handle(
                        session,
                        request.handle,
                        generation=request.generation,
                    )
                    if request.kind == grpc_pb2.SAMPLE_FRAME_OPEN:
                        if not request.operation_id:
                            raise RemoteRFProtocolError(
                                "sample OPEN requires an operation id"
                            )
                        if not (
                            entry.type_id.endswith("RXStreamer")
                            or entry.type_id.endswith("TXStreamer")
                        ):
                            raise RemoteRFProtocolError("sample handle is not a streamer")
                        if request.direction not in {
                            grpc_pb2.SAMPLE_DIRECTION_RX,
                            grpc_pb2.SAMPLE_DIRECTION_TX,
                        }:
                            raise RemoteRFProtocolError(
                                "sample direction must be RX or TX"
                            )
                        if (
                            request.direction == grpc_pb2.SAMPLE_DIRECTION_RX
                            and not entry.type_id.endswith("RXStreamer")
                        ) or (
                            request.direction == grpc_pb2.SAMPLE_DIRECTION_TX
                            and not entry.type_id.endswith("TXStreamer")
                        ):
                            raise RemoteRFProtocolError(
                                "sample direction does not match the streamer type"
                            )
                        with entry.lock:
                            if entry.active_operation:
                                raise RemoteRFServerOverloadedError(
                                    "the streamer already has an active operation"
                                )
                            if int(request.sequence) <= entry.sequence:
                                raise RemoteRFProtocolError(
                                    "sample frame sequence is not monotonic"
                                )
                            entry.sequence = int(request.sequence)
                            entry.active_operation = request.operation_id
                        opened = (
                            session,
                            entry,
                            request.operation_id,
                            int(request.direction),
                        )
                        yield grpc_pb2.SampleFrame(
                            session_id=session.session_id,
                            handle=entry.handle,
                            generation=entry.generation,
                            operation_id=request.operation_id,
                            sequence=request.sequence,
                            direction=request.direction,
                            kind=grpc_pb2.SAMPLE_FRAME_RESULT,
                            credits=min(
                                _MAX_CREDITS,
                                max(1, int(request.credits or 1)),
                            ),
                        )
                        continue

                    if opened is None or opened[1].handle != entry.handle:
                        raise RemoteRFProtocolError("sample stream must begin with OPEN")
                    if opened[0].session_id != session.session_id:
                        raise RemoteRFProtocolError(
                            "sample session changed after OPEN"
                        )
                    if (
                        request.operation_id != opened[2]
                        or int(request.direction) != opened[3]
                    ):
                        raise RemoteRFProtocolError(
                            "sample operation id or direction changed after OPEN"
                        )
                    if int(request.sequence) <= entry.sequence:
                        raise RemoteRFProtocolError("sample frame sequence is not monotonic")
                    entry.sequence = int(request.sequence)

                    if request.kind == grpc_pb2.SAMPLE_FRAME_CANCEL:
                        self._finish_operation(entry, request.operation_id)
                        yield grpc_pb2.SampleFrame(
                            session_id=session.session_id,
                            handle=entry.handle,
                            generation=entry.generation,
                            operation_id=request.operation_id,
                            sequence=request.sequence,
                            direction=request.direction,
                            kind=grpc_pb2.SAMPLE_FRAME_RESULT,
                            cancelled=True,
                            end_of_stream=True,
                        )
                        continue

                    if request.kind == grpc_pb2.SAMPLE_FRAME_CLOSE:
                        self._finish_operation(entry, request.operation_id)
                        session_manager.close_handle(session.session_id, entry.handle)
                        yield grpc_pb2.SampleFrame(
                            session_id=session.session_id,
                            handle=entry.handle,
                            generation=request.generation,
                            operation_id=request.operation_id,
                            sequence=request.sequence,
                            direction=request.direction,
                            kind=grpc_pb2.SAMPLE_FRAME_RESULT,
                            end_of_stream=True,
                        )
                        return

                    dtype = _sample_dtype(request.dtype)
                    try:
                        shape = tuple(int(item) for item in request.shape)
                    except (TypeError, ValueError, OverflowError) as exc:
                        raise RemoteRFProtocolError(
                            "sample shape contains a non-integer dimension"
                        ) from exc
                    if len(shape) not in {1, 2} or any(item < 0 for item in shape):
                        raise RemoteRFProtocolError(
                            "sample shape must be one- or two-dimensional"
                        )
                    byte_count = math.prod(shape) * dtype.itemsize
                    if byte_count > _MAX_SAMPLE_PAYLOAD_BYTES:
                        raise RemoteRFProtocolError(
                            f"sample operation exceeds {_MAX_SAMPLE_PAYLOAD_BYTES} bytes"
                        )
                    if int(request.sample_count) != int(shape[-1]):
                        raise RemoteRFProtocolError(
                            "sample_count must match the final shape dimension"
                        )
                    if entry.stream_channels and list(request.channels) != entry.stream_channels:
                        raise RemoteRFProtocolError(
                            "sample channels do not match the stream handle"
                        )
                    if (
                        len(shape) == 2
                        and request.channels
                        and shape[0] != len(request.channels)
                    ):
                        raise RemoteRFProtocolError(
                            "sample channel dimension does not match channel metadata"
                        )
                    if (
                        len(shape) == 1
                        and len(request.channels) > 1
                    ):
                        raise RemoteRFProtocolError(
                            "multi-channel samples require a channel-major array"
                        )
                    expected_dtype = {
                        "fc32": np.dtype(np.complex64),
                        "fc64": np.dtype(np.complex128),
                        "f32": np.dtype(np.float32),
                        "f64": np.dtype(np.float64),
                        "s16": np.dtype(np.int16),
                    }.get(entry.cpu_format.lower())
                    if expected_dtype is not None and dtype != expected_dtype:
                        raise RemoteRFProtocolError(
                            f"sample dtype {dtype} does not match CPU format "
                            f"{entry.cpu_format}"
                        )

                    if (
                        request.direction == grpc_pb2.SAMPLE_DIRECTION_RX
                        and request.kind == grpc_pb2.SAMPLE_FRAME_REQUEST
                    ):
                        if not entry.type_id.endswith("RXStreamer"):
                            raise RemoteRFStaleHandleError("RX request used a non-RX handle")
                        buffer = np.empty(shape, dtype=dtype)
                        metadata = self._metadata_object(
                            session.schema, "RXMetadata", request.metadata_json
                        )
                        if request.one_packet:
                            raise RemoteRFProtocolError(
                                "one_packet is not exposed by the pinned "
                                "UHD 4.10 Python RXStreamer.recv binding"
                            )
                        timeout = _sample_timeout(request.timeout_sec)
                        deadline = time.monotonic() + timeout
                        count = 0
                        metadata_snapshot = snapshot_native(metadata)
                        with entry.lock:
                            while count < int(request.sample_count):
                                remaining = max(0.0, deadline - time.monotonic())
                                if count and remaining <= 0.0:
                                    break
                                current_metadata = (
                                    metadata
                                    if count == 0
                                    else self._metadata_object(
                                        session.schema,
                                        "RXMetadata",
                                        request.metadata_json,
                                    )
                                )
                                target = buffer[..., count:]
                                received = int(
                                    entry.value.recv(
                                        target,
                                        current_metadata,
                                        timeout if count == 0 else remaining,
                                    )
                                )
                                if received < 0 or received > target.shape[-1]:
                                    raise RemoteRFProtocolError(
                                        "native RX returned an invalid sample count"
                                    )
                                current_snapshot = snapshot_native(current_metadata)
                                error_code = str(
                                    current_snapshot.get("error_code", "none")
                                ).rsplit(".", 1)[-1].lower()
                                has_error = error_code not in {
                                    "none",
                                    "error_code_none",
                                }
                                if count == 0 or has_error:
                                    metadata = current_metadata
                                    metadata_snapshot = current_snapshot
                                count += received
                                if received == 0 or has_error:
                                    break
                        session_manager.get(session.session_id)
                        if count < 0 or count > int(request.sample_count):
                            raise RemoteRFProtocolError(
                                "native RX returned an invalid sample count"
                            )
                        sliced = buffer[..., :count] if buffer.ndim > 1 else buffer[:count]
                        payload = np.ascontiguousarray(sliced).tobytes(order="C")
                        time_spec = getattr(metadata, "time_spec", None)
                        device_time = _call_value(
                            time_spec,
                            "get_real_secs",
                            0.0,
                        )
                        self._finish_operation(entry, request.operation_id)
                        yield grpc_pb2.SampleFrame(
                            session_id=session.session_id,
                            handle=entry.handle,
                            generation=entry.generation,
                            operation_id=request.operation_id,
                            sequence=request.sequence,
                            direction=request.direction,
                            kind=grpc_pb2.SAMPLE_FRAME_DATA,
                            dtype=dtype.str,
                            shape=list(sliced.shape),
                            channels=list(request.channels),
                            sample_count=count,
                            payload=payload,
                            metadata_json=json.dumps(
                                metadata_snapshot,
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                            device_time_secs=float(device_time or 0.0),
                            credits=1,
                        )
                        continue

                    if (
                        request.direction == grpc_pb2.SAMPLE_DIRECTION_TX
                        and request.kind == grpc_pb2.SAMPLE_FRAME_DATA
                    ):
                        if not entry.type_id.endswith("TXStreamer"):
                            raise RemoteRFStaleHandleError("TX data used a non-TX handle")
                        if len(request.payload) != byte_count:
                            raise RemoteRFProtocolError(
                                "TX payload byte length does not match dtype/shape"
                            )
                        samples = np.frombuffer(request.payload, dtype=dtype).reshape(shape)
                        metadata = self._metadata_object(
                            session.schema, "TXMetadata", request.metadata_json
                        )
                        timeout = _sample_timeout(request.timeout_sec)
                        with entry.lock:
                            count = int(
                                entry.value.send(
                                    samples,
                                    metadata,
                                    timeout,
                                )
                            )
                        session_manager.get(session.session_id)
                        if count < 0 or count > int(request.sample_count):
                            raise RemoteRFProtocolError(
                                "native TX returned an invalid sample count"
                            )
                        self._finish_operation(entry, request.operation_id)
                        yield grpc_pb2.SampleFrame(
                            session_id=session.session_id,
                            handle=entry.handle,
                            generation=entry.generation,
                            operation_id=request.operation_id,
                            sequence=request.sequence,
                            direction=request.direction,
                            kind=grpc_pb2.SAMPLE_FRAME_RESULT,
                            sample_count=count,
                            credits=1,
                        )
                        continue

                    raise RemoteRFProtocolError("unsupported sample frame transition")
                except Exception as exc:
                    if opened is not None:
                        self._finish_operation(opened[1], opened[2])
                    yield self._error_frame(request, exc)
                    return
        finally:
            if opened is not None:
                self._finish_operation(opened[1], opened[2])
