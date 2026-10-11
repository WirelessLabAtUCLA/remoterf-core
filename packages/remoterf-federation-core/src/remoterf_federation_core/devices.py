"""Pure federated device action payload and result rules.

These are the device-plane companions to the Gate E control actions in
``federation.py``.  The grant/result envelope, signing, replay consumption,
and contract binding are unchanged and still live there; this module only
adds the per-action payload and payload-result grammars plus the larger,
explicitly-stated byte ceilings that device traffic needs.

Nothing here signs, stores, resolves hardware, or performs I/O.  A
destination remains authoritative for its own inventory, permissions,
reservations, and hardware; a HOME never learns a destination-local
hardware credential from any shape defined here.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Mapping

from .schemas import ValidationError, canonical_json, canonical_uuid, strict_json

# Device actions carry serialized RemoteRF device RPC frames, which are far
# larger than the control-plane actions.  The ceilings stay explicit and
# per-family so raising them never silently relaxes the Gate E actions.
MAX_DEVICE_ACTION_REQUEST_BYTES = 262144
MAX_DEVICE_RESULT_BYTES = 1048576
MAX_DEVICE_RESULT_TOKEN_BYTES = 1572864
MAX_DEVICE_FORWARD_REQUEST_BYTES = 393216
MAX_DEVICE_FORWARD_RESPONSE_BYTES = 1835008
# Raw device RPC frame ceilings: exactly what the base64 ceilings above admit,
# so a detached frame never passes where the legacy encoding would not.
MAX_DEVICE_RPC_REQUEST_FRAME_BYTES = (MAX_DEVICE_ACTION_REQUEST_BYTES // 4) * 3
MAX_DEVICE_RPC_RESPONSE_FRAME_BYTES = (MAX_DEVICE_RESULT_BYTES // 4) * 3
# HTTP body: u32be(len(envelope)) || canonical JSON envelope || raw frame.
FRAMED_CONTENT_TYPE = "application/x-remoterf-framed"

MAX_DEVICES_PER_RESULT = 512
MAX_RESERVATIONS_PER_RESULT = 512
# A reservation may not be scheduled further out than this from the
# destination's own clock; the destination still applies its own policy.
MAX_RESERVATION_HORIZON_SECONDS = 365 * 24 * 3600

# Time budgets.  Reads and reservation writes are quick owner-table work and
# share the Gate G per-destination budget; a device RPC drives real hardware
# and gets its own, larger budget.  Each hop's budget is strictly larger than
# the hop below it so a timeout is always reported by the nearest hop.
DEVICE_READ_TIMEOUT_SECONDS = 11.0
DEVICE_WRITE_TIMEOUT_SECONDS = 11.0
DEVICE_RPC_TIMEOUT_SECONDS = 30.0
# An ICE offer/answer is a few candidate lines; the owner only parses it.
MAX_ICE_BYTES = 8192
# Broker end-to-end budget for one forwarded device_rpc.
DEVICE_FORWARD_TOTAL_TIMEOUT_SECONDS = 35.0
# HOME fan-out budget for a cross-deployment device or reservation listing.
DEVICE_AGGREGATION_TIMEOUT_SECONDS = 15.0
# Client HTTPS budget for one device RPC through its HOME.
DEVICE_RPC_CLIENT_TIMEOUT_SECONDS = 40.0
# Client HTTPS ceilings for HOME device responses: the forwarded body plus
# the HOME's own envelope fields.
MAX_DEVICE_HTTP_RESPONSE_BYTES = MAX_DEVICE_FORWARD_RESPONSE_BYTES + 131072
MAX_DEVICE_LIST_HTTP_RESPONSE_BYTES = 1048576


def device_action_timeout(action: object) -> float:
    """Per-destination transport budget for one device action."""

    if action == "device_rpc":
        return DEVICE_RPC_TIMEOUT_SECONDS
    if action in ("device_reserve", "device_cancel", "direct_open"):
        return DEVICE_WRITE_TIMEOUT_SECONDS
    if action in READ_ONLY_DEVICE_ACTIONS:
        return DEVICE_READ_TIMEOUT_SECONDS
    raise DeviceProtocolError("unknown_action")


# HOME-visible references.  A HOME never renumbers a destination's devices or
# reservations; it exposes ``<destination_deployment_id>:<local_id>`` and
# splits it again to route.  Clients treat the whole string as opaque.
_GLOBAL_REF = re.compile(
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):(0|[1-9][0-9]{0,19})"
)


def global_device_ref(deployment_id: object, local_device_id: object) -> str:
    return f"{canonical_uuid(deployment_id)}:{_local_id(local_device_id, 'invalid_local_device_id')}"


def global_reservation_ref(deployment_id: object, reservation_id: object) -> str:
    return f"{canonical_uuid(deployment_id)}:{_local_id(reservation_id, 'invalid_reservation_id')}"


def parse_global_ref(value: object, *, code: str = "invalid_global_ref") -> tuple[str, str]:
    """Split a HOME-visible reference into (deployment_id, local_id)."""

    if type(value) is not str or _GLOBAL_REF.fullmatch(value) is None:
        raise DeviceProtocolError(code)
    deployment_id, local_id = value.split(":", 1)
    return canonical_uuid(deployment_id), local_id


def is_global_ref(value: object) -> bool:
    return type(value) is str and _GLOBAL_REF.fullmatch(value) is not None

DEVICE_ACTION_CAPABILITIES = {
    "device_list": "DEVICE_READ",
    "device_reserve": "DEVICE_RESERVE",
    "device_reservations": "DEVICE_READ",
    "device_cancel": "DEVICE_RESERVE",
    "device_rpc": "DEVICE_CONTROL",
    # Gate I across deployments: the owner answers a client's ICE offer for a
    # live reservation, then the data plane runs client <-> owner directly.
    "direct_open": "DEVICE_CONTROL",
}
DEVICE_CONTRACT_CAPABILITIES = frozenset(DEVICE_ACTION_CAPABILITIES.values())
DEVICE_ACTIONS = frozenset(DEVICE_ACTION_CAPABILITIES)
# Reads may be retried after an unsigned transport failure; a reservation
# write or a device RPC may not, because the destination may have applied it.
READ_ONLY_DEVICE_ACTIONS = frozenset({"device_list", "device_reservations"})

DEVICE_RESULT_FIELDS = frozenset(
    {
        "status",
        "error_code",
        "deployment_id",
        "display_name",
        "contract_id",
        "contract_version",
        "state",
        "retrieved_at",
        "payload",
    }
)

_BASE_PAYLOAD_FIELDS = frozenset(
    {
        "request_id",
        "destination_deployment_id",
        "contract_id",
        "contract_version",
        "terms_sha256",
    }
)
DEVICE_PAYLOAD_FIELDS = {
    "device_list": _BASE_PAYLOAD_FIELDS,
    "device_reserve": _BASE_PAYLOAD_FIELDS
    | {"local_device_id", "start_time", "end_time"},
    "device_reservations": _BASE_PAYLOAD_FIELDS,
    "device_cancel": _BASE_PAYLOAD_FIELDS | {"reservation_id"},
    "device_rpc": _BASE_PAYLOAD_FIELDS | {"local_device_id", "request_b64"},
    "direct_open": _BASE_PAYLOAD_FIELDS | {"reservation_id", "ice"},
}
# device_rpc with the frame carried beside the signed JSON: the grant's
# request_sha256 covers this descriptor, which binds the frame bytes.
DEVICE_RPC_DETACHED_PAYLOAD_FIELDS = _BASE_PAYLOAD_FIELDS | {
    "local_device_id",
    "frame_sha256",
    "frame_len",
}

# Destination-local identifiers are opaque decimal strings on the wire.  A
# destination keeps its own integer IDs; nothing here renumbers them.
_LOCAL_ID = re.compile(r"0|[1-9][0-9]{0,19}")
_DEVICE_TYPE = re.compile(r"[A-Za-z0-9_.-]{1,100}")
_FUNCTION_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,200}")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class DeviceProtocolError(ValidationError):
    """Stable, non-secret federated device protocol failure."""


def is_device_action(action: object) -> bool:
    return type(action) is str and action in DEVICE_ACTIONS


def device_action_capability(action: object) -> str:
    if not is_device_action(action):
        raise DeviceProtocolError("unknown_action")
    return DEVICE_ACTION_CAPABILITIES[action]


def _local_id(value: object, code: str) -> str:
    if type(value) is not str or _LOCAL_ID.fullmatch(value) is None:
        raise DeviceProtocolError(code)
    return value


def _epoch(value: object, code: str) -> int:
    if type(value) is not int or type(value) is bool or not 0 <= value <= 1 << 40:
        raise DeviceProtocolError(code)
    return value


def _text(value: object, code: str, maximum: int, *, allow_empty: bool = False) -> str:
    if (
        type(value) is not str
        or len(value) > maximum
        or (not allow_empty and not value)
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise DeviceProtocolError(code)
    return value


def _flag(value: object, code: str) -> bool:
    if type(value) is not bool:
        raise DeviceProtocolError(code)
    return value


def decode_device_b64(
    value: object, *, code: str, max_bytes: int, allow_empty: bool = False
) -> bytes:
    """Decode a strictly canonical, size-bounded base64 device frame.

    A response frame may legitimately be empty: a setter answers with no
    results, and an empty GenericRPCResponse serializes to zero bytes.
    """

    if (
        type(value) is not str
        or (not value and not allow_empty)
        or len(value) > max_bytes
        or _BASE64.fullmatch(value) is None
    ):
        raise DeviceProtocolError(code)
    if not value:
        return b""
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise DeviceProtocolError(code) from None
    if base64.b64encode(raw).decode("ascii") != value:
        raise DeviceProtocolError(code)
    return raw


def encode_device_b64(raw: object, *, code: str, max_bytes: int) -> str:
    if type(raw) is not bytes:
        raise DeviceProtocolError(code)
    encoded = base64.b64encode(raw).decode("ascii")
    if len(encoded) > max_bytes:
        raise DeviceProtocolError(code)
    return encoded


def _descriptor(value: Mapping, *, code: str, minimum: int, maximum: int) -> dict:
    length = value["frame_len"]
    digest = value["frame_sha256"]
    if (
        type(length) is not int
        or not minimum <= length <= maximum
        or type(digest) is not str
        or _SHA256.fullmatch(digest) is None
    ):
        raise DeviceProtocolError(code)
    return {"frame_sha256": digest, "frame_len": length}


def frame_digest(frame: object, *, max_bytes: int, code: str) -> dict:
    """The signed descriptor of a detached frame."""

    if type(frame) is not bytes or len(frame) > max_bytes:
        raise DeviceProtocolError(code)
    return {"frame_sha256": hashlib.sha256(frame).hexdigest(), "frame_len": len(frame)}


def verify_frame(frame: object, descriptor: Mapping, *, max_bytes: int, code: str) -> bytes:
    """Return ``frame`` iff it matches the descriptor; length before hashing."""

    length = descriptor.get("frame_len") if isinstance(descriptor, Mapping) else None
    if (
        type(frame) is not bytes
        or type(length) is not int
        or len(frame) != length
        or length > max_bytes
        or hashlib.sha256(frame).hexdigest() != descriptor.get("frame_sha256")
    ):
        raise DeviceProtocolError(code)
    return frame


def device_request_frame(payload: Mapping, frame: object) -> bytes:
    """Raw GenericRPCRequest from a validated device_rpc payload in either form."""

    code = "invalid_device_request"
    if "frame_sha256" in payload:
        if frame == b"":
            raise DeviceProtocolError(code)
        return verify_frame(
            frame, payload, max_bytes=MAX_DEVICE_RPC_REQUEST_FRAME_BYTES, code=code
        )
    if type(frame) is not bytes or frame:
        raise DeviceProtocolError(code)
    return decode_device_b64(
        payload.get("request_b64"), code=code, max_bytes=MAX_DEVICE_ACTION_REQUEST_BYTES
    )


def device_response_frame(payload: Mapping, frame: object) -> bytes:
    """Raw GenericRPCResponse from a validated ok device_rpc result payload."""

    code = "invalid_device_response"
    if "frame_sha256" in payload:
        return verify_frame(
            frame, payload, max_bytes=MAX_DEVICE_RPC_RESPONSE_FRAME_BYTES, code=code
        )
    if type(frame) is not bytes or frame:
        raise DeviceProtocolError(code)
    return decode_device_b64(
        payload.get("response_b64"),
        code=code,
        max_bytes=MAX_DEVICE_RESULT_BYTES,
        allow_empty=True,
    )


def pack_framed(envelope: Mapping, frame: bytes = b"") -> bytes:
    if not isinstance(envelope, Mapping) or type(frame) is not bytes:
        raise ValidationError("invalid_framed_body")
    encoded = canonical_json(dict(envelope)).encode("utf-8")
    return len(encoded).to_bytes(4, "big") + encoded + frame


def unpack_framed(raw: object, *, max_bytes: int) -> tuple[dict, bytes]:
    """Split a framed body; ``max_bytes`` bounds the envelope, callers cap the frame."""

    if type(raw) is not bytes or len(raw) < 4:
        raise ValidationError("invalid_framed_body")
    end = 4 + int.from_bytes(raw[:4], "big")
    if end > len(raw):
        raise ValidationError("invalid_framed_body")
    try:
        envelope = strict_json(raw[4:end], max_bytes=max_bytes)
    except ValidationError:
        raise ValidationError("invalid_framed_body") from None
    if type(envelope) is not dict:
        raise ValidationError("invalid_framed_body")
    return envelope, raw[end:]


def validate_device_payload(action: str, payload: object) -> dict:
    """Return the canonical destination-facing payload for a device action."""

    expected = DEVICE_PAYLOAD_FIELDS.get(action)
    if expected is None:
        raise DeviceProtocolError("unknown_action")
    detached = action == "device_rpc" and type(payload) is dict and "frame_sha256" in payload
    if detached:
        expected = DEVICE_RPC_DETACHED_PAYLOAD_FIELDS
    if type(payload) is not dict or set(payload) != expected:
        raise DeviceProtocolError("invalid_payload_fields")
    clean = {}
    if action in ("device_reserve", "device_rpc"):
        clean["local_device_id"] = _local_id(
            payload["local_device_id"], "invalid_local_device_id"
        )
    if action == "device_reserve":
        start = _epoch(payload["start_time"], "invalid_reservation_time")
        end = _epoch(payload["end_time"], "invalid_reservation_time")
        if end <= start or end - start > MAX_RESERVATION_HORIZON_SECONDS:
            raise DeviceProtocolError("invalid_reservation_time")
        clean["start_time"] = start
        clean["end_time"] = end
    if action in ("device_cancel", "direct_open"):
        clean["reservation_id"] = _local_id(
            payload["reservation_id"], "invalid_reservation_id"
        )
    if action == "direct_open":
        clean["ice"] = _text(payload["ice"], "invalid_ice", MAX_ICE_BYTES)
    if detached:
        clean.update(
            _descriptor(
                payload,
                code="invalid_device_request",
                minimum=1,
                maximum=MAX_DEVICE_RPC_REQUEST_FRAME_BYTES,
            )
        )
    elif action == "device_rpc":
        # Kept as the encoded string: the canonical request bytes are what the
        # grant's request_sha256 commits to.
        decode_device_b64(
            payload["request_b64"],
            code="invalid_device_request",
            max_bytes=MAX_DEVICE_ACTION_REQUEST_BYTES,
        )
        clean["request_b64"] = payload["request_b64"]
    return clean


def build_device_payload(
    *,
    action: str,
    local_device_id: str | None = None,
    start_time: int | None = None,
    end_time: int | None = None,
    reservation_id: str | None = None,
    request_b64: str | None = None,
    ice: str | None = None,
    frame_sha256: str | None = None,
    frame_len: int | None = None,
) -> dict:
    """Return only the action-specific payload fields, unvalidated bases aside."""

    extra: dict = {}
    if action in ("device_reserve", "device_rpc"):
        extra["local_device_id"] = local_device_id
    if action == "device_reserve":
        extra["start_time"] = start_time
        extra["end_time"] = end_time
    if action in ("device_cancel", "direct_open"):
        extra["reservation_id"] = reservation_id
    if action == "device_rpc" and frame_sha256 is not None:
        extra["frame_sha256"] = frame_sha256
        extra["frame_len"] = frame_len
    elif action == "device_rpc":
        extra["request_b64"] = request_b64
    if action == "direct_open":
        extra["ice"] = ice
    if action not in DEVICE_PAYLOAD_FIELDS:
        raise DeviceProtocolError("unknown_action")
    return extra


def is_device_handle(value: object) -> bool:
    """A lab-chosen device handle, as in ``Pluto("<handle>@<lab>")``.

    Only parse safety is enforced: '@' splits the deployment off, ':' marks a
    global ref, 'rfg_'/'bridge-' are token namespaces, whitespace would not
    survive a command line, and invisible characters (controls, zero-width,
    bidi overrides) would let two handles look identical.
    """
    return (
        type(value) is str
        and value != ""
        and not value.startswith(("rfg_", "bridge-"))
        and not any(c in "@:" or c.isspace() or not c.isprintable() for c in value)
    )


def _device_entry(value: object) -> dict:
    if type(value) is not dict or set(value) - {"handle"} != {
        "local_device_id",
        "display_name",
        "device_type",
        "online",
        "max_reservation_time_sec",
    }:
        raise DeviceProtocolError("invalid_device_entry")
    if "handle" in value and not is_device_handle(value["handle"]):
        raise DeviceProtocolError("invalid_device_entry")
    device_type = value["device_type"]
    if device_type is not None and (
        type(device_type) is not str or _DEVICE_TYPE.fullmatch(device_type) is None
    ):
        raise DeviceProtocolError("invalid_device_entry")
    block = value["max_reservation_time_sec"]
    if block is not None:
        block = _epoch(block, "invalid_device_entry")
    return {
        "local_device_id": _local_id(value["local_device_id"], "invalid_device_entry"),
        "display_name": _text(value["display_name"], "invalid_device_entry", 200),
        "device_type": device_type,
        "online": _flag(value["online"], "invalid_device_entry"),
        "max_reservation_time_sec": block,
        **({"handle": value["handle"]} if "handle" in value else {}),
    }


def _reservation_entry(value: object) -> dict:
    if type(value) is not dict or set(value) != {
        "reservation_id",
        "local_device_id",
        "display_name",
        "start_time",
        "end_time",
        "mine",
    }:
        raise DeviceProtocolError("invalid_reservation_entry")
    start = _epoch(value["start_time"], "invalid_reservation_entry")
    end = _epoch(value["end_time"], "invalid_reservation_entry")
    if end <= start:
        raise DeviceProtocolError("invalid_reservation_entry")
    return {
        "reservation_id": _local_id(
            value["reservation_id"], "invalid_reservation_entry"
        ),
        "local_device_id": _local_id(
            value["local_device_id"], "invalid_reservation_entry"
        ),
        # Other principals' reservations are shown as occupancy only, so the
        # destination is free to send an opaque label instead of a username.
        "display_name": _text(value["display_name"], "invalid_reservation_entry", 200),
        "start_time": start,
        "end_time": end,
        "mine": _flag(value["mine"], "invalid_reservation_entry"),
    }


def validate_device_payload_result(value: object, *, action: str) -> dict:
    """Validate the action-specific body carried inside a device result."""

    if not is_device_action(action):
        raise DeviceProtocolError("unknown_action")
    if type(value) is not dict:
        raise DeviceProtocolError("invalid_result_payload")
    if action == "device_list":
        if set(value) != {"devices"}:
            raise DeviceProtocolError("invalid_result_payload")
        devices = value["devices"]
        if type(devices) is not list or len(devices) > MAX_DEVICES_PER_RESULT:
            raise DeviceProtocolError("invalid_result_payload")
        seen: set[str] = set()
        handles: set[str] = set()
        entries = []
        for item in devices:
            entry = _device_entry(item)
            if entry["local_device_id"] in seen:
                raise DeviceProtocolError("duplicate_local_device_id")
            if entry.get("handle") in handles:
                raise DeviceProtocolError("duplicate_handle")
            seen.add(entry["local_device_id"])
            if "handle" in entry:
                handles.add(entry["handle"])
            entries.append(entry)
        entries.sort(key=lambda item: int(item["local_device_id"]))
        return {"devices": entries}
    if action == "device_reservations":
        if set(value) != {"reservations"}:
            raise DeviceProtocolError("invalid_result_payload")
        reservations = value["reservations"]
        if (
            type(reservations) is not list
            or len(reservations) > MAX_RESERVATIONS_PER_RESULT
        ):
            raise DeviceProtocolError("invalid_result_payload")
        seen = set()
        entries = []
        for item in reservations:
            entry = _reservation_entry(item)
            if entry["reservation_id"] in seen:
                raise DeviceProtocolError("duplicate_reservation_id")
            seen.add(entry["reservation_id"])
            entries.append(entry)
        entries.sort(
            key=lambda item: (
                int(item["local_device_id"]),
                item["start_time"],
                int(item["reservation_id"]),
            )
        )
        return {"reservations": entries}
    if action == "device_reserve":
        if set(value) != {"reservation"}:
            raise DeviceProtocolError("invalid_result_payload")
        reservation = value["reservation"]
        if type(reservation) is not dict or set(reservation) != {
            "reservation_id",
            "local_device_id",
            "start_time",
            "end_time",
        }:
            raise DeviceProtocolError("invalid_result_payload")
        start = _epoch(reservation["start_time"], "invalid_reservation_time")
        end = _epoch(reservation["end_time"], "invalid_reservation_time")
        if end <= start:
            raise DeviceProtocolError("invalid_reservation_time")
        return {
            "reservation": {
                "reservation_id": _local_id(
                    reservation["reservation_id"], "invalid_reservation_id"
                ),
                "local_device_id": _local_id(
                    reservation["local_device_id"], "invalid_local_device_id"
                ),
                "start_time": start,
                "end_time": end,
            }
        }
    if action == "device_cancel":
        if set(value) != {"cancelled"}:
            raise DeviceProtocolError("invalid_result_payload")
        return {"cancelled": _flag(value["cancelled"], "invalid_result_payload")}
    if action == "direct_open":
        if set(value) != {"ice"}:
            raise DeviceProtocolError("invalid_result_payload")
        return {"ice": _text(value["ice"], "invalid_result_payload", MAX_ICE_BYTES)}
    if set(value) == {"frame_sha256", "frame_len"}:
        return _descriptor(
            value,
            code="invalid_device_response",
            minimum=0,
            maximum=MAX_DEVICE_RPC_RESPONSE_FRAME_BYTES,
        )
    if set(value) != {"response_b64"}:
        raise DeviceProtocolError("invalid_result_payload")
    decode_device_b64(
        value["response_b64"],
        code="invalid_device_response",
        max_bytes=MAX_DEVICE_RESULT_BYTES,
        allow_empty=True,
    )
    return {"response_b64": value["response_b64"]}


def empty_device_payload(action: str) -> dict:
    """The canonical no-content payload an error result carries."""

    if action == "device_list":
        return {"devices": []}
    if action == "device_reservations":
        return {"reservations": []}
    if action == "device_reserve":
        return {"reservation": None}
    if action == "device_cancel":
        return {"cancelled": False}
    if action == "device_rpc":
        return {"response_b64": None}
    if action == "direct_open":
        return {"ice": None}
    raise DeviceProtocolError("unknown_action")


def validate_device_result(value: object, *, action: str) -> dict:
    """Validate the whole destination-signed result body for a device action."""

    if not is_device_action(action):
        raise DeviceProtocolError("unknown_action")
    if type(value) is not dict or set(value) != DEVICE_RESULT_FIELDS:
        raise DeviceProtocolError("invalid_result_fields")
    status = value["status"]
    if status not in {"ok", "error"}:
        raise DeviceProtocolError("invalid_result_status")
    error_code = value["error_code"]
    if status == "ok":
        if error_code is not None:
            raise DeviceProtocolError("invalid_result_status")
    elif (
        type(error_code) is not str
        or re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", error_code) is None
    ):
        raise DeviceProtocolError("invalid_result_error")

    payload = value["payload"]
    if status == "error":
        # An error carries no observations at all, so a presentation layer can
        # never render a destination failure as an authoritative empty answer.
        if payload != empty_device_payload(action):
            raise DeviceProtocolError("invalid_result_semantics")
        normalized_payload = empty_device_payload(action)
    else:
        normalized_payload = validate_device_payload_result(payload, action=action)

    result = {
        "status": status,
        "error_code": error_code,
        "deployment_id": canonical_uuid(value["deployment_id"]),
        "display_name": _text(value["display_name"], "invalid_display_name", 256),
        "contract_id": canonical_uuid(value["contract_id"]),
        "contract_version": _epoch(
            value["contract_version"], "invalid_contract_version"
        ),
        "state": value["state"],
        "retrieved_at": _epoch(value["retrieved_at"], "invalid_result_time"),
        "payload": normalized_payload,
    }
    if result["contract_version"] <= 0:
        raise DeviceProtocolError("invalid_contract_version")
    if len(canonical_json(result).encode("utf-8")) > MAX_DEVICE_RESULT_BYTES:
        raise DeviceProtocolError("result_too_large")
    return result
