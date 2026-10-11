"""Detached device_rpc frames: descriptors, framed bodies, and legacy parity."""

import base64
import hashlib
import json
from types import SimpleNamespace

import pytest

from remoterf_federation_core import (
    DEVICE_PAYLOAD_FIELDS,
    DEVICE_RPC_DETACHED_PAYLOAD_FIELDS,
    FRAMED_CONTENT_TYPE,
    MAX_DEVICE_ACTION_REQUEST_BYTES,
    MAX_DEVICE_RESULT_BYTES,
    MAX_DEVICE_RPC_REQUEST_FRAME_BYTES,
    MAX_DEVICE_RPC_RESPONSE_FRAME_BYTES,
    DeviceProtocolError,
    FederationError,
    ValidationError,
    build_action_request,
    build_device_payload,
    canonical_json,
    decode_device_b64,
    device_request_frame,
    device_response_frame,
    empty_device_payload,
    frame_digest,
    pack_framed,
    parse_canonical_action_request,
    strict_json,
    unpack_framed,
    validate_device_payload,
    validate_device_result,
    validate_transport_response,
    verify_frame,
)
from remoterf_federation_core import devices

DEST = "22222222-2222-4222-8222-222222222222"
CONTRACT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
REQUEST_ID = "44444444-4444-4444-8444-444444444444"
TERMS = "b" * 64
REQ = b"\x0a\x14Pluto:rx_lo:SET\x12\x05\x0a\x01a\x12\x00"
RESP = b"\x0a\x06\x0a\x02rx\x12\x00" * 7
BASE = {
    "request_id": REQUEST_ID,
    "destination_deployment_id": DEST,
    "contract_id": CONTRACT,
    "contract_version": 3,
    "terms_sha256": TERMS,
}
SIGNED = {"protocol_version": "2", "signed_result": "a.b.c", "error": None}
ERROR = {
    "protocol_version": "2",
    "signed_result": None,
    "error": {"code": "route_unavailable", "message": "x", "retryable": True},
}


def b64(raw):
    return base64.b64encode(raw).decode()


def request(**device):
    return build_action_request(
        action="device_rpc", **BASE, device_payload={"local_device_id": "7", **device}
    )


def result(payload, *, status="ok"):
    return {
        "status": status,
        "error_code": None if status == "ok" else "device_unavailable",
        "deployment_id": DEST,
        "display_name": "Lab",
        "contract_id": CONTRACT,
        "contract_version": 3,
        "state": "active",
        "retrieved_at": 1700000000,
        "payload": payload,
    }


# --- constants and legacy parity ---------------------------------------------


def test_frame_caps_are_exactly_what_the_legacy_base64_caps_admit():
    assert MAX_DEVICE_RPC_REQUEST_FRAME_BYTES == 196608
    assert MAX_DEVICE_RPC_RESPONSE_FRAME_BYTES == 786432
    assert FRAMED_CONTENT_TYPE == "application/x-remoterf-framed"
    for cap, b64_cap, code in (
        (MAX_DEVICE_RPC_REQUEST_FRAME_BYTES, MAX_DEVICE_ACTION_REQUEST_BYTES, "q"),
        (MAX_DEVICE_RPC_RESPONSE_FRAME_BYTES, MAX_DEVICE_RESULT_BYTES, "r"),
    ):
        decode_device_b64(b64(b"\0" * cap), code=code, max_bytes=b64_cap)
        frame_digest(b"\0" * cap, max_bytes=cap, code=code)
        with pytest.raises(DeviceProtocolError, match=code):
            decode_device_b64(b64(b"\0" * (cap + 1)), code=code, max_bytes=b64_cap)
        with pytest.raises(DeviceProtocolError, match=code):
            frame_digest(b"\0" * (cap + 1), max_bytes=cap, code=code)


def test_legacy_request_is_byte_identical_and_old_field_set_is_unchanged():
    assert DEVICE_PAYLOAD_FIELDS["device_rpc"] == DEVICE_RPC_DETACHED_PAYLOAD_FIELDS - {
        "frame_sha256",
        "frame_len",
    } | {"request_b64"}
    payload = build_device_payload(
        action="device_rpc", local_device_id="7", request_b64=b64(REQ)
    )
    assert payload == {"local_device_id": "7", "request_b64": b64(REQ)}
    legacy = request(request_b64=b64(REQ))
    expected = canonical_json(
        {
            "protocol_version": "2",
            "action": "device_rpc",
            "payload": {**BASE, "local_device_id": "7", "request_b64": b64(REQ)},
        }
    )
    assert legacy.json == expected
    assert legacy.sha256 == hashlib.sha256(expected.encode()).hexdigest()
    assert device_request_frame(legacy.value["payload"], b"") == REQ


def test_old_validators_reject_the_detached_shape():
    # An old peer validates device_rpc with the legacy field set only, so a
    # detached request or result is refused before anything runs.
    detached = {**BASE, "local_device_id": "7", **frame_digest(REQ, max_bytes=9**9, code="x")}
    assert set(detached) != DEVICE_PAYLOAD_FIELDS["device_rpc"]
    assert set(frame_digest(RESP, max_bytes=9**9, code="x")) != {"response_b64"}


# --- descriptors ---------------------------------------------------------------


def test_frame_digest_and_verify_round_trip_including_empty():
    for raw in (REQ, b""):
        descriptor = frame_digest(raw, max_bytes=1024, code="bad")
        assert descriptor == {
            "frame_sha256": hashlib.sha256(raw).hexdigest(),
            "frame_len": len(raw),
        }
        assert verify_frame(raw, descriptor, max_bytes=1024, code="bad") is raw


@pytest.mark.parametrize(
    "frame",
    [
        REQ[:-1],  # truncated
        REQ + b"\0",  # extended
        bytes([REQ[0] ^ 1]) + REQ[1:],  # same length, flipped byte
        b"",
        RESP,  # swapped: the response where the request belongs
        bytearray(REQ),
        memoryview(REQ),
        REQ.decode("latin-1"),
        None,
    ],
)
def test_verify_frame_rejects_tampered_or_mistyped_frames(frame):
    descriptor = frame_digest(REQ, max_bytes=1024, code="bad")
    with pytest.raises(DeviceProtocolError, match="bad"):
        verify_frame(frame, descriptor, max_bytes=1024, code="bad")


@pytest.mark.parametrize(
    "change",
    [
        {"frame_sha256": hashlib.sha256(b"other").hexdigest()},
        {"frame_sha256": hashlib.sha256(REQ).hexdigest().upper()},
        {"frame_sha256": None},
        {"frame_len": len(REQ) + 1},
        {"frame_len": len(REQ) - 1},
        {"frame_len": float(len(REQ))},
        {"frame_len": str(len(REQ))},
        {"frame_len": None},
    ],
)
def test_verify_frame_rejects_wrong_descriptor(change):
    descriptor = {**frame_digest(REQ, max_bytes=1024, code="bad"), **change}
    with pytest.raises(DeviceProtocolError, match="bad"):
        verify_frame(REQ, descriptor, max_bytes=1024, code="bad")
    with pytest.raises(DeviceProtocolError, match="bad"):
        verify_frame(REQ, None, max_bytes=1024, code="bad")


def test_bool_length_is_not_an_int():
    descriptor = frame_digest(b"\x01", max_bytes=8, code="bad")
    with pytest.raises(DeviceProtocolError):
        verify_frame(b"\x01", {**descriptor, "frame_len": True}, max_bytes=8, code="bad")


def test_oversized_and_length_mismatch_are_rejected_before_hashing(monkeypatch):
    descriptor = frame_digest(REQ, max_bytes=1024, code="bad")

    def boom(*_):
        raise AssertionError("hashed before the length check")

    monkeypatch.setattr(devices, "hashlib", SimpleNamespace(sha256=boom))
    for frame, cap in ((REQ, len(REQ) - 1), (REQ + b"\0", 1024), (REQ[:-1], 1024)):
        with pytest.raises(DeviceProtocolError, match="bad"):
            verify_frame(frame, descriptor, max_bytes=cap, code="bad")
    with pytest.raises(DeviceProtocolError, match="bad"):
        frame_digest(REQ, max_bytes=len(REQ) - 1, code="bad")


# --- request payload -----------------------------------------------------------


def test_detached_request_is_canonical_and_binds_the_frame():
    detached = request(**frame_digest(REQ, max_bytes=9**9, code="x"))
    payload = detached.value["payload"]
    assert set(payload) == DEVICE_RPC_DETACHED_PAYLOAD_FIELDS
    assert "request_b64" not in detached.json
    assert parse_canonical_action_request(detached.json) == detached
    assert device_request_frame(payload, REQ) == REQ
    assert device_request_frame(payload, REQ) == device_request_frame(
        request(request_b64=b64(REQ)).value["payload"], b""
    )
    other_hash = request(frame_sha256="c" * 64, frame_len=len(REQ))
    other_len = request(frame_sha256=payload["frame_sha256"], frame_len=len(REQ) + 1)
    assert len({detached.sha256, other_hash.sha256, other_len.sha256}) == 3
    built = build_device_payload(
        action="device_rpc", local_device_id="7", **frame_digest(REQ, max_bytes=9**9, code="x")
    )
    assert set(built) == {"local_device_id", "frame_sha256", "frame_len"}


@pytest.mark.parametrize(
    "fields",
    [
        {"frame_sha256": "c" * 64, "frame_len": 4, "request_b64": b64(REQ)},
        {"frame_sha256": "c" * 64},
        {"frame_sha256": "c" * 64, "frame_len": 0},
        {"frame_sha256": "c" * 64, "frame_len": MAX_DEVICE_RPC_REQUEST_FRAME_BYTES + 1},
        {"frame_sha256": "c" * 64, "frame_len": True},
        {"frame_sha256": "c" * 64, "frame_len": "4"},
        {"frame_sha256": "C" * 64, "frame_len": 4},
        {"frame_sha256": "c" * 63, "frame_len": 4},
        {"frame_sha256": None, "frame_len": 4},
        {"frame_len": 4, "request_b64": b64(REQ)},
    ],
)
def test_malformed_detached_request_is_refused(fields):
    with pytest.raises(FederationError):
        request(**fields)
    with pytest.raises(DeviceProtocolError):
        validate_device_payload("device_rpc", {**BASE, "local_device_id": "7", **fields})


def test_request_cap_boundary():
    at_cap = request(frame_sha256="c" * 64, frame_len=MAX_DEVICE_RPC_REQUEST_FRAME_BYTES)
    assert at_cap.value["payload"]["frame_len"] == MAX_DEVICE_RPC_REQUEST_FRAME_BYTES


def test_only_device_rpc_has_a_detached_form():
    with pytest.raises(FederationError, match="invalid_payload_fields"):
        build_action_request(
            action="device_list", **BASE, device_payload={"frame_sha256": "c" * 64, "frame_len": 4}
        )


def test_device_request_frame_rejects_tamper_and_stray_frames():
    detached = request(**frame_digest(REQ, max_bytes=9**9, code="x")).value["payload"]
    legacy = request(request_b64=b64(REQ)).value["payload"]
    for frame in (b"", REQ[:-1], REQ + b"\0", RESP, None, bytearray(REQ)):
        with pytest.raises(DeviceProtocolError, match="invalid_device_request"):
            device_request_frame(detached, frame)
    for frame in (REQ, b"\0", None, bytearray()):
        with pytest.raises(DeviceProtocolError, match="invalid_device_request"):
            device_request_frame(legacy, frame)


# --- result payload ------------------------------------------------------------


def test_detached_result_round_trip_and_legacy_parity():
    for raw in (RESP, b""):
        descriptor = frame_digest(raw, max_bytes=9**9, code="x")
        clean = validate_device_result(result(descriptor), action="device_rpc")
        assert clean["payload"] == descriptor
        legacy = validate_device_result(result({"response_b64": b64(raw)}), action="device_rpc")
        assert device_response_frame(clean["payload"], raw) == raw
        assert device_response_frame(legacy["payload"], b"") == raw


def test_response_cap_boundary():
    for length, ok in (
        (MAX_DEVICE_RPC_RESPONSE_FRAME_BYTES, True),
        (MAX_DEVICE_RPC_RESPONSE_FRAME_BYTES + 1, False),
        (-1, False),
    ):
        value = result({"frame_sha256": "c" * 64, "frame_len": length})
        if ok:
            validate_device_result(value, action="device_rpc")
        else:
            with pytest.raises(DeviceProtocolError, match="invalid_device_response"):
                validate_device_result(value, action="device_rpc")


@pytest.mark.parametrize(
    "payload",
    [
        {"frame_sha256": "c" * 64, "frame_len": 1, "response_b64": ""},
        {"frame_sha256": "c" * 64},
        {"frame_len": 1},
    ],
)
def test_mixed_or_partial_result_payload_is_refused(payload):
    with pytest.raises(DeviceProtocolError, match="invalid_result_payload"):
        validate_device_result(result(payload), action="device_rpc")


def test_error_results_never_detach():
    assert empty_device_payload("device_rpc") == {"response_b64": None}
    validate_device_result(result(empty_device_payload("device_rpc"), status="error"), action="device_rpc")
    with pytest.raises(DeviceProtocolError, match="invalid_result_semantics"):
        validate_device_result(
            result(frame_digest(b"", max_bytes=1, code="x"), status="error"),
            action="device_rpc",
        )


def test_device_response_frame_rejects_tamper_and_stray_frames():
    detached = frame_digest(RESP, max_bytes=9**9, code="x")
    for frame in (RESP[:-1], RESP + b"\0", REQ, b"", None, bytearray(RESP)):
        with pytest.raises(DeviceProtocolError, match="invalid_device_response"):
            device_response_frame(detached, frame)
    with pytest.raises(DeviceProtocolError, match="invalid_device_response"):
        device_response_frame({"response_b64": b64(RESP)}, RESP)
    with pytest.raises(DeviceProtocolError, match="invalid_device_response"):
        device_response_frame({"response_b64": None}, b"")


# --- framed HTTP body ------------------------------------------------------------


def test_pack_unpack_round_trip():
    envelope = {"protocol_version": "2", "grant": "g", "request_json": "{}"}
    for frame in (REQ, b""):
        body = pack_framed(envelope, frame)
        encoded = canonical_json(envelope).encode()
        assert body == len(encoded).to_bytes(4, "big") + encoded + frame
        assert unpack_framed(body, max_bytes=len(encoded)) == (envelope, frame)
    assert pack_framed({}) == b"\0\0\0\x02{}"


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"\0\0\0",  # truncated prefix
        b"\0\0\0\x05{}",  # prefix past the end
        b"\xff\xff\xff\xff{}",
        b"\0\0\0\x02[]",  # not an object
        b"\0\0\0\x02{]",
        b"\0\0\0\x0d{\"a\":1,\"a\":2}",  # duplicate key
        b"\0\0\0\x00",
        bytearray(b"\0\0\0\x02{}"),
        "\0\0\0\x02{}",
        None,
    ],
)
def test_unpack_framed_rejects_malformed_bodies(body):
    with pytest.raises(ValidationError, match="invalid_framed_body"):
        unpack_framed(body, max_bytes=1024)


def test_unpack_framed_bounds_the_envelope_not_the_frame():
    body = pack_framed({"k": "v" * 100}, b"\0" * 5000)
    with pytest.raises(ValidationError, match="invalid_framed_body"):
        unpack_framed(body, max_bytes=50)
    assert len(unpack_framed(body, max_bytes=200)[1]) == 5000


def test_swapped_content_types_do_not_parse():
    envelope = {"protocol_version": "2", "signed_result": "a.b.c", "error": None}
    with pytest.raises(ValidationError, match="invalid_framed_body"):
        unpack_framed(json.dumps(envelope).encode(), max_bytes=1 << 20)
    with pytest.raises(ValidationError):
        strict_json(pack_framed(envelope, RESP))


def test_pack_framed_rejects_bad_inputs():
    for envelope, frame in (([], b""), ({}, "x"), ({}, bytearray()), ({"f": 1.5}, b"")):
        with pytest.raises(ValidationError):
            pack_framed(envelope, frame)


# --- transport response ----------------------------------------------------------


def test_transport_response_without_frame_is_unchanged():
    assert validate_transport_response(dict(SIGNED)) == SIGNED
    assert "frame" not in validate_transport_response(dict(ERROR))


def test_transport_response_carries_a_bytes_frame_beside_a_token():
    for frame in (RESP, b"", b"\0" * MAX_DEVICE_RPC_RESPONSE_FRAME_BYTES):
        out = validate_transport_response({**SIGNED, "frame": frame}, expected_action="device_rpc")
        assert out == {**SIGNED, "frame": frame}
        assert validate_transport_response({**SIGNED, "frame": frame})["frame"] == frame
    assert validate_transport_response(
        {**SIGNED, "frame": b""}, expected_action="permissions_read"
    ) == {**SIGNED, "frame": b""}


@pytest.mark.parametrize(
    "value, action",
    [
        ({**SIGNED, "frame": b64(RESP)}, None),
        ({**SIGNED, "frame": bytearray(RESP)}, None),
        ({**SIGNED, "frame": None}, None),
        ({**SIGNED, "frame": b"\0" * (MAX_DEVICE_RPC_RESPONSE_FRAME_BYTES + 1)}, None),
        ({**ERROR, "frame": RESP}, None),
        ({**ERROR, "frame": b""}, None),
        ({**SIGNED, "frame": RESP}, "permissions_read"),
        ({**SIGNED, "frame": RESP}, "device_list"),
        ({**SIGNED, "frame": RESP, "extra": 1}, None),
    ],
)
def test_transport_response_rejects_bad_frames(value, action):
    with pytest.raises(FederationError, match="invalid_transport_response"):
        validate_transport_response(value, expected_action=action)
