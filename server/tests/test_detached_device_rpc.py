"""Detached device_rpc frames on the Server: destination executor, gRPC
servicer and HOME outbound negotiation, plus the second-boundary race that
returned an unsigned internal_error on relayed calls.

The Gate H `world` destination is real (grants, contracts, JTIs); brokers and
peers are in-process fakes that behave like the new or the old versions.
"""

import base64
import hashlib
import json
import sqlite3
import uuid

import pytest
import requests

from remoterf_federation_core import (
    FRAMED_CONTENT_TYPE,
    MAX_DEVICE_RPC_REQUEST_FRAME_BYTES,
    OwnerSignedFailure,
    TransportFailure,
    build_device_payload,
    frame_digest,
    pack_framed,
    unpack_framed,
)
from remoteRF_server.common.grpc import federation_pb2 as pb
from remoteRF_server.common.grpc import federation_pb2_grpc as pb_grpc
from remoteRF_server.common.grpc import grpc_pb2
from remoteRF_server.server.federation import home as home_module
from remoteRF_server.server.federation.destination import (
    error_response,
    register_grpc_federation,
)
from remoteRF_server.server.federation.home import HomeFederationOutbound

from test_gate_e_federation import CONTRACT, DEST
from test_gate_h_devices import _decode, _frame, _window, world  # noqa: F401 - fixture


def _raw(function_name, **args):
    return base64.b64decode(_frame(function_name, **args))


def _response(raw):
    response = grpc_pb2.GenericRPCResponse()
    response.ParseFromString(raw)
    return response


@pytest.fixture
def reserved(world):
    world["enroll"](devices=[world["allowed"]])
    start, end = _window(-5)
    world["call"]("device_reserve", local_device_id=str(world["allowed"]), start_time=start, end_time=end)
    return world


def _issue(world, action="device_rpc", **payload):
    return world["issuer"].issue(
        local_account_id=1, destination_deployment_id=DEST, contract_id=CONTRACT,
        contract_version=1, action=action,
        device_payload=build_device_payload(action=action, **payload),
    )


def _detached_issue(world, raw):
    return _issue(
        world, local_device_id=str(world["allowed"]),
        **frame_digest(raw, max_bytes=MAX_DEVICE_RPC_REQUEST_FRAME_BYTES, code="x"),
    )


def _jtis(world):
    with sqlite3.connect(world["dest_db"]) as conn:
        return conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0]


# -- relay internal_error: a second boundary between two clock reads ------


def test_a_second_ticking_over_before_the_handler_stamps_still_signs(reserved):
    world = reserved

    def tick():  # the wall clock crosses a second right as the handler reads it
        world["now"][0] += 1
        return world["now"][0]

    world["executor"].registry.get("device_rpc").clock = tick
    calls = len(world["rpc"].device_calls)
    result, _ = world["call"](
        "device_rpc", local_device_id=str(world["allowed"]), request_b64=_frame("test:ip:CALL0")
    )
    assert result["status"] == "ok", result
    assert len(world["rpc"].device_calls) == calls + 1
    world["executor"].registry.get("device_list").clock = tick
    listed, _ = world["call"]("device_list")
    assert listed["status"] == "ok", listed


# -- destination executor ---------------------------------------------------


def test_accept_detached_signs_a_digest_and_returns_the_raw_frame(reserved):
    world = reserved
    issued = _issue(world, local_device_id=str(world["allowed"]), request_b64=_frame("test:ip:CALL0"))
    response = world["executor"].execute("2", issued.grant, issued.request.json, b"", True)
    result = world["issuer"].verify_result(response["signed_result"], issued)
    frame = response["frame"]
    assert result["payload"] == {"frame_sha256": hashlib.sha256(frame).hexdigest(), "frame_len": len(frame)}
    assert _decode(base64.b64encode(frame)) == {"value": 42}

    # Without accept_detached the result is exactly today's shape, no frame.
    issued = _issue(world, local_device_id=str(world["allowed"]), request_b64=_frame("test:ip:CALL0"))
    response = world["executor"].execute("2", issued.grant, issued.request.json)
    assert set(response) == {"protocol_version", "signed_result", "error"}
    result = world["issuer"].verify_result(response["signed_result"], issued)
    assert set(result["payload"]) == {"response_b64"}


def test_a_detached_request_runs_and_a_tampered_frame_consumes_nothing(reserved):
    world = reserved
    raw = _raw("test:ip:CALL0", a="smuggled-bearer-token")
    issued = _detached_issue(world, raw)
    calls, jtis = len(world["rpc"].device_calls), _jtis(world)
    for bad in (raw[:-1], raw + b"\0", bytes([raw[0] ^ 1]) + raw[1:], b""):
        refused = world["executor"].execute("2", issued.grant, issued.request.json, bad, True)
        assert refused["signed_result"] is None and refused["error"]["code"] == "invalid_grant"
    assert len(world["rpc"].device_calls) == calls and _jtis(world) == jtis

    # The very same grant then succeeds: its JTI was never consumed.
    response = world["executor"].execute("2", issued.grant, issued.request.json, raw, True)
    result = world["issuer"].verify_result(response["signed_result"], issued)
    assert result["status"] == "ok"
    gid, function_name, args = world["rpc"].device_calls[-1]
    assert (gid, function_name) == (world["allowed"], "test:ip:CALL0") and "a" not in args
    assert _response(response["frame"]).results["value"].int64_value == 42


def test_stray_frames_are_refused_before_the_grant_is_consumed(reserved):
    world = reserved
    issued = _issue(world, local_device_id=str(world["allowed"]), request_b64=_frame("test:ip:CALL0"))
    refused = world["executor"].execute("2", issued.grant, issued.request.json, b"x", True)
    assert refused["error"]["code"] == "invalid_grant"
    assert world["executor"].execute("2", issued.grant, issued.request.json)["error"] is None

    listed = _issue(world, action="device_list")
    refused = world["executor"].execute("2", listed.grant, listed.request.json, b"x")
    assert refused["error"]["code"] == "invalid_grant"
    assert world["executor"].execute("2", listed.grant, listed.request.json)["error"] is None


def test_error_results_never_detach(reserved):
    world = reserved
    issued = _issue(world, local_device_id=str(world["allowed"]), request_b64=_frame("test:x:explode"))
    response = world["executor"].execute("2", issued.grant, issued.request.json, b"", True)
    assert "frame" not in response
    result = world["issuer"].verify_result(response["signed_result"], issued)
    assert result["error_code"] == "device_unavailable"
    assert result["payload"] == {"response_b64": None}


def test_grpc_servicer_carries_frame_and_accept_detached(monkeypatch):
    seen = []

    class Executor:
        def execute(self, *args):
            seen.append(args)
            return {"protocol_version": "2", "signed_result": "t", "error": None, "frame": b"raw"}

    servicers = []
    monkeypatch.setattr(pb_grpc, "add_FederationV2Servicer_to_server", lambda s, server: servicers.append(s))
    register_grpc_federation(object(), Executor())
    response = servicers[0].Execute(
        pb.FederationRequest(protocol_version="2", grant="g", request_json="{}", frame=b"in", accept_detached=True),
        None,
    )
    assert seen == [("2", "g", "{}", b"in", True)]
    assert (response.signed_result, response.frame) == ("t", b"raw")


# -- HOME outbound ----------------------------------------------------------


class _Reply:
    def __init__(self, status, body, content_type):
        self.status_code, self._body = status, body
        self.headers = {"Content-Type": content_type, "Content-Length": str(len(body))}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def iter_content(self, chunk_size):
        for start in range(0, len(self._body), 65536):
            yield self._body[start:start + 65536]


class _Broker:
    """requests.post for the forward path: a new broker, or an old one (JSON only)."""

    def __init__(self, lab, *, new=True):
        self.lab, self.new, self.seen, self.tamper = lab, new, [], False

    def post(self, url, *, data, headers, **_kwargs):
        framed_body = headers["Content-Type"] == FRAMED_CONTENT_TYPE
        self.seen.append(framed_body)
        if framed_body and not self.new:
            return _Reply(400, b'{"error":"invalid_federation_request"}', "application/json")
        envelope, frame = unpack_framed(data, max_bytes=1 << 20) if framed_body else (json.loads(data), b"")
        framed_reply = self.new and FRAMED_CONTENT_TYPE in headers.get("Accept", "")
        out = self.lab("2", envelope["grant"], envelope["request_json"], frame, framed_reply)
        frame = out.pop("frame", b"")
        if self.tamper and frame:
            frame = bytes([frame[0] ^ 1]) + frame[1:]
        if framed_reply:
            return _Reply(200, pack_framed(out, frame), FRAMED_CONTENT_TYPE)
        return _Reply(200, json.dumps(out).encode(), "application/json")


def _outbound(world):
    issuer = world["issuer"]
    return HomeFederationOutbound(
        issuer, broker_base_url="https://broker.invalid", broker_deployment_id=str(uuid.uuid4()),
        broker_private_key=issuer.private_key, broker_kid=issuer.signing_kid,
    )


def _rpc(world, outbound, function_name="test:ip:CALL0"):
    return outbound.execute(
        local_account_id=1, destination_deployment_id=DEST, contract_id=CONTRACT,
        contract_version=1, action="device_rpc",
        device_payload=build_device_payload(action="device_rpc", local_device_id=str(world["allowed"])),
        request_frame=_raw(function_name),
    )


def _old_lab(world):
    """A lab without detached support: its parser refuses the field set."""

    def execute(protocol_version, grant, request_json, frame=b"", accept_detached=False):
        if "frame_sha256" in json.loads(request_json)["payload"]:
            return error_response("invalid_grant")
        return world["executor"].execute(protocol_version, grant, request_json)

    return execute


def test_home_learns_framing_then_detaches_requests_through_a_new_broker(reserved, monkeypatch):
    world = reserved
    broker = _Broker(world["executor"].execute)
    monkeypatch.setattr(home_module.requests, "post", broker.post)
    outbound = _outbound(world)
    for _ in range(3):
        result = _rpc(world, outbound)
        assert _response(result["frame"]).results["value"].int64_value == 42
    # First call: JSON body, framed reply, detached result; then framed both ways.
    assert broker.seen == [False, True, True]
    assert outbound._broker_framed and DEST in outbound._detached_destinations


def test_home_stays_legacy_through_an_old_broker(reserved, monkeypatch):
    world = reserved
    broker = _Broker(world["executor"].execute, new=False)
    monkeypatch.setattr(home_module.requests, "post", broker.post)
    outbound = _outbound(world)
    for _ in range(2):
        result = _rpc(world, outbound)
        assert set(result["payload"]) == {"response_b64"}
        assert _response(result["frame"]).results["value"].int64_value == 42
    assert broker.seen == [False, False] and not outbound._broker_framed


def test_a_rolled_back_broker_gets_one_legacy_resend(reserved, monkeypatch):
    world = reserved
    broker = _Broker(world["executor"].execute)
    monkeypatch.setattr(home_module.requests, "post", broker.post)
    outbound = _outbound(world)
    _rpc(world, outbound)
    broker.new = False
    calls = len(world["rpc"].device_calls)
    result = _rpc(world, outbound)
    assert _response(result["frame"]).results["value"].int64_value == 42
    assert broker.seen == [False, True, False]
    assert len(world["rpc"].device_calls) == calls + 1 and not outbound._broker_framed


def test_a_rolled_back_lab_gets_one_legacy_resend(reserved, monkeypatch):
    world = reserved
    broker = _Broker(world["executor"].execute)
    monkeypatch.setattr(home_module.requests, "post", broker.post)
    outbound = _outbound(world)
    _rpc(world, outbound)
    broker.lab = _old_lab(world)
    calls = len(world["rpc"].device_calls)
    result = _rpc(world, outbound)
    assert set(result["payload"]) == {"response_b64"}
    assert _response(result["frame"]).results["value"].int64_value == 42
    assert len(world["rpc"].device_calls) == calls + 1
    assert DEST not in outbound._detached_destinations
    _rpc(world, outbound)  # stays legacy, no second probe
    assert broker.seen == [False, True, False, False]


@pytest.mark.parametrize("lie", ["http_400", "invalid_grant"])
def test_a_forged_refusal_after_the_lab_ran_cannot_run_the_call_twice(reserved, monkeypatch, lie):
    world = reserved
    broker = _Broker(world["executor"].execute)
    monkeypatch.setattr(home_module.requests, "post", broker.post)
    outbound = _outbound(world)
    _rpc(world, outbound)
    honest = broker.post

    def lying(url, *, data, headers, **kwargs):
        reply = honest(url, data=data, headers=headers, **kwargs)
        if headers["Content-Type"] != FRAMED_CONTENT_TYPE:
            return reply
        if lie == "http_400":
            return _Reply(400, b'{"error":"invalid_federation_request"}', "application/json")
        return _Reply(200, pack_framed(error_response("invalid_grant")), FRAMED_CONTENT_TYPE)

    monkeypatch.setattr(home_module.requests, "post", lying)
    calls = len(world["rpc"].device_calls)
    with pytest.raises(OwnerSignedFailure) as failure:
        _rpc(world, outbound)
    assert failure.value.code == "replayed"
    assert len(world["rpc"].device_calls) == calls + 1


def test_a_tampered_response_frame_is_an_invalid_signed_result(reserved, monkeypatch):
    world = reserved
    broker = _Broker(world["executor"].execute)
    broker.tamper = True
    monkeypatch.setattr(home_module.requests, "post", broker.post)
    with pytest.raises(TransportFailure) as failure:
        _rpc(world, _outbound(world))
    assert failure.value.code == "invalid_signed_result"


def test_a_direct_peer_is_dialed_with_accept_detached(reserved, monkeypatch):
    world = reserved
    sent = []

    class Stub:
        def __init__(self, channel):
            pass

        def Execute(self, request, timeout):
            sent.append((request.frame, request.accept_detached))
            out = world["executor"].execute(
                request.protocol_version, request.grant, request.request_json,
                request.frame, request.accept_detached,
            )
            return pb.FederationResponse(
                protocol_version="2", signed_result=out["signed_result"], frame=out.get("frame", b"")
            )

    class Channel:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(pb_grpc, "FederationV2Stub", Stub)
    monkeypatch.setattr(home_module.grpc, "secure_channel", lambda *a, **k: Channel())
    monkeypatch.setattr(home_module.grpc, "ssl_channel_credentials", lambda **k: None)
    outbound = _outbound(world)
    outbound.peer = lambda deployment_id: {
        "ca_pem": "-", "tls_server_name": "lab.example.org", "endpoint": "lab.example.org:1", "via": "direct",
    }
    for _ in range(2):
        assert _response(_rpc(world, outbound)["frame"]).results["value"].int64_value == 42
    assert sent == [(b"", True), (_raw("test:ip:CALL0"), True)]
