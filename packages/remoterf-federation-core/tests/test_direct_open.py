"""The direct_open action's grammar: what an owner accepts and answers."""

import pytest

from remoterf_federation_core import (
    ACTION_CAPABILITIES,
    DEFAULT_ACTION_RETRY_POLICIES,
    ActionRetryPolicy,
    DeviceProtocolError,
    build_device_payload,
    device_action_timeout,
    empty_device_payload,
    validate_device_payload,
    validate_device_payload_result,
)
from remoterf_federation_core.devices import MAX_ICE_BYTES

BASE = {
    "request_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "destination_deployment_id": "22222222-2222-4222-8222-222222222222",
    "contract_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "contract_version": 1,
    "terms_sha256": "0" * 64,
}


def test_direct_open_is_a_device_control_action_that_is_never_retried():
    assert ACTION_CAPABILITIES["direct_open"] == "DEVICE_CONTROL"
    assert DEFAULT_ACTION_RETRY_POLICIES["direct_open"] is ActionRetryPolicy.NO_RETRY
    assert device_action_timeout("direct_open") == 11.0
    assert build_device_payload(action="direct_open", reservation_id="7", ice="{}") == {"reservation_id": "7", "ice": "{}"}
    assert empty_device_payload("direct_open") == {"ice": None}


def test_the_offer_and_answer_are_bounded_text():
    ok = validate_device_payload("direct_open", {**BASE, "reservation_id": "7", "ice": "{}"})
    assert ok == {"reservation_id": "7", "ice": "{}"}
    for bad in ("", "x" * (MAX_ICE_BYTES + 1), "a\x00b", 7):
        with pytest.raises(DeviceProtocolError, match="invalid_ice"):
            validate_device_payload("direct_open", {**BASE, "reservation_id": "7", "ice": bad})
    with pytest.raises(DeviceProtocolError):
        validate_device_payload("direct_open", {**BASE, "reservation_id": "-1", "ice": "{}"})
    with pytest.raises(DeviceProtocolError):
        validate_device_payload("direct_open", {**BASE, "reservation_id": "7"})  # ice missing
    assert validate_device_payload_result({"ice": "{}"}, action="direct_open") == {"ice": "{}"}
    for bad in ({"ice": "x" * (MAX_ICE_BYTES + 1)}, {"ice": None}, {"ice": "{}", "server_name": "x"}, {}):
        with pytest.raises(DeviceProtocolError):
            validate_device_payload_result(bad, action="direct_open")
