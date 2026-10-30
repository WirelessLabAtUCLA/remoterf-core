"""The optional device handle in a device_list entry."""

import pytest

from remoterf_federation_core import (
    DeviceProtocolError,
    is_device_handle,
    validate_device_payload_result,
)


def entry(local_id="1", **extra):
    return {
        "local_device_id": local_id,
        "display_name": "Pluto SDR",
        "device_type": "adalm_pluto",
        "online": True,
        "max_reservation_time_sec": 1800,
        **extra,
    }


def listed(*devices):
    return validate_device_payload_result({"devices": list(devices)}, action="device_list")


def test_handle_rule_is_parse_safety_only():
    for good in ("PlutoA", "p", "7", "lab-1_x", "a.b", "x" * 300, "Plüto", "Pluto\u0301A"):
        assert is_device_handle(good), good
    for bad in ("", "a@b", "a:b", "a b", "a\tb", "a\x1bb", "a\x7fb",
                "Pluto\u200bA", "\u202ePlutoA", "\ufeffPlutoA", "a\x9bb", "a\u00a0b",
                "rfg_x", "bridge-1-x", None, 7, b"PlutoA"):
        assert not is_device_handle(bad), bad


def test_an_entry_without_a_handle_is_unchanged():
    assert listed(entry()) == {"devices": [entry()]}


def test_a_valid_handle_passes_through():
    assert listed(entry(handle="PlutoA"))["devices"][0]["handle"] == "PlutoA"


@pytest.mark.parametrize("handle", ["", "a@b", "a:b", "a b", "rfg_x", "bridge-1", None, 7])
def test_an_invalid_handle_rejects_the_entry(handle):
    with pytest.raises(DeviceProtocolError, match="invalid_device_entry"):
        listed(entry(handle=handle))


def test_no_other_extra_key_is_accepted():
    with pytest.raises(DeviceProtocolError, match="invalid_device_entry"):
        listed(entry(alias="PlutoA"))


def test_handles_are_unique_within_one_listing():
    assert len(listed(entry("1", handle="A"), entry("2", handle="B"), entry("3"))["devices"]) == 3
    with pytest.raises(DeviceProtocolError, match="duplicate_handle"):
        listed(entry("1", handle="A"), entry("2", handle="A"))
