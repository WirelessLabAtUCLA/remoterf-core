import pytest

from remoterf_federation_core import (
    HomePermissionsError,
    validate_home_permissions_summary,
)


HOME = "11111111-1111-4111-8111-111111111111"
DEST = "22222222-2222-4222-8222-222222222222"
CONTRACT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def summary(entry):
    return {
        "local": {
            "deployment_id": HOME,
            "display_name": "Home",
            "groups": [{"group_id": "1", "group_name": "local-users"}],
        },
        "federation": [entry],
    }


def entry(**changes):
    value = {
        "deployment_id": DEST,
        "display_name": "Destination",
        "contract_id": CONTRACT,
        "contract_version": 1,
        "state": "active",
        "groups": [{"group_id": "9", "group_name": "remote-users"}],
        "retrieved_at": 100,
        "status": "ok",
        "provenance": "destination_signed",
        "error_code": None,
    }
    value.update(changes)
    return value


def test_home_permissions_model_preserves_authority_and_sorts():
    value = summary(entry())
    value["local"]["groups"].append(
        {"group_id": "2", "group_name": "alpha-users"}
    )
    result = validate_home_permissions_summary(value)
    assert [group["group_name"] for group in result["local"]["groups"]] == [
        "alpha-users",
        "local-users",
    ]
    assert result["federation"][0]["provenance"] == "destination_signed"


@pytest.mark.parametrize(
    "bad",
    [
        entry(status="unavailable", provenance="transport"),
        entry(status="unavailable", provenance="transport", groups=[], retrieved_at=100),
        entry(status="blocked", groups=[], error_code=None),
        entry(status="blocked", groups=[], error_code="principal_disabled", provenance="transport"),
        entry(status="ok", groups=[], provenance="transport"),
    ],
)
def test_home_permissions_model_rejects_contradictory_provenance(bad):
    with pytest.raises(HomePermissionsError):
        validate_home_permissions_summary(summary(bad))


def test_transport_unavailable_is_not_empty_owner_state():
    result = validate_home_permissions_summary(
        summary(
            entry(
                status="unavailable",
                provenance="transport",
                groups=[],
                retrieved_at=None,
            )
        )
    )
    assert result["federation"][0] == entry(
        status="unavailable",
        provenance="transport",
        groups=[],
        retrieved_at=None,
    )


def test_signed_owner_failure_is_separate_from_transport():
    result = validate_home_permissions_summary(
        summary(
            entry(
                status="blocked",
                groups=[],
                error_code="principal_disabled",
            )
        )
    )
    assert result["federation"][0]["provenance"] == "destination_signed"
