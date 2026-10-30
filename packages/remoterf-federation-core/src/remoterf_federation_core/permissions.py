"""Pure HOME-facing permissions summary validation.

The model deliberately contains no grants or signed-result tokens.  It keeps
owner-signed observations, unsigned transport failures, and HOME-local state
structurally distinct so a presentation layer cannot turn an outage into an
authoritative empty membership snapshot.
"""

from __future__ import annotations

import re

from .contracts import CONTRACT_STATES
from .schemas import canonical_json, canonical_uuid

MAX_HOME_PERMISSION_DESTINATIONS = 64
MAX_HOME_PERMISSION_GROUPS = 256
PERMISSIONS_AGGREGATION_TIMEOUT_SECONDS = 15.0
PERMISSIONS_DESTINATION_TIMEOUT_SECONDS = 11.0
PERMISSIONS_CONNECT_TIMEOUT_SECONDS = 3.0
PERMISSIONS_CLIENT_OVERALL_TIMEOUT_SECONDS = PERMISSIONS_AGGREGATION_TIMEOUT_SECONDS + 3.0
# A destination result is already bounded to 12 KiB.  Sixty-four such results,
# plus the HOME-local section and envelope overhead, fit below this producer
# ceiling.  Consumers use the companion HTTP ceiling so every valid response a
# HOME can emit is receivable without making unrelated account calls unbounded.
MAX_HOME_PERMISSIONS_SUMMARY_BYTES = 1024 * 1024
MAX_HOME_PERMISSIONS_HTTP_RESPONSE_BYTES = MAX_HOME_PERMISSIONS_SUMMARY_BYTES + 128 * 1024
HOME_PERMISSION_STATUSES = frozenset({"ok", "unavailable", "blocked"})
HOME_PERMISSION_PROVENANCE = frozenset(
    {"local", "destination_signed", "transport"}
)

_DECIMAL_ID = re.compile(r"0|[1-9][0-9]{0,19}")
_ERROR_CODE = re.compile(r"[a-z][a-z0-9_.-]{0,63}")


class HomePermissionsError(ValueError):
    """Stable structural failure for a HOME-facing permissions summary."""


def _text(value, code, maximum):
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise HomePermissionsError(code)
    return value


def _groups(value):
    if type(value) is not list or len(value) > MAX_HOME_PERMISSION_GROUPS:
        raise HomePermissionsError("invalid_home_permissions_groups")
    result = []
    seen = set()
    for group in value:
        if type(group) is not dict or set(group) != {"group_id", "group_name"}:
            raise HomePermissionsError("invalid_home_permissions_groups")
        group_id = group["group_id"]
        if type(group_id) is not str or _DECIMAL_ID.fullmatch(group_id) is None:
            raise HomePermissionsError("invalid_home_permissions_groups")
        group_name = _text(
            group["group_name"], "invalid_home_permissions_groups", 128
        )
        if group_id in seen:
            raise HomePermissionsError("invalid_home_permissions_groups")
        seen.add(group_id)
        result.append({"group_id": group_id, "group_name": group_name})
    return sorted(result, key=lambda item: (item["group_name"].casefold(), item["group_id"]))


def validate_home_permissions_summary(value):
    """Return the normalized exact Phase-1 HOME permissions model."""

    if type(value) is not dict or set(value) not in (
        {"local", "federation"},
        {"local", "federation", "incomplete", "omitted_count"},
    ):
        raise HomePermissionsError("invalid_home_permissions_summary")
    incomplete = value.get("incomplete", False)
    omitted_count = value.get("omitted_count", 0)
    if type(incomplete) is not bool or type(omitted_count) is not int:
        raise HomePermissionsError("invalid_home_permissions_completeness")
    if omitted_count < 0 or omitted_count > 1_000_000:
        raise HomePermissionsError("invalid_home_permissions_completeness")
    if incomplete != (omitted_count > 0):
        raise HomePermissionsError("invalid_home_permissions_completeness")
    local = value["local"]
    if type(local) is not dict or set(local) != {
        "deployment_id",
        "display_name",
        "groups",
    }:
        raise HomePermissionsError("invalid_home_permissions_local")
    normalized_local = {
        "deployment_id": canonical_uuid(local["deployment_id"]),
        "display_name": _text(
            local["display_name"], "invalid_home_permissions_local", 256
        ),
        "groups": _groups(local["groups"]),
    }

    federation = value["federation"]
    if type(federation) is not list or len(federation) > MAX_HOME_PERMISSION_DESTINATIONS:
        raise HomePermissionsError("invalid_home_permissions_federation")
    normalized_federation = []
    seen = set()
    required = {
        "deployment_id",
        "display_name",
        "contract_id",
        "contract_version",
        "state",
        "groups",
        "retrieved_at",
        "status",
        "provenance",
        "error_code",
    }
    for item in federation:
        if type(item) is not dict or set(item) != required:
            raise HomePermissionsError("invalid_home_permissions_federation")
        deployment_id = canonical_uuid(item["deployment_id"])
        contract_id = canonical_uuid(item["contract_id"])
        version = item["contract_version"]
        if type(version) is not int or version <= 0:
            raise HomePermissionsError("invalid_home_permissions_contract")
        identity = (contract_id, version)
        if identity in seen:
            raise HomePermissionsError("duplicate_home_permissions_contract")
        seen.add(identity)
        status = item["status"]
        provenance = item["provenance"]
        state = item["state"]
        error_code = item["error_code"]
        retrieved_at = item["retrieved_at"]
        groups = _groups(item["groups"])
        if status not in HOME_PERMISSION_STATUSES or provenance not in HOME_PERMISSION_PROVENANCE:
            raise HomePermissionsError("invalid_home_permissions_status")
        if state not in CONTRACT_STATES:
            raise HomePermissionsError("invalid_home_permissions_contract")
        if error_code is not None and (
            type(error_code) is not str or _ERROR_CODE.fullmatch(error_code) is None
        ):
            raise HomePermissionsError("invalid_home_permissions_error")
        if retrieved_at is not None and (
            type(retrieved_at) is not int or retrieved_at < 0
        ):
            raise HomePermissionsError("invalid_home_permissions_time")

        if status == "ok":
            valid = (
                provenance == "destination_signed"
                and error_code is None
                and retrieved_at is not None
            )
        elif status == "unavailable":
            valid = (
                provenance == "transport"
                and not groups
                and error_code is None
                and retrieved_at is None
            )
        else:
            valid = (
                provenance in {"destination_signed", "local"}
                and not groups
                and error_code is not None
                and (
                    (provenance == "destination_signed" and retrieved_at is not None)
                    or (provenance == "local" and retrieved_at is None)
                )
            )
        if not valid:
            raise HomePermissionsError("invalid_home_permissions_semantics")
        normalized_federation.append(
            {
                "deployment_id": deployment_id,
                "display_name": _text(
                    item["display_name"],
                    "invalid_home_permissions_federation",
                    256,
                ),
                "contract_id": contract_id,
                "contract_version": version,
                "state": state,
                "groups": groups,
                "retrieved_at": retrieved_at,
                "status": status,
                "provenance": provenance,
                "error_code": error_code,
            }
        )
    normalized_federation.sort(
        key=lambda item: (
            item["display_name"].casefold(),
            item["deployment_id"],
            item["contract_id"],
            item["contract_version"],
        )
    )
    result = {
        "local": normalized_local,
        "federation": normalized_federation,
        "incomplete": incomplete,
        "omitted_count": omitted_count,
    }
    if len(canonical_json(result).encode("utf-8")) > MAX_HOME_PERMISSIONS_SUMMARY_BYTES:
        raise HomePermissionsError("home_permissions_too_large")
    return result
