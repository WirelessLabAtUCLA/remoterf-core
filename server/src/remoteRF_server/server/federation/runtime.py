"""Explicit stock Server composition for the complete Phase-1 federation path."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from cryptography.hazmat.primitives import serialization
from remoterf_federation_core import canonical_uuid

from .enrollment import ServerFederatedEnrollmentHome
from .home import HomeFederationOutbound, ServerHomeGrantIssuer
from .identity import PROTOCOL_VERSION, load_private_key, load_state
from .migrations import initialize_native_subjects
from .permissions import ServerHomePermissions, build_server_gate_g_executor


def federation_enabled() -> bool:
    raw = os.environ.get("REMOTERF_FEDERATION_ENABLED", "0").strip().lower()
    if raw not in {"0", "1", "false", "true"}:
        raise RuntimeError("REMOTERF_FEDERATION_ENABLED must be 0/1/false/true")
    return raw in {"1", "true"}


@dataclass(frozen=True)
class ServerFederationRuntime:
    executor: object
    enroller: object
    permissions: object


def _path(value, field):
    if type(value) is not str or not value.strip():
        raise RuntimeError(f"Federation config {field} must be a path")
    return Path(value).expanduser().resolve()


def _load_config():
    raw_path = os.environ.get("REMOTERF_FEDERATION_CONFIG_PATH")
    if not raw_path:
        raise RuntimeError(
            "Set REMOTERF_FEDERATION_CONFIG_PATH when federation is enabled"
        )
    config_path = _path(raw_path, "path")
    try:
        value = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RuntimeError(f"Could not load federation config: {exc}") from exc
    if type(value) is not dict or set(value) != {
        "protocol_version",
        "identity_dir",
        "display_name",
        "broker",
        "databases",
    }:
        raise RuntimeError("Federation config has an unsupported shape")
    if value["protocol_version"] != "2":
        raise RuntimeError("Federation config protocol_version must be '2'")
    if type(value["display_name"]) is not str or not value["display_name"].strip():
        raise RuntimeError("Federation config display_name is required")
    broker, databases = value["broker"], value["databases"]
    if type(broker) is not dict or set(broker) != {"origin", "deployment_id"}:
        raise RuntimeError("Federation config broker shape is invalid")
    if type(databases) is not dict or set(databases) != {
        "reservations",
        "usergroups",
        "permissions",
    }:
        raise RuntimeError("Federation config databases shape is invalid")
    if type(broker["origin"]) is not str or not broker["origin"].startswith(
        "https://"
    ):
        raise RuntimeError("Federation broker origin must be https://")
    return value


def build_configured_server_federation(reservation_handler):
    from ..acc_perms import perms
    from ..user_group_handler import user_group_handler

    config = _load_config()
    identity_dir = _path(config["identity_dir"], "identity_dir")
    database_paths = {
        name: _path(config["databases"][name], f"databases.{name}")
        for name in ("reservations", "usergroups", "permissions")
    }
    if len(set(database_paths.values())) != 3:
        raise RuntimeError("Federation database paths must be distinct")
    if database_paths["reservations"] != Path(reservation_handler.filepath).resolve():
        raise RuntimeError(
            "Federation reservations path does not match the running Server"
        )
    if database_paths["usergroups"] != Path(user_group_handler.filepath).resolve():
        raise RuntimeError(
            "Federation usergroups path does not match the running Server"
        )
    if database_paths["permissions"] != Path(perms.filepath).resolve():
        raise RuntimeError(
            "Federation permissions path does not match the running Server"
        )
    state = load_state(identity_dir)
    if (
        not state.enrolled
        or state.protocol_version != PROTOCOL_VERSION
        or state.display_name != config["display_name"]
    ):
        raise RuntimeError("Federation identity state/config binding is invalid")
    deployment_id = canonical_uuid(state.deployment_id)
    broker_id = canonical_uuid(config["broker"]["deployment_id"])
    key = load_private_key(identity_dir)
    raw_public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    signing_kid = hashlib.sha256(raw_public).hexdigest()[:32]
    initialize_native_subjects(database_paths["reservations"], deployment_id)
    issuer = ServerHomeGrantIssuer(
        reservations_path=database_paths["reservations"],
        usergroups_path=database_paths["usergroups"],
        local_deployment_id=deployment_id,
        private_key=key,
        signing_kid=signing_kid,
    )
    outbound = HomeFederationOutbound(
        issuer,
        broker_base_url=config["broker"]["origin"],
        broker_deployment_id=broker_id,
        broker_private_key=key,
        broker_kid=signing_kid,
    )
    executor = build_server_gate_g_executor(
        usergroups_path=database_paths["usergroups"],
        reservations_path=database_paths["reservations"],
        perms_path=database_paths["permissions"],
        local_deployment_id=deployment_id,
        private_key=key,
        signing_kid=signing_kid,
        display_name=config["display_name"],
    )
    return ServerFederationRuntime(
        executor=executor,
        enroller=ServerFederatedEnrollmentHome(outbound),
        permissions=ServerHomePermissions(
            usergroups_path=database_paths["usergroups"],
            local_deployment_id=deployment_id,
            display_name=config["display_name"],
            outbound=outbound,
        ),
    )
