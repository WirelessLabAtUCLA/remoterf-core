"""Pure Gate D trust, contract, event, and lifecycle rules.

This module deliberately owns no key store, database, HTTP client, listener,
or runtime singleton.  Application adapters supply persistence, Ed25519
signing/verification, locking, and clocks.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .schemas import PROTOCOL_VERSION, ValidationError, canonical_json, canonical_uuid

CONTRACT_EVENT_TYP = "remoterf-contract-event+jwt"
CONTRACT_EVENT_TOKEN_TYPE = "federation_contract_event"
BROKER_REQUEST_TYP = "remoterf-broker-request+jwt"
BROKER_REQUEST_TOKEN_TYPE = "broker_request"
MAX_CONTRACT_BYTES = 4096
MAX_EVENT_TOKEN_BYTES = 8192
MAX_BROKER_REQUEST_TOKEN_BYTES = 8192
MAX_BROKER_REQUEST_SECONDS = 120
MAX_PROTOCOL_INTEGER = (1 << 63) - 1

CONTRACT_CAPABILITIES = frozenset(
    {
        "FEDERATED_ENROLL",
        "PERMISSIONS_READ",
        # Device-plane capabilities. A contract that omits one still
        # cannot carry the corresponding action, so an existing
        # control-plane contract grants no hardware reach.
        "DEVICE_READ",
        "DEVICE_RESERVE",
        "DEVICE_CONTROL",
    }
)
CONTRACT_STATES = frozenset(
    {"proposed", "accepted", "active", "suspended", "revoked", "expired"}
)
CONTRACT_EVENT_TYPES = frozenset(
    {"propose", "accept", "activate", "suspend", "revoke", "supersede"}
)

CONTRACT_TERMS_FIELDS = frozenset(
    {
        "contract_id",
        "version",
        "deployment_a",
        "deployment_b",
        "valid_from",
        "valid_until",
        "allowed_capabilities",
        "key_a_kid",
        "key_a_sha256",
        "key_b_kid",
        "key_b_sha256",
        "supersedes_version",
    }
)
TRUST_MATERIAL_FIELDS = frozenset(
    {
        "deployment_id",
        "kid",
        "public_key_b64",
        "public_key_sha256",
        "valid_from",
        "valid_until",
    }
)
CONTRACT_EVENT_FIELDS = frozenset(
    {
        "token_type",
        "protocol_version",
        "iss",
        "event_id",
        "contract_id",
        "contract_version",
        "event_type",
        "terms_sha256",
        "actor_sequence",
        "occurred_at",
        "actor_admin_ref",
        "reason_code",
    }
)
BROKER_REQUEST_FIELDS = frozenset(
    {
        "token_type",
        "protocol_version",
        "iss",
        "sub",
        "aud",
        "method",
        "path",
        "body_sha256",
        "iat",
        "exp",
        "jti",
    }
)

_KID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_REASON = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_BROKER_PATHS = frozenset(
    {
        "/v2/broker/contracts",
        "/v2/broker/contracts/events",
        "/v2/broker/federation/forward",
        # Self-registration plane.  These carry no authorization and no
        # account state: a deployment asks to be listed, reads its own
        # request status, or withdraws.
        "/v2/broker/deployments/request",
        "/v2/broker/deployments/verify",
        "/v2/broker/deployments/me",
        "/v2/broker/deployments/leave",
        "/v2/broker/deployments/report",
        # Cluster invites: identity relay for `global cluster invite|join`.
        "/v2/broker/invites",
        "/v2/broker/invites/join",
        # Cluster rosters: the owner's signed member list, so members mesh.
        "/v2/broker/clusters/roster",
    }
)


class ContractError(ValidationError):
    """Stable typed contract rejection with no secret-bearing text."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _integer(value, *, code: str, positive: bool = False) -> int:
    if (
        type(value) is not int
        or (positive and value <= 0)
        or value < 0
        or value > MAX_PROTOCOL_INTEGER
    ):
        raise ContractError(code)
    return value


def validate_kid(value: object) -> str:
    if type(value) is not str or _KID.fullmatch(value) is None:
        raise ContractError("invalid_kid")
    return value


def validate_sha256(value: object, *, code: str = "invalid_sha256") -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ContractError(code)
    return value


def validate_trusted_key_material(value: object) -> dict:
    """Validate reviewed raw Ed25519 public identity material.

    The raw standard padded Base64 encoding is canonical.  Application
    adapters additionally instantiate an Ed25519 key object before storage.
    """

    if type(value) is not dict or set(value) != TRUST_MATERIAL_FIELDS:
        raise ContractError("invalid_trust_fields")
    deployment_id = canonical_uuid(value["deployment_id"])
    kid = validate_kid(value["kid"])
    encoded = value["public_key_b64"]
    if type(encoded) is not str or len(encoded) > 64:
        raise ContractError("invalid_public_key")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ContractError("invalid_public_key") from exc
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != encoded:
        raise ContractError("invalid_public_key")
    fingerprint = validate_sha256(
        value["public_key_sha256"], code="invalid_key_fingerprint"
    )
    if hashlib.sha256(raw).hexdigest() != fingerprint:
        raise ContractError("key_fingerprint_mismatch")
    valid_from = _integer(value["valid_from"], code="invalid_key_time")
    valid_until = value["valid_until"]
    if valid_until is not None:
        valid_until = _integer(valid_until, code="invalid_key_time", positive=True)
        if valid_until <= valid_from:
            raise ContractError("invalid_key_time")
    return {
        "deployment_id": deployment_id,
        "kid": kid,
        "public_key_b64": encoded,
        "public_key_sha256": fingerprint,
        "valid_from": valid_from,
        "valid_until": valid_until,
    }


def public_key_bytes(value: Mapping) -> bytes:
    material = validate_trusted_key_material(dict(value))
    return base64.b64decode(material["public_key_b64"], validate=True)


def key_is_current(value: Mapping, now: int) -> bool:
    now = _integer(now, code="invalid_time")
    return (
        value.get("state") == "active"
        and type(value.get("valid_from")) is int
        and value["valid_from"] <= now
        and (
            value.get("valid_until") is None
            or (type(value["valid_until"]) is int and now < value["valid_until"])
        )
    )


@dataclass(frozen=True)
class ContractTerms:
    contract_id: str
    version: int
    deployment_a: str
    deployment_b: str
    valid_from: int
    valid_until: int
    allowed_capabilities: tuple[str, ...]
    key_a_kid: str
    key_a_sha256: str
    key_b_kid: str
    key_b_sha256: str
    supersedes_version: int | None

    def to_dict(self) -> dict:
        return {
            "contract_id": self.contract_id,
            "version": self.version,
            "deployment_a": self.deployment_a,
            "deployment_b": self.deployment_b,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "allowed_capabilities": list(self.allowed_capabilities),
            "key_a_kid": self.key_a_kid,
            "key_a_sha256": self.key_a_sha256,
            "key_b_kid": self.key_b_kid,
            "key_b_sha256": self.key_b_sha256,
            "supersedes_version": self.supersedes_version,
        }

    def key_binding(self, deployment_id: str) -> tuple[str, str]:
        deployment_id = canonical_uuid(deployment_id)
        if deployment_id == self.deployment_a:
            return self.key_a_kid, self.key_a_sha256
        if deployment_id == self.deployment_b:
            return self.key_b_kid, self.key_b_sha256
        raise ContractError("actor_not_participant")


def validate_contract_terms(value: object) -> ContractTerms:
    if type(value) is not dict or set(value) != CONTRACT_TERMS_FIELDS:
        raise ContractError("invalid_contract_fields")
    contract_id = canonical_uuid(value["contract_id"])
    version = _integer(value["version"], code="invalid_contract_version", positive=True)
    deployment_a = canonical_uuid(value["deployment_a"])
    deployment_b = canonical_uuid(value["deployment_b"])
    if deployment_a >= deployment_b:
        raise ContractError(
            "participants_equal" if deployment_a == deployment_b else "participants_not_canonical"
        )
    valid_from = _integer(value["valid_from"], code="invalid_contract_time")
    valid_until = _integer(
        value["valid_until"], code="invalid_contract_time", positive=True
    )
    if valid_until <= valid_from:
        raise ContractError("invalid_contract_time")
    capabilities = value["allowed_capabilities"]
    if type(capabilities) is not list or not capabilities:
        raise ContractError("invalid_capabilities")
    if any(type(item) is not str or item not in CONTRACT_CAPABILITIES for item in capabilities):
        raise ContractError("unknown_capability")
    if capabilities != sorted(capabilities) or len(capabilities) != len(set(capabilities)):
        raise ContractError("capabilities_not_canonical")
    supersedes = value["supersedes_version"]
    if supersedes is not None:
        supersedes = _integer(
            supersedes, code="invalid_supersedes_version", positive=True
        )
        if supersedes >= version:
            raise ContractError("invalid_supersedes_version")
    result = ContractTerms(
        contract_id=contract_id,
        version=version,
        deployment_a=deployment_a,
        deployment_b=deployment_b,
        valid_from=valid_from,
        valid_until=valid_until,
        allowed_capabilities=tuple(capabilities),
        key_a_kid=validate_kid(value["key_a_kid"]),
        key_a_sha256=validate_sha256(
            value["key_a_sha256"], code="invalid_key_fingerprint"
        ),
        key_b_kid=validate_kid(value["key_b_kid"]),
        key_b_sha256=validate_sha256(
            value["key_b_sha256"], code="invalid_key_fingerprint"
        ),
        supersedes_version=supersedes,
    )
    encoded = canonical_json(result.to_dict()).encode("utf-8")
    if len(encoded) > MAX_CONTRACT_BYTES:
        raise ContractError("contract_too_large")
    return result


def build_contract_terms(
    *,
    contract_id: str,
    version: int,
    participant_1: str,
    participant_1_kid: str,
    participant_1_sha256: str,
    participant_2: str,
    participant_2_kid: str,
    participant_2_sha256: str,
    valid_from: int,
    valid_until: int,
    allowed_capabilities: Iterable[str],
    supersedes_version: int | None = None,
) -> ContractTerms:
    capabilities = list(allowed_capabilities)
    if len(capabilities) != len(set(capabilities)):
        raise ContractError("capabilities_not_canonical")
    participants = sorted(
        [
            (canonical_uuid(participant_1), participant_1_kid, participant_1_sha256),
            (canonical_uuid(participant_2), participant_2_kid, participant_2_sha256),
        ],
        key=lambda item: item[0],
    )
    first, second = participants
    return validate_contract_terms(
        {
            "contract_id": contract_id,
            "version": version,
            "deployment_a": first[0],
            "deployment_b": second[0],
            "valid_from": valid_from,
            "valid_until": valid_until,
            "allowed_capabilities": sorted(capabilities),
            "key_a_kid": first[1],
            "key_a_sha256": first[2],
            "key_b_kid": second[1],
            "key_b_sha256": second[2],
            "supersedes_version": supersedes_version,
        }
    )


def canonical_contract_bytes(value: ContractTerms | Mapping) -> bytes:
    terms = value if isinstance(value, ContractTerms) else validate_contract_terms(dict(value))
    return canonical_json(terms.to_dict()).encode("utf-8")


def contract_terms_sha256(value: ContractTerms | Mapping) -> str:
    return hashlib.sha256(canonical_contract_bytes(value)).hexdigest()


def validate_contract_event_header(value: object) -> dict:
    if type(value) is not dict or set(value) != {"alg", "typ", "kid"}:
        raise ContractError("invalid_event_header")
    if value["alg"] != "EdDSA" or value["typ"] != CONTRACT_EVENT_TYP:
        raise ContractError("invalid_event_domain")
    return {"alg": "EdDSA", "typ": CONTRACT_EVENT_TYP, "kid": validate_kid(value["kid"])}


def build_contract_event_claims(
    *,
    actor_deployment_id: str,
    event_id: str,
    contract_id: str,
    contract_version: int,
    event_type: str,
    terms_sha256: str,
    actor_sequence: int,
    occurred_at: int,
    actor_admin_ref: str | None,
    reason_code: str,
) -> dict:
    return validate_contract_event_claims(
        {
            "token_type": CONTRACT_EVENT_TOKEN_TYPE,
            "protocol_version": PROTOCOL_VERSION,
            "iss": actor_deployment_id,
            "event_id": event_id,
            "contract_id": contract_id,
            "contract_version": contract_version,
            "event_type": event_type,
            "terms_sha256": terms_sha256,
            "actor_sequence": actor_sequence,
            "occurred_at": occurred_at,
            "actor_admin_ref": actor_admin_ref,
            "reason_code": reason_code,
        }
    )


def validate_contract_event_claims(value: object, terms: ContractTerms | Mapping | None = None) -> dict:
    if type(value) is not dict or set(value) != CONTRACT_EVENT_FIELDS:
        raise ContractError("invalid_event_fields")
    if value["token_type"] != CONTRACT_EVENT_TOKEN_TYPE or value["protocol_version"] != PROTOCOL_VERSION:
        raise ContractError("invalid_event_domain")
    actor = canonical_uuid(value["iss"])
    event_id = canonical_uuid(value["event_id"])
    contract_id = canonical_uuid(value["contract_id"])
    version = _integer(
        value["contract_version"], code="invalid_contract_version", positive=True
    )
    event_type = value["event_type"]
    if type(event_type) is not str or event_type not in CONTRACT_EVENT_TYPES:
        raise ContractError("invalid_event_type")
    digest = validate_sha256(value["terms_sha256"], code="invalid_terms_hash")
    sequence = _integer(value["actor_sequence"], code="invalid_event_sequence", positive=True)
    occurred_at = _integer(value["occurred_at"], code="invalid_event_time")
    admin_ref = value["actor_admin_ref"]
    if admin_ref is not None and (
        type(admin_ref) is not str
        or not 1 <= len(admin_ref) <= 128
        or any(ord(char) < 32 or ord(char) == 127 for char in admin_ref)
    ):
        raise ContractError("invalid_admin_ref")
    reason = value["reason_code"]
    if type(reason) is not str or _REASON.fullmatch(reason) is None:
        raise ContractError("invalid_reason_code")
    result = {
        "token_type": CONTRACT_EVENT_TOKEN_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "iss": actor,
        "event_id": event_id,
        "contract_id": contract_id,
        "contract_version": version,
        "event_type": event_type,
        "terms_sha256": digest,
        "actor_sequence": sequence,
        "occurred_at": occurred_at,
        "actor_admin_ref": admin_ref,
        "reason_code": reason,
    }
    if terms is not None:
        contract = terms if isinstance(terms, ContractTerms) else validate_contract_terms(dict(terms))
        if (
            actor not in {contract.deployment_a, contract.deployment_b}
            or contract_id != contract.contract_id
            or version != contract.version
            or digest != contract_terms_sha256(contract)
        ):
            raise ContractError("event_terms_mismatch")
    return result


def _validated_events(terms: ContractTerms, events: Sequence[Mapping]) -> list[dict]:
    return [validate_contract_event_claims(dict(event), terms) for event in events]


def project_contract_state(
    terms: ContractTerms | Mapping, events: Sequence[Mapping], *, now: int
) -> str:
    contract = terms if isinstance(terms, ContractTerms) else validate_contract_terms(dict(terms))
    now = _integer(now, code="invalid_time")
    checked = _validated_events(contract, events)
    if any(event["event_type"] == "revoke" for event in checked):
        return "revoked"
    if now >= contract.valid_until:
        return "expired"
    if any(event["event_type"] in {"suspend", "supersede"} for event in checked):
        return "suspended"
    proposals = {event["iss"] for event in checked if event["event_type"] == "propose"}
    acceptances = {event["iss"] for event in checked if event["event_type"] == "accept"}
    activation = {event["iss"] for event in checked if event["event_type"] == "activate"}
    mutually_accepted = any(actor not in proposals for actor in acceptances) and bool(proposals)
    if mutually_accepted and activation == {contract.deployment_a, contract.deployment_b}:
        return "active"
    if mutually_accepted:
        return "accepted"
    return "proposed"


def validate_contract_transition(
    terms: ContractTerms | Mapping,
    events: Sequence[Mapping],
    event: Mapping,
    *,
    now: int,
    contract_id_revoked: bool = False,
) -> str:
    contract = terms if isinstance(terms, ContractTerms) else validate_contract_terms(dict(terms))
    checked = _validated_events(contract, events)
    candidate = validate_contract_event_claims(dict(event), contract)
    current = project_contract_state(contract, checked, now=now)
    event_type = candidate["event_type"]
    actor = candidate["iss"]
    if contract_id_revoked or current == "revoked":
        raise ContractError("contract_revoked")
    if current == "expired" and event_type != "revoke":
        raise ContractError("contract_expired")
    if event_type == "propose":
        if checked:
            raise ContractError("illegal_contract_transition")
    elif event_type == "accept":
        proposers = {item["iss"] for item in checked if item["event_type"] == "propose"}
        if not proposers or actor in proposers or current != "proposed":
            raise ContractError("illegal_contract_transition")
    elif event_type == "activate":
        if current != "accepted" or any(
            item["event_type"] == "activate" and item["iss"] == actor
            for item in checked
        ):
            raise ContractError("illegal_contract_transition")
    elif event_type == "suspend":
        if current != "active":
            raise ContractError("illegal_contract_transition")
    elif event_type == "supersede":
        if current != "active":
            raise ContractError("illegal_contract_transition")
    elif event_type == "revoke":
        pass
    return project_contract_state(contract, [*checked, candidate], now=now)


def contract_allows(
    terms: ContractTerms | Mapping,
    state: str,
    capability: str,
    *,
    now: int,
    superseded: bool = False,
) -> bool:
    contract = terms if isinstance(terms, ContractTerms) else validate_contract_terms(dict(terms))
    return (
        state == "active"
        and not superseded
        and type(now) is int
        and contract.valid_from <= now < contract.valid_until
        and capability in contract.allowed_capabilities
    )


def validate_broker_request_header(value: object) -> dict:
    if type(value) is not dict or set(value) != {"alg", "typ", "kid"}:
        raise ContractError("invalid_broker_header")
    if value["alg"] != "EdDSA" or value["typ"] != BROKER_REQUEST_TYP:
        raise ContractError("invalid_broker_domain")
    return {"alg": "EdDSA", "typ": BROKER_REQUEST_TYP, "kid": validate_kid(value["kid"])}


def build_broker_request_claims(
    *,
    deployment_id: str,
    broker_deployment_id: str,
    method: str,
    path: str,
    body_sha256: str,
    issued_at: int,
    expires_at: int,
    jti: str,
) -> dict:
    return validate_broker_request_claims(
        {
            "token_type": BROKER_REQUEST_TOKEN_TYPE,
            "protocol_version": PROTOCOL_VERSION,
            "iss": deployment_id,
            "sub": deployment_id,
            "aud": broker_deployment_id,
            "method": method,
            "path": path,
            "body_sha256": body_sha256,
            "iat": issued_at,
            "exp": expires_at,
            "jti": jti,
        },
        now=issued_at,
        broker_deployment_id=broker_deployment_id,
        method=method,
        path=path,
        body_sha256=body_sha256,
    )


def validate_broker_request_claims(
    value: object,
    *,
    now: int,
    broker_deployment_id: str,
    method: str,
    path: str,
    body_sha256: str,
) -> dict:
    if type(value) is not dict or set(value) != BROKER_REQUEST_FIELDS:
        raise ContractError("invalid_broker_fields")
    if value["token_type"] != BROKER_REQUEST_TOKEN_TYPE or value["protocol_version"] != PROTOCOL_VERSION:
        raise ContractError("invalid_broker_domain")
    issuer = canonical_uuid(value["iss"])
    if value["sub"] != issuer or value["aud"] != canonical_uuid(broker_deployment_id):
        raise ContractError("invalid_broker_identity")
    if type(method) is not str or method not in {"GET", "POST"}:
        raise ContractError("invalid_broker_method")
    if path not in _BROKER_PATHS:
        raise ContractError("invalid_broker_path")
    if value["method"] != method or value["path"] != path:
        raise ContractError("broker_request_mismatch")
    digest = validate_sha256(body_sha256, code="invalid_body_hash")
    if value["body_sha256"] != digest:
        raise ContractError("broker_request_mismatch")
    issued_at = _integer(value["iat"], code="invalid_broker_time")
    expires_at = _integer(value["exp"], code="invalid_broker_time", positive=True)
    now = _integer(now, code="invalid_time")
    if not 0 < expires_at - issued_at <= MAX_BROKER_REQUEST_SECONDS:
        raise ContractError("invalid_broker_time")
    if issued_at > now + 5 or now >= expires_at:
        raise ContractError("broker_request_expired")
    return {
        "token_type": BROKER_REQUEST_TOKEN_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "iss": issuer,
        "sub": issuer,
        "aud": canonical_uuid(broker_deployment_id),
        "method": method,
        "path": path,
        "body_sha256": digest,
        "iat": issued_at,
        "exp": expires_at,
        "jti": canonical_uuid(value["jti"]),
    }
