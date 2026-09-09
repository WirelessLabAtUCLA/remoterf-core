"""Pure Gate E federation action and signed-result protocol rules.

This module deliberately performs no signing, key lookup, persistence, HTTP,
or gRPC work.  Applications select local contract-bound keys, verify Ed25519
signatures, own transaction boundaries, and then call these strict validators.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping

from .contracts import (
    ContractError,
    ContractTerms,
    validate_contract_terms,
    validate_kid,
    validate_sha256,
)
from .schemas import (
    PROTOCOL_VERSION,
    ValidationError,
    canonical_json,
    canonical_uuid,
    strict_json,
)

FEDERATION_GRANT_TYP = "remoterf-federation-grant+jwt"
FEDERATION_GRANT_TOKEN_TYPE = "federation_grant"
FEDERATION_RESULT_TYP = "remoterf-federation-result+jwt"
FEDERATION_RESULT_TOKEN_TYPE = "federation_result"

MAX_GRANT_TOKEN_BYTES = 8192
MAX_RESULT_TOKEN_BYTES = 16384
MAX_ACTION_REQUEST_BYTES = 4096
MAX_RESULT_BYTES = 12288
MAX_GRANT_SECONDS = 60
MAX_RESULT_SECONDS = 60
MAX_GROUPS = 256
MAX_PROTOCOL_INTEGER = (1 << 63) - 1
MAX_RESULT_SNAPSHOT_AGE_SECONDS = 60
FEDERATION_INVITATION_PREFIX = "rrf2."
MAX_FEDERATION_INVITATION_BYTES = 1024
INVITATION_FIELDS = frozenset(
    {
        "destination_deployment_id",
        "contract_id",
        "contract_version",
        "code_name",
    }
)

ACTION_CAPABILITIES = {
    "federated_enroll": "FEDERATED_ENROLL",
    "permissions_read": "PERMISSIONS_READ",
}
READ_ONLY_ACTIONS = frozenset({"permissions_read"})


class ActionRetryPolicy(Enum):
    """Trusted integration policy; ordinary action callers never select it."""

    NO_RETRY = "no_retry"
    READ_ONLY = "read_only"
    RECEIPT_IDEMPOTENT = "receipt_idempotent"


DEFAULT_ACTION_RETRY_POLICIES = MappingProxyType(
    {
        "federated_enroll": ActionRetryPolicy.RECEIPT_IDEMPOTENT,
        "permissions_read": ActionRetryPolicy.READ_ONLY,
    }
)
ACTION_REQUEST_FIELDS = frozenset({"protocol_version", "action", "payload"})
ENROLL_PAYLOAD_FIELDS = frozenset(
    {
        "request_id",
        "destination_deployment_id",
        "contract_id",
        "contract_version",
        "terms_sha256",
        "code_name",
    }
)
PERMISSIONS_PAYLOAD_FIELDS = ENROLL_PAYLOAD_FIELDS - {"code_name"}
GRANT_FIELDS = frozenset(
    {
        "token_type",
        "protocol_version",
        "iss",
        "sub",
        "aud",
        "contract_id",
        "contract_version",
        "terms_sha256",
        "action",
        "capability",
        "request_id",
        "request_sha256",
        "iat",
        "exp",
        "jti",
    }
)
RESULT_FIELDS = frozenset(
    {
        "token_type",
        "protocol_version",
        "iss",
        "aud",
        "sub",
        "contract_id",
        "contract_version",
        "terms_sha256",
        "action",
        "request_id",
        "request_sha256",
        "grant_jti",
        "iat",
        "exp",
        "result",
    }
)
TYPED_RESULT_FIELDS = frozenset(
    {
        "status",
        "error_code",
        "deployment_id",
        "display_name",
        "contract_id",
        "contract_version",
        "state",
        "groups",
        "retrieved_at",
        "redemption_id",
        "membership_present",
    }
)
RESULT_STATES = frozenset(
    {"proposed", "accepted", "active", "suspended", "revoked", "expired"}
)
_ERROR_CODE = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_DECIMAL_ID = re.compile(r"0|[1-9][0-9]{0,19}")


class FederationError(ContractError):
    """Stable, non-secret federation protocol failure."""


class TransportFailure(FederationError):
    """Unsigned broker/network/protocol failure, never an owner decision."""

    def __init__(self, code: str, *, retryable: bool = False):
        self.retryable = retryable
        super().__init__(code)


class OwnerSignedFailure(FederationError):
    """Cryptographically verified destination business decision."""

    def __init__(self, result: Mapping):
        self.result = dict(result)
        super().__init__(self.result["error_code"])


@dataclass(frozen=True)
class CanonicalActionRequest:
    value: dict
    json: str
    sha256: str


@dataclass(frozen=True)
class FederationInvitation:
    """Strict untrusted routing wrapper around a destination-owned code."""

    value: dict
    json: str
    text: str


def federation_invitation(value: object) -> FederationInvitation:
    if type(value) is not dict or set(value) != INVITATION_FIELDS:
        raise FederationError("invalid_invitation_fields")
    normalized = {
        "destination_deployment_id": canonical_uuid(
            value["destination_deployment_id"]
        ),
        "contract_id": canonical_uuid(value["contract_id"]),
        "contract_version": _integer(
            value["contract_version"],
            "invalid_contract_version",
            positive=True,
        ),
        "code_name": _printable(value["code_name"], "invalid_code_name", 256),
    }
    encoded_json = canonical_json(normalized)
    payload = base64.urlsafe_b64encode(encoded_json.encode("utf-8")).rstrip(b"=")
    text = FEDERATION_INVITATION_PREFIX + payload.decode("ascii")
    if len(text.encode("ascii")) > MAX_FEDERATION_INVITATION_BYTES:
        raise FederationError("invitation_too_large")
    return FederationInvitation(normalized, encoded_json, text)


def build_federation_invitation(
    *,
    destination_deployment_id: str,
    contract_id: str,
    contract_version: int,
    code_name: str,
) -> FederationInvitation:
    return federation_invitation(
        {
            "destination_deployment_id": destination_deployment_id,
            "contract_id": contract_id,
            "contract_version": contract_version,
            "code_name": code_name,
        }
    )


def parse_federation_invitation(value: object) -> FederationInvitation:
    if (
        type(value) is not str
        or not value.startswith(FEDERATION_INVITATION_PREFIX)
        or len(value.encode("utf-8")) > MAX_FEDERATION_INVITATION_BYTES
    ):
        raise FederationError("invalid_invitation")
    segment = value[len(FEDERATION_INVITATION_PREFIX) :]
    if not segment or re.fullmatch(r"[A-Za-z0-9_-]+", segment) is None:
        raise FederationError("invalid_invitation_encoding")
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, binascii.Error):
        raise FederationError("invalid_invitation_encoding") from None
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != segment:
        raise FederationError("invalid_invitation_encoding")
    try:
        parsed = strict_json(raw, max_bytes=768)
        invitation = federation_invitation(parsed)
    except (ValidationError, ValueError, UnicodeError):
        raise FederationError("invalid_invitation") from None
    if invitation.text != value:
        raise FederationError("invitation_not_canonical")
    return invitation


def _integer(value: object, code: str, *, positive: bool = False) -> int:
    if (
        type(value) is not int
        or value < 0
        or value > MAX_PROTOCOL_INTEGER
        or (positive and value <= 0)
    ):
        raise FederationError(code)
    return value


def _printable(value: object, code: str, maximum: int, *, allow_empty=False) -> str:
    if (
        type(value) is not str
        or len(value) > maximum
        or (not allow_empty and not value)
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise FederationError(code)
    return value


def action_capability(action: object) -> str:
    if type(action) is not str or action not in ACTION_CAPABILITIES:
        raise FederationError("unknown_action")
    return ACTION_CAPABILITIES[action]


def canonical_action_request(value: object) -> CanonicalActionRequest:
    """Validate and canonicalize the entire action request object."""

    if type(value) is not dict or set(value) != ACTION_REQUEST_FIELDS:
        raise FederationError("invalid_request_fields")
    if value["protocol_version"] != PROTOCOL_VERSION:
        raise FederationError("unsupported_version")
    action = value["action"]
    action_capability(action)
    payload = value["payload"]
    expected = (
        ENROLL_PAYLOAD_FIELDS
        if action == "federated_enroll"
        else PERMISSIONS_PAYLOAD_FIELDS
    )
    if type(payload) is not dict or set(payload) != expected:
        raise FederationError("invalid_payload_fields")
    clean = {
        "request_id": canonical_uuid(payload["request_id"]),
        "destination_deployment_id": canonical_uuid(
            payload["destination_deployment_id"]
        ),
        "contract_id": canonical_uuid(payload["contract_id"]),
        "contract_version": _integer(
            payload["contract_version"], "invalid_contract_version", positive=True
        ),
        "terms_sha256": validate_sha256(
            payload["terms_sha256"], code="invalid_terms_hash"
        ),
    }
    if action == "federated_enroll":
        clean["code_name"] = _printable(
            payload["code_name"], "invalid_code_name", 256
        )
    normalized = {
        "protocol_version": PROTOCOL_VERSION,
        "action": action,
        "payload": clean,
    }
    encoded = canonical_json(normalized)
    raw = encoded.encode("utf-8")
    if len(raw) > MAX_ACTION_REQUEST_BYTES:
        raise FederationError("request_too_large")
    return CanonicalActionRequest(
        value=normalized,
        json=encoded,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def parse_canonical_action_request(value: str | bytes) -> CanonicalActionRequest:
    parsed = strict_json(value, max_bytes=MAX_ACTION_REQUEST_BYTES)
    request = canonical_action_request(parsed)
    supplied = value.encode("utf-8") if isinstance(value, str) else value
    if supplied != request.json.encode("utf-8"):
        raise FederationError("request_not_canonical")
    return request


def build_action_request(
    *,
    action: str,
    request_id: str,
    destination_deployment_id: str,
    contract_id: str,
    contract_version: int,
    terms_sha256: str,
    code_name: str | None = None,
) -> CanonicalActionRequest:
    payload = {
        "request_id": request_id,
        "destination_deployment_id": destination_deployment_id,
        "contract_id": contract_id,
        "contract_version": contract_version,
        "terms_sha256": terms_sha256,
    }
    if action == "federated_enroll":
        payload["code_name"] = code_name
    elif code_name is not None:
        raise FederationError("invalid_payload_fields")
    return canonical_action_request(
        {"protocol_version": PROTOCOL_VERSION, "action": action, "payload": payload}
    )


def validate_grant_header(value: object) -> dict:
    if type(value) is not dict or set(value) != {"alg", "kid", "typ"}:
        raise FederationError("invalid_grant_header")
    if value["alg"] != "EdDSA" or value["typ"] != FEDERATION_GRANT_TYP:
        raise FederationError("invalid_grant_domain")
    return {
        "alg": "EdDSA",
        "kid": validate_kid(value["kid"]),
        "typ": FEDERATION_GRANT_TYP,
    }


def build_grant_claims(
    *,
    issuer_deployment_id: str,
    subject_id: str,
    destination_deployment_id: str,
    contract_id: str,
    contract_version: int,
    terms_sha256: str,
    action: str,
    request_id: str,
    request_sha256: str,
    issued_at: int,
    expires_at: int,
    jti: str,
) -> dict:
    return validate_grant_claims(
        {
            "token_type": FEDERATION_GRANT_TOKEN_TYPE,
            "protocol_version": PROTOCOL_VERSION,
            "iss": issuer_deployment_id,
            "sub": subject_id,
            "aud": destination_deployment_id,
            "contract_id": contract_id,
            "contract_version": contract_version,
            "terms_sha256": terms_sha256,
            "action": action,
            "capability": action_capability(action),
            "request_id": request_id,
            "request_sha256": request_sha256,
            "iat": issued_at,
            "exp": expires_at,
            "jti": jti,
        },
        now=issued_at,
    )


def validate_grant_claims(
    value: object,
    *,
    now: int,
    request: CanonicalActionRequest | None = None,
    expected_issuer: str | None = None,
    expected_destination: str | None = None,
    expected_terms: ContractTerms | Mapping | None = None,
    expected_terms_sha256: str | None = None,
) -> dict:
    if type(value) is not dict or set(value) != GRANT_FIELDS:
        raise FederationError("invalid_grant_fields")
    if (
        value["token_type"] != FEDERATION_GRANT_TOKEN_TYPE
        or value["protocol_version"] != PROTOCOL_VERSION
    ):
        raise FederationError("invalid_grant_domain")
    issuer = canonical_uuid(value["iss"])
    subject = canonical_uuid(value["sub"])
    if type(value["aud"]) is not str:
        raise FederationError("invalid_grant_audience")
    destination = canonical_uuid(value["aud"])
    contract_id = canonical_uuid(value["contract_id"])
    version = _integer(
        value["contract_version"], "invalid_contract_version", positive=True
    )
    terms_hash = validate_sha256(value["terms_sha256"], code="invalid_terms_hash")
    action = value["action"]
    capability = action_capability(action)
    if value["capability"] != capability:
        raise FederationError("action_capability_mismatch")
    request_id = canonical_uuid(value["request_id"])
    request_hash = validate_sha256(
        value["request_sha256"], code="invalid_request_hash"
    )
    issued_at = _integer(value["iat"], "invalid_grant_time")
    expires_at = _integer(value["exp"], "invalid_grant_time", positive=True)
    checked_now = _integer(now, "invalid_time")
    if not 0 < expires_at - issued_at <= MAX_GRANT_SECONDS:
        raise FederationError("invalid_grant_time")
    if issued_at > checked_now + 5 or checked_now >= expires_at:
        raise FederationError("grant_expired")
    jti = canonical_uuid(value["jti"])
    if expected_issuer is not None and issuer != canonical_uuid(expected_issuer):
        raise FederationError("counterparty_mismatch")
    if expected_destination is not None and destination != canonical_uuid(
        expected_destination
    ):
        raise FederationError("wrong_destination")
    if expected_terms is not None:
        terms = (
            expected_terms
            if isinstance(expected_terms, ContractTerms)
            else validate_contract_terms(dict(expected_terms))
        )
        if (
            contract_id != terms.contract_id
            or version != terms.version
            or issuer not in {terms.deployment_a, terms.deployment_b}
            or destination not in {terms.deployment_a, terms.deployment_b}
            or issuer == destination
        ):
            raise FederationError("contract_version_mismatch")
    if expected_terms_sha256 is not None and terms_hash != validate_sha256(
        expected_terms_sha256, code="invalid_terms_hash"
    ):
        raise FederationError("terms_hash_mismatch")
    if request is not None:
        payload = request.value["payload"]
        if (
            request.value["protocol_version"] != value["protocol_version"]
            or request.value["action"] != action
            or payload["request_id"] != request_id
            or payload["destination_deployment_id"] != destination
            or payload["contract_id"] != contract_id
            or payload["contract_version"] != version
            or payload["terms_sha256"] != terms_hash
            or request.sha256 != request_hash
        ):
            raise FederationError("request_binding_mismatch")
    return {
        "token_type": FEDERATION_GRANT_TOKEN_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "iss": issuer,
        "sub": subject,
        "aud": destination,
        "contract_id": contract_id,
        "contract_version": version,
        "terms_sha256": terms_hash,
        "action": action,
        "capability": capability,
        "request_id": request_id,
        "request_sha256": request_hash,
        "iat": issued_at,
        "exp": expires_at,
        "jti": jti,
    }


def validate_typed_result(value: object, *, action: str) -> dict:
    action_capability(action)
    if type(value) is not dict or set(value) != TYPED_RESULT_FIELDS:
        raise FederationError("invalid_result_fields")
    status = value["status"]
    if status not in {"ok", "error"}:
        raise FederationError("invalid_result_status")
    error_code = value["error_code"]
    if status == "ok":
        if error_code is not None:
            raise FederationError("invalid_result_status")
    elif type(error_code) is not str or _ERROR_CODE.fullmatch(error_code) is None:
        raise FederationError("invalid_result_error")
    display_name = _printable(value["display_name"], "invalid_display_name", 256)
    groups = value["groups"]
    if type(groups) is not list or len(groups) > MAX_GROUPS:
        raise FederationError("invalid_result_groups")
    normalized_groups = []
    seen = set()
    for group in groups:
        if type(group) is not dict or set(group) != {"group_id", "group_name"}:
            raise FederationError("invalid_result_groups")
        group_id = group["group_id"]
        if type(group_id) is not str or _DECIMAL_ID.fullmatch(group_id) is None:
            raise FederationError("invalid_result_groups")
        group_name = _printable(
            group["group_name"], "invalid_result_groups", 128
        )
        if group_id in seen:
            raise FederationError("invalid_result_groups")
        seen.add(group_id)
        normalized_groups.append({"group_id": group_id, "group_name": group_name})
    redemption_id = value["redemption_id"]
    if redemption_id is not None:
        redemption_id = canonical_uuid(redemption_id)
    membership = value["membership_present"]
    if membership is not None and type(membership) is not bool:
        raise FederationError("invalid_membership_state")
    result = {
        "status": status,
        "error_code": error_code,
        "deployment_id": canonical_uuid(value["deployment_id"]),
        "display_name": display_name,
        "contract_id": canonical_uuid(value["contract_id"]),
        "contract_version": _integer(
            value["contract_version"], "invalid_contract_version", positive=True
        ),
        "state": value["state"],
        "groups": normalized_groups,
        "retrieved_at": _integer(value["retrieved_at"], "invalid_result_time"),
        "redemption_id": redemption_id,
        "membership_present": membership,
    }
    if result["state"] not in RESULT_STATES:
        raise FederationError("invalid_contract_state")
    if status == "error":
        if normalized_groups or redemption_id is not None or membership is not None:
            raise FederationError("invalid_result_semantics")
    elif action == "permissions_read":
        if redemption_id is not None or membership is not None:
            raise FederationError("invalid_result_semantics")
    elif redemption_id is None or membership is None:
        raise FederationError("invalid_result_semantics")
    if membership is False and normalized_groups:
        raise FederationError("invalid_result_semantics")
    if len(canonical_json(result).encode("utf-8")) > MAX_RESULT_BYTES:
        raise FederationError("result_too_large")
    return result


def build_result_claims(
    *,
    destination_deployment_id: str,
    home_deployment_id: str,
    subject_id: str,
    contract_id: str,
    contract_version: int,
    terms_sha256: str,
    action: str,
    request_id: str,
    request_sha256: str,
    grant_jti: str,
    issued_at: int,
    expires_at: int,
    result: Mapping,
) -> dict:
    return validate_result_claims(
        {
            "token_type": FEDERATION_RESULT_TOKEN_TYPE,
            "protocol_version": PROTOCOL_VERSION,
            "iss": destination_deployment_id,
            "aud": home_deployment_id,
            "sub": subject_id,
            "contract_id": contract_id,
            "contract_version": contract_version,
            "terms_sha256": terms_sha256,
            "action": action,
            "request_id": request_id,
            "request_sha256": request_sha256,
            "grant_jti": grant_jti,
            "iat": issued_at,
            "exp": expires_at,
            "result": dict(result),
        },
        now=issued_at,
    )


def validate_result_header(value: object) -> dict:
    if type(value) is not dict or set(value) != {"alg", "kid", "typ"}:
        raise FederationError("invalid_result_header")
    if value["alg"] != "EdDSA" or value["typ"] != FEDERATION_RESULT_TYP:
        raise FederationError("invalid_result_domain")
    return {
        "alg": "EdDSA",
        "kid": validate_kid(value["kid"]),
        "typ": FEDERATION_RESULT_TYP,
    }


def validate_result_claims(
    value: object,
    *,
    now: int,
    expected_destination: str | None = None,
    expected_home: str | None = None,
    expected_subject: str | None = None,
    expected_contract_id: str | None = None,
    expected_contract_version: int | None = None,
    expected_terms_sha256: str | None = None,
    expected_action: str | None = None,
    expected_request_id: str | None = None,
    expected_request_sha256: str | None = None,
    expected_grant_jti: str | None = None,
) -> dict:
    if type(value) is not dict or set(value) != RESULT_FIELDS:
        raise FederationError("invalid_result_claims")
    if (
        value["token_type"] != FEDERATION_RESULT_TOKEN_TYPE
        or value["protocol_version"] != PROTOCOL_VERSION
    ):
        raise FederationError("invalid_result_domain")
    issuer = canonical_uuid(value["iss"])
    if type(value["aud"]) is not str:
        raise FederationError("invalid_result_audience")
    audience = canonical_uuid(value["aud"])
    subject = canonical_uuid(value["sub"])
    contract_id = canonical_uuid(value["contract_id"])
    version = _integer(
        value["contract_version"], "invalid_contract_version", positive=True
    )
    terms_hash = validate_sha256(value["terms_sha256"], code="invalid_terms_hash")
    action_capability(value["action"])
    request_id = canonical_uuid(value["request_id"])
    request_hash = validate_sha256(
        value["request_sha256"], code="invalid_request_hash"
    )
    grant_jti = canonical_uuid(value["grant_jti"])
    issued_at = _integer(value["iat"], "invalid_result_time")
    expires_at = _integer(value["exp"], "invalid_result_time", positive=True)
    checked_now = _integer(now, "invalid_time")
    if not 0 < expires_at - issued_at <= MAX_RESULT_SECONDS:
        raise FederationError("invalid_result_time")
    if issued_at > checked_now + 5 or checked_now >= expires_at:
        raise FederationError("result_expired")
    result = validate_typed_result(value["result"], action=value["action"])
    if not (
        issued_at - MAX_RESULT_SNAPSHOT_AGE_SECONDS
        <= result["retrieved_at"]
        <= issued_at
    ):
        raise FederationError("invalid_result_time")
    expected = (
        (issuer, expected_destination, "result_destination_mismatch", canonical_uuid),
        (audience, expected_home, "result_home_mismatch", canonical_uuid),
        (subject, expected_subject, "result_subject_mismatch", canonical_uuid),
        (contract_id, expected_contract_id, "result_contract_mismatch", canonical_uuid),
        (version, expected_contract_version, "result_contract_mismatch", None),
        (terms_hash, expected_terms_sha256, "result_terms_mismatch", None),
        (value["action"], expected_action, "result_action_mismatch", None),
        (request_id, expected_request_id, "result_request_mismatch", canonical_uuid),
        (request_hash, expected_request_sha256, "result_request_mismatch", None),
        (grant_jti, expected_grant_jti, "result_grant_mismatch", canonical_uuid),
    )
    for actual, wanted, code, normalizer in expected:
        if wanted is not None:
            wanted = normalizer(wanted) if normalizer else wanted
            if actual != wanted:
                raise FederationError(code)
    if (
        result["deployment_id"] != issuer
        or result["contract_id"] != contract_id
        or result["contract_version"] != version
    ):
        raise FederationError("result_payload_mismatch")
    return {
        "token_type": FEDERATION_RESULT_TOKEN_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "iss": issuer,
        "aud": audience,
        "sub": subject,
        "contract_id": contract_id,
        "contract_version": version,
        "terms_sha256": terms_hash,
        "action": value["action"],
        "request_id": request_id,
        "request_sha256": request_hash,
        "grant_jti": grant_jti,
        "iat": issued_at,
        "exp": expires_at,
        "result": result,
    }


def _decode_segment(value: str) -> object:
    if type(value) is not str or not value:
        raise FederationError("invalid_token")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        raise FederationError("invalid_token") from None
    return strict_json(raw, max_bytes=MAX_RESULT_BYTES)


def parse_unverified_jwt(token: object, *, max_bytes: int) -> tuple[dict, dict]:
    """Strictly parse only routing candidates; this establishes no trust."""

    if type(token) is not str or not token or len(token.encode("utf-8")) > max_bytes:
        raise FederationError("invalid_token")
    segments = token.split(".")
    if len(segments) != 3 or not segments[2]:
        raise FederationError("invalid_token")
    header = _decode_segment(segments[0])
    claims = _decode_segment(segments[1])
    if type(header) is not dict or type(claims) is not dict:
        raise FederationError("invalid_token")
    return header, claims


def parse_unverified_grant(token: object) -> tuple[dict, dict]:
    header, claims = parse_unverified_jwt(token, max_bytes=MAX_GRANT_TOKEN_BYTES)
    return validate_grant_header(header), claims


def parse_unverified_result(token: object) -> tuple[dict, dict]:
    header, claims = parse_unverified_jwt(token, max_bytes=MAX_RESULT_TOKEN_BYTES)
    return validate_result_header(header), claims


def validate_transport_response(value: object) -> dict:
    """Require exactly one of a destination token or an unsigned safe error."""

    if type(value) is not dict or set(value) != {
        "protocol_version",
        "signed_result",
        "error",
    }:
        raise FederationError("invalid_transport_response")
    if value["protocol_version"] != PROTOCOL_VERSION:
        raise FederationError("unsupported_version")
    signed, error = value["signed_result"], value["error"]
    if (signed is None) == (error is None):
        raise FederationError("invalid_transport_response")
    if signed is not None:
        if type(signed) is not str or not signed or len(signed.encode()) > MAX_RESULT_TOKEN_BYTES:
            raise FederationError("invalid_transport_response")
        return {"protocol_version": PROTOCOL_VERSION, "signed_result": signed, "error": None}
    if type(error) is not dict or set(error) != {"code", "message", "retryable"}:
        raise FederationError("invalid_transport_response")
    code = error["code"]
    if type(code) is not str or _ERROR_CODE.fullmatch(code) is None:
        raise FederationError("invalid_transport_response")
    message = _printable(error["message"], "invalid_transport_response", 256)
    if type(error["retryable"]) is not bool:
        raise FederationError("invalid_transport_response")
    return {
        "protocol_version": PROTOCOL_VERSION,
        "signed_result": None,
        "error": {"code": code, "message": message, "retryable": error["retryable"]},
    }
