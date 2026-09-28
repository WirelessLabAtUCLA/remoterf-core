"""Pure deployment and Gate C identity schemas.

There is deliberately no trust, grant, contract, storage, or transport code in
this package.  A federated identity is only an immutable deployment/subject
tuple; display data and destination-local IDs are never part of that identity.
"""
import hashlib
import json
import re
from dataclasses import dataclass
from uuid import UUID

PROTOCOL_VERSION = "2"
MAX_DOCUMENT_BYTES = 16384
MAX_DISPLAY_METADATA_BYTES = 2048
OPERATIONS = frozenset({
    "ACC:create_user", "ACC:login", "ACC:verify_email", "ACC:refresh_session",
    "ACC:logout", "ACC:me", "ACC:set_enroll", "ACC:get_perms", "ACC:get_dev",
    "ACC:get_res", "ACC:reserve_device", "ACC:cancel_res",
    "ACC:forgot_password", "ACC:reset_password",
    # A HOME that relays serialized device RPC frames to federated hardware.
    "DEV:rpc",
})
POLICY_FIELDS = frozenset({"enabled", "username_required", "email_required",
                          "email_verification_required", "enrollment_code_required"})
CAPABILITY_FIELDS = frozenset({"protocol_version", "deployment_id", "display_name",
    "account_transport", "account_api_base", "federation_enabled",
    "federation_protocol_version", "registration_policy", "supported_operations",
    # How to reach this deployment, and the certificate a client should pin
    # when it does. A LAN route is advertised only when the deployment shares
    # it; a relay route only once RemoteRF Global has approved the deployment.
    "routes", "cert_sha256"})
ROUTE_KINDS = ("lan", "relay", "direct")
ROUTE_FIELDS = frozenset({"kind", "host", "port", "cert_port"})
MAX_ROUTES = 4


class ValidationError(ValueError):
    """Safe, typed protocol validation failure (never includes secret values)."""


def canonical_uuid(value):
    if not isinstance(value, str) or len(value) != 36:
        raise ValidationError("Expected canonical UUID")
    try:
        valid = str(UUID(value)) == value and UUID(value).int != 0
    except ValueError:
        valid = False
    if not valid:
        raise ValidationError("Expected canonical UUID")
    return value


@dataclass(frozen=True)
class FederatedIdentity:
    """Canonical remote identity, independent of names, email, and routing."""

    issuer_deployment_id: str
    remote_subject_id: str

    def __post_init__(self):
        canonical_uuid(self.issuer_deployment_id)
        canonical_uuid(self.remote_subject_id)

    def as_json_value(self):
        return [self.issuer_deployment_id, self.remote_subject_id]


def federated_identity(issuer_deployment_id, remote_subject_id):
    return FederatedIdentity(
        issuer_deployment_id=canonical_uuid(issuer_deployment_id),
        remote_subject_id=canonical_uuid(remote_subject_id),
    )


def federated_proxy_adapter(issuer_deployment_id, remote_subject_id):
    """Return deterministic non-canonical adapter username/email values."""

    identity = federated_identity(issuer_deployment_id, remote_subject_id)
    digest = hashlib.sha256(
        canonical_json(identity.as_json_value()).encode("utf-8")
    ).hexdigest()
    username = f"fed-{digest}"
    return username, f"{username}@federation.invalid"


def validate_display_metadata(value):
    """Validate small, printable, string-only informational metadata."""

    if type(value) is not dict or len(value) > 16:
        raise ValidationError("Invalid display metadata")
    for key, item in value.items():
        if (
            type(key) is not str
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", key)
            or type(item) is not str
            or len(item) > 256
            or any(ord(char) < 32 or ord(char) == 127 for char in item)
        ):
            raise ValidationError("Invalid display metadata")
    encoded = canonical_json(value)
    if len(encoded.encode("utf-8")) > MAX_DISPLAY_METADATA_BYTES:
        raise ValidationError("Display metadata exceeds limit")
    return strict_json(encoded, max_bytes=MAX_DISPLAY_METADATA_BYTES)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("Duplicate JSON key")
        result[key] = value
    return result


def strict_json(value, *, max_bytes=MAX_DOCUMENT_BYTES):
    if not isinstance(value, (str, bytes)) or len(value.encode() if isinstance(value, str) else value) > max_bytes:
        raise ValidationError("JSON document exceeds limit or has invalid type")
    try:
        return json.loads(value, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValidationError("Non-finite number")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValidationError("Invalid JSON document") from exc


def canonical_json(value):
    def check(v):
        if v is None or type(v) in (str, bool, int):
            return
        if type(v) is list:
            for item in v:
                check(item)
        elif type(v) is dict and all(type(k) is str for k in v):
            for item in v.values():
                check(item)
        else:
            raise ValidationError("Canonical JSON requires integer numbers and string keys")
    try:
        check(value)
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (ValueError, RecursionError) as exc:
        raise ValidationError("Invalid canonical JSON") from exc


def validate_capabilities(value):
    if isinstance(value, (str, bytes)):
        value = strict_json(value)
    if type(value) is not dict or set(value) != CAPABILITY_FIELDS:
        raise ValidationError("Invalid capability fields")
    if len(canonical_json(value).encode()) > MAX_DOCUMENT_BYTES:
        raise ValidationError("Capability document exceeds limit")
    if value["protocol_version"] != PROTOCOL_VERSION:
        raise ValidationError("Unsupported deployment protocol version")
    ident = value["deployment_id"]
    if ident is not None:
        canonical_uuid(ident)
    name = value["display_name"]
    if not isinstance(name, str) or not 1 <= len(name) <= 256 or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValidationError("Invalid display name")
    transport, path = value["account_transport"], value["account_api_base"]
    if transport == "grpc":
        if path is not None:
            raise ValidationError("gRPC cannot advertise an HTTP account path")
    elif transport == "https-json":
        if ident is None or not isinstance(path, str) or len(path) > 128 or not re.fullmatch(r"/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", path):
            raise ValidationError("HTTPS requires deployment UUID and same-origin account path")
    else:
        raise ValidationError("Unsupported account transport")
    enabled, version = value["federation_enabled"], value["federation_protocol_version"]
    if type(enabled) is not bool or version not in (None, PROTOCOL_VERSION):
        raise ValidationError("Invalid federation readiness")
    if enabled and (ident is None or version != PROTOCOL_VERSION):
        raise ValidationError("Federation requires identity and supported version")
    policy = value["registration_policy"]
    if type(policy) is not dict or set(policy) != POLICY_FIELDS or any(type(v) is not bool for v in policy.values()):
        raise ValidationError("Invalid registration policy")
    if policy["email_verification_required"] and not policy["email_required"]:
        raise ValidationError("Verification requires email")
    routes = value["routes"]
    if type(routes) is not list or len(routes) > MAX_ROUTES:
        raise ValidationError("Invalid routes")
    kinds = []
    for route in routes:
        if type(route) is not dict or set(route) != ROUTE_FIELDS:
            raise ValidationError("Invalid route fields")
        if route["kind"] not in ROUTE_KINDS:
            raise ValidationError("Unsupported route kind")
        host = route["host"]
        if not isinstance(host, str) or not 1 <= len(host) <= 253 or any(
            ord(c) < 33 or ord(c) == 127 for c in host
        ):
            raise ValidationError("Invalid route host")
        for field in ("port", "cert_port"):
            port = route[field]
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValidationError("Invalid route port")
        kinds.append(route["kind"])
    if len(set(kinds)) != len(kinds):
        raise ValidationError("Duplicate route kind")
    digest = value["cert_sha256"]
    if digest is not None and (
        not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
    ):
        raise ValidationError("Invalid certificate digest")
    ops = value["supported_operations"]
    if type(ops) is not list or not 1 <= len(ops) <= len(OPERATIONS) or any(type(o) is not str or o not in OPERATIONS for o in ops) or len(set(ops)) != len(ops):
        raise ValidationError("Unsupported or duplicate account operation")
    if policy["email_verification_required"] and "ACC:verify_email" not in ops:
        raise ValidationError("Required verification operation is unavailable")
    return strict_json(canonical_json(value))


def local_capabilities(*, display_name="RemoteRF", deployment_id=None,
                       routes=None, cert_sha256=None):
    return validate_capabilities({
        "routes": list(routes or []), "cert_sha256": cert_sha256,
        "protocol_version": PROTOCOL_VERSION, "deployment_id": deployment_id,
        "display_name": display_name, "account_transport": "grpc", "account_api_base": None,
        "federation_enabled": False, "federation_protocol_version": None,
        "registration_policy": {"enabled": True, "username_required": True,
            "email_required": True, "email_verification_required": False, "enrollment_code_required": True},
        "supported_operations": ["ACC:create_user", "ACC:login", "ACC:set_enroll", "ACC:get_perms",
            "ACC:get_dev", "ACC:get_res", "ACC:reserve_device", "ACC:cancel_res"],
    })
