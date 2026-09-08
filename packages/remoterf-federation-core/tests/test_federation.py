import copy
import base64
import hashlib
import json
from uuid import uuid4

import pytest

from remoterf_federation_core import (
    FEDERATION_GRANT_TYP,
    FEDERATION_RESULT_TYP,
    BROKER_REQUEST_TYP,
    CONTRACT_EVENT_TYP,
    ContractError,
    FederationError,
    build_action_request,
    build_grant_claims,
    build_result_claims,
    parse_canonical_action_request,
    parse_unverified_grant,
    validate_broker_request_header,
    validate_contract_event_header,
    validate_grant_claims,
    validate_grant_header,
    validate_result_claims,
    validate_result_header,
    validate_transport_response,
)

HOME = "11111111-1111-4111-8111-111111111111"
DEST = "22222222-2222-4222-8222-222222222222"
SUBJECT = "33333333-3333-4333-8333-333333333333"
CONTRACT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
TERMS = "b" * 64


def grant_fixture(action="permissions_read"):
    request_id = str(uuid4())
    request = build_action_request(
        action=action,
        request_id=request_id,
        destination_deployment_id=DEST,
        contract_id=CONTRACT,
        contract_version=2,
        terms_sha256=TERMS,
        **({"code_name": "future-code"} if action == "federated_enroll" else {}),
    )
    claims = build_grant_claims(
        issuer_deployment_id=HOME,
        subject_id=SUBJECT,
        destination_deployment_id=DEST,
        contract_id=CONTRACT,
        contract_version=2,
        terms_sha256=TERMS,
        action=action,
        request_id=request_id,
        request_sha256=request.sha256,
        issued_at=100,
        expires_at=160,
        jti=str(uuid4()),
    )
    return request, claims


def result_fixture():
    request, grant = grant_fixture()
    result = {
        "status": "ok",
        "error_code": None,
        "deployment_id": DEST,
        "display_name": "Destination",
        "contract_id": CONTRACT,
        "contract_version": 2,
        "state": "active",
        "groups": [{"group_id": "7", "group_name": "readers"}],
        "retrieved_at": 101,
        "redemption_id": None,
        "membership_present": None,
    }
    claims = build_result_claims(
        destination_deployment_id=DEST,
        home_deployment_id=HOME,
        subject_id=SUBJECT,
        contract_id=CONTRACT,
        contract_version=2,
        terms_sha256=TERMS,
        action="permissions_read",
        request_id=grant["request_id"],
        request_sha256=request.sha256,
        grant_jti=grant["jti"],
        issued_at=101,
        expires_at=161,
        result=result,
    )
    return request, grant, claims


def test_canonical_requests_are_complete_exact_and_bound():
    request, claims = grant_fixture("federated_enroll")
    assert request.json == json.dumps(
        request.value, sort_keys=True, separators=(",", ":")
    )
    assert request.sha256 == hashlib.sha256(request.json.encode()).hexdigest()
    assert parse_canonical_action_request(request.json) == request
    with pytest.raises(FederationError, match="request_not_canonical"):
        parse_canonical_action_request(json.dumps(request.value))
    assert validate_grant_claims(claims, now=100, request=request) == claims


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("token_type", "broker_request", "invalid_grant_domain"),
        ("protocol_version", "1", "invalid_grant_domain"),
        ("aud", [DEST], "invalid_grant_audience"),
        ("contract_version", True, "invalid_contract_version"),
        ("capability", "PERMISSIONS_READ_EXTRA", "action_capability_mismatch"),
        ("terms_sha256", "0" * 64, "request_binding_mismatch"),
        ("request_id", str(uuid4()), "request_binding_mismatch"),
        ("request_sha256", "0" * 64, "request_binding_mismatch"),
    ],
)
def test_grant_strict_rejections(field, value, code):
    request, claims = grant_fixture()
    claims[field] = value
    with pytest.raises(FederationError, match=code):
        validate_grant_claims(claims, now=100, request=request)


def test_grant_headers_reject_cross_domain_and_remote_key_headers():
    assert validate_grant_header(
        {"alg": "EdDSA", "kid": "home-key", "typ": FEDERATION_GRANT_TYP}
    )["kid"] == "home-key"
    for header in (
        {"alg": "HS256", "kid": "home-key", "typ": FEDERATION_GRANT_TYP},
        {"alg": "EdDSA", "kid": "home-key", "typ": FEDERATION_RESULT_TYP},
        {
            "alg": "EdDSA",
            "kid": "home-key",
            "typ": FEDERATION_GRANT_TYP,
            "jku": "https://attacker.invalid/key",
        },
    ):
        with pytest.raises(FederationError):
            validate_grant_header(header)


def test_grant_lifetime_is_strict_without_expiry_grace():
    request, claims = grant_fixture()
    with pytest.raises(FederationError, match="grant_expired"):
        validate_grant_claims(claims, now=claims["exp"], request=request)
    claims["exp"] = claims["iat"] + 61
    with pytest.raises(FederationError, match="invalid_grant_time"):
        validate_grant_claims(claims, now=100, request=request)
    claims["exp"] = claims["iat"] + 60
    claims["iat"] = 106
    claims["exp"] = 160
    with pytest.raises(FederationError, match="grant_expired"):
        validate_grant_claims(claims, now=100, request=request)


def test_result_exact_binding_and_substitution_matrix():
    request, grant, claims = result_fixture()
    expected = dict(
        expected_destination=DEST,
        expected_home=HOME,
        expected_subject=SUBJECT,
        expected_contract_id=CONTRACT,
        expected_contract_version=2,
        expected_terms_sha256=TERMS,
        expected_action="permissions_read",
        expected_request_id=request.value["payload"]["request_id"],
        expected_request_sha256=request.sha256,
        expected_grant_jti=grant["jti"],
    )
    assert validate_result_claims(claims, now=101, **expected) == claims
    substitutions = {
        "sub": str(uuid4()),
        "aud": str(uuid4()),
        "request_id": str(uuid4()),
        "grant_jti": str(uuid4()),
        "action": "federated_enroll",
        "terms_sha256": "0" * 64,
        "contract_id": str(uuid4()),
        "contract_version": 3,
    }
    for field, value in substitutions.items():
        changed = copy.deepcopy(claims)
        changed[field] = value
        with pytest.raises(FederationError):
            validate_result_claims(changed, now=101, **expected)


def test_result_header_and_transport_one_of():
    assert validate_result_header(
        {"alg": "EdDSA", "kid": "destination", "typ": FEDERATION_RESULT_TYP}
    )["kid"] == "destination"
    with pytest.raises(FederationError):
        validate_result_header(
            {"alg": "EdDSA", "kid": "destination", "typ": FEDERATION_GRANT_TYP}
        )
    signed = {
        "protocol_version": "2",
        "signed_result": "a.b.c",
        "error": None,
    }
    assert validate_transport_response(signed) == signed
    for bad in (
        {"protocol_version": "2", "signed_result": None, "error": None},
        {
            "protocol_version": "2",
            "signed_result": "a.b.c",
            "error": {"code": "x", "message": "x", "retryable": False},
        },
    ):
        with pytest.raises(FederationError, match="invalid_transport_response"):
            validate_transport_response(bad)


def _unsigned_token(typ):
    def segment(value):
        return base64.urlsafe_b64encode(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    return segment({"alg": "EdDSA", "kid": "domain-test", "typ": typ}) + "." + segment(
        {"iss": HOME, "aud": DEST}
    ) + ".AA"


@pytest.mark.parametrize(
    "foreign_typ",
    [
        "remoterf-home-access+jwt",
        BROKER_REQUEST_TYP,
        CONTRACT_EVENT_TYP,
        FEDERATION_RESULT_TYP,
        "remoterf-global-v1+jwt",
        "JWT",
    ],
)
def test_every_foreign_jwt_domain_is_rejected_as_federation_grant(foreign_typ):
    with pytest.raises(FederationError):
        parse_unverified_grant(_unsigned_token(foreign_typ))


def test_federation_grant_header_cannot_enter_other_signed_domains():
    header = {"alg": "EdDSA", "kid": "home-key", "typ": FEDERATION_GRANT_TYP}
    for validator in (
        validate_broker_request_header,
        validate_contract_event_header,
        validate_result_header,
    ):
        with pytest.raises(ContractError):
            validator(header)
