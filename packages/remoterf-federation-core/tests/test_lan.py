import hashlib
import hmac
from uuid import uuid4

import pytest

from remoterf_federation_core import (
    LAN_UPDATE_CODE,
    FederationError,
    held_keys,
    build_action_request,
    lan_secret,
    lan_verifier,
    parse_canonical_action_request,
)

LAB = "880a50a0-fb9f-4828-96be-ff6124643196"
# RemoteRF-Client vendors lan_secret (it stays on an older core); its test
# asserts this same vector, so the two can never drift apart.
VECTOR = "93167784b0fab1e28a1e832140fc75851ba6bd7b4cbfdbe38eddb0598c202fbb"


def test_lan_secret_is_fixed_and_bound_to_the_lab_and_the_name():
    assert lan_secret("correct horse battery", LAB, "jdoe") == VECTOR
    assert lan_secret("correct horse battery", LAB, "JDoe") == VECTOR
    assert lan_secret("correct horse battery", str(uuid4()), "jdoe") != VECTOR
    assert lan_secret("correct horse battery", LAB, "jdoe2") != VECTOR
    assert lan_secret("correct horse batterz", LAB, "jdoe") != VECTOR


def test_lan_verifier_is_the_labs_own_password_format():
    salt, hashed = lan_verifier(VECTOR)
    _, rounds, digest = hashed.split("$", 2)
    assert hashed.startswith("pbkdf2$") and len(salt) == 32
    expected = hashlib.pbkdf2_hmac("sha256", VECTOR.encode(), bytes.fromhex(salt), int(rounds))
    assert hmac.compare_digest(expected.hex(), digest)


def enroll(code="CODE1", **enrollee):
    return build_action_request(
        action="federated_enroll", request_id=str(uuid4()), destination_deployment_id=LAB,
        contract_id=str(uuid4()), contract_version=1, terms_sha256="a" * 64,
        code_name=code, enrollee=enrollee,
    )


def test_enroll_carries_a_lab_login_and_lan_update_is_a_code():
    salt, hashed = lan_verifier(VECTOR)
    request = enroll(LAN_UPDATE_CODE, email="jdoe@example.org", username="jdoe", lan_salt=salt, lan_hash=hashed)
    payload = parse_canonical_action_request(request.json).value["payload"]
    assert (payload["code_name"], payload["username"], payload["lan_salt"], payload["lan_hash"]) == (
        LAN_UPDATE_CODE, "jdoe", salt, hashed)
    assert "lan_salt" not in enroll(display_name="jdoe@global").value["payload"]  # still optional


@pytest.mark.parametrize("bad", [
    {"username": "jdoe", "lan_salt": "0" * 32},                          # not all three
    {"username": "JDoe", "lan_salt": "0" * 32, "lan_hash": "pbkdf2$210000$" + "0" * 64},
    {"username": "jdoe", "lan_salt": "0" * 31, "lan_hash": "pbkdf2$210000$" + "0" * 64},
    {"username": "jdoe", "lan_salt": "0" * 32, "lan_hash": "pbkdf2$1000$" + "0" * 64},
    {"username": "jdoe", "lan_salt": "0" * 32, "lan_hash": "pbkdf2$9000000$" + "0" * 64},
    {"username": "jdoe", "lan_salt": "0" * 32, "lan_hash": "sha256$" + "0" * 64},
])
def test_a_malformed_lab_login_is_refused(bad):
    with pytest.raises(FederationError, match="invalid_enrollee"):
        enroll(**bad)


def test_held_keys_ignore_case_and_spacing_and_keep_name_and_email_apart():
    name, email = held_keys("JDoe", " JDoe@Example.org ")
    assert (name, email) == held_keys("jdoe", "jdoe@example.org")
    assert len(name) == len(email) == 12 and name != held_keys("jdoe@example.org", "x")[0]
