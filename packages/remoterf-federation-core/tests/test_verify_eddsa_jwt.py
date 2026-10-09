import base64
import json
import os
import time

import pytest

jwt = pytest.importorskip("jwt")
ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")

from remoterf_federation_core import (
    FEDERATION_RESULT_TYP,
    MAX_DEVICE_RESULT_TOKEN_BYTES,
    FederationError,
    verify_eddsa_jwt,
)

PYJWT_OPTIONS = {
    "verify_aud": False,
    "verify_exp": False,
    "verify_iat": False,
    "verify_nbf": False,
}
HEADER = {"kid": "k1", "typ": FEDERATION_RESULT_TYP}


@pytest.fixture(scope="module")
def private_key():
    return ed25519.Ed25519PrivateKey.generate()


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign_raw(private_key, header_segment: str, payload_segment: str) -> str:
    signing_input = f"{header_segment}.{payload_segment}"
    return f"{signing_input}.{b64(private_key.sign(signing_input.encode()))}"


def header_segment(header=None) -> str:
    return b64(json.dumps(header or {"alg": "EdDSA", **HEADER}).encode())


def pyjwt_decode(token, public_key):
    return jwt.decode(token, public_key, algorithms=["EdDSA"], options=PYJWT_OPTIONS)


def rejected(token, public_key, **kwargs):
    with pytest.raises(FederationError) as error:
        verify_eddsa_jwt(token, public_key, code="invalid_result_signature", **kwargs)
    return error.value.args[0] == "invalid_result_signature"


@pytest.mark.parametrize(
    "claims",
    [
        {},
        {"sub": "s", "jti": "j", "exp": 1, "iat": 2, "aud": "elsewhere"},
        {"result": {"data": "A" * 1_000_000}, "n": [1, None, True, "é"]},
    ],
)
def test_matches_pyjwt_on_valid_tokens(private_key, claims):
    token = jwt.encode(claims, private_key, algorithm="EdDSA", headers=HEADER)
    public_key = private_key.public_key()
    assert verify_eddsa_jwt(token, public_key) == pyjwt_decode(token, public_key)


def test_signs_and_parses_every_canonical_tail_length(private_key):
    for size in range(3, 9):
        payload = json.dumps({"p": "x" * size}).encode()
        token = sign_raw(private_key, header_segment(), b64(payload))
        assert verify_eddsa_jwt(token, private_key.public_key()) == {"p": "x" * size}


def test_rejects_tampering_and_wrong_key(private_key):
    public_key = private_key.public_key()
    token = jwt.encode({"sub": "s"}, private_key, algorithm="EdDSA", headers=HEADER)
    header, payload, signature = token.split(".")
    other_payload = b64(json.dumps({"sub": "t"}).encode())
    other_header = header_segment({"alg": "EdDSA", "kid": "k2", "typ": HEADER["typ"]})
    for bad in (
        f"{header}.{other_payload}.{signature}",
        f"{other_header}.{payload}.{signature}",
        f"{header}.{payload}.{b64(bytes(64))}",
        f"{header}.{payload}.{signature[:-2]}",
    ):
        assert rejected(bad, public_key)
        with pytest.raises(jwt.PyJWTError):
            pyjwt_decode(bad, public_key)
    wrong_key = ed25519.Ed25519PrivateKey.generate().public_key()
    assert rejected(token, wrong_key)
    with pytest.raises(jwt.PyJWTError):
        pyjwt_decode(token, wrong_key)


def test_rejects_other_algorithms_and_headers(private_key):
    public_key = private_key.public_key()
    payload = b64(b'{"sub":"s"}')
    for header in (
        {"alg": "none", **HEADER},
        {"alg": "HS256", **HEADER},
        {"alg": "ES256", **HEADER},
        {**HEADER},
        {"alg": "EdDSA", "kid": 7},
        {"alg": "EdDSA", "crit": ["b64"], "b64": False},
        {"alg": "EdDSA", "jku": "https://example.org/keys"},
    ):
        assert rejected(sign_raw(private_key, header_segment(header), payload), public_key)
    assert rejected(f"{header_segment({'alg': 'none'})}.{payload}.", public_key)
    assert rejected(b64(b'["alg"]') + f".{payload}.AAAA", public_key)


def test_rejects_non_canonical_base64(private_key):
    public_key = private_key.public_key()
    header = header_segment()
    payload = b64(b'{"p":"xx"}')  # 14 chars: one 2-bit unused tail
    assert len(payload) % 4 == 2 and payload[-1] in "AQgw"
    tail = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    sloppy_tail = tail[tail.index(payload[-1]) + 1]
    assert base64.urlsafe_b64decode(payload[:-1] + sloppy_tail + "==") == b'{"p":"xx"}'
    for bad_payload in (
        payload + "==",
        payload[:-1] + sloppy_tail,
        payload.replace("e", "+", 1),
        payload[:4] + "/" + payload[5:],
        payload[:4] + " " + payload[4:],
        payload + "A",  # length % 4 == 1
        "",
    ):
        assert rejected(sign_raw(private_key, header, bad_payload), public_key)
    token = sign_raw(private_key, header, payload)
    assert rejected(token + "=", public_key)
    assert rejected(token.encode(), public_key)
    assert rejected("." + token, public_key)
    assert rejected(token.replace(".", "..", 1), public_key)
    assert rejected(f"{token}.{token.rsplit('.', 1)[1]}", public_key)


def test_rejects_claims_pyjwt_or_strict_json_reject(private_key):
    public_key = private_key.public_key()
    header = header_segment()
    for payload in (b'["sub"]', b'{"sub":1}', b'{"jti":null}', b'{"a":1,"a":2}', b'{"a":NaN}'):
        assert rejected(sign_raw(private_key, header, b64(payload)), public_key)


def test_rejects_oversized_tokens_and_wrong_key_types(private_key):
    token = jwt.encode({"p": "x" * 200}, private_key, algorithm="EdDSA", headers=HEADER)
    public_key = private_key.public_key()
    assert verify_eddsa_jwt(token, public_key, max_bytes=len(token))
    assert rejected(token, public_key, max_bytes=len(token) - 1)
    huge = "A" * (MAX_DEVICE_RESULT_TOKEN_BYTES + 1)
    assert rejected(sign_raw(private_key, header_segment(), huge), public_key)
    for key in (private_key, public_key.public_bytes_raw(), None):
        assert rejected(token, key)
    with pytest.raises(FederationError) as error:
        verify_eddsa_jwt("x", public_key)
    assert error.value.args[0] == "invalid_token"


def test_large_token_verifies_much_faster_than_pyjwt(private_key):
    raw = os.urandom(768 * 1024)
    claims = {"sub": "s", "result": {"response_b64": base64.b64encode(raw).decode()}}
    token = jwt.encode(claims, private_key, algorithm="EdDSA", headers=HEADER)
    public_key = private_key.public_key()

    def best(fn):
        timings = []
        for _ in range(5):
            started = time.perf_counter()
            fn()
            timings.append(time.perf_counter() - started)
        return min(timings)

    helper = best(lambda: verify_eddsa_jwt(token, public_key))
    pyjwt = best(lambda: pyjwt_decode(token, public_key))
    if not hasattr(jwt.api_jws.PyJWS, "_decode_base64url_segment"):
        # PyJWT < 2.15 lacks the per-character alphabet loop production runs.
        alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        payload = token.split(".")[1].encode()
        pyjwt += best(lambda: any(ch not in alphabet for ch in payload))
    assert helper * 3 < pyjwt, (helper, pyjwt)
