# Copyright (C) 2026 RemoteRF
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from __future__ import annotations

import base64
import time
import unittest
import uuid
from unittest.mock import MagicMock, patch

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from remoteRF_server.server.global_access.assertion_verifier import (
    GlobalAssertionError,
    verify_assertion,
)
from remoteRF_server.server.global_access.jwks_cache import JWKSCache
from remoteRF_server.server.global_access.jwt_tools import (
    DEPLOYMENT_TOKEN_TYPE,
    sign_deployment_jwt,
)

ISSUER = "https://global.remoterf.net"
DEPLOYMENT_ID = "11111111-1111-1111-1111-111111111111"
KID = "test-key-1"


def _jwk_from_public_key(pub, kid: str) -> dict:
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    x = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": x}


def _mint_assertion(priv, *, kid=KID, **claim_overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": "global-user-uuid-0001",
        "aud": DEPLOYMENT_ID,
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
        "email_verified": True,
        "scope": ["remoterf:connect"],
        "token_type": "deployment_access",
    }
    claims.update(claim_overrides)
    return jwt.encode(claims, priv, algorithm="EdDSA", headers={"kid": kid})


def _mock_response(json_body):
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = json_body
    return resp


class DeploymentJwtTests(unittest.TestCase):
    def setUp(self):
        self.priv = Ed25519PrivateKey.generate()

    def test_signed_jwt_has_expected_claims_and_verifies(self):
        token = sign_deployment_jwt(
            self.priv, deployment_id=DEPLOYMENT_ID, audience=f"{ISSUER}/v1/deployment"
        )
        claims = jwt.decode(
            token, self.priv.public_key(), algorithms=["EdDSA"], audience=f"{ISSUER}/v1/deployment"
        )
        self.assertEqual(claims["iss"], f"deployment:{DEPLOYMENT_ID}")
        self.assertEqual(claims["sub"], DEPLOYMENT_ID)
        self.assertEqual(claims["token_type"], DEPLOYMENT_TOKEN_TYPE)
        self.assertLessEqual(claims["exp"] - claims["iat"], 120)

    def test_each_signed_jwt_has_a_unique_jti(self):
        t1 = sign_deployment_jwt(self.priv, deployment_id=DEPLOYMENT_ID, audience="aud")
        t2 = sign_deployment_jwt(self.priv, deployment_id=DEPLOYMENT_ID, audience="aud")
        c1 = jwt.decode(t1, self.priv.public_key(), algorithms=["EdDSA"], audience="aud")
        c2 = jwt.decode(t2, self.priv.public_key(), algorithms=["EdDSA"], audience="aud")
        self.assertNotEqual(c1["jti"], c2["jti"])

    def test_header_algorithm_is_eddsa_only(self):
        token = sign_deployment_jwt(self.priv, deployment_id=DEPLOYMENT_ID, audience="aud")
        header = jwt.get_unverified_header(token)
        self.assertEqual(header["alg"], "EdDSA")


class JWKSCacheTests(unittest.TestCase):
    def setUp(self):
        self.priv = Ed25519PrivateKey.generate()
        self.jwk = _jwk_from_public_key(self.priv.public_key(), KID)

    def test_cache_hit_does_not_refetch_within_ttl(self):
        with patch("requests.get", return_value=_mock_response({"keys": [self.jwk]})) as mock_get:
            cache = JWKSCache("https://example/.well-known/jwks.json", ttl_seconds=300)
            k1 = cache.get_key(KID)
            k2 = cache.get_key(KID)
            self.assertIsNotNone(k1)
            self.assertEqual(mock_get.call_count, 1)
            self.assertIsNotNone(k2)
            self.assertEqual(mock_get.call_count, 1)

    def test_unknown_kid_triggers_exactly_one_forced_refresh(self):
        with patch("requests.get", return_value=_mock_response({"keys": [self.jwk]})) as mock_get:
            cache = JWKSCache("https://example/.well-known/jwks.json", ttl_seconds=300)
            result = cache.get_key("some-other-kid")
            self.assertIsNone(result)
            self.assertEqual(mock_get.call_count, 1)

    def test_expired_cache_triggers_refresh(self):
        with patch("requests.get", return_value=_mock_response({"keys": [self.jwk]})) as mock_get:
            cache = JWKSCache("https://example/.well-known/jwks.json", ttl_seconds=0)
            cache.get_key(KID)
            cache.get_key(KID)
            self.assertEqual(mock_get.call_count, 2)

    def test_symmetric_key_type_is_never_accepted(self):
        bad_jwk = {"kty": "oct", "kid": "sym-1", "k": "deadbeef"}
        with patch("requests.get", return_value=_mock_response({"keys": [bad_jwk]})):
            cache = JWKSCache("https://example/.well-known/jwks.json")
            self.assertIsNone(cache.get_key("sym-1"))

    def test_unreachable_endpoint_with_no_cache_fails_closed(self):
        with patch("requests.get", side_effect=ConnectionError("no route")):
            cache = JWKSCache("https://example/.well-known/jwks.json")
            self.assertIsNone(cache.get_key(KID))

    def test_unreachable_endpoint_with_fresh_cached_key_still_serves_it(self):
        call_count = {"n": 0}

        def _get(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _mock_response({"keys": [self.jwk]})
            raise ConnectionError("global is down")

        with patch("requests.get", side_effect=_get):
            cache = JWKSCache("https://example/.well-known/jwks.json", ttl_seconds=300)
            self.assertIsNotNone(cache.get_key(KID))
            # Still within TTL: no second fetch attempted, so the outage
            # never even gets exercised for a still-fresh cache hit.
            self.assertIsNotNone(cache.get_key(KID))
            self.assertEqual(call_count["n"], 1)


class AssertionVerifierTests(unittest.TestCase):
    def setUp(self):
        self.priv = Ed25519PrivateKey.generate()
        self.jwk = _jwk_from_public_key(self.priv.public_key(), KID)
        self._patcher = patch("requests.get", return_value=_mock_response({"keys": [self.jwk]}))
        self._patcher.start()
        self.addCleanup(self._patcher.stop)
        self.jwks = JWKSCache("https://example/.well-known/jwks.json")

    def _verify(self, token):
        return verify_assertion(
            token, expected_issuer=ISSUER, expected_deployment_id=DEPLOYMENT_ID, jwks=self.jwks
        )

    def test_valid_assertion_is_accepted(self):
        token = _mint_assertion(self.priv)
        result = self._verify(token)
        self.assertEqual(result.subject, "global-user-uuid-0001")
        self.assertEqual(result.issuer, ISSUER)

    def test_wrong_issuer_rejected(self):
        token = _mint_assertion(self.priv, iss="https://evil.example")
        with self.assertRaises(GlobalAssertionError) as ctx:
            self._verify(token)
        self.assertEqual(ctx.exception.code, "wrong_issuer")

    def test_wrong_audience_rejected(self):
        token = _mint_assertion(self.priv, aud="some-other-deployment-uuid")
        with self.assertRaises(GlobalAssertionError) as ctx:
            self._verify(token)
        self.assertEqual(ctx.exception.code, "wrong_audience")

    def test_expired_assertion_rejected(self):
        now = int(time.time())
        token = _mint_assertion(self.priv, iat=now - 300, exp=now - 200)
        with self.assertRaises(GlobalAssertionError) as ctx:
            self._verify(token)
        self.assertEqual(ctx.exception.code, "expired")

    def test_future_issued_assertion_rejected(self):
        now = int(time.time())
        token = _mint_assertion(self.priv, iat=now + 300, exp=now + 360)
        with self.assertRaises(GlobalAssertionError) as ctx:
            self._verify(token)
        self.assertEqual(ctx.exception.code, "not_yet_valid")

    def test_excessive_lifetime_rejected(self):
        now = int(time.time())
        token = _mint_assertion(self.priv, iat=now, exp=now + 3600)
        with self.assertRaises(GlobalAssertionError) as ctx:
            self._verify(token)
        self.assertEqual(ctx.exception.code, "excessive_lifetime")

    def test_wrong_token_type_rejected(self):
        token = _mint_assertion(self.priv, token_type="deployment_connector")
        with self.assertRaises(GlobalAssertionError) as ctx:
            self._verify(token)
        self.assertEqual(ctx.exception.code, "wrong_token_type")

    def test_missing_scope_rejected(self):
        token = _mint_assertion(self.priv, scope=["some:other:scope"])
        with self.assertRaises(GlobalAssertionError) as ctx:
            self._verify(token)
        self.assertEqual(ctx.exception.code, "missing_scope")

    def test_unverified_email_rejected(self):
        token = _mint_assertion(self.priv, email_verified=False)
        with self.assertRaises(GlobalAssertionError) as ctx:
            self._verify(token)
        self.assertEqual(ctx.exception.code, "email_not_verified")

    def test_malformed_subject_rejected(self):
        token = _mint_assertion(self.priv, sub="")
        with self.assertRaises(GlobalAssertionError) as ctx:
            self._verify(token)
        self.assertEqual(ctx.exception.code, "malformed_subject")

    def test_wrong_algorithm_rejected(self):
        now = int(time.time())
        claims = {
            "iss": ISSUER, "sub": "u1", "aud": DEPLOYMENT_ID, "iat": now, "exp": now + 60,
            "jti": str(uuid.uuid4()), "email_verified": True, "scope": ["remoterf:connect"],
            "token_type": "deployment_access",
        }
        token = jwt.encode(claims, "some-shared-secret", algorithm="HS256", headers={"kid": KID})
        with self.assertRaises(GlobalAssertionError) as ctx:
            self._verify(token)
        self.assertEqual(ctx.exception.code, "wrong_algorithm")

    def test_unknown_signing_key_rejected(self):
        other_priv = Ed25519PrivateKey.generate()
        token = _mint_assertion(other_priv, kid="unknown-kid-999")
        with self.assertRaises(GlobalAssertionError) as ctx:
            self._verify(token)
        self.assertEqual(ctx.exception.code, "unknown_kid")

    def test_wrong_key_for_known_kid_rejected(self):
        # Same kid the cache knows, but signed with a *different* private
        # key: signature must fail even though the kid resolves.
        other_priv = Ed25519PrivateKey.generate()
        token = _mint_assertion(other_priv, kid=KID)
        with self.assertRaises(GlobalAssertionError) as ctx:
            self._verify(token)
        self.assertEqual(ctx.exception.code, "invalid_signature")


if __name__ == "__main__":
    unittest.main()
