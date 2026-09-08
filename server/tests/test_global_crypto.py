from __future__ import annotations

import unittest

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from remoteRF_server.server.global_access.jwt_tools import (
    DEPLOYMENT_TOKEN_TYPE,
    sign_deployment_jwt,
)

DEPLOYMENT_ID = "11111111-1111-1111-1111-111111111111"


class DeploymentJwtTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()

    def test_signed_connector_jwt_has_expected_claims_and_verifies(self):
        audience = "https://global.remoterf.net/v1/deployment"
        token = sign_deployment_jwt(
            self.private, deployment_id=DEPLOYMENT_ID, audience=audience
        )
        claims = jwt.decode(
            token, self.private.public_key(), algorithms=["EdDSA"], audience=audience
        )
        self.assertEqual(claims["iss"], f"deployment:{DEPLOYMENT_ID}")
        self.assertEqual(claims["sub"], DEPLOYMENT_ID)
        self.assertEqual(claims["token_type"], DEPLOYMENT_TOKEN_TYPE)
        self.assertLessEqual(claims["exp"] - claims["iat"], 120)

    def test_each_connector_jwt_has_a_unique_jti(self):
        first = sign_deployment_jwt(
            self.private, deployment_id=DEPLOYMENT_ID, audience="aud"
        )
        second = sign_deployment_jwt(
            self.private, deployment_id=DEPLOYMENT_ID, audience="aud"
        )
        options = {"algorithms": ["EdDSA"], "audience": "aud"}
        first_claims = jwt.decode(first, self.private.public_key(), **options)
        second_claims = jwt.decode(second, self.private.public_key(), **options)
        self.assertNotEqual(first_claims["jti"], second_claims["jti"])

    def test_header_algorithm_is_eddsa(self):
        token = sign_deployment_jwt(
            self.private, deployment_id=DEPLOYMENT_ID, audience="aud"
        )
        self.assertEqual(jwt.get_unverified_header(token)["alg"], "EdDSA")
