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

"""
Signs short-lived Ed25519 (EdDSA) JWTs the connector uses to authenticate
its own requests to RemoteRF Global. Centralizes claim construction so no
call site hand-builds a token or handles the private key directly.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEPLOYMENT_JWT_TTL_SECONDS = 120
DEPLOYMENT_TOKEN_TYPE = "deployment_connector"


def sign_deployment_jwt(
    private_key: Ed25519PrivateKey,
    *,
    deployment_id: str,
    audience: str,
    ttl_seconds: int = DEPLOYMENT_JWT_TTL_SECONDS,
) -> str:
    now = int(datetime.now(timezone.utc).timestamp())
    claims = {
        "iss": f"deployment:{deployment_id}",
        "sub": deployment_id,
        "aud": audience,
        "iat": now,
        "exp": now + int(ttl_seconds),
        "jti": str(uuid.uuid4()),
        "token_type": DEPLOYMENT_TOKEN_TYPE,
    }
    # PyJWT never logs the key or the encoded token; callers must not log
    # the return value either (see connector.py / docs/remoterf-global-security.md).
    return jwt.encode(claims, private_key, algorithm="EdDSA")
