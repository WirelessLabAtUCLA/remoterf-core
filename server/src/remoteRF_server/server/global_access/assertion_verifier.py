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
Verifies short-lived RemoteRF Global user access assertions presented to
GlobalAuthV1.ExchangeAssertion. Every rejection path fails closed: no
mapping/account/session is ever created from a token that doesn't pass
every check below. The assertion string itself is never logged.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import jwt

from .jwks_cache import JWKSCache

REQUIRED_TOKEN_TYPE = "deployment_access"
REQUIRED_SCOPE = "remoterf:connect"
MAX_LIFETIME_SECONDS = 120
DEFAULT_CLOCK_SKEW_SECONDS = 30


class GlobalAssertionError(Exception):
    """Raised for any assertion rejection. `code` is a stable short string
    suitable for a structured ErrorEnvelope; the message is safe to log
    (never includes the token itself)."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class VerifiedAssertion:
    subject: str
    issuer: str
    jti: str
    issued_at: datetime
    expires_at: datetime


def verify_assertion(
    token: str,
    *,
    expected_issuer: str,
    expected_deployment_id: str,
    jwks: JWKSCache,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> VerifiedAssertion:
    try:
        header = jwt.get_unverified_header(token)
    except Exception as exc:
        raise GlobalAssertionError("malformed", f"could not parse token header: {exc}") from exc

    if header.get("alg") != "EdDSA":
        raise GlobalAssertionError(
            "wrong_algorithm", f"unsupported alg {header.get('alg')!r} (only EdDSA is accepted)"
        )

    kid = header.get("kid")
    if not kid:
        raise GlobalAssertionError("malformed", "missing 'kid' in token header")

    key = jwks.get_key(kid)
    if key is None:
        raise GlobalAssertionError("unknown_kid", f"unknown signing key {kid!r}")

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=["EdDSA"],
            audience=expected_deployment_id,
            issuer=expected_issuer,
            leeway=clock_skew_seconds,
            options={
                "require": [
                    "iss", "sub", "aud", "iat", "exp", "jti",
                    "token_type", "scope", "email_verified",
                ],
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise GlobalAssertionError("expired", "assertion has expired") from exc
    except jwt.ImmatureSignatureError as exc:
        raise GlobalAssertionError("not_yet_valid", "assertion is not yet valid") from exc
    except jwt.InvalidAudienceError as exc:
        raise GlobalAssertionError(
            "wrong_audience", "assertion audience does not match this deployment"
        ) from exc
    except jwt.InvalidIssuerError as exc:
        raise GlobalAssertionError("wrong_issuer", "unexpected issuer") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise GlobalAssertionError("malformed", str(exc)) from exc
    except jwt.InvalidTokenError as exc:
        raise GlobalAssertionError("invalid_signature", str(exc)) from exc

    token_type = claims.get("token_type")
    if token_type != REQUIRED_TOKEN_TYPE:
        raise GlobalAssertionError(
            "wrong_token_type", f"expected token_type {REQUIRED_TOKEN_TYPE!r}, got {token_type!r}"
        )

    scope = claims.get("scope")
    scopes = scope if isinstance(scope, list) else str(scope or "").split()
    if REQUIRED_SCOPE not in scopes:
        raise GlobalAssertionError(
            "missing_scope", f"assertion missing required scope {REQUIRED_SCOPE!r}"
        )

    if claims.get("email_verified") is not True:
        raise GlobalAssertionError("email_not_verified", "assertion email_verified must be true")

    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub.strip():
        raise GlobalAssertionError("malformed_subject", "'sub' must be a non-empty string")

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti.strip():
        raise GlobalAssertionError("malformed", "'jti' must be a non-empty string")

    try:
        iat_i = int(claims["iat"])
        exp_i = int(claims["exp"])
    except (TypeError, ValueError) as exc:
        raise GlobalAssertionError("malformed", "'iat'/'exp' must be numeric") from exc

    lifetime = exp_i - iat_i
    if lifetime <= 0 or lifetime > MAX_LIFETIME_SECONDS:
        raise GlobalAssertionError(
            "excessive_lifetime",
            f"assertion lifetime {lifetime}s exceeds the {MAX_LIFETIME_SECONDS}s maximum",
        )

    return VerifiedAssertion(
        subject=sub.strip(),
        issuer=str(claims.get("iss")),
        jti=jti.strip(),
        issued_at=datetime.fromtimestamp(iat_i, tz=timezone.utc),
        expires_at=datetime.fromtimestamp(exp_i, tz=timezone.utc),
    )
