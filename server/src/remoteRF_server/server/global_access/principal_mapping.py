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
Orchestrates GlobalAuthV1.ExchangeAssertion: verifies the assertion, applies
replay protection, resolves/creates the local JIT mapping + shadow account,
and issues a local session — reusing the existing account/group/perms
systems rather than inventing a parallel one. See
docs/remoterf-global-security.md for the end-to-end trust model.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime

from .assertion_verifier import GlobalAssertionError, VerifiedAssertion, verify_assertion
from .config import GlobalConfig
from .jwks_cache import JWKSCache


class GlobalAuthError(Exception):
    """Mirrors GlobalAssertionError's (code, message) shape for every other
    way ExchangeAssertion can reject a request (disabled integration,
    locally-disabled mapping, misconfigured public_group)."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class ExchangeResult:
    local_username: str
    local_session_token: str
    local_account_id: int
    mapping_id: int
    expires_at: datetime
    deployment_id: str
    effective_policy_summary: str


def username_for_subject(issuer: str, subject: str) -> str:
    """Deterministic, unique, PII-free local username for a Global
    identity. Deterministic so a concurrent first-login race for the same
    subject converges on the same shadow account (see create_external_account's
    own IntegrityError fallback for the other half of that race)."""
    digest = hashlib.sha256(f"{issuer}|{subject}".encode("utf-8")).hexdigest()[:20]
    return f"global-{digest}"


def exchange_assertion(
    token: str,
    *,
    cfg: GlobalConfig,
    deployment_id: str,
    jwks: JWKSCache,
    session_minutes: int,
) -> ExchangeResult:
    if not cfg.enabled:
        raise GlobalAuthError(
            "global_disabled", "RemoteRF Global integration is disabled on this deployment"
        )

    try:
        verified: VerifiedAssertion = verify_assertion(
            token,
            expected_issuer=cfg.issuer,
            expected_deployment_id=deployment_id,
            jwks=jwks,
        )
    except GlobalAssertionError as exc:
        raise GlobalAuthError(exc.code, str(exc)) from exc

    from .db import get_global_db

    db = get_global_db()

    fresh = db.consume_jti(
        issuer=verified.issuer,
        jti=verified.jti,
        global_subject=verified.subject,
        expires_at=verified.expires_at,
    )
    if not fresh:
        raise GlobalAuthError("replayed", "this assertion has already been used")

    existing = db.get_mapping(issuer=verified.issuer, global_subject=verified.subject)
    if existing is not None and existing.status == "disabled":
        raise GlobalAuthError(
            "mapping_disabled", "this RemoteRF Global identity has been disabled on this deployment"
        )

    # Local imports: avoids any import-time coupling between global_access
    # and the rest of the server package when Global is disabled.
    from ..reservation import reservation_handler
    from ..acc_perms import perms
    from ..user_group_handler import user_group_handler

    if existing is None:
        username = username_for_subject(verified.issuer, verified.subject)
        local_account_id = reservation_handler.create_external_account(username=username)
        perms.set_user(username)
        if not user_group_handler.group_exists(group_name=cfg.public_group):
            raise GlobalAuthError(
                "public_group_missing",
                f"configured public_group {cfg.public_group!r} does not exist locally "
                "(an administrator must create it with 'serverrf --global validate-config' "
                "guidance or the existing group CLI before Global users can authenticate)",
            )
        user_group_handler.add_user_to_group_by_name(uid=local_account_id, group_name=cfg.public_group)
        mapping = db.get_or_create_mapping(
            issuer=verified.issuer,
            global_subject=verified.subject,
            local_account_id=local_account_id,
        )
    else:
        mapping = db.get_or_create_mapping(
            issuer=verified.issuer,
            global_subject=verified.subject,
            local_account_id=existing.local_account_id,
        )
        username = reservation_handler.get_username_by_acc_id(mapping.local_account_id)
        if username is None:
            raise GlobalAuthError(
                "shadow_account_missing",
                "the local shadow account for this mapping no longer exists",
            )

    db.touch_last_seen(mapping_id=mapping.id)

    session_token, expires_at = db.create_session(
        mapping_id=mapping.id,
        local_account_id=mapping.local_account_id,
        minutes=session_minutes,
    )

    policy_summary = json.dumps(
        {"public_group": cfg.public_group, "export_count": len(cfg.exports)}
    )

    return ExchangeResult(
        local_username=username,
        local_session_token=session_token,
        local_account_id=mapping.local_account_id,
        mapping_id=mapping.id,
        expires_at=expires_at,
        deployment_id=deployment_id,
        effective_policy_summary=policy_summary,
    )
