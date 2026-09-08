"""Deployment-local, explicitly approved Ed25519 trust pins."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from remoterf_federation_core import (
    ContractError,
    canonical_json,
    key_is_current,
    public_key_bytes,
    validate_trusted_key_material,
)

from .migrations import configure_connection, migrate_gate_d_usergroups_schema

APPROVAL_SOURCES = frozenset({"manual_offline", "identity_file", "broker_candidate"})


def _label(value: object, *, code: str, maximum: int = 256) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ContractError(code)
    return value


class TrustedKeyStore:
    """Trust is changed only by explicit local administrative operations."""

    def __init__(self, path: str | Path, *, clock=None):
        self.path = Path(path)
        self.clock = clock or (lambda: int(time.time()))
        with sqlite3.connect(self.path) as conn:
            migrate_gate_d_usergroups_schema(conn)

    @staticmethod
    def _audit(conn, *, now: int, actor_ref: str, event_type: str, result: str, metadata: dict) -> None:
        conn.execute(
            "INSERT INTO FederationAuditEvents "
            "(id,occurred_at,actor_kind,actor_ref,event_type,result_code,metadata_json) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                now,
                "local_admin",
                actor_ref,
                event_type,
                result,
                canonical_json(metadata),
            ),
        )

    def import_key(
        self,
        material: dict,
        *,
        approved_by: str,
        approval_source: str,
        confirm_deployment_id: str,
        confirm_kid: str,
        confirm_fingerprint: str,
    ) -> dict:
        material = validate_trusted_key_material(material)
        approved_by = _label(approved_by, code="invalid_approved_by")
        if approval_source not in APPROVAL_SOURCES:
            raise ContractError("invalid_approval_source")
        if (
            confirm_deployment_id != material["deployment_id"]
            or confirm_kid != material["kid"]
            or confirm_fingerprint != material["public_key_sha256"]
        ):
            raise ContractError("trust_confirmation_mismatch")
        try:
            Ed25519PublicKey.from_public_bytes(public_key_bytes(material))
        except ValueError as exc:
            raise ContractError("invalid_public_key") from exc
        with sqlite3.connect(self.path, timeout=5.0) as conn:
            configure_connection(conn)
            conn.execute("BEGIN IMMEDIATE")
            now = int(self.clock())
            existing = conn.execute(
                "SELECT public_key_b64,public_key_sha256,state,valid_from,valid_until "
                "FROM TrustedDeploymentKeys WHERE deployment_id=? AND kid=?",
                (material["deployment_id"], material["kid"]),
            ).fetchone()
            if existing is not None:
                exact = existing == (
                    material["public_key_b64"],
                    material["public_key_sha256"],
                    "active",
                    material["valid_from"],
                    material["valid_until"],
                )
                raise ContractError(
                    "duplicate_trusted_key" if exact else "trusted_key_conflict"
                )
            conn.execute(
                "INSERT INTO TrustedDeploymentKeys "
                "(deployment_id,kid,public_key_b64,public_key_sha256,state,"
                "valid_from,valid_until,approved_at,approved_by,approval_source) "
                "VALUES (?,?,?,?,'active',?,?,?,?,?)",
                (
                    material["deployment_id"],
                    material["kid"],
                    material["public_key_b64"],
                    material["public_key_sha256"],
                    material["valid_from"],
                    material["valid_until"],
                    now,
                    approved_by,
                    approval_source,
                ),
            )
            self._audit(
                conn,
                now=now,
                actor_ref=approved_by,
                event_type="trust_import",
                result="ok",
                metadata={
                    "deployment_id": material["deployment_id"],
                    "kid": material["kid"],
                    "public_key_sha256": material["public_key_sha256"],
                    "approval_source": approval_source,
                },
            )
        return self.get(material["deployment_id"], material["kid"])

    def get(self, deployment_id: str, kid: str) -> dict:
        from remoterf_federation_core import canonical_uuid, validate_kid

        deployment_id = canonical_uuid(deployment_id)
        kid = validate_kid(kid)
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM TrustedDeploymentKeys WHERE deployment_id=? AND kid=?",
                (deployment_id, kid),
            ).fetchone()
        if row is None:
            raise ContractError("unknown_kid")
        return dict(row)

    def require_current(
        self,
        deployment_id: str,
        kid: str,
        *,
        fingerprint: str | None = None,
        now: int | None = None,
    ) -> dict:
        row = self.get(deployment_id, kid)
        if fingerprint is not None and row["public_key_sha256"] != fingerprint:
            raise ContractError("key_fingerprint_mismatch")
        if not key_is_current(row, int(self.clock()) if now is None else now):
            raise ContractError(
                "key_revoked" if row["state"] == "revoked" else "key_not_current"
            )
        return row

    def list(self, deployment_id: str | None = None) -> list[dict]:
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            if deployment_id is None:
                rows = conn.execute(
                    "SELECT * FROM TrustedDeploymentKeys ORDER BY deployment_id,kid"
                ).fetchall()
            else:
                from remoterf_federation_core import canonical_uuid

                rows = conn.execute(
                    "SELECT * FROM TrustedDeploymentKeys WHERE deployment_id=? ORDER BY kid",
                    (canonical_uuid(deployment_id),),
                ).fetchall()
        return [dict(row) for row in rows]

    def revoke(self, deployment_id: str, kid: str, *, approved_by: str) -> dict:
        from remoterf_federation_core import canonical_uuid, validate_kid

        deployment_id = canonical_uuid(deployment_id)
        kid = validate_kid(kid)
        approved_by = _label(approved_by, code="invalid_approved_by")
        with sqlite3.connect(self.path, timeout=5.0) as conn:
            configure_connection(conn)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT state,public_key_sha256 FROM TrustedDeploymentKeys "
                "WHERE deployment_id=? AND kid=?",
                (deployment_id, kid),
            ).fetchone()
            if row is None:
                raise ContractError("unknown_kid")
            if row[0] == "revoked":
                conn.row_factory = sqlite3.Row
                current = conn.execute(
                    "SELECT * FROM TrustedDeploymentKeys "
                    "WHERE deployment_id=? AND kid=?",
                    (deployment_id, kid),
                ).fetchone()
                return dict(current)
            now = int(self.clock())
            conn.execute(
                "UPDATE TrustedDeploymentKeys SET state='revoked' "
                "WHERE deployment_id=? AND kid=?",
                (deployment_id, kid),
            )
            self._audit(
                conn,
                now=now,
                actor_ref=approved_by,
                event_type="trust_revoke",
                result="ok",
                metadata={
                    "deployment_id": deployment_id,
                    "kid": kid,
                    "public_key_sha256": row[1],
                },
            )
        return self.get(deployment_id, kid)
