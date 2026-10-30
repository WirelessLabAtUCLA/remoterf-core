"""Deployment-local Gate D contract evidence and enforcement.

The broker is deliberately absent from this module.  A contract is usable only
when this store has independently verified and projected the bilateral signed
evidence against its own trusted-key pins.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
from pathlib import Path
from typing import Mapping
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from remoterf_federation_core import (
    CONTRACT_EVENT_TYP,
    ContractError,
    ContractTerms,
    build_contract_event_claims,
    canonical_json,
    canonical_uuid,
    contract_allows,
    contract_terms_sha256,
    key_is_current,
    strict_json,
    validate_contract_event_claims,
    validate_contract_event_header,
    validate_contract_terms,
    validate_contract_transition,
    validate_kid,
)

from .migrations import configure_connection, migrate_gate_d_usergroups_schema

BUNDLE_FIELDS = frozenset({"protocol_version", "terms", "events"})
MAX_BUNDLE_BYTES = 65536
MAX_BUNDLE_EVENTS = 256
MAX_EVENT_TOKEN_BYTES = 8192


def _safe_label(value: object, *, code: str, maximum: int) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ContractError(code)
    return value


def _raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


class ContractStore:
    """SQLite adapter for one deployment's independent contract projection."""

    def __init__(
        self,
        path: str | Path,
        *,
        local_deployment_id: str,
        private_key: Ed25519PrivateKey,
        signing_kid: str,
        clock=None,
    ):
        self.path = Path(path)
        self.local_deployment_id = canonical_uuid(local_deployment_id)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ContractError("invalid_private_key")
        self.private_key = private_key
        self.signing_kid = validate_kid(signing_kid)
        self.signing_fingerprint = hashlib.sha256(_raw_public_key(private_key)).hexdigest()
        self.clock = clock or (lambda: int(time.time()))
        with sqlite3.connect(self.path) as conn:
            migrate_gate_d_usergroups_schema(conn)

    @staticmethod
    def _audit(
        conn: sqlite3.Connection,
        *,
        now: int,
        actor_ref: str,
        event_type: str,
        contract_id: str,
        version: int,
        result_code: str = "ok",
        metadata: Mapping | None = None,
    ) -> None:
        conn.execute(
            "INSERT INTO FederationAuditEvents "
            "(id,occurred_at,actor_kind,actor_ref,event_type,contract_id,version,"
            "result_code,metadata_json) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                now,
                "local_admin" if actor_ref != "peer_deployment" else "deployment",
                actor_ref,
                event_type,
                contract_id,
                version,
                result_code,
                canonical_json(dict(metadata or {})),
            ),
        )

    @staticmethod
    def _terms_from_row(row: sqlite3.Row) -> ContractTerms:
        return validate_contract_terms(
            {
                "contract_id": row["contract_id"],
                "version": row["version"],
                "deployment_a": row["deployment_a"],
                "deployment_b": row["deployment_b"],
                "valid_from": row["valid_from"],
                "valid_until": row["valid_until"],
                "allowed_capabilities": strict_json(
                    row["allowed_capabilities_json"], max_bytes=512
                ),
                "key_a_kid": row["key_a_kid"],
                "key_a_sha256": row["key_a_sha256"],
                "key_b_kid": row["key_b_kid"],
                "key_b_sha256": row["key_b_sha256"],
                "supersedes_version": row["supersedes_version"],
            }
        )

    @staticmethod
    def _event_claims(conn: sqlite3.Connection, terms: ContractTerms) -> list[dict]:
        rows = conn.execute(
            "SELECT event_id,actor_deployment_id,actor_sequence,event_type,"
            "terms_sha256,occurred_at,actor_admin_ref,reason_code "
            "FROM FederationContractEvents WHERE contract_id=? AND version=? "
            "ORDER BY rowid",
            (terms.contract_id, terms.version),
        ).fetchall()
        return [
            validate_contract_event_claims(
                {
                    "token_type": "federation_contract_event",
                    "protocol_version": "2",
                    "iss": row[1],
                    "event_id": row[0],
                    "contract_id": terms.contract_id,
                    "contract_version": terms.version,
                    "event_type": row[3],
                    "terms_sha256": row[4],
                    "actor_sequence": row[2],
                    "occurred_at": row[5],
                    "actor_admin_ref": row[6],
                    "reason_code": row[7],
                },
                terms,
            )
            for row in rows
        ]

    @staticmethod
    def _trusted_key(
        conn: sqlite3.Connection,
        deployment_id: str,
        kid: str,
        fingerprint: str,
        *,
        now: int,
        occurred_at: int | None = None,
    ) -> tuple[sqlite3.Row, Ed25519PublicKey]:
        row = conn.execute(
            "SELECT * FROM TrustedDeploymentKeys WHERE deployment_id=? AND kid=?",
            (deployment_id, kid),
        ).fetchone()
        if row is None:
            raise ContractError("unknown_kid")
        if row["public_key_sha256"] != fingerprint:
            raise ContractError("key_fingerprint_mismatch")
        if not key_is_current(dict(row), now):
            raise ContractError(
                "key_revoked" if row["state"] == "revoked" else "key_not_current"
            )
        if occurred_at is not None and not (
            row["valid_from"] <= occurred_at
            and (row["valid_until"] is None or occurred_at < row["valid_until"])
        ):
            raise ContractError("key_not_current_at_event")
        import base64

        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(row["public_key_b64"], validate=True)
            )
        except (ValueError, TypeError) as exc:
            raise ContractError("invalid_public_key") from exc
        return row, public_key

    def _check_participant_pins(
        self, conn: sqlite3.Connection, terms: ContractTerms, *, now: int
    ) -> None:
        if self.local_deployment_id not in {terms.deployment_a, terms.deployment_b}:
            raise ContractError("local_deployment_not_participant")
        self._trusted_key(
            conn, terms.deployment_a, terms.key_a_kid, terms.key_a_sha256, now=now
        )
        self._trusted_key(
            conn, terms.deployment_b, terms.key_b_kid, terms.key_b_sha256, now=now
        )
        local_kid, local_fingerprint = terms.key_binding(self.local_deployment_id)
        if (
            local_kid != self.signing_kid
            or local_fingerprint != self.signing_fingerprint
        ):
            raise ContractError("local_signing_key_mismatch")

    @staticmethod
    def _insert_contract(
        conn: sqlite3.Connection, terms: ContractTerms, *, now: int
    ) -> None:
        conn.execute(
            "INSERT INTO FederationContracts "
            "(contract_id,version,deployment_a,deployment_b,state,valid_from,"
            "valid_until,allowed_capabilities_json,key_a_kid,key_a_sha256,"
            "key_b_kid,key_b_sha256,terms_sha256,supersedes_version,"
            "superseded_by_version,created_at,updated_at) "
            "VALUES (?,?,?,?,'proposed',?,?,?,?,?,?,?,?,?,NULL,?,?)",
            (
                terms.contract_id,
                terms.version,
                terms.deployment_a,
                terms.deployment_b,
                terms.valid_from,
                terms.valid_until,
                canonical_json(list(terms.allowed_capabilities)),
                terms.key_a_kid,
                terms.key_a_sha256,
                terms.key_b_kid,
                terms.key_b_sha256,
                contract_terms_sha256(terms),
                terms.supersedes_version,
                now,
                now,
            ),
        )

    @staticmethod
    def _insert_event(
        conn: sqlite3.Connection, claims: Mapping, signed_event: str
    ) -> None:
        conn.execute(
            "INSERT INTO FederationContractEvents "
            "(event_id,contract_id,version,actor_deployment_id,actor_sequence,"
            "event_type,terms_sha256,occurred_at,actor_admin_ref,reason_code,signed_event) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                claims["event_id"],
                claims["contract_id"],
                claims["contract_version"],
                claims["iss"],
                claims["actor_sequence"],
                claims["event_type"],
                claims["terms_sha256"],
                claims["occurred_at"],
                claims["actor_admin_ref"],
                claims["reason_code"],
                signed_event,
            ),
        )

    @staticmethod
    def _next_sequence(
        conn: sqlite3.Connection, contract_id: str, actor_deployment_id: str
    ) -> int:
        row = conn.execute(
            "SELECT MAX(actor_sequence) FROM FederationContractEvents "
            "WHERE contract_id=? AND actor_deployment_id=?",
            (contract_id, actor_deployment_id),
        ).fetchone()
        return (0 if row[0] is None else int(row[0])) + 1

    @staticmethod
    def _validate_new_version(conn: sqlite3.Connection, terms: ContractTerms) -> None:
        rows = conn.execute(
            "SELECT version,state FROM FederationContracts WHERE contract_id=? "
            "ORDER BY version",
            (terms.contract_id,),
        ).fetchall()
        if any(row["state"] == "revoked" for row in rows):
            raise ContractError("contract_revoked")
        if not rows:
            if terms.version != 1 or terms.supersedes_version is not None:
                raise ContractError("invalid_contract_version")
            return
        maximum = int(rows[-1]["version"])
        if terms.version != maximum + 1 or terms.supersedes_version != maximum:
            raise ContractError("invalid_contract_version")

    def _sign(self, claims: Mapping) -> str:
        return jwt.encode(
            dict(claims),
            self.private_key,
            algorithm="EdDSA",
            headers={"typ": CONTRACT_EVENT_TYP, "kid": self.signing_kid},
        )

    def propose(
        self,
        terms: ContractTerms | Mapping,
        *,
        actor_admin_ref: str,
        reason_code: str = "operator_request",
    ) -> dict:
        terms = terms if isinstance(terms, ContractTerms) else validate_contract_terms(dict(terms))
        actor_admin_ref = _safe_label(
            actor_admin_ref, code="invalid_admin_ref", maximum=128
        )
        with sqlite3.connect(self.path, timeout=10.0) as conn:
            conn.row_factory = sqlite3.Row
            configure_connection(conn)
            conn.execute("BEGIN IMMEDIATE")
            now = int(self.clock())
            self._check_participant_pins(conn, terms, now=now)
            if now >= terms.valid_until:
                raise ContractError("contract_expired")
            if conn.execute(
                "SELECT 1 FROM FederationContracts WHERE contract_id=? AND version=?",
                (terms.contract_id, terms.version),
            ).fetchone():
                raise ContractError("contract_version_exists")
            self._validate_new_version(conn, terms)
            self._insert_contract(conn, terms, now=now)
            claims = build_contract_event_claims(
                actor_deployment_id=self.local_deployment_id,
                event_id=str(uuid4()),
                contract_id=terms.contract_id,
                contract_version=terms.version,
                event_type="propose",
                terms_sha256=contract_terms_sha256(terms),
                actor_sequence=self._next_sequence(
                    conn, terms.contract_id, self.local_deployment_id
                ),
                occurred_at=now,
                actor_admin_ref=actor_admin_ref,
                reason_code=reason_code,
            )
            validate_contract_transition(terms, [], claims, now=now)
            signed = self._sign(claims)
            self._insert_event(conn, claims, signed)
            self._audit(
                conn,
                now=now,
                actor_ref=actor_admin_ref,
                event_type="contract_propose",
                contract_id=terms.contract_id,
                version=terms.version,
                metadata={"terms_sha256": contract_terms_sha256(terms)},
            )
        return self.show(terms.contract_id, terms.version)

    def _local_event(
        self,
        contract_id: str,
        version: int,
        event_type: str,
        *,
        actor_admin_ref: str,
        reason_code: str,
    ) -> dict:
        contract_id = canonical_uuid(contract_id)
        if type(version) is not int or version <= 0:
            raise ContractError("invalid_contract_version")
        actor_admin_ref = _safe_label(
            actor_admin_ref, code="invalid_admin_ref", maximum=128
        )
        with sqlite3.connect(self.path, timeout=10.0) as conn:
            conn.row_factory = sqlite3.Row
            configure_connection(conn)
            conn.execute("BEGIN IMMEDIATE")
            now = int(self.clock())
            row = conn.execute(
                "SELECT * FROM FederationContracts WHERE contract_id=? AND version=?",
                (contract_id, version),
            ).fetchone()
            if row is None:
                raise ContractError("unknown_contract")
            terms = self._terms_from_row(row)
            self._check_participant_pins(conn, terms, now=now)
            contract_id_revoked = conn.execute(
                "SELECT 1 FROM FederationContracts WHERE contract_id=? AND state='revoked'",
                (contract_id,),
            ).fetchone() is not None
            claims = build_contract_event_claims(
                actor_deployment_id=self.local_deployment_id,
                event_id=str(uuid4()),
                contract_id=contract_id,
                contract_version=version,
                event_type=event_type,
                terms_sha256=contract_terms_sha256(terms),
                actor_sequence=self._next_sequence(
                    conn, contract_id, self.local_deployment_id
                ),
                occurred_at=now,
                actor_admin_ref=actor_admin_ref,
                reason_code=reason_code,
            )
            events = self._event_claims(conn, terms)
            new_state = validate_contract_transition(
                terms,
                events,
                claims,
                now=now,
                contract_id_revoked=contract_id_revoked,
            )
            signed = self._sign(claims)
            self._insert_event(conn, claims, signed)
            self._apply_projection(conn, terms, new_state, now=now)
            self._audit(
                conn,
                now=now,
                actor_ref=actor_admin_ref,
                event_type=f"contract_{event_type}",
                contract_id=contract_id,
                version=version,
                metadata={"event_id": claims["event_id"]},
            )
        return self.show(contract_id, version)

    @staticmethod
    def _apply_projection(
        conn: sqlite3.Connection,
        terms: ContractTerms,
        new_state: str,
        *,
        now: int,
    ) -> None:
        if new_state == "revoked":
            conn.execute(
                "UPDATE FederationContracts SET state='revoked',updated_at=? "
                "WHERE contract_id=?",
                (now, terms.contract_id),
            )
            return
        if new_state == "active" and terms.supersedes_version is not None:
            old = conn.execute(
                "SELECT state FROM FederationContracts WHERE contract_id=? AND version=?",
                (terms.contract_id, terms.supersedes_version),
            ).fetchone()
            if old is None or old["state"] == "revoked":
                raise ContractError("invalid_supersedes_version")
            conn.execute(
                "UPDATE FederationContracts SET state=CASE WHEN state='active' "
                "THEN 'suspended' ELSE state END,superseded_by_version=?,updated_at=? "
                "WHERE contract_id=? AND version=?",
                (terms.version, now, terms.contract_id, terms.supersedes_version),
            )
        conn.execute(
            "UPDATE FederationContracts SET state=?,updated_at=? "
            "WHERE contract_id=? AND version=?",
            (new_state, now, terms.contract_id, terms.version),
        )

    def accept(self, contract_id: str, version: int, *, actor_admin_ref: str) -> dict:
        return self._local_event(
            contract_id,
            version,
            "accept",
            actor_admin_ref=actor_admin_ref,
            reason_code="operator_accept",
        )

    def activate(self, contract_id: str, version: int, *, actor_admin_ref: str) -> dict:
        return self._local_event(
            contract_id,
            version,
            "activate",
            actor_admin_ref=actor_admin_ref,
            reason_code="operator_activate",
        )

    def suspend(
        self,
        contract_id: str,
        version: int,
        *,
        actor_admin_ref: str,
        reason_code: str = "operator_suspend",
    ) -> dict:
        return self._local_event(
            contract_id,
            version,
            "suspend",
            actor_admin_ref=actor_admin_ref,
            reason_code=reason_code,
        )

    def revoke(
        self,
        contract_id: str,
        version: int,
        *,
        actor_admin_ref: str,
        reason_code: str = "operator_revoke",
    ) -> dict:
        return self._local_event(
            contract_id,
            version,
            "revoke",
            actor_admin_ref=actor_admin_ref,
            reason_code=reason_code,
        )

    def import_event(self, terms: ContractTerms | Mapping, signed_event: str) -> bool:
        """Verify and apply one peer event; return False for exact reimport."""

        terms = terms if isinstance(terms, ContractTerms) else validate_contract_terms(dict(terms))
        if (
            type(signed_event) is not str
            or not signed_event
            or len(signed_event.encode("utf-8")) > MAX_EVENT_TOKEN_BYTES
        ):
            raise ContractError("invalid_signed_event")
        try:
            header = validate_contract_event_header(jwt.get_unverified_header(signed_event))
            unchecked = validate_contract_event_claims(
                jwt.decode(signed_event, options={"verify_signature": False}), terms
            )
        except ContractError:
            raise
        except Exception as exc:
            raise ContractError("invalid_signed_event") from exc
        actor = unchecked["iss"]
        actor_kid, actor_fingerprint = terms.key_binding(actor)
        if header["kid"] != actor_kid:
            raise ContractError("event_key_mismatch")
        with sqlite3.connect(self.path, timeout=10.0) as conn:
            conn.row_factory = sqlite3.Row
            configure_connection(conn)
            conn.execute("BEGIN IMMEDIATE")
            now = int(self.clock())
            existing_event = conn.execute(
                "SELECT signed_event FROM FederationContractEvents WHERE event_id=?",
                (unchecked["event_id"],),
            ).fetchone()
            if existing_event is not None:
                if existing_event["signed_event"] == signed_event:
                    return False
                raise ContractError("event_id_conflict")
            if unchecked["occurred_at"] > now + 5:
                raise ContractError("event_from_future")
            _, public_key = self._trusted_key(
                conn,
                actor,
                actor_kid,
                actor_fingerprint,
                now=now,
                occurred_at=unchecked["occurred_at"],
            )
            try:
                verified_raw = jwt.decode(
                    signed_event,
                    public_key,
                    algorithms=["EdDSA"],
                    options={
                        "verify_aud": False,
                        "verify_exp": False,
                        "verify_iat": False,
                        "verify_nbf": False,
                    },
                )
                verified = validate_contract_event_claims(verified_raw, terms)
            except ContractError:
                raise
            except Exception as exc:
                raise ContractError("invalid_event_signature") from exc
            if verified != unchecked:
                raise ContractError("invalid_signed_event")
            expected_sequence = self._next_sequence(conn, terms.contract_id, actor)
            if verified["actor_sequence"] != expected_sequence:
                raise ContractError(
                    "event_sequence_replay"
                    if verified["actor_sequence"] < expected_sequence
                    else "event_sequence_gap"
                )
            row = conn.execute(
                "SELECT * FROM FederationContracts WHERE contract_id=? AND version=?",
                (terms.contract_id, terms.version),
            ).fetchone()
            if row is None:
                if verified["event_type"] != "propose":
                    raise ContractError("proposal_required")
                self._validate_new_version(conn, terms)
                self._check_participant_pins(conn, terms, now=now)
                self._insert_contract(conn, terms, now=now)
                events = []
            else:
                stored = self._terms_from_row(row)
                if stored.to_dict() != terms.to_dict():
                    raise ContractError("contract_terms_conflict")
                self._check_participant_pins(conn, terms, now=now)
                events = self._event_claims(conn, terms)
            contract_id_revoked = conn.execute(
                "SELECT 1 FROM FederationContracts WHERE contract_id=? AND state='revoked'",
                (terms.contract_id,),
            ).fetchone() is not None
            new_state = validate_contract_transition(
                terms,
                events,
                verified,
                now=now,
                contract_id_revoked=contract_id_revoked,
            )
            self._insert_event(conn, verified, signed_event)
            self._apply_projection(conn, terms, new_state, now=now)
            self._audit(
                conn,
                now=now,
                actor_ref="peer_deployment",
                event_type=f"contract_import_{verified['event_type']}",
                contract_id=terms.contract_id,
                version=terms.version,
                metadata={
                    "actor_deployment_id": actor,
                    "event_id": verified["event_id"],
                },
            )
        return True

    def import_bundle(self, value: str | bytes) -> dict:
        parsed = strict_json(value, max_bytes=MAX_BUNDLE_BYTES)
        if type(parsed) is not dict or set(parsed) != BUNDLE_FIELDS:
            raise ContractError("invalid_bundle_fields")
        if parsed["protocol_version"] != "2":
            raise ContractError("invalid_bundle_version")
        terms = validate_contract_terms(parsed["terms"])
        tokens = parsed["events"]
        if (
            type(tokens) is not list
            or not 1 <= len(tokens) <= MAX_BUNDLE_EVENTS
            or any(type(token) is not str for token in tokens)
        ):
            raise ContractError("invalid_bundle_events")
        applied = 0
        for token in tokens:
            applied += int(self.import_event(terms, token))
        result = self.show(terms.contract_id, terms.version)
        result["events_applied"] = applied
        return result

    def export_bundle(self, contract_id: str, version: int) -> str:
        item = self.show(contract_id, version, include_signed_events=True)
        return canonical_json(
            {
                "protocol_version": "2",
                "terms": item["terms"],
                "events": [event["signed_event"] for event in item["events"]],
            }
        )

    def show(
        self,
        contract_id: str,
        version: int,
        *,
        include_signed_events: bool = False,
    ) -> dict:
        contract_id = canonical_uuid(contract_id)
        if type(version) is not int or version <= 0:
            raise ContractError("invalid_contract_version")
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM FederationContracts WHERE contract_id=? AND version=?",
                (contract_id, version),
            ).fetchone()
            if row is None:
                raise ContractError("unknown_contract")
            terms = self._terms_from_row(row)
            event_rows = conn.execute(
                "SELECT event_id,actor_deployment_id,actor_sequence,event_type,"
                "terms_sha256,occurred_at,actor_admin_ref,reason_code,signed_event "
                "FROM FederationContractEvents WHERE contract_id=? AND version=? "
                "ORDER BY rowid",
                (contract_id, version),
            ).fetchall()
        events = []
        for event in event_rows:
            item = {
                "event_id": event["event_id"],
                "actor_deployment_id": event["actor_deployment_id"],
                "actor_sequence": event["actor_sequence"],
                "event_type": event["event_type"],
                "terms_sha256": event["terms_sha256"],
                "occurred_at": event["occurred_at"],
                "actor_admin_ref": event["actor_admin_ref"],
                "reason_code": event["reason_code"],
            }
            if include_signed_events:
                item["signed_event"] = event["signed_event"]
            events.append(item)
        return {
            "terms": terms.to_dict(),
            "terms_sha256": row["terms_sha256"],
            "state": row["state"],
            "superseded_by_version": row["superseded_by_version"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "events": events,
        }

    def list(self) -> list[dict]:
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(
                "SELECT contract_id,version FROM FederationContracts "
                "ORDER BY contract_id,version"
            ).fetchall()
        return [self.show(row[0], row[1]) for row in rows]

    def is_active(
        self,
        contract_id: str,
        version: int,
        capability: str,
        *,
        now: int | None = None,
    ) -> bool:
        """Return owner-local enforcement state; no broker input is accepted."""

        try:
            contract_id = canonical_uuid(contract_id)
            checked_now = int(self.clock()) if now is None else now
            with sqlite3.connect(self.path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT * FROM FederationContracts WHERE contract_id=? AND version=?",
                    (contract_id, version),
                ).fetchone()
                if row is None:
                    return False
                terms = self._terms_from_row(row)
                if not contract_allows(
                    terms,
                    row["state"],
                    capability,
                    now=checked_now,
                    superseded=row["superseded_by_version"] is not None,
                ):
                    return False
                self._trusted_key(
                    conn,
                    terms.deployment_a,
                    terms.key_a_kid,
                    terms.key_a_sha256,
                    now=checked_now,
                )
                self._trusted_key(
                    conn,
                    terms.deployment_b,
                    terms.key_b_kid,
                    terms.key_b_sha256,
                    now=checked_now,
                )
                return True
        except (ContractError, ValueError, TypeError):
            return False
