"""Server owner-local Gate E destination execution.

The broker is deliberately absent.  This adapter verifies only local pins and
the exact local contract, serializes authorization with owner state, consumes
the grant JTI in that transaction, commits, and only then signs the result.
No production action handler is registered by default.

Gate H adds an optional post-commit ``finalize`` step for handlers whose
observation cannot run inside the owner transaction (a device RPC against
real hardware).  Authorization and JTI consumption are still decided and
committed first; finalize only replaces the result payload that is signed.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Mapping

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from remoterf_federation_core import (
    ACTION_CAPABILITIES,
    FEDERATION_RESULT_TYP,
    MAX_PROTOCOL_INTEGER,
    ContractError,
    FederationError,
    ValidationError,
    build_result_claims,
    canonical_uuid,
    contract_terms_sha256,
    contract_allows,
    empty_device_payload,
    is_device_action,
    key_is_current,
    max_result_token_bytes,
    parse_canonical_action_request,
    parse_unverified_grant,
    public_key_bytes,
    strict_json,
    validate_action_result,
    validate_contract_terms,
    validate_grant_claims,
    validate_trusted_key_material,
)

from .migrations import configure_connection, migrate_gate_f_usergroups_schema


# A handler with a post-commit ``finalize`` returns this typed error from the
# owner transaction to mean "authorized; observation follows after commit".
# It is a valid signed-error shape, so if finalization is somehow skipped the
# HOME receives a stable error rather than a fabricated success, and the
# executor refuses to sign it unless finalize has replaced it.
FINALIZE_PENDING = "finalize_pending"


class FederationBusinessError(Exception):
    """A bounded expected result; its verified grant JTI remains consumed."""

    def __init__(self, code: str):
        if (
            type(code) is not str
            or not code
            or len(code) > 64
            or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_.-" for char in code)
        ):
            raise ValueError("invalid federation business error")
        self.code = code
        super().__init__(code)


class ActionRegistry:
    """Explicit two-action registry; never performs reflection or dynamic import."""

    def __init__(self, handlers: Mapping[str, Callable] | None = None):
        self._handlers: dict[str, Callable] = {}
        for action, handler in dict(handlers or {}).items():
            self.register(action, handler)

    def register(self, action: str, handler: Callable) -> None:
        if action not in ACTION_CAPABILITIES or not callable(handler):
            raise ValueError("unsupported federation action handler")
        self._handlers[action] = handler

    def get(self, action: str) -> Callable | None:
        return self._handlers.get(action)


_BLOCKED_SQL = frozenset(
    {"begin", "commit", "end", "rollback", "savepoint", "release", "attach", "detach", "vacuum", "pragma"}
)


def _sql_keyword(statement: str) -> str:
    if type(statement) is not str or not statement or len(statement) > 65536:
        raise ValueError("invalid federation action statement")
    remaining = statement.lstrip()
    while True:
        if remaining.startswith("--"):
            newline = remaining.find("\n")
            remaining = "" if newline < 0 else remaining[newline + 1 :].lstrip()
            continue
        if remaining.startswith("/*"):
            end = remaining.find("*/", 2)
            if end < 0:
                raise ValueError("invalid federation action statement")
            remaining = remaining[end + 2 :].lstrip()
            continue
        break
    keyword = remaining.split(None, 1)[0].rstrip(";").lower() if remaining else ""
    if not keyword or keyword in _BLOCKED_SQL:
        raise ValueError("transaction lifecycle is executor-owned")
    return keyword


class FederationActionCursor:
    """Cursor view that deliberately exposes no connection or lifecycle API."""

    __slots__ = ("_cursor",)

    def __init__(self, cursor: sqlite3.Cursor):
        self._cursor = cursor

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    @property
    def lastrowid(self) -> int | None:
        return self._cursor.lastrowid

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchmany(self, size: int | None = None):
        return self._cursor.fetchmany() if size is None else self._cursor.fetchmany(size)

    def fetchall(self):
        return self._cursor.fetchall()

    def __iter__(self) -> Iterator:
        return iter(self._cursor)


class FederationActionTransaction:
    """Small SQL surface inside an executor-owned SQLite transaction."""

    __slots__ = ("__connection",)

    def __init__(self, connection: sqlite3.Connection):
        self.__connection = connection

    def execute(self, statement: str, parameters=()) -> FederationActionCursor:
        _sql_keyword(statement)
        return FederationActionCursor(self.__connection.execute(statement, parameters))

    def executemany(self, statement: str, parameters) -> FederationActionCursor:
        _sql_keyword(statement)
        return FederationActionCursor(self.__connection.executemany(statement, parameters))


@dataclass(frozen=True)
class VerifiedAction:
    claims: dict
    request: object
    terms: object
    state: str
    prepared: object | None = None


def error_response(code: str, *, retryable: bool = False) -> dict:
    messages = {
        "federation_disabled": "Federation execution is disabled.",
        "unsupported_version": "Unsupported federation protocol version.",
        "invalid_grant": "Federation authorization was rejected.",
        "contract_unknown": "Federation contract is unavailable.",
        "route_unavailable": "Federation route is unavailable.",
        "internal_error": "Federation execution failed.",
    }
    return {
        "protocol_version": "2",
        "signed_result": None,
        "error": {
            "code": code,
            "message": messages.get(code, "Federation request was rejected."),
            "retryable": bool(retryable),
        },
    }


class ServerFederationExecutor:
    """One destination deployment's contract-bound Execute implementation."""

    def __init__(
        self,
        usergroups_path: str | Path,
        *,
        local_deployment_id: str,
        private_key: Ed25519PrivateKey,
        signing_kid: str,
        display_name: str,
        clock=None,
        registry: ActionRegistry | None = None,
    ):
        self.path = Path(usergroups_path)
        self.local_deployment_id = canonical_uuid(local_deployment_id)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise FederationError("invalid_private_key")
        self.private_key = private_key
        self.signing_kid = signing_kid
        raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.signing_fingerprint = hashlib.sha256(raw).hexdigest()
        if (
            type(display_name) is not str
            or not 1 <= len(display_name) <= 256
            or any(ord(char) < 32 or ord(char) == 127 for char in display_name)
        ):
            raise FederationError("invalid_display_name")
        self.display_name = display_name
        self.clock = clock or (lambda: int(time.time()))
        self.registry = registry or ActionRegistry()
        with sqlite3.connect(self.path) as conn:
            migrate_gate_f_usergroups_schema(conn)

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        configure_connection(conn)
        return conn

    @staticmethod
    def _terms(row):
        terms = validate_contract_terms(
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
        if contract_terms_sha256(terms) != row["terms_sha256"]:
            raise FederationError("contract_material_mismatch")
        return terms

    @staticmethod
    def _key_row(conn, deployment_id, kid, fingerprint):
        row = conn.execute(
            "SELECT * FROM TrustedDeploymentKeys WHERE deployment_id=? AND kid=?",
            (deployment_id, kid),
        ).fetchone()
        if row is None:
            raise FederationError("contract_key_mismatch")
        try:
            material = validate_trusted_key_material(
                {
                    "deployment_id": row["deployment_id"],
                    "kid": row["kid"],
                    "public_key_b64": row["public_key_b64"],
                    "public_key_sha256": row["public_key_sha256"],
                    "valid_from": row["valid_from"],
                    "valid_until": row["valid_until"],
                }
            )
            Ed25519PublicKey.from_public_bytes(public_key_bytes(material))
        except (ContractError, ValueError):
            raise FederationError("contract_key_mismatch") from None
        if material["public_key_sha256"] != fingerprint:
            raise FederationError("contract_key_mismatch")
        return row

    @staticmethod
    def _public_key(row):
        try:
            material = validate_trusted_key_material(
                {
                    "deployment_id": row["deployment_id"],
                    "kid": row["kid"],
                    "public_key_b64": row["public_key_b64"],
                    "public_key_sha256": row["public_key_sha256"],
                    "valid_from": row["valid_from"],
                    "valid_until": row["valid_until"],
                }
            )
            return Ed25519PublicKey.from_public_bytes(public_key_bytes(material))
        except (ContractError, ValueError, TypeError):
            raise FederationError("invalid_public_key") from None

    def _prevalidate(self, protocol_version, grant, request_json):
        if protocol_version != "2":
            raise FederationError("unsupported_version")
        try:
            request = parse_canonical_action_request(request_json)
            header, unchecked = parse_unverified_grant(grant)
            issuer = canonical_uuid(unchecked["iss"])
            contract_id = canonical_uuid(unchecked["contract_id"])
            version = unchecked["contract_version"]
            if type(version) is not int or not 0 < version <= MAX_PROTOCOL_INTEGER:
                raise ValueError()
        except (ContractError, ValidationError, KeyError, ValueError, TypeError):
            raise FederationError("invalid_grant") from None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM FederationContracts WHERE contract_id=? AND version=?",
                (contract_id, version),
            ).fetchone()
            if row is None:
                raise FederationError("contract_unknown")
            terms = self._terms(row)
            if issuer == self.local_deployment_id:
                raise FederationError("counterparty_mismatch")
            try:
                expected_kid, fingerprint = terms.key_binding(issuer)
            except ContractError:
                raise FederationError("counterparty_mismatch") from None
            if header["kid"] != expected_kid:
                raise FederationError("contract_key_mismatch")
            key_row = self._key_row(conn, issuer, expected_kid, fingerprint)
            public_key = self._public_key(key_row)
        try:
            verified_raw = jwt.decode(
                grant,
                public_key,
                algorithms=["EdDSA"],
                options={
                    "verify_aud": False,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.PyJWTError:
            raise FederationError("invalid_grant") from None
        now = int(self.clock())
        claims = validate_grant_claims(
            verified_raw,
            now=now,
            request=request,
            expected_issuer=issuer,
            expected_destination=self.local_deployment_id,
            expected_terms=terms,
            expected_terms_sha256=row["terms_sha256"],
        )
        if verified_raw != unchecked:
            raise FederationError("invalid_grant")
        if claims["exp"] > terms.valid_until:
            raise FederationError("invalid_grant_time")
        if key_row["valid_until"] is not None and claims["exp"] > key_row["valid_until"]:
            raise FederationError("invalid_grant_time")
        return request, claims, terms

    def _fresh_authorization(self, conn, claims):
        now = int(self.clock())
        clock_row = conn.execute(
            "SELECT max_seen_at FROM FederationClockState WHERE singleton_id=1"
        ).fetchone()
        if clock_row is None or now < clock_row["max_seen_at"] - 5:
            return now, None, "clock_rollback"
        if now > clock_row["max_seen_at"]:
            conn.execute(
                "UPDATE FederationClockState SET max_seen_at=? WHERE singleton_id=1",
                (now,),
            )
        row = conn.execute(
            "SELECT * FROM FederationContracts WHERE contract_id=? AND version=?",
            (claims["contract_id"], claims["contract_version"]),
        ).fetchone()
        if row is None:
            return now, None, "contract_unknown"
        terms = self._terms(row)
        try:
            validate_grant_claims(claims, now=now)
        except FederationError:
            return now, (row, terms), "grant_expired"
        if row["terms_sha256"] != claims["terms_sha256"]:
            return now, (row, terms), "terms_hash_mismatch"
        try:
            issuer_kid, issuer_fp = terms.key_binding(claims["iss"])
            local_kid, local_fp = terms.key_binding(self.local_deployment_id)
            issuer_key = self._key_row(conn, claims["iss"], issuer_kid, issuer_fp)
            local_key = self._key_row(
                conn, self.local_deployment_id, local_kid, local_fp
            )
        except (ContractError, FederationError):
            return now, (row, terms), "contract_key_mismatch"
        if (
            local_kid != self.signing_kid
            or local_fp != self.signing_fingerprint
            or not key_is_current(dict(issuer_key), now)
            or not key_is_current(dict(local_key), now)
            or claims["exp"] > terms.valid_until
            or (
                issuer_key["valid_until"] is not None
                and claims["exp"] > issuer_key["valid_until"]
            )
        ):
            return now, (row, terms), "contract_inactive"
        if not contract_allows(
            terms,
            row["state"],
            claims["capability"],
            now=now,
            superseded=row["superseded_by_version"] is not None,
        ):
            code = (
                "capability_missing"
                if claims["capability"] not in terms.allowed_capabilities
                else "contract_inactive"
            )
            return now, (row, terms), code
        principal = conn.execute(
            "SELECT status FROM FederatedPrincipals "
            "WHERE issuer_deployment_id=? AND remote_subject_id=?",
            (claims["iss"], claims["sub"]),
        ).fetchone()
        if principal is not None and principal["status"] != "active":
            return now, (row, terms), "principal_disabled"
        return now, (row, terms), None

    def _preparation_authorized(self, claims):
        """Read-only current-authority gate before any split-store preparation."""
        now = int(self.clock())
        with self._connect() as conn:
            clock_row = conn.execute(
                "SELECT max_seen_at FROM FederationClockState WHERE singleton_id=1"
            ).fetchone()
            if clock_row is None or now < clock_row["max_seen_at"] - 5:
                return False
            row = conn.execute(
                "SELECT * FROM FederationContracts WHERE contract_id=? AND version=?",
                (claims["contract_id"], claims["contract_version"]),
            ).fetchone()
            if row is None or row["terms_sha256"] != claims["terms_sha256"]:
                return False
            terms = self._terms(row)
            try:
                validate_grant_claims(claims, now=now)
                issuer_kid, issuer_fp = terms.key_binding(claims["iss"])
                local_kid, local_fp = terms.key_binding(self.local_deployment_id)
                issuer_key = self._key_row(conn, claims["iss"], issuer_kid, issuer_fp)
                local_key = self._key_row(
                    conn, self.local_deployment_id, local_kid, local_fp
                )
            except (ContractError, FederationError):
                return False
            if (
                local_kid != self.signing_kid
                or local_fp != self.signing_fingerprint
                or not key_is_current(dict(issuer_key), now)
                or not key_is_current(dict(local_key), now)
                or claims["exp"] > terms.valid_until
                or (
                    issuer_key["valid_until"] is not None
                    and claims["exp"] > issuer_key["valid_until"]
                )
                or not contract_allows(
                    terms,
                    row["state"],
                    claims["capability"],
                    now=now,
                    superseded=row["superseded_by_version"] is not None,
                )
            ):
                return False
            principal = conn.execute(
                "SELECT status FROM FederatedPrincipals "
                "WHERE issuer_deployment_id=? AND remote_subject_id=?",
                (claims["iss"], claims["sub"]),
            ).fetchone()
            return principal is None or principal["status"] == "active"

    @staticmethod
    def _consume(conn, claims, now):
        conn.execute(
            "DELETE FROM FederationGrantJTIs WHERE retain_until < ?",
            (now,),
        )
        conn.execute(
            "INSERT INTO FederationGrantJTIs "
            "(issuer_deployment_id,jti,remote_subject_id,destination_deployment_id,"
            "contract_id,contract_version,terms_sha256,action,request_id,"
            "request_sha256,expires_at,retain_until,consumed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                claims["iss"],
                claims["jti"],
                claims["sub"],
                claims["aud"],
                claims["contract_id"],
                claims["contract_version"],
                claims["terms_sha256"],
                claims["action"],
                claims["request_id"],
                claims["request_sha256"],
                claims["exp"],
                claims["exp"] + 5,
                now,
            ),
        )

    def _typed_error(self, claims, state, code, now):
        action = claims["action"]
        common = {
            "status": "error",
            "error_code": code,
            "deployment_id": self.local_deployment_id,
            "display_name": self.display_name,
            "contract_id": claims["contract_id"],
            "contract_version": claims["contract_version"],
            "state": state,
            "retrieved_at": now,
        }
        if is_device_action(action):
            # A device error carries the canonical empty payload for its
            # action so it can never be rendered as an authoritative answer.
            body = {**common, "payload": empty_device_payload(action)}
        else:
            body = {
                **common,
                "groups": [],
                "redemption_id": None,
                "membership_present": None,
            }
        return validate_action_result(body, action=action)

    @staticmethod
    def _audit_rejection(conn, claims, code, now):
        from uuid import uuid4

        conn.execute(
            "INSERT INTO FederationAuditEvents"
            "(id,occurred_at,actor_kind,actor_ref,event_type,principal_id,"
            "contract_id,version,request_id,result_code,metadata_json) "
            "VALUES (?,?,?,?,?,NULL,?,?,?,?,?)",
            (
                str(uuid4()),
                now,
                "deployment",
                claims["iss"],
                "federation_action_rejected",
                claims["contract_id"],
                claims["contract_version"],
                claims["request_id"],
                code,
                "{}",
            ),
        )

    def _encode_result(self, claims, result, *, now, expires):
        result_claims = build_result_claims(
            destination_deployment_id=self.local_deployment_id,
            home_deployment_id=claims["iss"],
            subject_id=claims["sub"],
            contract_id=claims["contract_id"],
            contract_version=claims["contract_version"],
            terms_sha256=claims["terms_sha256"],
            action=claims["action"],
            request_id=claims["request_id"],
            request_sha256=claims["request_sha256"],
            grant_jti=claims["jti"],
            issued_at=now,
            expires_at=expires,
            result=result,
        )
        return jwt.encode(
            result_claims,
            self.private_key,
            algorithm="EdDSA",
            headers={"typ": FEDERATION_RESULT_TYP, "kid": self.signing_kid},
        )

    def _ensure_result_fits_before_commit(self, conn, claims, result, now):
        if not now - 60 <= result["retrieved_at"] <= now:
            raise FederationError("invalid_result_snapshot_time")
        row = conn.execute(
            "SELECT * FROM FederationContracts WHERE contract_id=? AND version=?",
            (claims["contract_id"], claims["contract_version"]),
        ).fetchone()
        if row is None:
            raise FederationError("result_signing_unavailable")
        terms = self._terms(row)
        kid, fingerprint = terms.key_binding(self.local_deployment_id)
        key_row = self._key_row(conn, self.local_deployment_id, kid, fingerprint)
        expires = min(now + 60, key_row["valid_until"] or now + 60)
        token = self._encode_result(claims, result, now=now, expires=expires)
        # 64 bytes covers the maximum possible decimal-width growth of both
        # JWT timestamps between this prediction and the immediate final sign.
        if len(token.encode("utf-8")) > max_result_token_bytes(claims["action"]) - 64:
            raise FederationError("result_too_large")

    def _sign_after_commit(self, claims, result):
        if result["status"] == "error" and result["error_code"] == FINALIZE_PENDING:
            raise FederationError("finalize_incomplete")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            now = int(self.clock())
            row = conn.execute(
                "SELECT * FROM FederationContracts WHERE contract_id=? AND version=?",
                (claims["contract_id"], claims["contract_version"]),
            ).fetchone()
            if row is None:
                raise FederationError("result_signing_unavailable")
            terms = self._terms(row)
            kid, fingerprint = terms.key_binding(self.local_deployment_id)
            key_row = self._key_row(
                conn, self.local_deployment_id, kid, fingerprint
            )
            if (
                kid != self.signing_kid
                or fingerprint != self.signing_fingerprint
                or not key_is_current(dict(key_row), now)
                or not now - 60 <= result["retrieved_at"] <= now
            ):
                raise FederationError("result_signing_unavailable")
            expires = now + 60
            if key_row["valid_until"] is not None:
                expires = min(expires, key_row["valid_until"])
            if expires <= now:
                raise FederationError("result_signing_unavailable")
            hook = getattr(self, "_signing_lock_hook", None)
            if hook is not None:
                hook()
            token = self._encode_result(claims, result, now=now, expires=expires)
            if len(token.encode("utf-8")) > max_result_token_bytes(claims["action"]):
                raise FederationError("result_too_large")
        return {"protocol_version": "2", "signed_result": token, "error": None}

    def _finalize_after_commit(self, handler, verified, claims, state, result):
        """Run a handler's post-commit observation and re-shape the result.

        Only a ``finalize_pending`` marker is finalized: any other result was
        decided inside the owner transaction and is already final.  Whatever
        finalize returns is validated with the action's own grammar and
        re-stamped with the current clock, because the observation happened
        now, not at authorization time.  A finalize failure becomes a
        destination-signed error; the grant JTI is already consumed either
        way, so the outcome is never ambiguous.
        """

        finalize = getattr(handler, "finalize", None)
        pending = (
            result["status"] == "error" and result["error_code"] == FINALIZE_PENDING
        )
        if not pending:
            return result
        if not callable(finalize):
            return self._typed_error(
                claims, state, "finalize_failed", int(self.clock())
            )
        try:
            candidate = finalize(verified, result)
            candidate = validate_action_result(
                {**candidate, "retrieved_at": int(self.clock())},
                action=claims["action"],
            )
            if candidate["error_code"] == FINALIZE_PENDING:
                raise FederationError("finalize_incomplete")
        except FederationBusinessError as exc:
            return self._typed_error(claims, state, exc.code, int(self.clock()))
        except Exception:
            return self._typed_error(
                claims, state, "finalize_failed", int(self.clock())
            )
        # Predict the signed size before committing to this payload so an
        # oversized hardware response degrades to a stable signed error
        # instead of an unsigned transport failure.
        probe_now = int(self.clock())
        probe = self._encode_result(
            claims, candidate, now=probe_now, expires=probe_now + 60
        )
        if len(probe.encode("utf-8")) > max_result_token_bytes(claims["action"]) - 64:
            return self._typed_error(claims, state, "result_too_large", probe_now)
        return candidate

    def execute(self, protocol_version: str, grant: str, request_json: str) -> dict:
        """Return exactly one of signed_result/error; raw tokens are never logged."""

        try:
            request, claims, terms = self._prevalidate(
                protocol_version, grant, request_json
            )
        except FederationError as exc:
            safe = exc.code if exc.code in {"unsupported_version", "contract_unknown"} else "invalid_grant"
            return error_response(safe)
        except (ContractError, ValidationError, sqlite3.Error):
            return error_response("internal_error", retryable=False)

        handler = self.registry.get(claims["action"])
        prepared = None
        if (
            handler is not None
            and callable(getattr(handler, "prepare", None))
            and self._preparation_authorized(claims)
        ):
            try:
                prepared = handler.prepare(
                    VerifiedAction(claims, request, terms, "active")
                )
            except Exception:
                return error_response("internal_error", retryable=False)

        result = None
        state = "active"
        verified = None
        try:
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                now, current, rejection = self._fresh_authorization(conn, claims)
                state = current[0]["state"] if current is not None else "suspended"
                if rejection in {"grant_expired", "clock_rollback"}:
                    result = self._typed_error(claims, state, rejection, now)
                else:
                    try:
                        self._consume(conn, claims, now)
                    except sqlite3.IntegrityError:
                        conn.rollback()
                        result = self._typed_error(claims, state, "replayed", now)
                    else:
                        if rejection is not None:
                            self._audit_rejection(conn, claims, rejection, now)
                            result = self._typed_error(claims, state, rejection, now)
                        else:
                            if handler is None:
                                self._audit_rejection(
                                    conn, claims, "action_unavailable", now
                                )
                                result = self._typed_error(
                                    claims, state, "action_unavailable", now
                                )
                            else:
                                conn.execute("SAVEPOINT federation_action")
                                try:
                                    verified = VerifiedAction(
                                        claims=claims,
                                        request=request,
                                        terms=current[1],
                                        state=state,
                                        prepared=prepared,
                                    )
                                    candidate = handler(
                                        FederationActionTransaction(conn), verified
                                    )
                                    result = validate_action_result(
                                        candidate, action=claims["action"]
                                    )
                                    pending = (
                                        result["status"] == "error"
                                        and result["error_code"] == FINALIZE_PENDING
                                        and callable(getattr(handler, "finalize", None))
                                    )
                                    if result["status"] != "ok" and not pending:
                                        raise FederationError(
                                            "handler_must_raise_business_error"
                                        )
                                    try:
                                        self._ensure_result_fits_before_commit(
                                            conn, claims, result, now
                                        )
                                    except FederationError as exc:
                                        if exc.code != "result_too_large":
                                            raise
                                        conn.execute("ROLLBACK TO federation_action")
                                        conn.execute("RELEASE federation_action")
                                        result = self._typed_error(
                                            claims, state, "result_too_large", now
                                        )
                                        self._ensure_result_fits_before_commit(
                                            conn, claims, result, now
                                        )
                                    else:
                                        conn.execute("RELEASE federation_action")
                                except FederationBusinessError as exc:
                                    conn.execute("ROLLBACK TO federation_action")
                                    conn.execute("RELEASE federation_action")
                                    self._audit_rejection(
                                        conn, claims, exc.code, now
                                    )
                                    result = self._typed_error(
                                        claims, state, exc.code, now
                                    )
                                    self._ensure_result_fits_before_commit(
                                        conn, claims, result, now
                                    )
                if conn.in_transaction and result is not None:
                    self._ensure_result_fits_before_commit(
                        conn, claims, result, now
                    )
        except Exception:
            return error_response("internal_error", retryable=False)
        if verified is not None and handler is not None:
            result = self._finalize_after_commit(
                handler, verified, claims, state, result
            )
        try:
            return self._sign_after_commit(claims, result)
        except Exception:
            # The owner/JTI transaction is already committed. Never claim rollback.
            return error_response("internal_error", retryable=False)


def register_grpc_federation(server, executor: ServerFederationExecutor | None = None):
    """Mount Execute on the caller's existing TLS listener."""

    from ...common.grpc import federation_pb2 as pb
    from ...common.grpc import federation_pb2_grpc as rpc
    from ...common.grpc import grpc_pb2

    class Servicer(rpc.FederationV2Servicer):
        def Execute(self, request, context):
            from ..global_onboarding import RELAYED

            # A federation peer is never on the LAN, whatever route it used.
            token = RELAYED.set(True)
            try:
                response = (
                    executor.execute(
                        request.protocol_version, request.grant, request.request_json
                    )
                    if executor is not None
                    else error_response("federation_disabled")
                )
            finally:
                RELAYED.reset(token)
            if response["signed_result"] is not None:
                return pb.FederationResponse(
                    protocol_version="2", signed_result=response["signed_result"]
                )
            error = response["error"]
            return pb.FederationResponse(
                protocol_version="2",
                error=grpc_pb2.ErrorEnvelope(
                    code=error["code"],
                    message=error["message"],
                    retryable=error["retryable"],
                ),
            )

    rpc.add_FederationV2Servicer_to_server(Servicer(), server)
