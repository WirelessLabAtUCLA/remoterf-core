"""Server owner-local Gate E destination execution.

The broker is deliberately absent.  This adapter verifies only local pins and
the exact local contract, serializes authorization with owner state, consumes
the grant JTI in that transaction, commits, and only then signs the result.
No production action handler is registered by default.
"""

from __future__ import annotations

import base64
import hashlib
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from remoterf_federation_core import (
    ACTION_CAPABILITIES,
    FEDERATION_RESULT_TYP,
    ContractError,
    FederationError,
    build_result_claims,
    canonical_uuid,
    contract_allows,
    key_is_current,
    parse_canonical_action_request,
    parse_unverified_grant,
    strict_json,
    validate_contract_terms,
    validate_grant_claims,
    validate_typed_result,
)

from .migrations import configure_connection, migrate_gate_e_usergroups_schema


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


@dataclass(frozen=True)
class VerifiedAction:
    claims: dict
    request: object
    terms: object
    state: str


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
            migrate_gate_e_usergroups_schema(conn)

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        configure_connection(conn)
        return conn

    @staticmethod
    def _terms(row):
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
    def _key_row(conn, deployment_id, kid, fingerprint):
        row = conn.execute(
            "SELECT * FROM TrustedDeploymentKeys WHERE deployment_id=? AND kid=?",
            (deployment_id, kid),
        ).fetchone()
        if row is None or row["public_key_sha256"] != fingerprint:
            raise FederationError("contract_key_mismatch")
        return row

    @staticmethod
    def _public_key(row):
        try:
            return Ed25519PublicKey.from_public_bytes(
                base64.b64decode(row["public_key_b64"], validate=True)
            )
        except (ValueError, TypeError):
            raise FederationError("invalid_public_key") from None

    def _prevalidate(self, protocol_version, grant, request_json):
        if protocol_version != "2":
            raise FederationError("unsupported_version")
        request = parse_canonical_action_request(request_json)
        header, unchecked = parse_unverified_grant(grant)
        try:
            issuer = canonical_uuid(unchecked["iss"])
            contract_id = canonical_uuid(unchecked["contract_id"])
            version = unchecked["contract_version"]
            if type(version) is not int or version <= 0:
                raise ValueError()
        except (KeyError, ValueError, TypeError):
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
        row = conn.execute(
            "SELECT * FROM FederationContracts WHERE contract_id=? AND version=?",
            (claims["contract_id"], claims["contract_version"]),
        ).fetchone()
        if row is None:
            return now, None, "contract_unknown"
        terms = self._terms(row)
        if now >= claims["exp"]:
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
        return validate_typed_result(
            {
                "status": "error",
                "error_code": code,
                "deployment_id": self.local_deployment_id,
                "display_name": self.display_name,
                "contract_id": claims["contract_id"],
                "contract_version": claims["contract_version"],
                "state": state,
                "groups": [],
                "retrieved_at": now,
                "redemption_id": None,
                "membership_present": None,
            }
        )

    def _sign_after_commit(self, claims, result):
        now = int(self.clock())
        with self._connect() as conn:
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
            ):
                raise FederationError("result_signing_unavailable")
            expires = now + 60
            if key_row["valid_until"] is not None:
                expires = min(expires, key_row["valid_until"])
            if expires <= now:
                raise FederationError("result_signing_unavailable")
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
        token = jwt.encode(
            result_claims,
            self.private_key,
            algorithm="EdDSA",
            headers={"typ": FEDERATION_RESULT_TYP, "kid": self.signing_kid},
        )
        return {"protocol_version": "2", "signed_result": token, "error": None}

    def execute(self, protocol_version: str, grant: str, request_json: str) -> dict:
        """Return exactly one of signed_result/error; raw tokens are never logged."""

        try:
            request, claims, _ = self._prevalidate(
                protocol_version, grant, request_json
            )
        except FederationError as exc:
            safe = exc.code if exc.code in {"unsupported_version", "contract_unknown"} else "invalid_grant"
            return error_response(safe)

        result = None
        state = "active"
        try:
            with self._connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                now, current, rejection = self._fresh_authorization(conn, claims)
                state = current[0]["state"] if current is not None else "suspended"
                if rejection == "grant_expired":
                    result = self._typed_error(claims, state, rejection, now)
                else:
                    try:
                        self._consume(conn, claims, now)
                    except sqlite3.IntegrityError:
                        conn.rollback()
                        result = self._typed_error(claims, state, "replayed", now)
                    else:
                        if rejection is not None:
                            result = self._typed_error(claims, state, rejection, now)
                        else:
                            handler = self.registry.get(claims["action"])
                            if handler is None:
                                result = self._typed_error(
                                    claims, state, "action_unavailable", now
                                )
                            else:
                                conn.execute("SAVEPOINT federation_action")
                                try:
                                    candidate = handler(
                                        conn,
                                        VerifiedAction(
                                            claims=claims,
                                            request=request,
                                            terms=current[1],
                                            state=state,
                                        ),
                                    )
                                    result = validate_typed_result(candidate)
                                    conn.execute("RELEASE federation_action")
                                except FederationBusinessError as exc:
                                    conn.execute("ROLLBACK TO federation_action")
                                    conn.execute("RELEASE federation_action")
                                    result = self._typed_error(
                                        claims, state, exc.code, now
                                    )
        except Exception:
            return error_response("internal_error", retryable=False)
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
            response = (
                executor.execute(
                    request.protocol_version, request.grant, request.request_json
                )
                if executor is not None
                else error_response("federation_disabled")
            )
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
