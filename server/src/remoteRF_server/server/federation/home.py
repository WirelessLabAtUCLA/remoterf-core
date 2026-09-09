"""Server home-side Gate E grant issuance, forwarding, and result verification."""

from __future__ import annotations

import hashlib
import inspect
import logging
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from uuid import uuid4

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from remoterf_federation_core import (
    BROKER_REQUEST_TYP,
    DEFAULT_ACTION_RETRY_POLICIES,
    FEDERATION_GRANT_TYP,
    MAX_PROTOCOL_INTEGER,
    PERMISSIONS_CONNECT_TIMEOUT_SECONDS,
    ActionRetryPolicy,
    ContractError,
    FederationError,
    OwnerSignedFailure,
    TransportFailure,
    ValidationError,
    build_action_request,
    build_broker_request_claims,
    build_grant_claims,
    canonical_json,
    canonical_uuid,
    contract_terms_sha256,
    contract_allows,
    key_is_current,
    parse_unverified_result,
    public_key_bytes,
    strict_json,
    validate_contract_terms,
    validate_result_claims,
    validate_transport_response,
    validate_trusted_key_material,
)

from .migrations import configure_connection, migrate_gate_e_usergroups_schema

FORWARD_PATH = "/v2/broker/federation/forward"
MAX_FORWARD_RESPONSE_BYTES = 32768
logger = logging.getLogger("remoteRF_server.federation.home")


@dataclass(frozen=True)
class IssuedGrant:
    grant: str
    claims: dict
    request: object


class ServerHomeGrantIssuer:
    """Issue only for an active native Server account and exact local contract."""

    def __init__(
        self,
        *,
        reservations_path: str | Path,
        usergroups_path: str | Path,
        local_deployment_id: str,
        private_key: Ed25519PrivateKey,
        signing_kid: str,
        clock=None,
    ):
        self.reservations_path = Path(reservations_path)
        self.usergroups_path = Path(usergroups_path)
        self.local_deployment_id = canonical_uuid(local_deployment_id)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise FederationError("invalid_private_key")
        self.private_key = private_key
        self.signing_kid = signing_kid
        raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.signing_fingerprint = hashlib.sha256(raw).hexdigest()
        self.clock = clock or (lambda: int(time.time()))
        with sqlite3.connect(self.usergroups_path) as conn:
            migrate_gate_e_usergroups_schema(conn)

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
    def _key(conn, deployment_id, kid, fingerprint, now):
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
        if material["public_key_sha256"] != fingerprint or not key_is_current(
            dict(row), now
        ):
            raise FederationError("contract_key_mismatch")
        return row

    def _native_subject(self, local_account_id: int, *, conn=None) -> str:
        if type(local_account_id) is not int or local_account_id <= 0:
            raise FederationError("native_account_required")
        owned = conn is None
        if owned:
            conn = sqlite3.connect(self.reservations_path)
            conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT a.auth_type,s.subject_id,s.status,b.local_account_id AS binding_id "
                "FROM Accounts a "
                "JOIN LocalAccountSubjects s ON s.local_account_id=a.acc_id "
                "LEFT JOIN FederatedAccountBindings b ON b.local_account_id=a.acc_id "
                "WHERE a.acc_id=?",
                (local_account_id,),
            ).fetchone()
        finally:
            if owned:
                conn.close()
        if (
            row is None
            or row["auth_type"] != "local_password"
            or row["status"] != "active"
            or row["binding_id"] is not None
        ):
            raise FederationError("native_account_required")
        return canonical_uuid(row["subject_id"])

    def issue(
        self,
        *,
        local_account_id: int,
        destination_deployment_id: str,
        contract_id: str,
        contract_version: int,
        action: str,
        request_id: str | None = None,
        code_name: str | None = None,
    ) -> IssuedGrant:
        destination = canonical_uuid(destination_deployment_id)
        request_id = canonical_uuid(request_id or str(uuid4()))
        if type(contract_version) is not int or not 0 < contract_version <= MAX_PROTOCOL_INTEGER:
            raise FederationError("invalid_contract_version")
        try:
            conn = sqlite3.connect(self.usergroups_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            configure_connection(conn)
            conn.execute("BEGIN IMMEDIATE")
        except Exception:
            raise
        try:
            subject_conn = sqlite3.connect(
                self.reservations_path, timeout=10.0, check_same_thread=False
            )
        except Exception:
            conn.rollback()
            conn.close()
            raise
        subject_conn.row_factory = sqlite3.Row
        try:
            configure_connection(subject_conn)
            subject_conn.execute("BEGIN IMMEDIATE")
            subject = self._native_subject(local_account_id, conn=subject_conn)
        except Exception:
            conn.rollback()
            conn.close()
            subject_conn.close()
            raise
        now = int(self.clock())
        try:
            row = conn.execute(
                "SELECT * FROM FederationContracts WHERE contract_id=? AND version=?",
                (canonical_uuid(contract_id), contract_version),
            ).fetchone()
            if row is None:
                raise FederationError("contract_unknown")
            terms = self._terms(row)
            if self.local_deployment_id not in {terms.deployment_a, terms.deployment_b}:
                raise FederationError("contract_inactive")
            peer = (
                terms.deployment_b
                if self.local_deployment_id == terms.deployment_a
                else terms.deployment_a
            )
            if peer != destination:
                raise FederationError("counterparty_mismatch")
            capability = {
                "federated_enroll": "FEDERATED_ENROLL",
                "permissions_read": "PERMISSIONS_READ",
            }.get(action)
            if capability is None:
                raise FederationError("unknown_action")
            if not contract_allows(
                terms,
                row["state"],
                capability,
                now=now,
                superseded=row["superseded_by_version"] is not None,
            ):
                raise FederationError("contract_inactive")
            home_kid, home_fp = terms.key_binding(self.local_deployment_id)
            peer_kid, peer_fp = terms.key_binding(destination)
            home_key = self._key(
                conn, self.local_deployment_id, home_kid, home_fp, now
            )
            self._key(conn, destination, peer_kid, peer_fp, now)
            if home_kid != self.signing_kid or home_fp != self.signing_fingerprint:
                raise FederationError("local_signing_key_mismatch")
            request = build_action_request(
                action=action,
                request_id=request_id,
                destination_deployment_id=destination,
                contract_id=terms.contract_id,
                contract_version=terms.version,
                terms_sha256=row["terms_sha256"],
                code_name=code_name,
            )
            expires = min(now + 60, terms.valid_until)
            if home_key["valid_until"] is not None:
                expires = min(expires, home_key["valid_until"])
            if expires - now < 5:
                raise FederationError("insufficient_grant_validity")
            # Re-read while the reservations writer lock is still held.  The
            # signed subject and every authorization input are therefore one
            # serialized snapshot, not a pre-sign check separated by a race.
            issuance_hook = getattr(self, "_issuance_lock_hook", None)
            if issuance_hook is not None:
                issuance_hook()
            subject = self._native_subject(local_account_id, conn=subject_conn)
            claims = build_grant_claims(
                issuer_deployment_id=self.local_deployment_id,
                subject_id=subject,
                destination_deployment_id=destination,
                contract_id=terms.contract_id,
                contract_version=terms.version,
                terms_sha256=row["terms_sha256"],
                action=action,
                request_id=request_id,
                request_sha256=request.sha256,
                issued_at=now,
                expires_at=expires,
                jti=str(uuid4()),
            )
            token = jwt.encode(
                claims,
                self.private_key,
                algorithm="EdDSA",
                headers={"typ": FEDERATION_GRANT_TYP, "kid": self.signing_kid},
            )
            return IssuedGrant(token, claims, request)
        finally:
            conn.rollback()
            conn.close()
            subject_conn.rollback()
            subject_conn.close()

    def verify_result(self, token: str, issued: IssuedGrant) -> dict:
        header, unchecked = parse_unverified_result(token)
        destination = issued.claims["aud"]
        now = int(self.clock())
        with sqlite3.connect(self.usergroups_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM FederationContracts WHERE contract_id=? AND version=?",
                (issued.claims["contract_id"], issued.claims["contract_version"]),
            ).fetchone()
            if row is None or row["terms_sha256"] != issued.claims["terms_sha256"]:
                raise FederationError("result_contract_mismatch")
            terms = self._terms(row)
            kid, fingerprint = terms.key_binding(destination)
            if header["kid"] != kid:
                raise FederationError("result_key_mismatch")
            key_row = self._key(conn, destination, kid, fingerprint, now)
            try:
                material = validate_trusted_key_material(
                    {
                        "deployment_id": key_row["deployment_id"],
                        "kid": key_row["kid"],
                        "public_key_b64": key_row["public_key_b64"],
                        "public_key_sha256": key_row["public_key_sha256"],
                        "valid_from": key_row["valid_from"],
                        "valid_until": key_row["valid_until"],
                    }
                )
                key = Ed25519PublicKey.from_public_bytes(public_key_bytes(material))
            except (ContractError, ValueError, TypeError):
                raise FederationError("result_key_mismatch") from None
        try:
            verified = jwt.decode(
                token,
                key,
                algorithms=["EdDSA"],
                options={
                    "verify_aud": False,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.PyJWTError:
            raise FederationError("invalid_result_signature") from None
        if verified != unchecked:
            raise FederationError("invalid_result")
        claims = validate_result_claims(
            verified,
            now=now,
            expected_destination=destination,
            expected_home=self.local_deployment_id,
            expected_subject=issued.claims["sub"],
            expected_contract_id=issued.claims["contract_id"],
            expected_contract_version=issued.claims["contract_version"],
            expected_terms_sha256=issued.claims["terms_sha256"],
            expected_action=issued.claims["action"],
            expected_request_id=issued.claims["request_id"],
            expected_request_sha256=issued.claims["request_sha256"],
            expected_grant_jti=issued.claims["jti"],
        )
        return claims["result"]


class HomeFederationOutbound:
    """Fresh grant and broker credentials per attempt, with one bounded retry."""

    def __init__(
        self,
        issuer: ServerHomeGrantIssuer,
        *,
        broker_base_url: str,
        broker_deployment_id: str,
        broker_private_key: Ed25519PrivateKey,
        broker_kid: str,
        timeout: float = 5.0,
        sender=None,
        retry_policies: Mapping[str, ActionRetryPolicy] | None = None,
    ):
        self.issuer = issuer
        self.broker_base_url = broker_base_url.rstrip("/")
        if not self.broker_base_url.startswith("https://"):
            raise FederationError("invalid_broker_url")
        self.broker_deployment_id = canonical_uuid(broker_deployment_id)
        self.broker_private_key = broker_private_key
        self.broker_kid = broker_kid
        self.timeout = float(timeout)
        if self.timeout <= 0:
            raise FederationError("invalid_transport_timeout")
        self.connect_timeout = min(self.timeout, PERMISSIONS_CONNECT_TIMEOUT_SECONDS)
        self.read_timeout = self.timeout
        self.overall_timeout = self.timeout * 2
        self.sender = sender
        self._sender_accepts_deadline = bool(
            sender is not None
            and len(inspect.signature(sender).parameters) >= 3
        )
        policies = dict(DEFAULT_ACTION_RETRY_POLICIES)
        for action, policy in dict(retry_policies or {}).items():
            if action not in policies or type(policy) is not ActionRetryPolicy:
                raise FederationError("invalid_retry_policy")
            policies[action] = policy
        self.retry_policies = policies

    def _send(self, body: bytes, authorization: str, deadline: float) -> dict:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        with requests.post(
            self.broker_base_url + FORWARD_PATH,
            data=body,
            headers={
                "Authorization": "Bearer " + authorization,
                "Content-Type": "application/json",
                "Accept-Encoding": "identity",
            },
            timeout=(
                min(self.connect_timeout, remaining),
                min(self.read_timeout, remaining),
            ),
            allow_redirects=False,
            stream=True,
        ) as response:
            response.raise_for_status()
            declared = response.headers.get("Content-Length")
            if declared is not None:
                try:
                    length = int(declared)
                except ValueError:
                    raise TransportFailure(
                        "invalid_transport_response", retryable=False
                    ) from None
                if length < 0:
                    raise TransportFailure(
                        "invalid_transport_response", retryable=False
                    )
                if length > MAX_FORWARD_RESPONSE_BYTES:
                    raise TransportFailure("response_too_large", retryable=False)
            raw = bytearray()
            # A one-byte iterator is deliberate: requests/urllib3 otherwise
            # waits to fill a large requested chunk while a peer can drip data
            # forever just inside the inactivity timeout.  The body is only
            # 32 KiB, so checking the absolute monotonic deadline per received
            # byte is bounded and closes the response immediately on expiry.
            for chunk in response.iter_content(chunk_size=1):
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                if len(raw) + len(chunk) > MAX_FORWARD_RESPONSE_BYTES:
                    raise TransportFailure("response_too_large", retryable=False)
                raw.extend(chunk)
        try:
            return strict_json(bytes(raw), max_bytes=MAX_FORWARD_RESPONSE_BYTES)
        except (FederationError, ValidationError):
            raise TransportFailure(
                "invalid_transport_response", retryable=False
            ) from None

    def _broker_token(self, body: bytes) -> str:
        now = int(self.issuer.clock())
        claims = build_broker_request_claims(
            deployment_id=self.issuer.local_deployment_id,
            broker_deployment_id=self.broker_deployment_id,
            method="POST",
            path=FORWARD_PATH,
            body_sha256=hashlib.sha256(body).hexdigest(),
            issued_at=now,
            expires_at=now + 60,
            jti=str(uuid4()),
        )
        return jwt.encode(
            claims,
            self.broker_private_key,
            algorithm="EdDSA",
            headers={"typ": BROKER_REQUEST_TYP, "kid": self.broker_kid},
        )

    def execute(
        self,
        *,
        local_account_id: int,
        destination_deployment_id: str,
        contract_id: str,
        contract_version: int,
        action: str,
        request_id: str | None = None,
        code_name: str | None = None,
        retry_ambiguous: bool = True,
        deadline: float | None = None,
    ) -> dict:
        logical_request_id = canonical_uuid(request_id or str(uuid4()))
        if type(retry_ambiguous) is not bool:
            raise FederationError("invalid_retry_policy")
        try:
            policy = self.retry_policies[action]
        except KeyError:
            raise FederationError("unknown_action") from None
        may_retry = retry_ambiguous and policy is not ActionRetryPolicy.NO_RETRY
        attempts = 2 if may_retry else 1
        own_deadline = time.monotonic() + self.overall_timeout
        deadline = own_deadline if deadline is None else min(float(deadline), own_deadline)
        for attempt in range(attempts):
            if time.monotonic() >= deadline:
                raise TransportFailure("route_unavailable", retryable=False)
            issued = self.issuer.issue(
                local_account_id=local_account_id,
                destination_deployment_id=destination_deployment_id,
                contract_id=contract_id,
                contract_version=contract_version,
                action=action,
                request_id=logical_request_id,
                code_name=code_name,
            )
            body = canonical_json(
                {
                    "protocol_version": "2",
                    "grant": issued.grant,
                    "request_json": issued.request.json,
                }
            ).encode("utf-8")
            outer = self._broker_token(body)
            try:
                received = (
                    self.sender(body, outer, deadline)
                    if self._sender_accepts_deadline
                    else self.sender(body, outer)
                    if self.sender is not None
                    else self._send(body, outer, deadline)
                )
            except (requests.RequestException, TimeoutError, ConnectionError, OSError):
                if attempt + 1 < attempts:
                    continue
                raise TransportFailure("route_unavailable", retryable=False) from None
            try:
                response = validate_transport_response(received)
            except (FederationError, ValidationError):
                raise TransportFailure("invalid_transport_response", retryable=False) from None
            if response["error"] is not None:
                if (
                    response["error"]["retryable"]
                    and attempt + 1 < attempts
                ):
                    continue
                raise TransportFailure(
                    response["error"]["code"],
                    retryable=response["error"]["retryable"],
                )
            try:
                result = self.issuer.verify_result(response["signed_result"], issued)
            except FederationError as exc:
                logger.warning(
                    "federation_result_verification_failed destination=%s action=%s code=%s",
                    issued.claims["aud"],
                    issued.claims["action"],
                    exc.code,
                )
                raise TransportFailure("invalid_signed_result", retryable=False) from None
            if result["status"] == "error":
                raise OwnerSignedFailure(result)
            return result
        raise TransportFailure("route_unavailable", retryable=False)
