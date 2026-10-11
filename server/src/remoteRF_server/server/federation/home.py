"""Server home-side Gate E grant issuance, forwarding, and result verification."""

from __future__ import annotations

import hashlib
import inspect
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from uuid import uuid4

import grpc
import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from remoterf_federation_core import (
    ACTION_CAPABILITIES,
    BROKER_REQUEST_TYP,
    DEFAULT_ACTION_RETRY_POLICIES,
    FEDERATION_GRANT_TYP,
    FRAMED_CONTENT_TYPE,
    MAX_DEVICE_ACTION_REQUEST_BYTES,
    MAX_DEVICE_FORWARD_REQUEST_BYTES,
    MAX_DEVICE_FORWARD_RESPONSE_BYTES,
    MAX_DEVICE_RPC_REQUEST_FRAME_BYTES,
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
    device_action_timeout,
    device_response_frame,
    encode_device_b64,
    frame_digest,
    is_device_action,
    key_is_current,
    pack_framed,
    parse_unverified_result,
    public_key_bytes,
    strict_json,
    unpack_framed,
    validate_contract_terms,
    validate_result_claims,
    validate_transport_response,
    validate_trusted_key_material,
    verify_eddsa_jwt,
)

from .migrations import configure_connection, migrate_gate_e_usergroups_schema
from .peers import PeerStore

FORWARD_PATH = "/v2/broker/federation/forward"
MAX_FORWARD_RESPONSE_BYTES = 32768
MAX_PEER_CHANNELS = 64  # open gRPC channels kept to direct peers
logger = logging.getLogger("remoteRF_server.federation.home")


def max_forward_response_bytes(action: str) -> int:
    """Decoded HTTP body ceiling for one forwarded action's response."""

    return (
        MAX_DEVICE_FORWARD_RESPONSE_BYTES
        if is_device_action(action)
        else MAX_FORWARD_RESPONSE_BYTES
    )


class _FramedBodyRefused(Exception):
    """A framed forward body answered 400: the broker cannot read framing."""


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
        device_payload: Mapping | None = None,
        enrollee: Mapping | None = None,
        jti: str | None = None,
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
            capability = ACTION_CAPABILITIES.get(action)
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
                device_payload=device_payload,
                enrollee=enrollee,
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
                jti=jti or str(uuid4()),
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
        verified = verify_eddsa_jwt(token, key, code="invalid_result_signature")
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
    """Fresh grant per attempt, with one bounded retry.

    A destination with a FederationPeers row is dialed directly: its own
    FederationV2 listener, TLS pinned to the CA in the row. Any other
    destination goes through the broker's forward path, as before. Grant,
    envelope and result verification are the same either way.

    A device_rpc frame travels beside the signed JSON (detached) once the
    hop has proven it can carry it: a framed broker reply, or a direct peer,
    plus a detached result from that destination. Until then, and after a
    refusal that provably ran nothing, it is base64 inside the request.
    """

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
        self.peers = PeerStore(issuer.usergroups_path)
        self._channels: dict = {}  # peer -> ((endpoint, TLS name, CA), open channel), oldest use first
        self._channels_lock = threading.Lock()
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
        self._broker_framed = False
        self._detached_destinations: set[str] = set()

    def _send(
        self,
        body: bytes,
        authorization: str,
        deadline: float,
        max_response_bytes: int = MAX_FORWARD_RESPONSE_BYTES,
        *,
        accept_framed: bool = False,
        framed_body: bool = False,
    ) -> dict:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        headers = {
            "Authorization": "Bearer " + authorization,
            "Content-Type": FRAMED_CONTENT_TYPE if framed_body else "application/json",
            "Accept-Encoding": "identity",
        }
        if accept_framed:
            headers["Accept"] = f"{FRAMED_CONTENT_TYPE}, application/json"
        with requests.post(
            self.broker_base_url + FORWARD_PATH,
            data=body,
            headers=headers,
            timeout=(
                min(self.connect_timeout, remaining),
                # Device bodies carry a hardware call whose budget is the
                # caller's deadline, not the control-plane inactivity timeout.
                remaining
                if max_response_bytes > MAX_FORWARD_RESPONSE_BYTES
                else min(self.read_timeout, remaining),
            ),
            allow_redirects=False,
            stream=True,
        ) as response:
            if framed_body and response.status_code == 400:
                raise _FramedBodyRefused()
            response.raise_for_status()
            framed_reply = accept_framed and (
                response.headers.get("Content-Type", "").split(";")[0].strip().lower()
                == FRAMED_CONTENT_TYPE
            )
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
                if length > max_response_bytes:
                    raise TransportFailure("response_too_large", retryable=False)
            raw = bytearray()
            # A small chunk iterator is deliberate: requests/urllib3 otherwise
            # waits to fill a large requested chunk while a peer can drip data
            # forever just inside the inactivity timeout.  Control-plane bodies
            # are 32 KiB and device bodies under 2 MiB, so checking the
            # absolute monotonic deadline per chunk stays bounded and closes
            # the response immediately on expiry.
            chunk_size = 1 if max_response_bytes <= MAX_FORWARD_RESPONSE_BYTES else 4096
            for chunk in response.iter_content(chunk_size=chunk_size):
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                if len(raw) + len(chunk) > max_response_bytes:
                    raise TransportFailure("response_too_large", retryable=False)
                raw.extend(chunk)
        if framed_reply:
            try:
                envelope, frame = unpack_framed(bytes(raw), max_bytes=max_response_bytes)
            except ValidationError:
                raise TransportFailure(
                    "invalid_transport_response", retryable=False
                ) from None
            self._broker_framed = True
            return {**envelope, "frame": frame} if frame else envelope
        try:
            return strict_json(bytes(raw), max_bytes=max_response_bytes)
        except (FederationError, ValidationError):
            raise TransportFailure(
                "invalid_transport_response", retryable=False
            ) from None

    def peer(self, deployment_id: str) -> dict | None:
        """The FederationPeers row for a destination, or None (broker path)."""
        return self.peers.get(deployment_id)

    def _dial(
        self, route: dict, grant: str, request_json: str, deadline: float, frame: bytes = b""
    ) -> dict:
        """FederationV2.Execute on the peer's own listener, pinned to its CA."""
        from ...common.grpc import federation_pb2 as pb
        from ...common.grpc import federation_pb2_grpc as rpc

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        # One channel per peer, reused so a call skips the TCP+TLS setup; the
        # grant is still per call. A dropped channel is never closed here:
        # it closes once calls still in flight on it let go of it.
        key = route.get("deployment_id") or route["endpoint"]
        pin = (route["endpoint"], route["tls_server_name"], route["ca_pem"])
        with self._channels_lock:
            cached = self._channels.pop(key, None)
            if cached is None or cached[0] != pin:  # new peer, moved route or rotated CA
                credentials = grpc.ssl_channel_credentials(
                    root_certificates=route["ca_pem"].encode("utf-8")
                )
                options = (
                    ("grpc.ssl_target_name_override", route["tls_server_name"]),
                    ("grpc.default_authority", route["tls_server_name"]),
                    ("grpc.max_send_message_length", MAX_DEVICE_FORWARD_REQUEST_BYTES),
                    ("grpc.max_receive_message_length", MAX_DEVICE_FORWARD_RESPONSE_BYTES),
                    # Reuse within a burst only: a connection a relay or NAT
                    # dropped silently while idle would hang a call to its deadline.
                    ("grpc.client_idle_timeout_ms", 60_000),
                )
                cached =(pin, grpc.secure_channel(route["endpoint"], credentials, options=options))
            self._channels[key] = cached
            while len(self._channels) > MAX_PEER_CHANNELS:
                self._channels.pop(next(iter(self._channels)))
        try:
            response = rpc.FederationV2Stub(cached[1]).Execute(
                pb.FederationRequest(
                    protocol_version="2",
                    grant=grant,
                    request_json=request_json,
                    frame=frame,
                    accept_detached=True,
                ),
                timeout=remaining,
            )
        except grpc.RpcError:
            with self._channels_lock:
                if self._channels.get(key) is cached:
                    del self._channels[key]
            raise
        return {
            **({"frame": response.frame} if response.frame else {}),
            "protocol_version": response.protocol_version,
            "signed_result": response.signed_result or None,
            "error": (
                {
                    "code": response.error.code,
                    "message": response.error.message,
                    "retryable": response.error.retryable,
                }
                if response.HasField("error")
                else None
            ),
        }

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
        device_payload: Mapping | None = None,
        retry_ambiguous: bool = True,
        deadline: float | None = None,
        request_frame: bytes | None = None,
    ) -> dict:
        """Verified result; an ok device_rpc result also carries ``frame``, its
        raw response. With ``request_frame`` the caller leaves ``request_b64``
        out of ``device_payload`` and the wire form is chosen here."""
        logical_request_id = canonical_uuid(request_id or str(uuid4()))
        if type(retry_ambiguous) is not bool:
            raise FederationError("invalid_retry_policy")
        try:
            policy = self.retry_policies[action]
        except KeyError:
            raise FederationError("unknown_action") from None
        may_retry = retry_ambiguous and policy is not ActionRetryPolicy.NO_RETRY
        attempts = 2 if may_retry else 1
        # A device action's budget is the destination's hardware budget, not
        # the 5 s control-plane one.
        budget = (
            max(self.overall_timeout, device_action_timeout(action) + 5.0)
            if is_device_action(action)
            else self.overall_timeout
        )
        own_deadline = time.monotonic() + budget
        deadline = own_deadline if deadline is None else min(float(deadline), own_deadline)
        route = None if self.sender is not None else self.peer(destination_deployment_id)
        destination = canonical_uuid(destination_deployment_id)
        logger.info(
            "federation_transport destination=%s action=%s via=%s",
            destination,
            action,
            "in-process" if self.sender is not None else route["via"] if route else "broker",
        )
        attempt = 0
        downgraded = False
        resend_jti = None
        while attempt < attempts:
            if time.monotonic() >= deadline:
                raise TransportFailure("route_unavailable", retryable=False)
            detached = (
                request_frame is not None
                and destination in self._detached_destinations
                and (route is not None or (self.sender is None and self._broker_framed))
            )
            payload = device_payload
            if request_frame is not None:
                payload = {k: v for k, v in dict(device_payload or {}).items() if k != "request_b64"}
                payload.update(
                    frame_digest(
                        request_frame,
                        max_bytes=MAX_DEVICE_RPC_REQUEST_FRAME_BYTES,
                        code="request_too_large",
                    )
                    if detached
                    else {
                        "request_b64": encode_device_b64(
                            request_frame,
                            code="request_too_large",
                            max_bytes=MAX_DEVICE_ACTION_REQUEST_BYTES,
                        )
                    }
                )
            issued = self.issuer.issue(
                local_account_id=local_account_id,
                destination_deployment_id=destination_deployment_id,
                contract_id=contract_id,
                contract_version=contract_version,
                action=action,
                request_id=logical_request_id,
                code_name=code_name,
                device_payload=payload,
                # A downgrade resend keeps the JTI: if the refusal was forged
                # after the first form ran, the destination answers "replayed".
                **({"jti": resend_jti} if resend_jti else {}),
            )
            resend_jti = None
            frame = request_frame if detached else b""
            try:
                if route is not None:
                    received = self._dial(
                        route, issued.grant, issued.request.json, deadline, frame
                    )
                else:
                    envelope = {
                        "protocol_version": "2",
                        "grant": issued.grant,
                        "request_json": issued.request.json,
                    }
                    body = (
                        pack_framed(envelope, frame)
                        if detached
                        else canonical_json(envelope).encode("utf-8")
                    )
                    outer = self._broker_token(body)
                    received = (
                        self.sender(body, outer, deadline)
                        if self._sender_accepts_deadline
                        else self.sender(body, outer)
                        if self.sender is not None
                        else self._send(
                            body,
                            outer,
                            deadline,
                            max_forward_response_bytes(action),
                            accept_framed=action == "device_rpc",
                            framed_body=detached,
                        )
                    )
            except _FramedBodyRefused:
                # Refused before broker auth and forwarding: the grant never
                # left, so the legacy form is resent once.
                self._broker_framed = False
                if downgraded:
                    raise TransportFailure("route_unavailable", retryable=False) from None
                downgraded = True
                resend_jti = issued.claims["jti"]
                continue
            except (requests.RequestException, grpc.RpcError, TimeoutError, ConnectionError, OSError):
                attempt += 1
                if attempt < attempts:
                    continue
                raise TransportFailure("route_unavailable", retryable=False) from None
            try:
                response = validate_transport_response(
                    received, expected_action=action
                )
            except (FederationError, ValidationError):
                raise TransportFailure("invalid_transport_response", retryable=False) from None
            if response["error"] is not None:
                if (
                    detached
                    and not downgraded
                    and response["error"]["code"] == "invalid_grant"
                ):
                    # An old destination refuses a detached request before it
                    # consumes the grant; resend the legacy form once.
                    self._detached_destinations.discard(destination)
                    downgraded = True
                    resend_jti = issued.claims["jti"]
                    continue
                if (
                    response["error"]["retryable"]
                    and attempt + 1 < attempts
                ):
                    attempt += 1
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
            if action == "device_rpc" and result["status"] == "ok":
                try:
                    raw = device_response_frame(result["payload"], response.get("frame", b""))
                except ValidationError:
                    raise TransportFailure("invalid_signed_result", retryable=False) from None
                if "frame_sha256" in result["payload"]:
                    self._detached_destinations.add(destination)
                result = {**result, "frame": raw}
            elif response.get("frame"):
                raise TransportFailure("invalid_signed_result", retryable=False)
            if result["status"] == "error":
                raise OwnerSignedFailure(result)
            return result
        raise TransportFailure("route_unavailable", retryable=False)
