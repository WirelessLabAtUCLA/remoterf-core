"""Gate G owner-authoritative permission reads and HOME aggregation."""

from __future__ import annotations

import sqlite3
import threading
import time
import inspect
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from uuid import uuid4

from remoterf_federation_core import (
    FederationError,
    MAX_HOME_PERMISSION_DESTINATIONS,
    OwnerSignedFailure,
    PERMISSIONS_AGGREGATION_TIMEOUT_SECONDS,
    PERMISSIONS_DESTINATION_TIMEOUT_SECONDS,
    TransportFailure,
    canonical_json,
    canonical_uuid,
    contract_allows,
    contract_terms_sha256,
    strict_json,
    validate_contract_terms,
    validate_home_permissions_summary,
)

from .destination import FederationBusinessError
from .enrollment import _legacy_created_epoch
from .migrations import configure_connection, migrate_gate_f_usergroups_schema

MAX_REMOTE_PERMISSION_CONTRACTS = MAX_HOME_PERMISSION_DESTINATIONS
DEFAULT_PERMISSION_CONCURRENCY = 4
DEFAULT_PERMISSION_DESTINATION_TIMEOUT = PERMISSIONS_DESTINATION_TIMEOUT_SECONDS
DEFAULT_PERMISSION_AGGREGATION_TIMEOUT = PERMISSIONS_AGGREGATION_TIMEOUT_SECONDS


def _server_group_current(row, now: int, *, invalid_is_error: bool) -> bool:
    try:
        lifetime = row[2]
        if type(lifetime) is not int or lifetime < 0 or lifetime > (1 << 63) - 1:
            raise ValueError("invalid lifetime")
        if lifetime == 0:
            return True
        created = _legacy_created_epoch(row[3])
        if created < 0 or created > (1 << 63) - 1 - lifetime:
            raise ValueError("invalid created timestamp")
    except (TypeError, ValueError, OverflowError, OSError):
        if invalid_is_error:
            raise FederationBusinessError("group_lifetime_invalid") from None
        return False
    return now < created + lifetime


class ServerPermissionsReadHandler:
    """Read current UsersLookup membership without creating any identity."""

    def __init__(self, *, local_deployment_id, display_name, clock=None):
        self.local_deployment_id = canonical_uuid(local_deployment_id)
        self.display_name = str(display_name)
        self.clock = clock or (lambda: int(time.time()))

    def __call__(self, tx, action):
        claims = action.claims
        now = int(self.clock())
        principal = tx.execute(
            "SELECT id,local_account_id,status FROM FederatedPrincipals "
            "WHERE issuer_deployment_id=? AND remote_subject_id=?",
            (claims["iss"], claims["sub"]),
        ).fetchone()
        groups = []
        principal_id = None
        if principal is not None:
            principal_id = principal[0]
            if principal[2] != "active":
                raise FederationBusinessError("principal_disabled")
            rows = tx.execute(
                "SELECT g.group_id,g.group_name,g.lifetime_sec,g.created_at "
                "FROM UsersLookup m JOIN UserGroups g ON g.group_id=m.group_id "
                "WHERE m.user_id=? ORDER BY lower(g.group_name),g.group_id",
                (int(principal[1]),),
            ).fetchall()
            for row in rows:
                if _server_group_current(row, now, invalid_is_error=True):
                    groups.append(
                        {"group_id": str(row[0]), "group_name": str(row[1])}
                    )
        tx.execute(
            "INSERT INTO FederationAuditEvents"
            "(id,occurred_at,actor_kind,actor_ref,event_type,principal_id,"
            "contract_id,version,request_id,result_code,metadata_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                now,
                "deployment",
                claims["iss"],
                "permissions_read",
                principal_id,
                claims["contract_id"],
                claims["contract_version"],
                claims["request_id"],
                "ok",
                canonical_json({"group_count": len(groups)}),
            ),
        )
        return {
            "status": "ok",
            "error_code": None,
            "deployment_id": self.local_deployment_id,
            "display_name": self.display_name,
            "contract_id": claims["contract_id"],
            "contract_version": claims["contract_version"],
            "state": action.state,
            "groups": groups,
            "retrieved_at": now,
            "redemption_id": None,
            "membership_present": None,
        }


class ServerHomePermissions:
    """Query only HOME-local active PERMISSIONS_READ contracts, boundedly."""

    def __init__(
        self,
        *,
        usergroups_path,
        local_deployment_id,
        display_name,
        outbound,
        clock=None,
        max_concurrency=DEFAULT_PERMISSION_CONCURRENCY,
        per_destination_timeout=DEFAULT_PERMISSION_DESTINATION_TIMEOUT,
        overall_timeout=DEFAULT_PERMISSION_AGGREGATION_TIMEOUT,
    ):
        self.path = Path(usergroups_path)
        self.local_deployment_id = canonical_uuid(local_deployment_id)
        self.display_name = str(display_name)
        self.outbound = outbound
        self.clock = clock or (lambda: int(time.time()))
        self.max_concurrency = int(max_concurrency)
        self.per_destination_timeout = float(per_destination_timeout)
        self.overall_timeout = float(overall_timeout)
        if not 1 <= self.max_concurrency <= 16:
            raise FederationError("invalid_permissions_concurrency")
        if self.per_destination_timeout <= 0 or self.overall_timeout <= 0:
            raise FederationError("invalid_permissions_timeout")
        self._work_slots = threading.BoundedSemaphore(self.max_concurrency)
        self._pool = ThreadPoolExecutor(
            max_workers=self.max_concurrency,
            thread_name_prefix="remoterf-permissions",
        )
        with sqlite3.connect(self.path) as conn:
            migrate_gate_f_usergroups_schema(conn)

    def close(self):
        self._pool.shutdown(wait=False, cancel_futures=True)

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

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        configure_connection(conn)
        return conn

    def _local_groups(self, local_account_id: int, now: int):
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT g.group_id,g.group_name,g.lifetime_sec,g.created_at "
                "FROM UsersLookup m JOIN UserGroups g ON g.group_id=m.group_id "
                "WHERE m.user_id=? ORDER BY lower(g.group_name),g.group_id",
                (int(local_account_id),),
            ).fetchall()
        return [
            {"group_id": str(row[0]), "group_name": str(row[1])}
            for row in rows
            if _server_group_current(row, now, invalid_is_error=False)
        ]

    def _candidates(self, now: int):
        candidates = []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM FederationContracts "
                "WHERE state='active' AND superseded_by_version IS NULL "
                "ORDER BY contract_id,version",
            ).fetchall()
        for row in rows:
            try:
                terms = self._terms(row)
            except Exception:
                continue
            if not contract_allows(
                terms,
                row["state"],
                "PERMISSIONS_READ",
                now=now,
                superseded=False,
            ):
                continue
            if self.local_deployment_id == terms.deployment_a:
                peer = terms.deployment_b
            elif self.local_deployment_id == terms.deployment_b:
                peer = terms.deployment_a
            else:
                continue
            candidates.append(
                {
                    "deployment_id": peer,
                    "contract_id": terms.contract_id,
                    "contract_version": terms.version,
                    "state": row["state"],
                }
            )
        omitted = max(0, len(candidates) - MAX_REMOTE_PERMISSION_CONTRACTS)
        return candidates[:MAX_REMOTE_PERMISSION_CONTRACTS], omitted

    @staticmethod
    def _unavailable(candidate):
        return {
            **candidate,
            "display_name": candidate["deployment_id"],
            "groups": [],
            "retrieved_at": None,
            "status": "unavailable",
            "provenance": "transport",
            "error_code": None,
        }

    @staticmethod
    def _blocked_local(candidate, code):
        return {
            **candidate,
            "display_name": candidate["deployment_id"],
            "groups": [],
            "retrieved_at": None,
            "status": "blocked",
            "provenance": "local",
            "error_code": code,
        }

    def _query(self, local_account_id, candidate, deadline):
        try:
            result = self.outbound.execute(
                local_account_id=local_account_id,
                destination_deployment_id=candidate["deployment_id"],
                contract_id=candidate["contract_id"],
                contract_version=candidate["contract_version"],
                action="permissions_read",
                deadline=deadline,
            )
        except OwnerSignedFailure as exc:
            result = exc.result
            return {
                "deployment_id": result["deployment_id"],
                "display_name": result["display_name"],
                "contract_id": result["contract_id"],
                "contract_version": result["contract_version"],
                "state": result["state"],
                "groups": [],
                "retrieved_at": result["retrieved_at"],
                "status": "blocked",
                "provenance": "destination_signed",
                "error_code": result["error_code"],
            }
        except TransportFailure:
            return self._unavailable(candidate)
        except FederationError as exc:
            return self._blocked_local(candidate, exc.code)
        except Exception:
            return self._unavailable(candidate)
        return {
            "deployment_id": result["deployment_id"],
            "display_name": result["display_name"],
            "contract_id": result["contract_id"],
            "contract_version": result["contract_version"],
            "state": result["state"],
            "groups": result["groups"],
            "retrieved_at": result["retrieved_at"],
            "status": "ok",
            "provenance": "destination_signed",
            "error_code": None,
        }

    def _run_query(self, local_account_id, candidate, deadline):
        try:
            if len(inspect.signature(self._query).parameters) >= 3:
                return self._query(local_account_id, candidate, deadline)
            return self._query(local_account_id, candidate)
        finally:
            self._work_slots.release()

    def summary(self, *, local_account_id: int):
        now = int(self.clock())
        candidate_result = self._candidates(now)
        if (
            type(candidate_result) is tuple
            and len(candidate_result) == 2
            and type(candidate_result[1]) is int
        ):
            candidates, omitted_count = candidate_result
        else:
            candidates, omitted_count = candidate_result, 0
        remote = []
        pending = list(candidates)
        active = {}
        deadline = time.monotonic() + self.overall_timeout
        while pending or active:
            while pending and len(active) < self.max_concurrency:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if not self._work_slots.acquire(timeout=remaining):
                    break
                candidate = pending.pop(0)
                operation_deadline = min(
                    deadline, time.monotonic() + self.per_destination_timeout
                )
                future = self._pool.submit(
                    self._run_query,
                    local_account_id,
                    candidate,
                    operation_deadline,
                )
                active[future] = candidate
            current = time.monotonic()
            if current >= deadline:
                break
            if not active:
                continue
            done, _ = wait(
                active,
                timeout=max(0.0, deadline - current),
                return_when=FIRST_COMPLETED,
            )
            for future, candidate in list(active.items()):
                if future in done:
                    try:
                        remote.append(future.result())
                    except Exception:
                        remote.append(self._unavailable(candidate))
                    del active[future]
        for future, candidate in active.items():
            remote.append(self._unavailable(candidate))
            future.cancel()
        remote.extend(self._unavailable(candidate) for candidate in pending)
        return validate_home_permissions_summary(
            {
                "local": {
                    "deployment_id": self.local_deployment_id,
                    "display_name": self.display_name,
                    "groups": self._local_groups(local_account_id, now),
                },
                "federation": remote,
                "incomplete": omitted_count > 0,
                "omitted_count": omitted_count,
            }
        )


def build_server_gate_g_executor(
    *,
    usergroups_path,
    reservations_path,
    local_deployment_id,
    private_key,
    signing_kid,
    display_name,
    perms_path=None,
    clock=None,
):
    """Final Phase-1 destination registry: enroll plus permissions read."""

    from .destination import ActionRegistry, ServerFederationExecutor
    from .enrollment import ServerFederatedEnrollHandler

    enrollment = ServerFederatedEnrollHandler(
        usergroups_path=usergroups_path,
        reservations_path=reservations_path,
        perms_path=perms_path,
        local_deployment_id=local_deployment_id,
        display_name=display_name,
        clock=clock,
    )
    permissions = ServerPermissionsReadHandler(
        local_deployment_id=local_deployment_id,
        display_name=display_name,
        clock=clock,
    )
    return ServerFederationExecutor(
        usergroups_path,
        local_deployment_id=local_deployment_id,
        private_key=private_key,
        signing_kid=signing_kid,
        display_name=display_name,
        clock=clock,
        registry=ActionRegistry(
            {
                "federated_enroll": enrollment,
                "permissions_read": permissions,
            }
        ),
    )
