"""Gate F destination-owned enrollment codes, receipts, and home dispatch."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from uuid import NAMESPACE_URL, uuid4, uuid5

from remoterf_federation_core import (
    FederationError,
    build_federation_invitation,
    canonical_json,
    canonical_uuid,
    contract_allows,
    contract_terms_sha256,
    key_is_current,
    parse_federation_invitation,
    strict_json,
    validate_contract_terms,
)

from .destination import ActionRegistry, FederationBusinessError, ServerFederationExecutor

CLUSTER_CODE = "cluster"
# A HOME that deleted the account tells each partner to drop its proxy. The
# `cluster.` prefix is reserved and minted codes are uppercase: no collision.
UNENROLL_CODE = "cluster.unenroll"
from .migrations import configure_connection, migrate_gate_f_usergroups_schema
from .principals import PreparedFederatedAccount, prepare_federated_account
from . import links
from remoterf_federation_core import LAN_UPDATE_CODE


class PreparedLinked:
    """A Global account's login here (links.py), made before the owner tx; or
    the reason it could not be (`error`), raised there as a typed refusal."""

    def __init__(self, local_account_id=None, error=None):
        self.local_account_id, self.error = local_account_id, error


def _code_hash(code_name: str) -> str:
    return hashlib.sha256(code_name.encode("utf-8")).hexdigest()


def _plain_code(contract_id, contract_version, issuer) -> bool:
    """A group code with no federation restrictions: the lab's ordinary invite."""
    return contract_id is None and contract_version is None and issuer is None


def _plain_code_expired(created_at, duration_sec, now: int) -> bool:
    """Plain codes age like local ones: `duration_sec` from creation, 0 = never."""
    if not duration_sec:
        return False
    try:
        created = datetime.fromisoformat(str(created_at)).timestamp()
    except ValueError:
        return True
    return now >= int(created) + int(duration_sec)


def _code_admits(code, claims, now: int) -> bool:
    if _plain_code(code["federation_contract_id"], code["federation_contract_version"],
                   code["allowed_issuer_deployment_id"]):
        return not _plain_code_expired(code["created_at"], code["duration_sec"], now)
    return (
        code["federation_contract_id"] == claims["contract_id"]
        and code["federation_contract_version"] == claims["contract_version"]
        and code["allowed_issuer_deployment_id"] == claims["iss"]
        and (code["federation_expires_at"] is None or now < code["federation_expires_at"])
    )


def _legacy_created_epoch(value) -> int:
    if type(value) is int:
        return value
    parsed = datetime.fromisoformat(str(value).strip())
    if parsed.tzinfo is not None:
        return int(parsed.timestamp())
    # Protected Server timestamps are naive local wall time. Preserve that
    # interpretation rather than relabeling historical rows as UTC.
    return int(time.mktime(parsed.timetuple()) + parsed.microsecond / 1_000_000)


def _group_current(row, now: int) -> bool:
    if row is None:
        return False
    lifetime = int(row[5])
    if lifetime <= 0:
        return True
    try:
        created = _legacy_created_epoch(row[6])
    except (TypeError, ValueError, OverflowError, OSError):
        return False
    return now < created + lifetime


def get_principal_tx(tx, issuer: str, subject: str):
    return tx.execute(
        "SELECT id,issuer_deployment_id,remote_subject_id,local_account_id,status "
        "FROM FederatedPrincipals WHERE issuer_deployment_id=? AND remote_subject_id=?",
        (issuer, subject),
    ).fetchone()


def resolve_or_create_principal_tx(
    tx, *, issuer: str, subject: str, prepared: PreparedFederatedAccount, now: int
):
    row = get_principal_tx(tx, issuer, subject)
    if row is None:
        principal_id = str(uuid4())
        tx.execute(
            "INSERT INTO FederatedPrincipals"
            "(id,issuer_deployment_id,remote_subject_id,local_account_id,status,"
            "created_at,last_seen_at,display_metadata_json) "
            "VALUES (?,?,?,?,'active',?,?,'{}')",
            (
                principal_id,
                issuer,
                subject,
                prepared.local_account_id,
                now,
                now,
            ),
        )
        row = get_principal_tx(tx, issuer, subject)
    elif int(row[3]) != prepared.local_account_id:
        raise RuntimeError("prepared principal binding mismatch")
    if row is None:
        raise RuntimeError("principal resolution failed")
    if row[4] != "active":
        raise FederationBusinessError("principal_disabled")
    tx.execute(
        "UPDATE FederatedPrincipals SET last_seen_at=? WHERE id=?", (now, row[0])
    )
    return row


def membership_exists_tx(tx, account_id: int, group_id: int) -> bool:
    return (
        tx.execute(
            "SELECT 1 FROM UsersLookup WHERE user_id=? AND group_id=?",
            (account_id, group_id),
        ).fetchone()
        is not None
    )


def add_membership_tx(tx, account_id: int, group_id: int) -> bool:
    if membership_exists_tx(tx, account_id, group_id):
        return False
    tx.execute(
        "INSERT INTO UsersLookup(user_id,group_id) VALUES (?,?)",
        (account_id, group_id),
    )
    return True


def lookup_redemption_tx(tx, issuer: str, subject: str, request_id: str):
    return tx.execute(
        "SELECT id,code_id,code_sha256,group_id,principal_id,local_account_id,"
        "issuer_deployment_id,remote_subject_id,contract_id,contract_version,"
        "request_id,request_sha256,redeemed_at,membership_added "
        "FROM EnrollmentRedemptions WHERE issuer_deployment_id=? "
        "AND remote_subject_id=? AND request_id=?",
        (issuer, subject, request_id),
    ).fetchone()


def insert_redemption_tx(tx, values: tuple) -> None:
    tx.execute(
        "INSERT INTO EnrollmentRedemptions"
        "(id,code_id,code_sha256,group_id,principal_id,local_account_id,"
        "issuer_deployment_id,remote_subject_id,contract_id,contract_version,"
        "request_id,request_sha256,redeemed_at,membership_added) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        values,
    )


def decrement_code_tx(tx, code_id: int) -> None:
    changed = tx.execute(
        "UPDATE EnrollmentCodes SET uses=uses-1 WHERE code_id=? AND uses>0",
        (code_id,),
    )
    if changed.rowcount != 1:
        raise FederationBusinessError("code_exhausted")
    tx.execute("DELETE FROM EnrollmentCodes WHERE code_id=? AND uses<=0", (code_id,))


class ServerEnrollmentCodeStore:
    """Create only high-entropy, exact-contract destination invitations."""

    def __init__(self, path, *, local_deployment_id, clock=None):
        self.path = Path(path)
        self.local_deployment_id = canonical_uuid(local_deployment_id)
        self.clock = clock or (lambda: int(time.time()))
        with sqlite3.connect(self.path) as conn:
            migrate_gate_f_usergroups_schema(conn)

    def create_federated(
        self,
        *,
        group_id: int,
        uses: int,
        duration_sec: int,
        contract_id: str,
        contract_version: int,
        allowed_issuer_deployment_id: str,
    ) -> str:
        group_id, uses, duration_sec = int(group_id), int(uses), int(duration_sec)
        issuer = canonical_uuid(allowed_issuer_deployment_id)
        contract_id = canonical_uuid(contract_id)
        if group_id < 0 or uses <= 0 or duration_sec < 0:
            raise FederationError("invalid_enrollment_code")
        now = int(self.clock())
        with sqlite3.connect(self.path, timeout=10.0) as conn:
            conn.row_factory = sqlite3.Row
            configure_connection(conn)
            conn.execute("BEGIN IMMEDIATE")
            contract = conn.execute(
                "SELECT * FROM FederationContracts WHERE contract_id=? AND version=?",
                (contract_id, contract_version),
            ).fetchone()
            if contract is None:
                raise FederationError("contract_unknown")
            terms = validate_contract_terms(
                {
                    "contract_id": contract["contract_id"],
                    "version": contract["version"],
                    "deployment_a": contract["deployment_a"],
                    "deployment_b": contract["deployment_b"],
                    "valid_from": contract["valid_from"],
                    "valid_until": contract["valid_until"],
                    "allowed_capabilities": strict_json(
                        contract["allowed_capabilities_json"], max_bytes=512
                    ),
                    "key_a_kid": contract["key_a_kid"],
                    "key_a_sha256": contract["key_a_sha256"],
                    "key_b_kid": contract["key_b_kid"],
                    "key_b_sha256": contract["key_b_sha256"],
                    "supersedes_version": contract["supersedes_version"],
                }
            )
            if contract_terms_sha256(terms) != contract["terms_sha256"]:
                raise FederationError("contract_material_mismatch")
            peers = {terms.deployment_a, terms.deployment_b}
            if self.local_deployment_id not in peers or issuer not in peers or issuer == self.local_deployment_id:
                raise FederationError("counterparty_mismatch")
            if not contract_allows(
                terms,
                contract["state"],
                "FEDERATED_ENROLL",
                now=now,
                superseded=contract["superseded_by_version"] is not None,
            ):
                raise FederationError("contract_inactive")
            for deployment_id in (self.local_deployment_id, issuer):
                kid, fingerprint = terms.key_binding(deployment_id)
                key = conn.execute(
                    "SELECT * FROM TrustedDeploymentKeys WHERE deployment_id=? AND kid=?",
                    (deployment_id, kid),
                ).fetchone()
                if (
                    key is None
                    or key["public_key_sha256"] != fingerprint
                    or not key_is_current(dict(key), now)
                ):
                    raise FederationError("contract_key_mismatch")
            group = conn.execute(
                "SELECT group_id,group_name,devices_whitelist,max_reservation_time_sec,"
                "max_reservations,lifetime_sec,created_at,lan_only FROM UserGroups WHERE group_id=?",
                (group_id,),
            ).fetchone()
            if not _group_current(group, now):
                raise FederationError("group_expired")
            if group[7]:
                # Federation is the opposite of LAN-only.
                raise FederationError("group_lan_only")
            code_name = secrets.token_urlsafe(24)
            expires = None if duration_sec == 0 else now + duration_sec
            conn.execute(
                "INSERT INTO EnrollmentCodes"
                "(code_name,group_id,uses,duration_sec,created_at,"
                "federation_contract_id,federation_contract_version,"
                "allowed_issuer_deployment_id,federation_expires_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    code_name,
                    group_id,
                    uses,
                    duration_sec,
                    datetime.now(),
                    contract_id,
                    contract_version,
                    issuer,
                    expires,
                ),
            )
        return build_federation_invitation(
            destination_deployment_id=self.local_deployment_id,
            contract_id=contract_id,
            contract_version=contract_version,
            code_name=code_name,
        ).text


class ServerFederatedEnrollHandler:
    """Transaction-bound owner mutation with receipt-backed completion."""

    def __init__(
        self,
        *,
        usergroups_path,
        reservations_path,
        local_deployment_id,
        display_name,
        perms_path=None,
        clock=None,
        account_preparer=prepare_federated_account,
        account_remover=None,
    ):
        self.usergroups_path = Path(usergroups_path)
        self.reservations_path = Path(reservations_path)
        self.perms_path = perms_path
        self.local_deployment_id = canonical_uuid(local_deployment_id)
        self.display_name = str(display_name)
        self.clock = clock or (lambda: int(time.time()))
        self.account_preparer = account_preparer
        self.account_remover = account_remover or _remove_account
        with sqlite3.connect(self.usergroups_path) as conn:
            migrate_gate_f_usergroups_schema(conn)

    def prepare(self, action):
        """Never mutates owner authorization; invalid cases wait for owner tx."""
        claims = action.claims
        payload = action.request.value["payload"]
        if payload["code_name"] == UNENROLL_CODE:
            # Runs only for a verified, current grant, and only ever touches
            # the grant's own (iss, sub): a lab can revoke nobody else's users.
            with sqlite3.connect(self.reservations_path) as conn:
                row = conn.execute(
                    "SELECT a.username FROM FederatedAccountBindings b JOIN Accounts a ON a.acc_id=b.local_account_id "
                    "WHERE b.issuer_deployment_id=? AND b.remote_subject_id=? AND a.auth_type='federated'",
                    (claims["iss"], claims["sub"]),
                ).fetchone()
                linked = links.lookup(claims["iss"], claims["sub"])
                linked = linked is not None and conn.execute(
                    "SELECT username FROM Accounts WHERE acc_id=?", (linked,)).fetchone()
            for found in (row, linked):
                if found:
                    self.account_remover(found[0])
            return None
        if "lan_hash" in payload:
            return self._prepare_linked(claims, payload)
        if payload["code_name"] == CLUSTER_CODE:
            # No code to check: the home lab's signature under an active
            # cluster contract is the vouching. Prepare a proxy only once.
            with sqlite3.connect(self.usergroups_path) as conn:
                if get_principal_tx(conn, claims["iss"], claims["sub"]) is not None:
                    return None
            return self.account_preparer(
                self.reservations_path,
                issuer_deployment_id=claims["iss"],
                remote_subject_id=claims["sub"],
                perms_path=self.perms_path,
                now=int(self.clock()),
            )
        with sqlite3.connect(self.usergroups_path) as conn:
            conn.row_factory = sqlite3.Row
            receipt = conn.execute(
                "SELECT request_sha256 FROM EnrollmentRedemptions "
                "WHERE issuer_deployment_id=? AND remote_subject_id=? AND request_id=?",
                (claims["iss"], claims["sub"], claims["request_id"]),
            ).fetchone()
            if receipt is not None:
                return None
            code = conn.execute(
                "SELECT code_id,group_id,uses,federation_contract_id,"
                "federation_contract_version,allowed_issuer_deployment_id,"
                "federation_expires_at,duration_sec,created_at FROM EnrollmentCodes WHERE code_name=?",
                (payload["code_name"],),
            ).fetchone()
            now = int(self.clock())
            if code is None or code["uses"] <= 0 or not _code_admits(code, claims, now):
                return None
        return self.account_preparer(
            self.reservations_path,
            issuer_deployment_id=claims["iss"],
            remote_subject_id=claims["sub"],
            perms_path=self.perms_path,
            now=int(self.clock()),
        )

    def _prepare_linked(self, claims, payload):
        """Only RemoteRF Global gives its accounts a login here; a partner lab
        cannot plant one. `lan.update` replaces the login's verifier (reset,
        disable); a code makes the login, once that code would admit them."""
        from ..reservation import reservation_handler

        if claims["iss"] != links.global_home_id():
            return PreparedLinked(error="enrollee_not_allowed")
        if payload["code_name"] == LAN_UPDATE_CODE:
            return PreparedLinked(error=reservation_handler.set_linked_verifier(
                issuer=claims["iss"], subject=claims["sub"], email=payload.get("email", ""),
                salt=payload["lan_salt"], hashed=payload["lan_hash"]))
        with sqlite3.connect(self.usergroups_path) as conn:
            conn.row_factory = sqlite3.Row
            code = conn.execute(
                "SELECT code_id,group_id,uses,federation_contract_id,"
                "federation_contract_version,allowed_issuer_deployment_id,"
                "federation_expires_at,duration_sec,created_at FROM EnrollmentCodes WHERE code_name=?",
                (payload["code_name"],),
            ).fetchone()
            if code is None or code["uses"] <= 0 or not _code_admits(code, claims, int(self.clock())):
                return PreparedLinked(error="code_invalid")
        uid, error, proxy = reservation_handler.link_global_account(
            issuer=claims["iss"], subject=claims["sub"], username=payload["username"],
            email=payload.get("email", ""), salt=payload["lan_salt"], hashed=payload["lan_hash"])
        if proxy:
            self.account_remover(proxy)
        return PreparedLinked(uid, error)

    def _linked_enroll(self, tx, action, now):
        """The membership for a linked login prepared above. A LAN-only group
        keeps meaning "be here": the login exists, but the code is redeemed
        only over the LAN (ACC:set_enroll), so neither is spent here."""
        claims, payload, prepared = action.claims, action.request.value["payload"], action.prepared
        if not isinstance(prepared, PreparedLinked):
            raise RuntimeError("linked login preparation unavailable")
        if prepared.error:
            raise FederationBusinessError(prepared.error)
        if payload["code_name"] == LAN_UPDATE_CODE:
            self._audit(tx, action, code="ok", metadata={"lan_update": True})
            return self._result(action, redemption_id=str(uuid5(NAMESPACE_URL, f"remoterf-lan:{claims['request_id']}")),
                                membership_present=False, groups=[], now=now)
        receipt = lookup_redemption_tx(tx, claims["iss"], claims["sub"], claims["request_id"])
        if receipt is not None:
            group = tx.execute("SELECT group_id,group_name FROM UserGroups WHERE group_id=?", (receipt[3],)).fetchone()
            return self._result(action, redemption_id=receipt[0], membership_present=group is not None,
                                groups=[{"group_id": str(group[0]), "group_name": group[1]}] if group else [], now=now)
        code = tx.execute(
            "SELECT code_id,code_name,group_id,uses,duration_sec,created_at,federation_contract_id,"
            "federation_contract_version,allowed_issuer_deployment_id,federation_expires_at "
            "FROM EnrollmentCodes WHERE code_name=?", (payload["code_name"],)).fetchone()
        if code is None or int(code[3]) <= 0:
            raise FederationBusinessError("code_invalid")
        if code[9] is not None and now >= int(code[9]):
            raise FederationBusinessError("code_expired")
        group = tx.execute(
            "SELECT group_id,group_name,devices_whitelist,max_reservation_time_sec,"
            "max_reservations,lifetime_sec,created_at,lan_only FROM UserGroups WHERE group_id=?",
            (code[2],)).fetchone()
        if not _group_current(group, now):
            raise FederationBusinessError("group_expired")
        if group[7]:
            self._audit(tx, action, code="ok", metadata={"linked": True, "lan_only": True})
            return self._result(action, redemption_id=str(uuid5(NAMESPACE_URL, f"remoterf-lan:{claims['request_id']}")),
                                membership_present=False, groups=[], now=now)
        membership_added = add_membership_tx(tx, prepared.local_account_id, int(code[2]))
        decrement_code_tx(tx, int(code[0]))
        redemption_id = str(uuid4())
        insert_redemption_tx(tx, (
            redemption_id, int(code[0]), _code_hash(payload["code_name"]), int(code[2]),
            links.principal_id(claims["sub"]), prepared.local_account_id, claims["iss"], claims["sub"],
            claims["contract_id"], claims["contract_version"], claims["request_id"], claims["request_sha256"],
            now, int(membership_added)))
        self._audit(tx, action, code="ok", metadata={"redemption_id": redemption_id, "linked": True})
        return self._result(action, redemption_id=redemption_id, membership_present=True,
                            groups=[{"group_id": str(group[0]), "group_name": group[1]}], now=now)

    def _audit(self, tx, action, *, code: str, principal_id=None, metadata=None):
        claims = action.claims
        tx.execute(
            "INSERT INTO FederationAuditEvents"
            "(id,occurred_at,actor_kind,actor_ref,event_type,principal_id,"
            "contract_id,version,request_id,result_code,metadata_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                int(self.clock()),
                "deployment",
                claims["iss"],
                "federated_enrollment",
                principal_id,
                claims["contract_id"],
                claims["contract_version"],
                claims["request_id"],
                code,
                canonical_json(metadata or {}),
            ),
        )

    def _result(self, action, *, redemption_id, membership_present, groups, now):
        return {
            "status": "ok",
            "error_code": None,
            "deployment_id": self.local_deployment_id,
            "display_name": self.display_name,
            "contract_id": action.claims["contract_id"],
            "contract_version": action.claims["contract_version"],
            "state": action.state,
            "groups": groups,
            "retrieved_at": now,
            "redemption_id": redemption_id,
            "membership_present": membership_present,
        }

    def _cluster_enroll(self, tx, action, now):
        """Cluster enrolment: the contract names the cluster; the proxy joins
        every group attached to it here. Re-running only re-adds memberships."""
        from . import cluster as cluster_module

        claims = action.claims
        found = cluster_module.contract_cluster(claims["contract_id"])
        if found is None:
            raise FederationBusinessError("code_invalid")
        name, cluster = found
        principal = get_principal_tx(tx, claims["iss"], claims["sub"])
        if principal is None:
            prepared = action.prepared
            if not isinstance(prepared, PreparedFederatedAccount):
                raise RuntimeError("federated proxy preparation unavailable")
            principal = resolve_or_create_principal_tx(
                tx, issuer=claims["iss"], subject=claims["sub"], prepared=prepared, now=now
            )
        elif principal[4] != "active":
            raise FederationBusinessError("principal_disabled")
        else:
            tx.execute("UPDATE FederatedPrincipals SET last_seen_at=? WHERE id=?", (now, principal[0]))
        cluster_module.join_account(tx, name, cluster, int(principal[3]), kind="proxy")
        self._audit(tx, action, code="ok", principal_id=principal[0], metadata={"cluster": name})
        # Group names stay local; the home lab learns only which cluster admitted it.
        return self._result(
            action, redemption_id=str(uuid5(NAMESPACE_URL, f"remoterf-cluster:{name}:{principal[0]}")),
            membership_present=True, groups=[{"group_id": "0", "group_name": f"cluster {name}"}], now=now,
        )

    def _unenroll(self, tx, action, now):
        """The proxy (and its reservations) went in prepare(); drop whatever
        rows here still name it. Unknown subjects are fine: idempotent."""
        claims = action.claims
        principal = get_principal_tx(tx, claims["iss"], claims["sub"])
        if principal is not None:
            for table, column in (("UsersLookup", "user_id"), ("ClusterMemberships", "local_account_id"),
                                  ("ClusterAccounts", "local_account_id")):
                tx.execute(f"DELETE FROM {table} WHERE {column}=?", (int(principal[3]),))
            tx.execute("DELETE FROM FederatedPrincipals WHERE id=?", (principal[0],))
        self._audit(tx, action, code="ok", principal_id=None,
                    metadata={"unenrolled": principal is not None})
        return self._result(
            action, redemption_id=str(uuid5(NAMESPACE_URL, f"remoterf-unenroll:{claims['iss']}:{claims['sub']}")),
            membership_present=False, groups=[], now=now,
        )

    def __call__(self, tx, action):
        claims = action.claims
        payload = action.request.value["payload"]
        now = int(self.clock())
        if payload["code_name"] == UNENROLL_CODE:
            return self._unenroll(tx, action, now)
        if payload["code_name"] == CLUSTER_CODE:
            return self._cluster_enroll(tx, action, now)
        if "lan_hash" in payload:
            return self._linked_enroll(tx, action, now)
        receipt = lookup_redemption_tx(
            tx, claims["iss"], claims["sub"], claims["request_id"]
        )
        expected_code_hash = _code_hash(payload["code_name"])
        if receipt is not None:
            if (
                receipt[11] != claims["request_sha256"]
                or receipt[2] != expected_code_hash
                or receipt[8] != claims["contract_id"]
                or int(receipt[9]) != claims["contract_version"]
            ):
                raise FederationBusinessError("request_conflict")
            principal = get_principal_tx(tx, claims["iss"], claims["sub"])
            if principal is None or principal[0] != receipt[4] or int(principal[3]) != int(receipt[5]):
                raise RuntimeError("redemption principal integrity failure")
            if principal[4] != "active":
                raise FederationBusinessError("principal_disabled")
            group = tx.execute(
                "SELECT group_id,group_name,devices_whitelist,max_reservation_time_sec,"
                "max_reservations,lifetime_sec,created_at,lan_only FROM UserGroups WHERE group_id=?",
                (receipt[3],),
            ).fetchone()
            present = (
                membership_exists_tx(tx, int(receipt[5]), int(receipt[3]))
                and _group_current(group, now)
                and not group[7]
            )
            groups = (
                [{"group_id": str(group[0]), "group_name": group[1]}]
                if present
                else []
            )
            self._audit(
                tx,
                action,
                code="idempotent_completion",
                principal_id=receipt[4],
                metadata={"redemption_id": receipt[0], "membership_present": present},
            )
            return self._result(
                action,
                redemption_id=receipt[0],
                membership_present=present,
                groups=groups,
                now=now,
            )

        code = tx.execute(
            "SELECT code_id,code_name,group_id,uses,duration_sec,created_at,"
            "federation_contract_id,federation_contract_version,"
            "allowed_issuer_deployment_id,federation_expires_at "
            "FROM EnrollmentCodes WHERE code_name=?",
            (payload["code_name"],),
        ).fetchone()
        if code is None:
            raise FederationBusinessError("code_invalid")
        if _plain_code(code[6], code[7], code[8]):
            # The lab's ordinary invite, handed to a user whose HOME is another
            # deployment (Global, say): the code itself is the authorization.
            if _plain_code_expired(code[5], code[4], now):
                raise FederationBusinessError("code_expired")
        elif (
            any(code[index] is None for index in (6, 7, 8))
            or code[6] != claims["contract_id"]
            or int(code[7]) != claims["contract_version"]
            or code[8] != claims["iss"]
        ):
            raise FederationBusinessError("code_restriction_mismatch")
        if code[9] is not None and now >= int(code[9]):
            raise FederationBusinessError("code_expired")
        if int(code[3]) <= 0:
            raise FederationBusinessError("code_exhausted")
        group = tx.execute(
            "SELECT group_id,group_name,devices_whitelist,max_reservation_time_sec,"
            "max_reservations,lifetime_sec,created_at,lan_only FROM UserGroups WHERE group_id=?",
            (code[2],),
        ).fetchone()
        if not _group_current(group, now):
            raise FederationBusinessError("group_expired")
        if group[7]:
            raise FederationBusinessError("group_lan_only")
        prepared = action.prepared
        if not isinstance(prepared, PreparedFederatedAccount):
            raise RuntimeError("federated proxy preparation unavailable")
        principal = resolve_or_create_principal_tx(
            tx,
            issuer=claims["iss"],
            subject=claims["sub"],
            prepared=prepared,
            now=now,
        )
        enrollee = {k: payload[k] for k in ("display_name", "email") if payload.get(k)}
        if enrollee:
            # The user chose this lab (a class roster needs a name); a
            # cluster walk-in stays anonymous.
            tx.execute(
                "UPDATE FederatedPrincipals SET display_metadata_json=? WHERE id=?",
                (json.dumps({**enrollee, "home": claims["iss"]}, sort_keys=True), principal[0]),
            )
        membership_added = add_membership_tx(
            tx, prepared.local_account_id, int(code[2])
        )
        decrement_code_tx(tx, int(code[0]))
        redemption_id = str(uuid4())
        insert_redemption_tx(
            tx,
            (
                redemption_id,
                int(code[0]),
                expected_code_hash,
                int(code[2]),
                principal[0],
                prepared.local_account_id,
                claims["iss"],
                claims["sub"],
                claims["contract_id"],
                claims["contract_version"],
                claims["request_id"],
                claims["request_sha256"],
                now,
                int(membership_added),
            ),
        )
        self._audit(
            tx,
            action,
            code="ok",
            principal_id=principal[0],
            metadata={
                "redemption_id": redemption_id,
                "membership_added": membership_added,
            },
        )
        return self._result(
            action,
            redemption_id=redemption_id,
            membership_present=True,
            groups=[{"group_id": str(group[0]), "group_name": group[1]}],
            now=now,
        )


def _remove_account(username: str) -> None:
    from ..reservation import reservation_handler

    reservation_handler.remove_user(username=username)


class ServerFederatedEnrollmentHome:
    def __init__(self, outbound):
        self.outbound = outbound

    def enroll(self, *, local_account_id: int, enrollment_input: str):
        invitation = parse_federation_invitation(enrollment_input)
        value = invitation.value
        return self.outbound.execute(
            local_account_id=local_account_id,
            destination_deployment_id=value["destination_deployment_id"],
            contract_id=value["contract_id"],
            contract_version=value["contract_version"],
            action="federated_enroll",
            code_name=value["code_name"],
        )


def build_server_gate_f_executor(
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
    """Compatibility alias for the final Phase-1 Gate G executor factory."""

    from .permissions import build_server_gate_g_executor

    return build_server_gate_g_executor(
        usergroups_path=usergroups_path,
        reservations_path=reservations_path,
        local_deployment_id=local_deployment_id,
        private_key=private_key,
        signing_kid=signing_kid,
        display_name=display_name,
        perms_path=perms_path,
        clock=clock,
    )
