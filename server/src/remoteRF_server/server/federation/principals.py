"""Generic destination-local federated principal persistence."""

from __future__ import annotations

import sqlite3
import threading
import time
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from remoterf_federation_core import (
    canonical_json,
    canonical_uuid,
    federated_identity,
    federated_proxy_adapter,
    strict_json,
    validate_display_metadata,
)

from .migrations import (
    FEDERATED_PASSWORD_HASH,
    FEDERATED_PASSWORD_SALT,
    configure_connection,
    migrate_usergroups_schema,
)


@dataclass(frozen=True)
class FederatedPrincipal:
    id: str
    issuer_deployment_id: str
    remote_subject_id: str
    local_account_id: int
    status: str
    created_at: int
    last_seen_at: int | None
    disabled_at: int | None
    display_metadata: dict[str, str]


@dataclass(frozen=True)
class PreparedFederatedAccount:
    local_account_id: int
    username: str


def prepare_federated_account(
    reservations_path: str | Path,
    *,
    issuer_deployment_id: str,
    remote_subject_id: str,
    perms_path: str | Path | None = None,
    now: int | None = None,
) -> PreparedFederatedAccount:
    """Idempotently prepare only the harmless cross-DB proxy and Normal role."""

    identity = federated_identity(issuer_deployment_id, remote_subject_id)
    username, email = federated_proxy_adapter(
        identity.issuer_deployment_id, identity.remote_subject_id
    )
    observed = int(time.time() if now is None else now)
    reservations_path = Path(reservations_path)
    from .migrations import migrate_reservations_schema

    with sqlite3.connect(reservations_path, timeout=10.0) as conn:
        configure_connection(conn)
        migrate_reservations_schema(conn)
        conn.commit()
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT b.local_account_id,a.username,a.email,a.pass_salt,a.pass_hash,"
            "a.auth_type FROM FederatedAccountBindings b JOIN Accounts a "
            "ON a.acc_id=b.local_account_id WHERE b.issuer_deployment_id=? "
            "AND b.remote_subject_id=?",
            (identity.issuer_deployment_id, identity.remote_subject_id),
        ).fetchone()
        if row is None:
            if conn.execute(
                "SELECT 1 FROM Accounts WHERE username=? OR email=? LIMIT 1",
                (username, email),
            ).fetchone():
                raise ValueError("federated proxy adapter collision")
            conn.execute(
                "INSERT INTO Accounts(username,email,pass_salt,pass_hash,created_at,auth_type) "
                "VALUES (?,?,?,?,?,'federated')",
                (
                    username,
                    email,
                    FEDERATED_PASSWORD_SALT,
                    FEDERATED_PASSWORD_HASH,
                    datetime.now(),
                ),
            )
            account_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
            conn.execute(
                "INSERT INTO FederatedAccountBindings"
                "(issuer_deployment_id,remote_subject_id,local_account_id,created_at) "
                "VALUES (?,?,?,?)",
                (
                    identity.issuer_deployment_id,
                    identity.remote_subject_id,
                    account_id,
                    observed,
                ),
            )
        else:
            expected = (
                username,
                email,
                FEDERATED_PASSWORD_SALT,
                FEDERATED_PASSWORD_HASH,
                "federated",
            )
            if tuple(row[1:]) != expected:
                raise ValueError("federated account binding is incoherent")
            account_id = int(row[0])

    role_path = Path(perms_path) if perms_path is not None else reservations_path.with_name("perms.db")
    with sqlite3.connect(role_path, timeout=10.0) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS Users (
              UserID INTEGER PRIMARY KEY AUTOINCREMENT, Username TEXT NOT NULL UNIQUE);
            CREATE TABLE IF NOT EXISTS PowerUsers (
              UserID INTEGER PRIMARY KEY AUTOINCREMENT, Username TEXT NOT NULL UNIQUE,
              MaxReservations INTEGER NOT NULL, MaxReservationTimeSec INTEGER NOT NULL,
              DevicesAllowed TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS Admins (
              AdminID INTEGER PRIMARY KEY AUTOINCREMENT, Username TEXT NOT NULL UNIQUE);
            """
        )
        conn.execute("BEGIN IMMEDIATE")
        exists = conn.execute(
            "SELECT 1 FROM Users WHERE Username=? UNION ALL "
            "SELECT 1 FROM PowerUsers WHERE Username=? UNION ALL "
            "SELECT 1 FROM Admins WHERE Username=? LIMIT 1",
            (username, username, username),
        ).fetchone()
        if exists is None:
            conn.execute("INSERT INTO Users(Username) VALUES (?)", (username,))
    return PreparedFederatedAccount(account_id, username)


class FederatedPrincipalStore:
    def __init__(self, path: str | Path, *, reservations_path: str | Path):
        self.path = Path(path)
        self.reservations_path = Path(reservations_path)
        self._lock = threading.RLock()
        with sqlite3.connect(self.path) as conn:
            migrate_usergroups_schema(conn)

    def _binding_is_exact(self, issuer: str, subject: str, account_id: int) -> bool:
        with sqlite3.connect(self.reservations_path) as conn:
            configure_connection(conn)
            row = conn.execute(
                """
                SELECT a.username, a.email, a.pass_salt, a.pass_hash, a.auth_type
                FROM FederatedAccountBindings b
                JOIN Accounts a ON a.acc_id = b.local_account_id
                WHERE b.issuer_deployment_id = ? AND b.remote_subject_id = ?
                  AND b.local_account_id = ?
                """,
                (issuer, subject, int(account_id)),
            ).fetchone()
        username, email = federated_proxy_adapter(issuer, subject)
        return row == (
            username,
            email,
            FEDERATED_PASSWORD_SALT,
            FEDERATED_PASSWORD_HASH,
            "federated",
        )

    @staticmethod
    def _decode(row) -> FederatedPrincipal:
        metadata = strict_json(row[8], max_bytes=2048)
        validate_display_metadata(metadata)
        status = str(row[4])
        disabled_at = None if row[7] is None else int(row[7])
        if status not in {"active", "disabled"} or (
            status == "active" and disabled_at is not None
        ) or (status == "disabled" and disabled_at is None):
            raise ValueError("principal status is incoherent")
        return FederatedPrincipal(
            id=canonical_uuid(row[0]),
            issuer_deployment_id=canonical_uuid(row[1]),
            remote_subject_id=canonical_uuid(row[2]),
            local_account_id=int(row[3]),
            status=status,
            created_at=int(row[5]),
            last_seen_at=None if row[6] is None else int(row[6]),
            disabled_at=disabled_at,
            display_metadata=metadata,
        )

    def resolve(
        self,
        *,
        issuer_deployment_id: str,
        remote_subject_id: str,
        local_account_id: int,
        display_metadata: dict[str, str] | None = None,
        now: int | None = None,
    ) -> FederatedPrincipal:
        identity = federated_identity(issuer_deployment_id, remote_subject_id)
        metadata = validate_display_metadata(display_metadata or {})
        encoded = canonical_json(metadata)
        local_account_id = int(local_account_id)
        if local_account_id <= 0 or not self._binding_is_exact(
            identity.issuer_deployment_id,
            identity.remote_subject_id,
            local_account_id,
        ):
            raise ValueError("principal account binding is absent or incoherent")
        observed = int(time.time() if now is None else now)
        with self._lock, sqlite3.connect(self.path, timeout=5.0) as conn:
            configure_connection(conn)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT id, issuer_deployment_id, remote_subject_id,
                       local_account_id, status, created_at, last_seen_at,
                       disabled_at, display_metadata_json
                FROM FederatedPrincipals
                WHERE issuer_deployment_id = ? AND remote_subject_id = ?
                """,
                (identity.issuer_deployment_id, identity.remote_subject_id),
            ).fetchone()
            if row is None:
                principal_id = str(uuid4())
                conn.execute(
                    """
                    INSERT INTO FederatedPrincipals
                    (id, issuer_deployment_id, remote_subject_id, local_account_id,
                     status, created_at, last_seen_at, display_metadata_json)
                    VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
                    """,
                    (
                        principal_id,
                        identity.issuer_deployment_id,
                        identity.remote_subject_id,
                        local_account_id,
                        observed,
                        observed,
                        encoded,
                    ),
                )
            else:
                if int(row[3]) != local_account_id:
                    raise ValueError("principal tuple is bound to another account")
                conn.execute(
                    "UPDATE FederatedPrincipals SET last_seen_at = ?, "
                    "display_metadata_json = ? WHERE id = ?",
                    (observed, encoded, row[0]),
                )
            final = conn.execute(
                """
                SELECT id, issuer_deployment_id, remote_subject_id,
                       local_account_id, status, created_at, last_seen_at,
                       disabled_at, display_metadata_json
                FROM FederatedPrincipals
                WHERE issuer_deployment_id = ? AND remote_subject_id = ?
                """,
                (identity.issuer_deployment_id, identity.remote_subject_id),
            ).fetchone()
            assert final is not None
            return self._decode(final)
