"""Small additive Gate C schemas for the protected Server databases."""

from __future__ import annotations

import hashlib
import sqlite3
import time
from pathlib import Path
from uuid import UUID, uuid5

from remoterf_federation_core import (
    canonical_uuid,
    federated_proxy_adapter,
    strict_json,
    validate_display_metadata,
)

AUTH_TYPES = frozenset({"local_password", "federated"})
MIGRATION_VERSION = 2
MIGRATION_NAME = "gate_c_identity_v2"
FEDERATED_PASSWORD_SALT = "!remoterf-federated-salt-v2!"
FEDERATED_PASSWORD_HASH = "!remoterf-federated-no-password-v2!"

_SUBJECTS_DDL = """
CREATE TABLE IF NOT EXISTS LocalAccountSubjects (
    local_account_id INTEGER PRIMARY KEY,
    subject_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
    created_at INTEGER NOT NULL,
    FOREIGN KEY(local_account_id) REFERENCES Accounts(acc_id) ON DELETE CASCADE
)
"""

_BINDINGS_DDL = """
CREATE TABLE IF NOT EXISTS FederatedAccountBindings (
    issuer_deployment_id TEXT NOT NULL,
    remote_subject_id TEXT NOT NULL,
    local_account_id INTEGER NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(issuer_deployment_id, remote_subject_id),
    FOREIGN KEY(local_account_id) REFERENCES Accounts(acc_id) ON DELETE CASCADE
)
"""

_PRINCIPALS_DDL = """
CREATE TABLE IF NOT EXISTS FederatedPrincipals (
    id TEXT PRIMARY KEY,
    issuer_deployment_id TEXT NOT NULL,
    remote_subject_id TEXT NOT NULL,
    local_account_id INTEGER NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER,
    disabled_at INTEGER,
    display_metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(issuer_deployment_id, remote_subject_id),
    CHECK((status = 'active' AND disabled_at IS NULL)
       OR (status = 'disabled' AND disabled_at IS NOT NULL))
)
"""

_MIGRATION_CHECKSUM = hashlib.sha256(
    (_SUBJECTS_DDL + _BINDINGS_DDL + _PRINCIPALS_DDL).encode("utf-8")
).hexdigest()


class SchemaNotReady(RuntimeError):
    pass


def configure_connection(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA journal_mode=WAL")


def _account_columns(conn: sqlite3.Connection) -> set[str]:
    return {str(row[1]) for row in conn.execute("PRAGMA table_info(Accounts)")}


def _reject_legacy_or_unknown_auth_types(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        "SELECT auth_type, COUNT(*) FROM Accounts "
        "GROUP BY auth_type ORDER BY auth_type"
    ).fetchall()
    invalid = [(value, int(count)) for value, count in rows if value not in AUTH_TYPES]
    if invalid:
        rendered = ", ".join(f"{value!r} ({count})" for value, count in invalid)
        raise SchemaNotReady(
            "Accounts contains legacy or unknown auth_type values: " + rendered
        )


def migrate_reservations_schema(conn: sqlite3.Connection) -> None:
    """Create/upgrade reservations.db without changing existing native rows."""

    configure_connection(conn)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS Accounts (
            acc_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            pass_salt TEXT NOT NULL,
            pass_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            auth_type TEXT NOT NULL DEFAULT 'local_password'
                CHECK(auth_type IN ('local_password','federated'))
        )
        """
    )
    columns = _account_columns(conn)
    if "auth_type" not in columns:
        conn.execute(
            "ALTER TABLE Accounts ADD COLUMN auth_type TEXT NOT NULL "
            "DEFAULT 'local_password'"
        )
    _reject_legacy_or_unknown_auth_types(conn)
    conn.execute(_SUBJECTS_DDL)
    conn.execute(_BINDINGS_DDL)
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS LocalAccountSubjects_native_insert
        BEFORE INSERT ON LocalAccountSubjects
        WHEN NOT EXISTS (
            SELECT 1 FROM Accounts
            WHERE acc_id = NEW.local_account_id AND auth_type = 'local_password'
        )
        BEGIN SELECT RAISE(ABORT, 'native subject requires local_password account'); END
        """
    )
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS FederatedAccountBindings_proxy_insert
        BEFORE INSERT ON FederatedAccountBindings
        WHEN NOT EXISTS (
            SELECT 1 FROM Accounts
            WHERE acc_id = NEW.local_account_id AND auth_type = 'federated'
        )
        BEGIN SELECT RAISE(ABORT, 'federated binding requires proxy account'); END
        """
    )
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS Accounts_federated_adapter_immutable
        BEFORE UPDATE OF username, email, pass_salt, pass_hash ON Accounts
        WHEN OLD.auth_type = 'federated' AND (
            NEW.username IS NOT OLD.username OR NEW.email IS NOT OLD.email
            OR NEW.pass_salt IS NOT OLD.pass_salt
            OR NEW.pass_hash IS NOT OLD.pass_hash
        )
        BEGIN SELECT RAISE(ABORT, 'federated account adapter is immutable'); END
        """
    )
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS Accounts_auth_type_insert
        BEFORE INSERT ON Accounts
        WHEN NEW.auth_type NOT IN ('local_password','federated')
        BEGIN SELECT RAISE(ABORT, 'invalid Accounts.auth_type'); END
        """
    )
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS Accounts_auth_type_immutable
        BEFORE UPDATE OF auth_type ON Accounts
        WHEN NEW.auth_type IS NOT OLD.auth_type
        BEGIN SELECT RAISE(ABORT, 'Accounts.auth_type is immutable'); END
        """
    )
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS LocalAccountSubjects_identity_immutable
        BEFORE UPDATE OF local_account_id, subject_id ON LocalAccountSubjects
        WHEN NEW.local_account_id IS NOT OLD.local_account_id
          OR NEW.subject_id IS NOT OLD.subject_id
        BEGIN SELECT RAISE(ABORT, 'native account subject is immutable'); END
        """
    )
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS FederatedAccountBindings_identity_immutable
        BEFORE UPDATE OF issuer_deployment_id, remote_subject_id, local_account_id
        ON FederatedAccountBindings
        WHEN NEW.issuer_deployment_id IS NOT OLD.issuer_deployment_id
          OR NEW.remote_subject_id IS NOT OLD.remote_subject_id
          OR NEW.local_account_id IS NOT OLD.local_account_id
        BEGIN SELECT RAISE(ABORT, 'federated account binding is immutable'); END
        """
    )


def migrate_usergroups_schema(conn: sqlite3.Connection) -> None:
    configure_connection(conn)
    conn.execute(_PRINCIPALS_DDL)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS SchemaMigrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            checksum TEXT NOT NULL,
            applied_at INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS FederatedPrincipals_identity_immutable
        BEFORE UPDATE OF id, issuer_deployment_id, remote_subject_id, local_account_id
        ON FederatedPrincipals
        WHEN NEW.id IS NOT OLD.id
          OR NEW.issuer_deployment_id IS NOT OLD.issuer_deployment_id
          OR NEW.remote_subject_id IS NOT OLD.remote_subject_id
          OR NEW.local_account_id IS NOT OLD.local_account_id
        BEGIN SELECT RAISE(ABORT, 'federated principal identity is immutable'); END
        """
    )
    row = conn.execute(
        "SELECT checksum FROM SchemaMigrations WHERE name = ?", (MIGRATION_NAME,)
    ).fetchone()
    if row is not None and row[0] != _MIGRATION_CHECKSUM:
        raise SchemaNotReady("Gate C migration checksum mismatch")
    conn.execute(
        "INSERT OR IGNORE INTO SchemaMigrations "
        "(version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
        (MIGRATION_VERSION, MIGRATION_NAME, _MIGRATION_CHECKSUM, int(time.time())),
    )


def migrate_gate_c(db_dir: str | Path) -> None:
    """Offline/idempotent Gate C schema preparation for a reviewed DB copy."""

    root = Path(db_dir)
    with sqlite3.connect(root / "reservations.db") as conn:
        migrate_reservations_schema(conn)
    with sqlite3.connect(root / "usergroups.db") as conn:
        migrate_usergroups_schema(conn)


def initialize_native_subjects(
    reservations_path: str | Path, deployment_id: str
) -> dict[int, str]:
    """Bootstrap only previously unmapped native accounts with UUIDv5."""

    deployment_id = canonical_uuid(deployment_id)
    namespace = UUID(deployment_id)
    with sqlite3.connect(Path(reservations_path), timeout=5.0) as conn:
        configure_connection(conn)
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            """
            SELECT a.acc_id
            FROM Accounts a
            LEFT JOIN FederatedAccountBindings b ON b.local_account_id = a.acc_id
            WHERE a.auth_type = 'local_password' AND b.local_account_id IS NULL
            ORDER BY a.acc_id
            """
        ).fetchall()
        now = int(time.time())
        for (account_id,) in rows:
            conn.execute(
                "INSERT OR IGNORE INTO LocalAccountSubjects "
                "(local_account_id, subject_id, status, created_at) "
                "VALUES (?, ?, 'active', ?)",
                (
                    int(account_id),
                    str(uuid5(namespace, f"account:{int(account_id)}")),
                    now,
                ),
            )
        return {
            int(account_id): canonical_uuid(subject_id)
            for account_id, subject_id in conn.execute(
                "SELECT local_account_id, subject_id FROM LocalAccountSubjects "
                "ORDER BY local_account_id"
            )
        }


def check_gate_c_ready(db_dir: str | Path) -> None:
    root = Path(db_dir)
    bindings: dict[int, tuple[str, str]] = {}
    with sqlite3.connect(root / "reservations.db") as conn:
        configure_connection(conn)
        if conn.execute("PRAGMA foreign_key_check").fetchone():
            raise SchemaNotReady("reservations.db foreign-key state is invalid")
        _reject_legacy_or_unknown_auth_types(conn)
        tables = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        required = {"Accounts", "LocalAccountSubjects", "FederatedAccountBindings"}
        if not required.issubset(tables):
            raise SchemaNotReady("reservations.db Gate C schema is incomplete")
        incoherent = conn.execute(
            """
            SELECT a.acc_id
            FROM Accounts a
            LEFT JOIN FederatedAccountBindings b ON b.local_account_id = a.acc_id
            GROUP BY a.acc_id
            HAVING (a.auth_type = 'local_password' AND COUNT(b.local_account_id) != 0)
                OR (a.auth_type = 'federated' AND COUNT(b.local_account_id) != 1)
            LIMIT 1
            """
        ).fetchone()
        if incoherent:
            raise SchemaNotReady("incoherent account authentication/binding state")
        missing_subject = conn.execute(
            """
            SELECT a.acc_id
            FROM Accounts a
            LEFT JOIN LocalAccountSubjects s ON s.local_account_id = a.acc_id
            WHERE a.auth_type = 'local_password'
            GROUP BY a.acc_id
            HAVING COUNT(s.local_account_id) != 1
            LIMIT 1
            """
        ).fetchone()
        if missing_subject:
            raise SchemaNotReady("native account subject mapping is incomplete")
        for account_id, subject_id, status in conn.execute(
            "SELECT local_account_id, subject_id, status FROM LocalAccountSubjects"
        ):
            try:
                canonical_uuid(subject_id)
            except ValueError as exc:
                raise SchemaNotReady("native account subject is invalid") from exc
            if status not in {"active", "disabled"}:
                raise SchemaNotReady("native account subject status is invalid")
        for issuer, subject, account_id, username, email, salt, hashed in conn.execute(
            """
            SELECT b.issuer_deployment_id, b.remote_subject_id, b.local_account_id,
                   a.username, a.email, a.pass_salt, a.pass_hash
            FROM FederatedAccountBindings b
            JOIN Accounts a ON a.acc_id = b.local_account_id
            """
        ):
            try:
                expected_username, expected_email = federated_proxy_adapter(
                    issuer, subject
                )
            except ValueError as exc:
                raise SchemaNotReady("federated account identity is invalid") from exc
            if (
                username != expected_username
                or email != expected_email
                or salt != FEDERATED_PASSWORD_SALT
                or hashed != FEDERATED_PASSWORD_HASH
            ):
                raise SchemaNotReady("federated proxy adapter is incoherent")
            bindings[int(account_id)] = (issuer, subject)
    with sqlite3.connect(root / "usergroups.db") as conn:
        configure_connection(conn)
        if conn.execute("PRAGMA foreign_key_check").fetchone():
            raise SchemaNotReady("usergroups.db foreign-key state is invalid")
        tables = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if not {"FederatedPrincipals", "SchemaMigrations"}.issubset(tables):
            raise SchemaNotReady("usergroups.db Gate C schema is incomplete")
        row = conn.execute(
            "SELECT checksum FROM SchemaMigrations WHERE name = ?", (MIGRATION_NAME,)
        ).fetchone()
        if row is None or row[0] != _MIGRATION_CHECKSUM:
            raise SchemaNotReady("Gate C migration ledger is missing or invalid")
        for row in conn.execute(
            "SELECT id, issuer_deployment_id, remote_subject_id, local_account_id, "
            "status, disabled_at, display_metadata_json FROM FederatedPrincipals"
        ):
            principal_id, issuer, subject, account_id, status, disabled_at, metadata = row
            try:
                canonical_uuid(principal_id)
                canonical_uuid(issuer)
                canonical_uuid(subject)
                validate_display_metadata(strict_json(metadata, max_bytes=2048))
            except ValueError as exc:
                raise SchemaNotReady("federated principal state is invalid") from exc
            if bindings.get(int(account_id)) != (issuer, subject):
                raise SchemaNotReady("federated principal binding is incoherent")
            if status not in {"active", "disabled"} or (
                status == "active" and disabled_at is not None
            ) or (
                status == "disabled" and disabled_at is None
            ):
                raise SchemaNotReady("federated principal status is incoherent")
