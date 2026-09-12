"""Small additive Gate C schemas for the protected Server databases."""

from __future__ import annotations

import hashlib
import sqlite3
import time
from pathlib import Path
from uuid import UUID, uuid5

from remoterf_federation_core import (
    canonical_uuid,
    contract_terms_sha256,
    federated_proxy_adapter,
    strict_json,
    validate_contract_event_claims,
    validate_contract_terms,
    validate_display_metadata,
    validate_trusted_key_material,
)

AUTH_TYPES = frozenset({"local_password", "federated"})
MIGRATION_VERSION = 2
MIGRATION_NAME = "gate_c_identity_v2"
GATE_D_MIGRATION_VERSION = 3
GATE_D_MIGRATION_NAME = "gate_d_trust_contracts_v1"
GATE_E_MIGRATION_VERSION = 4
GATE_E_MIGRATION_NAME = "gate_e_grant_jtis_v1"
GATE_E1_MIGRATION_VERSION = 5
GATE_E1_MIGRATION_NAME = "gate_e1_clock_floor_v1"
GATE_F_MIGRATION_VERSION = 6
GATE_F_MIGRATION_NAME = "gate_f_enrollment_receipts_v1"
GATE_H_MIGRATION_VERSION = 7
GATE_H_MIGRATION_NAME = "gate_h_device_federation_v1"
# The Gate E replay table pinned the two control actions in a CHECK. Device
# actions consume the same one-time JTIs, so the constraint is widened here by
# an ordinary SQLite table rebuild; evidence rows are copied, never dropped.
GATE_H_JTI_ACTIONS = (
    "federated_enroll",
    "permissions_read",
    "device_list",
    "device_reserve",
    "device_reservations",
    "device_cancel",
    "device_rpc",
)
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

_GATE_D_DDL = """
CREATE TABLE IF NOT EXISTS TrustedDeploymentKeys (
    deployment_id TEXT NOT NULL,
    kid TEXT NOT NULL,
    public_key_b64 TEXT NOT NULL,
    public_key_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('active','revoked')),
    valid_from INTEGER NOT NULL,
    valid_until INTEGER,
    approved_at INTEGER NOT NULL,
    approved_by TEXT NOT NULL,
    approval_source TEXT NOT NULL,
    PRIMARY KEY(deployment_id,kid),
    CHECK(length(deployment_id)=36),
    CHECK(length(public_key_sha256)=64),
    CHECK(valid_until IS NULL OR valid_until > valid_from)
);
CREATE TABLE IF NOT EXISTS FederationContracts (
    contract_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version > 0),
    deployment_a TEXT NOT NULL,
    deployment_b TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN
      ('proposed','accepted','active','suspended','revoked','expired')),
    valid_from INTEGER NOT NULL,
    valid_until INTEGER NOT NULL CHECK(valid_until > valid_from),
    allowed_capabilities_json TEXT NOT NULL,
    key_a_kid TEXT NOT NULL,
    key_a_sha256 TEXT NOT NULL,
    key_b_kid TEXT NOT NULL,
    key_b_sha256 TEXT NOT NULL,
    terms_sha256 TEXT NOT NULL,
    supersedes_version INTEGER,
    superseded_by_version INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(contract_id,version),
    CHECK(deployment_a < deployment_b),
    CHECK(length(contract_id)=36),
    CHECK(length(deployment_a)=36),
    CHECK(length(deployment_b)=36),
    CHECK(length(key_a_sha256)=64),
    CHECK(length(key_b_sha256)=64),
    CHECK(length(terms_sha256)=64),
    CHECK(supersedes_version IS NULL OR supersedes_version < version),
    CHECK(superseded_by_version IS NULL OR superseded_by_version > version)
);
CREATE UNIQUE INDEX IF NOT EXISTS FederationContracts_one_active
ON FederationContracts(contract_id)
WHERE state='active' AND superseded_by_version IS NULL;
CREATE TABLE IF NOT EXISTS FederationContractEvents (
    event_id TEXT PRIMARY KEY,
    contract_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    actor_deployment_id TEXT NOT NULL,
    actor_sequence INTEGER NOT NULL CHECK(actor_sequence > 0),
    event_type TEXT NOT NULL CHECK(event_type IN
      ('propose','accept','activate','suspend','revoke','supersede')),
    terms_sha256 TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    actor_admin_ref TEXT,
    reason_code TEXT NOT NULL,
    signed_event TEXT NOT NULL,
    UNIQUE(contract_id,actor_deployment_id,actor_sequence),
    FOREIGN KEY(contract_id,version)
      REFERENCES FederationContracts(contract_id,version)
);
CREATE TABLE IF NOT EXISTS FederationAuditEvents (
    id TEXT PRIMARY KEY,
    occurred_at INTEGER NOT NULL,
    actor_kind TEXT NOT NULL CHECK(actor_kind IN
      ('native_user','local_admin','deployment')),
    actor_ref TEXT NOT NULL,
    event_type TEXT NOT NULL,
    principal_id TEXT,
    contract_id TEXT,
    version INTEGER,
    request_id TEXT,
    result_code TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS TrustedDeploymentKeys_material_immutable
BEFORE UPDATE OF deployment_id,kid,public_key_b64,public_key_sha256,
  valid_from,valid_until,approved_at,approved_by,approval_source
ON TrustedDeploymentKeys
BEGIN SELECT RAISE(ABORT,'trusted key material is immutable'); END;
CREATE TRIGGER IF NOT EXISTS TrustedDeploymentKeys_no_reactivate
BEFORE UPDATE OF state ON TrustedDeploymentKeys
WHEN OLD.state='revoked' AND NEW.state!='revoked'
BEGIN SELECT RAISE(ABORT,'revoked trusted key is terminal'); END;
CREATE TRIGGER IF NOT EXISTS TrustedDeploymentKeys_no_delete
BEFORE DELETE ON TrustedDeploymentKeys
BEGIN SELECT RAISE(ABORT,'trusted key evidence is retained'); END;
CREATE TRIGGER IF NOT EXISTS FederationContracts_terms_immutable
BEFORE UPDATE OF contract_id,version,deployment_a,deployment_b,valid_from,
  valid_until,allowed_capabilities_json,key_a_kid,key_a_sha256,key_b_kid,
  key_b_sha256,terms_sha256,supersedes_version
ON FederationContracts
BEGIN SELECT RAISE(ABORT,'contract terms are immutable'); END;
CREATE TRIGGER IF NOT EXISTS FederationContracts_no_unrevoke
BEFORE UPDATE OF state ON FederationContracts
WHEN OLD.state='revoked' AND NEW.state!='revoked'
BEGIN SELECT RAISE(ABORT,'revoked contract is terminal'); END;
CREATE TRIGGER IF NOT EXISTS FederationContracts_no_delete
BEFORE DELETE ON FederationContracts
BEGIN SELECT RAISE(ABORT,'contract tombstone is retained'); END;
CREATE TRIGGER IF NOT EXISTS FederationContractEvents_append_only_update
BEFORE UPDATE ON FederationContractEvents
BEGIN SELECT RAISE(ABORT,'contract events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS FederationContractEvents_append_only_delete
BEFORE DELETE ON FederationContractEvents
BEGIN SELECT RAISE(ABORT,'contract events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS FederationAuditEvents_append_only_update
BEFORE UPDATE ON FederationAuditEvents
BEGIN SELECT RAISE(ABORT,'federation audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS FederationAuditEvents_append_only_delete
BEFORE DELETE ON FederationAuditEvents
BEGIN SELECT RAISE(ABORT,'federation audit is append-only'); END;
"""

_GATE_D_MIGRATION_CHECKSUM = hashlib.sha256(_GATE_D_DDL.encode("utf-8")).hexdigest()

_GATE_E_DDL = """
CREATE TABLE IF NOT EXISTS FederationGrantJTIs (
    issuer_deployment_id TEXT NOT NULL,
    jti TEXT NOT NULL,
    remote_subject_id TEXT NOT NULL,
    destination_deployment_id TEXT NOT NULL,
    contract_id TEXT NOT NULL,
    contract_version INTEGER NOT NULL CHECK(contract_version > 0),
    terms_sha256 TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('federated_enroll','permissions_read')),
    request_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    retain_until INTEGER NOT NULL,
    consumed_at INTEGER NOT NULL,
    PRIMARY KEY(issuer_deployment_id,jti),
    CHECK(length(issuer_deployment_id)=36),
    CHECK(length(jti)=36),
    CHECK(length(remote_subject_id)=36),
    CHECK(length(destination_deployment_id)=36),
    CHECK(length(contract_id)=36),
    CHECK(length(terms_sha256)=64),
    CHECK(length(request_id)=36),
    CHECK(length(request_sha256)=64),
    CHECK(retain_until=expires_at+5),
    CHECK(consumed_at < expires_at)
);
CREATE INDEX IF NOT EXISTS FederationGrantJTIs_retention
ON FederationGrantJTIs(retain_until);
CREATE TRIGGER IF NOT EXISTS FederationGrantJTIs_append_only_update
BEFORE UPDATE ON FederationGrantJTIs
BEGIN SELECT RAISE(ABORT,'federation grant JTI evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS FederationGrantJTIs_retain_delete
BEFORE DELETE ON FederationGrantJTIs
WHEN CAST(strftime('%s','now') AS INTEGER) <= OLD.retain_until
BEGIN SELECT RAISE(ABORT,'federation grant JTI is retained'); END;
"""

_GATE_E_MIGRATION_CHECKSUM = hashlib.sha256(_GATE_E_DDL.encode("utf-8")).hexdigest()

_GATE_E1_DDL = """
CREATE TABLE IF NOT EXISTS FederationClockState (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    max_seen_at INTEGER NOT NULL CHECK(max_seen_at >= 0)
);
INSERT OR IGNORE INTO FederationClockState(singleton_id,max_seen_at) VALUES (1,0);
"""

_GATE_E1_MIGRATION_CHECKSUM = hashlib.sha256(
    _GATE_E1_DDL.encode("utf-8")
).hexdigest()

_GATE_F_COLUMNS = (
    ("federation_contract_id", "TEXT"),
    ("federation_contract_version", "INTEGER"),
    ("allowed_issuer_deployment_id", "TEXT"),
    ("federation_expires_at", "INTEGER"),
)

_GATE_F_DDL = """
CREATE TABLE IF NOT EXISTS EnrollmentRedemptions (
    id TEXT PRIMARY KEY,
    code_id INTEGER NOT NULL,
    code_sha256 TEXT NOT NULL,
    group_id INTEGER NOT NULL,
    principal_id TEXT NOT NULL,
    local_account_id INTEGER NOT NULL,
    issuer_deployment_id TEXT NOT NULL,
    remote_subject_id TEXT NOT NULL,
    contract_id TEXT NOT NULL,
    contract_version INTEGER NOT NULL CHECK(contract_version > 0),
    request_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    redeemed_at INTEGER NOT NULL,
    membership_added INTEGER NOT NULL CHECK(membership_added IN (0,1)),
    UNIQUE(issuer_deployment_id,remote_subject_id,request_id),
    CHECK(length(id)=36),
    CHECK(length(code_sha256)=64),
    CHECK(length(principal_id)=36),
    CHECK(length(issuer_deployment_id)=36),
    CHECK(length(remote_subject_id)=36),
    CHECK(length(contract_id)=36),
    CHECK(length(request_id)=36),
    CHECK(length(request_sha256)=64)
);
CREATE INDEX IF NOT EXISTS EnrollmentRedemptions_request_lookup
ON EnrollmentRedemptions(issuer_deployment_id,remote_subject_id,request_id);
CREATE TRIGGER IF NOT EXISTS EnrollmentRedemptions_append_only_update
BEFORE UPDATE ON EnrollmentRedemptions
BEGIN SELECT RAISE(ABORT,'enrollment receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS EnrollmentRedemptions_append_only_delete
BEFORE DELETE ON EnrollmentRedemptions
BEGIN SELECT RAISE(ABORT,'enrollment receipts are append-only'); END;
CREATE TRIGGER IF NOT EXISTS EnrollmentCodes_federation_shape_insert
BEFORE INSERT ON EnrollmentCodes
WHEN NOT (
  (NEW.federation_contract_id IS NULL
   AND NEW.federation_contract_version IS NULL
   AND NEW.allowed_issuer_deployment_id IS NULL
   AND NEW.federation_expires_at IS NULL)
  OR
  (NEW.federation_contract_id IS NOT NULL
   AND NEW.federation_contract_version > 0
   AND NEW.allowed_issuer_deployment_id IS NOT NULL
   AND ((NEW.duration_sec = 0 AND NEW.federation_expires_at IS NULL)
        OR (NEW.duration_sec > 0 AND NEW.federation_expires_at IS NOT NULL)))
)
BEGIN SELECT RAISE(ABORT,'invalid federation enrollment code shape'); END;
CREATE TRIGGER IF NOT EXISTS EnrollmentCodes_federation_shape_update
BEFORE UPDATE OF federation_contract_id,federation_contract_version,
  allowed_issuer_deployment_id,federation_expires_at,duration_sec
ON EnrollmentCodes
WHEN NOT (
  (NEW.federation_contract_id IS NULL
   AND NEW.federation_contract_version IS NULL
   AND NEW.allowed_issuer_deployment_id IS NULL
   AND NEW.federation_expires_at IS NULL)
  OR
  (NEW.federation_contract_id IS NOT NULL
   AND NEW.federation_contract_version > 0
   AND NEW.allowed_issuer_deployment_id IS NOT NULL
   AND ((NEW.duration_sec = 0 AND NEW.federation_expires_at IS NULL)
        OR (NEW.duration_sec > 0 AND NEW.federation_expires_at IS NOT NULL)))
)
BEGIN SELECT RAISE(ABORT,'invalid federation enrollment code shape'); END;
"""

_GATE_F_MIGRATION_CHECKSUM = hashlib.sha256(
    (repr(_GATE_F_COLUMNS) + _GATE_F_DDL).encode("utf-8")
).hexdigest()


_GATE_H_JTI_ACTION_CHECK = ",".join(f"'{name}'" for name in GATE_H_JTI_ACTIONS)

_GATE_H_JTI_REBUILD = f"""
CREATE TABLE IF NOT EXISTS FederationGrantJTIsGateH (
    issuer_deployment_id TEXT NOT NULL,
    jti TEXT NOT NULL,
    remote_subject_id TEXT NOT NULL,
    destination_deployment_id TEXT NOT NULL,
    contract_id TEXT NOT NULL,
    contract_version INTEGER NOT NULL CHECK(contract_version > 0),
    terms_sha256 TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ({_GATE_H_JTI_ACTION_CHECK})),
    request_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    retain_until INTEGER NOT NULL,
    consumed_at INTEGER NOT NULL,
    PRIMARY KEY(issuer_deployment_id,jti),
    CHECK(length(issuer_deployment_id)=36),
    CHECK(length(jti)=36),
    CHECK(length(remote_subject_id)=36),
    CHECK(length(destination_deployment_id)=36),
    CHECK(length(contract_id)=36),
    CHECK(length(terms_sha256)=64),
    CHECK(length(request_id)=36),
    CHECK(length(request_sha256)=64),
    CHECK(retain_until=expires_at+5),
    CHECK(consumed_at < expires_at)
);
INSERT OR IGNORE INTO FederationGrantJTIsGateH
SELECT issuer_deployment_id,jti,remote_subject_id,destination_deployment_id,
       contract_id,contract_version,terms_sha256,action,request_id,
       request_sha256,expires_at,retain_until,consumed_at
FROM FederationGrantJTIs;
DROP TABLE FederationGrantJTIs;
ALTER TABLE FederationGrantJTIsGateH RENAME TO FederationGrantJTIs;
CREATE INDEX IF NOT EXISTS FederationGrantJTIs_retention
ON FederationGrantJTIs(retain_until);
CREATE TRIGGER IF NOT EXISTS FederationGrantJTIs_append_only_update
BEFORE UPDATE ON FederationGrantJTIs
BEGIN SELECT RAISE(ABORT,'federation grant JTI evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS FederationGrantJTIs_retain_delete
BEFORE DELETE ON FederationGrantJTIs
WHEN CAST(strftime('%s','now') AS INTEGER) <= OLD.retain_until
BEGIN SELECT RAISE(ABORT,'federation grant JTI is retained'); END;
"""

_GATE_H_DDL = """
CREATE TABLE IF NOT EXISTS FederatedDeviceReceipts (
    receipt_id TEXT PRIMARY KEY,
    issuer_deployment_id TEXT NOT NULL,
    remote_subject_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    action TEXT NOT NULL,
    local_device_id INTEGER,
    reservation_id INTEGER,
    contract_id TEXT NOT NULL,
    contract_version INTEGER NOT NULL CHECK(contract_version > 0),
    occurred_at INTEGER NOT NULL,
    result_code TEXT NOT NULL,
    UNIQUE(issuer_deployment_id,request_id,action),
    CHECK(length(receipt_id)=36),
    CHECK(length(issuer_deployment_id)=36),
    CHECK(length(remote_subject_id)=36),
    CHECK(length(request_id)=36),
    CHECK(length(contract_id)=36)
);
CREATE INDEX IF NOT EXISTS FederatedDeviceReceipts_principal
ON FederatedDeviceReceipts(issuer_deployment_id,remote_subject_id);
CREATE TRIGGER IF NOT EXISTS FederatedDeviceReceipts_append_only_update
BEFORE UPDATE ON FederatedDeviceReceipts
BEGIN SELECT RAISE(ABORT,'federated device receipts are append-only'); END;
"""

_GATE_H_MIGRATION_CHECKSUM = hashlib.sha256(
    (_GATE_H_JTI_REBUILD + _GATE_H_DDL).encode("utf-8")
).hexdigest()

# Written into reservations.db so a federated reservation row and the record
# authorizing it commit together in one transaction.
_GATE_H_RESERVATIONS_DDL = """
CREATE TABLE IF NOT EXISTS FederatedReservations (
    res_id INTEGER PRIMARY KEY,
    issuer_deployment_id TEXT NOT NULL,
    remote_subject_id TEXT NOT NULL,
    local_account_id INTEGER NOT NULL,
    contract_id TEXT NOT NULL,
    contract_version INTEGER NOT NULL CHECK(contract_version > 0),
    request_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(issuer_deployment_id,request_id),
    CHECK(length(issuer_deployment_id)=36),
    CHECK(length(remote_subject_id)=36),
    CHECK(length(contract_id)=36),
    CHECK(length(request_id)=36)
);
CREATE INDEX IF NOT EXISTS FederatedReservations_principal
ON FederatedReservations(issuer_deployment_id,remote_subject_id);
"""

_GATE_H_RESERVATIONS_CHECKSUM = hashlib.sha256(
    _GATE_H_RESERVATIONS_DDL.encode("utf-8")
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


def migrate_gate_d_usergroups_schema(conn: sqlite3.Connection) -> None:
    """Install the additive Gate D owner-local schema and append-only guards."""

    migrate_usergroups_schema(conn)
    row = conn.execute(
        "SELECT checksum FROM SchemaMigrations WHERE name = ?",
        (GATE_D_MIGRATION_NAME,),
    ).fetchone()
    if row is not None and row[0] != _GATE_D_MIGRATION_CHECKSUM:
        raise SchemaNotReady("Gate D migration checksum mismatch")
    conn.executescript(_GATE_D_DDL)
    conn.execute(
        "INSERT OR IGNORE INTO SchemaMigrations "
        "(version,name,checksum,applied_at) VALUES (?,?,?,?)",
        (
            GATE_D_MIGRATION_VERSION,
            GATE_D_MIGRATION_NAME,
            _GATE_D_MIGRATION_CHECKSUM,
            int(time.time()),
        ),
    )


def migrate_gate_d(db_dir: str | Path) -> None:
    """Idempotently prepare Gate C identity plus Gate D contract state."""

    migrate_gate_c(db_dir)
    with sqlite3.connect(Path(db_dir) / "usergroups.db") as conn:
        migrate_gate_d_usergroups_schema(conn)


def migrate_gate_e_usergroups_schema(conn: sqlite3.Connection) -> None:
    """Install only Gate E replay state; no enrollment receipt or membership schema."""

    migrate_gate_d_usergroups_schema(conn)
    row = conn.execute(
        "SELECT checksum FROM SchemaMigrations WHERE name=?",
        (GATE_E_MIGRATION_NAME,),
    ).fetchone()
    if row is not None and row[0] != _GATE_E_MIGRATION_CHECKSUM:
        raise SchemaNotReady("Gate E migration checksum mismatch")
    conn.executescript(_GATE_E_DDL)
    conn.execute(
        "INSERT OR IGNORE INTO SchemaMigrations "
        "(version,name,checksum,applied_at) VALUES (?,?,?,?)",
        (
            GATE_E_MIGRATION_VERSION,
            GATE_E_MIGRATION_NAME,
            _GATE_E_MIGRATION_CHECKSUM,
            int(time.time()),
        ),
    )
    row = conn.execute(
        "SELECT checksum FROM SchemaMigrations WHERE name=?",
        (GATE_E1_MIGRATION_NAME,),
    ).fetchone()
    if row is not None and row[0] != _GATE_E1_MIGRATION_CHECKSUM:
        raise SchemaNotReady("Gate E.1 migration checksum mismatch")
    conn.executescript(_GATE_E1_DDL)
    conn.execute(
        "INSERT OR IGNORE INTO SchemaMigrations "
        "(version,name,checksum,applied_at) VALUES (?,?,?,?)",
        (
            GATE_E1_MIGRATION_VERSION,
            GATE_E1_MIGRATION_NAME,
            _GATE_E1_MIGRATION_CHECKSUM,
            int(time.time()),
        ),
    )


def migrate_gate_e(db_dir: str | Path) -> None:
    migrate_gate_c(db_dir)
    with sqlite3.connect(Path(db_dir) / "usergroups.db") as conn:
        migrate_gate_e_usergroups_schema(conn)


def migrate_gate_f_usergroups_schema(conn: sqlite3.Connection) -> None:
    """Add only destination code restrictions and durable redemption receipts."""

    migrate_gate_e_usergroups_schema(conn)
    row = conn.execute(
        "SELECT checksum FROM SchemaMigrations WHERE name=?",
        (GATE_F_MIGRATION_NAME,),
    ).fetchone()
    if row is not None and row[0] != _GATE_F_MIGRATION_CHECKSUM:
        raise SchemaNotReady("Gate F migration checksum mismatch")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS UserGroups (
            group_id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name TEXT NOT NULL UNIQUE,
            devices_whitelist TEXT NOT NULL DEFAULT '[]',
            max_reservation_time_sec INTEGER NOT NULL,
            max_reservations INTEGER NOT NULL,
            lifetime_sec INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS UsersLookup (
            user_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            PRIMARY KEY(user_id,group_id)
        );
        CREATE TABLE IF NOT EXISTS EnrollmentCodes (
            code_id INTEGER PRIMARY KEY AUTOINCREMENT,
            code_name TEXT NOT NULL UNIQUE,
            group_id INTEGER NOT NULL,
            uses INTEGER NOT NULL,
            duration_sec INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    columns = {str(item[1]) for item in conn.execute("PRAGMA table_info(EnrollmentCodes)")}
    for name, sql_type in _GATE_F_COLUMNS:
        if name not in columns:
            conn.execute(f"ALTER TABLE EnrollmentCodes ADD COLUMN {name} {sql_type}")
    conn.executescript(_GATE_F_DDL)
    conn.execute(
        "INSERT OR IGNORE INTO SchemaMigrations "
        "(version,name,checksum,applied_at) VALUES (?,?,?,?)",
        (
            GATE_F_MIGRATION_VERSION,
            GATE_F_MIGRATION_NAME,
            _GATE_F_MIGRATION_CHECKSUM,
            int(time.time()),
        ),
    )


def migrate_gate_f(db_dir: str | Path) -> None:
    migrate_gate_c(db_dir)
    with sqlite3.connect(Path(db_dir) / "usergroups.db") as conn:
        migrate_gate_f_usergroups_schema(conn)


def _gate_h_jti_needs_rebuild(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        ("FederationGrantJTIs",),
    ).fetchone()
    return row is not None and "'device_rpc'" not in (row[0] or "")


def migrate_gate_h_usergroups_schema(conn: sqlite3.Connection) -> None:
    """Widen one-time grant replay state to device actions, additively."""

    migrate_gate_f_usergroups_schema(conn)
    row = conn.execute(
        "SELECT checksum FROM SchemaMigrations WHERE name=?",
        (GATE_H_MIGRATION_NAME,),
    ).fetchone()
    if row is not None and row[0] != _GATE_H_MIGRATION_CHECKSUM:
        raise SchemaNotReady("Gate H migration checksum mismatch")
    if _gate_h_jti_needs_rebuild(conn):
        conn.executescript(_GATE_H_JTI_REBUILD)
    conn.executescript(_GATE_H_DDL)
    conn.execute(
        "INSERT OR IGNORE INTO SchemaMigrations "
        "(version,name,checksum,applied_at) VALUES (?,?,?,?)",
        (
            GATE_H_MIGRATION_VERSION,
            GATE_H_MIGRATION_NAME,
            _GATE_H_MIGRATION_CHECKSUM,
            int(time.time()),
        ),
    )


def migrate_gate_h_reservations_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(_GATE_H_RESERVATIONS_DDL)


def migrate_gate_h(db_dir: str | Path) -> None:
    migrate_gate_c(db_dir)
    with sqlite3.connect(Path(db_dir) / "usergroups.db") as conn:
        configure_connection(conn)
        migrate_gate_h_usergroups_schema(conn)
    with sqlite3.connect(Path(db_dir) / "reservations.db") as conn:
        configure_connection(conn)
        migrate_gate_h_reservations_schema(conn)


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


def check_gate_d_ready(
    usergroups_path: str | Path, *, local_deployment_id: str | None = None
) -> None:
    """Validate Gate D owner-local tables without requiring any contract rows."""

    local_deployment_id = (
        None if local_deployment_id is None else canonical_uuid(local_deployment_id)
    )
    with sqlite3.connect(Path(usergroups_path)) as conn:
        configure_connection(conn)
        tables = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        required = {
            "TrustedDeploymentKeys",
            "FederationContracts",
            "FederationContractEvents",
            "FederationAuditEvents",
            "SchemaMigrations",
        }
        if not required.issubset(tables):
            raise SchemaNotReady("usergroups.db Gate D schema is incomplete")
        ledger = conn.execute(
            "SELECT checksum FROM SchemaMigrations WHERE name=?",
            (GATE_D_MIGRATION_NAME,),
        ).fetchone()
        if ledger is None or ledger[0] != _GATE_D_MIGRATION_CHECKSUM:
            raise SchemaNotReady("Gate D migration ledger is missing or invalid")
        if conn.execute("PRAGMA foreign_key_check").fetchone():
            raise SchemaNotReady("usergroups.db Gate D foreign-key state is invalid")
        keys = {}
        for row in conn.execute(
            "SELECT deployment_id,kid,public_key_b64,public_key_sha256,state,"
            "valid_from,valid_until,approved_at,approved_by,approval_source "
            "FROM TrustedDeploymentKeys"
        ):
            material = validate_trusted_key_material(
                {
                    "deployment_id": row[0],
                    "kid": row[1],
                    "public_key_b64": row[2],
                    "public_key_sha256": row[3],
                    "valid_from": row[5],
                    "valid_until": row[6],
                }
            )
            if row[4] not in {"active", "revoked"} or any(
                type(value) is not str or not value or len(value) > 256
                for value in (row[8], row[9])
            ):
                raise SchemaNotReady("trusted key approval state is invalid")
            keys[(material["deployment_id"], material["kid"])] = (
                material["public_key_sha256"],
                row[4],
            )
        terms_by_version = {}
        for row in conn.execute(
            "SELECT contract_id,version,deployment_a,deployment_b,state,valid_from,"
            "valid_until,allowed_capabilities_json,key_a_kid,key_a_sha256,"
            "key_b_kid,key_b_sha256,terms_sha256,supersedes_version,"
            "superseded_by_version FROM FederationContracts"
        ):
            terms = validate_contract_terms(
                {
                    "contract_id": row[0],
                    "version": row[1],
                    "deployment_a": row[2],
                    "deployment_b": row[3],
                    "valid_from": row[5],
                    "valid_until": row[6],
                    "allowed_capabilities": strict_json(row[7], max_bytes=512),
                    "key_a_kid": row[8],
                    "key_a_sha256": row[9],
                    "key_b_kid": row[10],
                    "key_b_sha256": row[11],
                    "supersedes_version": row[13],
                }
            )
            if (
                row[4] not in {"proposed", "accepted", "active", "suspended", "revoked", "expired"}
                or contract_terms_sha256(terms) != row[12]
                or (
                    local_deployment_id is not None
                    and local_deployment_id
                    not in {terms.deployment_a, terms.deployment_b}
                )
            ):
                raise SchemaNotReady("federation contract state is invalid")
            if keys.get((terms.deployment_a, terms.key_a_kid), (None,))[0] != terms.key_a_sha256:
                raise SchemaNotReady("contract participant A key binding is invalid")
            if keys.get((terms.deployment_b, terms.key_b_kid), (None,))[0] != terms.key_b_sha256:
                raise SchemaNotReady("contract participant B key binding is invalid")
            terms_by_version[(terms.contract_id, terms.version)] = terms
            if row[14] is not None and row[14] <= terms.version:
                raise SchemaNotReady("contract supersession link is invalid")
        for row in conn.execute(
            "SELECT event_id,contract_id,version,actor_deployment_id,actor_sequence,"
            "event_type,terms_sha256,occurred_at,actor_admin_ref,reason_code "
            "FROM FederationContractEvents"
        ):
            terms = terms_by_version.get((row[1], row[2]))
            if terms is None:
                raise SchemaNotReady("contract event references unknown terms")
            validate_contract_event_claims(
                {
                    "token_type": "federation_contract_event",
                    "protocol_version": "2",
                    "iss": row[3],
                    "event_id": row[0],
                    "contract_id": row[1],
                    "contract_version": row[2],
                    "event_type": row[5],
                    "terms_sha256": row[6],
                    "actor_sequence": row[4],
                    "occurred_at": row[7],
                    "actor_admin_ref": row[8],
                    "reason_code": row[9],
                },
                terms,
            )
        for (metadata,) in conn.execute(
            "SELECT metadata_json FROM FederationAuditEvents"
        ):
            value = strict_json(metadata, max_bytes=2048)
            if type(value) is not dict:
                raise SchemaNotReady("federation audit metadata is invalid")


def check_gate_e_ready(
    usergroups_path: str | Path, *, local_deployment_id: str | None = None
) -> None:
    """Validate Gate E replay state without requiring any live contract."""

    check_gate_d_ready(
        usergroups_path, local_deployment_id=local_deployment_id
    )
    with sqlite3.connect(Path(usergroups_path)) as conn:
        configure_connection(conn)
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        ledger = conn.execute(
            "SELECT checksum FROM SchemaMigrations WHERE name=?",
            (GATE_E_MIGRATION_NAME,),
        ).fetchone()
        clock_ledger = conn.execute(
            "SELECT checksum FROM SchemaMigrations WHERE name=?",
            (GATE_E1_MIGRATION_NAME,),
        ).fetchone()
        clock_row = conn.execute(
            "SELECT max_seen_at FROM FederationClockState WHERE singleton_id=1"
        ).fetchone() if "FederationClockState" in tables else None
        if (
            not {"FederationGrantJTIs", "FederationClockState"}.issubset(tables)
            or ledger is None
            or ledger[0] != _GATE_E_MIGRATION_CHECKSUM
            or clock_ledger is None
            or clock_ledger[0] != _GATE_E1_MIGRATION_CHECKSUM
            or clock_row is None
            or type(clock_row[0]) is not int
            or clock_row[0] < 0
        ):
            raise SchemaNotReady("Gate E migration ledger is missing or invalid")
        for row in conn.execute(
            "SELECT issuer_deployment_id,jti,remote_subject_id,"
            "destination_deployment_id,contract_id,contract_version,terms_sha256,"
            "action,request_id,request_sha256,expires_at,retain_until,consumed_at "
            "FROM FederationGrantJTIs"
        ):
            for value in (row[0], row[1], row[2], row[3], row[4], row[8]):
                canonical_uuid(value)
            if (
                type(row[5]) is not int
                or row[5] <= 0
                or row[7] not in {"federated_enroll", "permissions_read"}
                or row[11] != row[10] + 5
                or not row[12] < row[10]
            ):
                raise SchemaNotReady("Federation grant JTI state is invalid")
            from remoterf_federation_core import validate_sha256

            validate_sha256(row[6], code="invalid_terms_hash")
            validate_sha256(row[9], code="invalid_request_hash")


def check_gate_f_ready(
    usergroups_path: str | Path, *, local_deployment_id: str | None = None
) -> None:
    """Validate Gate F additive columns, receipt ledger, and stored rows."""

    from remoterf_federation_core import validate_sha256

    check_gate_e_ready(
        usergroups_path, local_deployment_id=local_deployment_id
    )
    with sqlite3.connect(Path(usergroups_path)) as conn:
        configure_connection(conn)
        tables = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        ledger = conn.execute(
            "SELECT checksum FROM SchemaMigrations WHERE name=?",
            (GATE_F_MIGRATION_NAME,),
        ).fetchone()
        columns = {
            str(row[1]) for row in conn.execute("PRAGMA table_info(EnrollmentCodes)")
        }
        if (
            "EnrollmentRedemptions" not in tables
            or ledger is None
            or ledger[0] != _GATE_F_MIGRATION_CHECKSUM
            or not {name for name, _ in _GATE_F_COLUMNS}.issubset(columns)
        ):
            raise SchemaNotReady("Gate F migration ledger is missing or invalid")
        for row in conn.execute(
            "SELECT federation_contract_id,federation_contract_version,"
            "allowed_issuer_deployment_id,federation_expires_at,duration_sec "
            "FROM EnrollmentCodes"
        ):
            unrestricted = all(row[index] is None for index in range(4))
            restricted = (
                row[0] is not None
                and type(row[1]) is int
                and row[1] > 0
                and row[2] is not None
                and ((row[4] == 0 and row[3] is None) or (row[4] > 0 and row[3] is not None))
            )
            if not unrestricted and not restricted:
                raise SchemaNotReady("Gate F enrollment-code restriction shape is invalid")
            if restricted:
                canonical_uuid(row[0])
                canonical_uuid(row[2])
        for row in conn.execute(
            "SELECT id,code_sha256,principal_id,issuer_deployment_id,remote_subject_id,"
            "contract_id,contract_version,request_id,request_sha256,membership_added "
            "FROM EnrollmentRedemptions"
        ):
            for value in (row[0], row[2], row[3], row[4], row[5], row[7]):
                canonical_uuid(value)
            validate_sha256(row[1], code="invalid_code_hash")
            validate_sha256(row[8], code="invalid_request_hash")
            if type(row[6]) is not int or row[6] <= 0 or row[9] not in (0, 1):
                raise SchemaNotReady("Gate F enrollment receipt is invalid")
