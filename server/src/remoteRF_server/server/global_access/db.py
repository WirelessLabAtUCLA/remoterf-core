# Copyright (C) 2026 RemoteRF
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
global.db — RemoteRF Global principal mappings, assertion replay guard, and
local session tokens. Same conventions as perms.db/reservations.db/
usergroups.db: raw sqlite3, one file under get_db_dir(), CREATE TABLE IF NOT
EXISTS, @db_connection per call. No SQLAlchemy/Alembic.

Never stores: complete JWTs, passwords, private keys.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from ...common.utils.db_connection import db_connection
from ...common.utils.db_location import get_db_dir
from ...common.utils.api_token import generate_token, validate_token


@dataclass
class PrincipalMapping:
    id: int
    issuer: str
    global_subject: str
    local_account_id: int
    status: str
    created_at: str
    last_seen_at: Optional[str]
    disabled_at: Optional[str]
    metadata_json: str


class GlobalDB:
    def __init__(self, db_dir: Optional[Path] = None):
        self.filepath = (db_dir or get_db_dir()) / "global.db"
        self.db = sqlite3.connect(str(self.filepath))
        self.cursor = self.db.cursor()

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS GlobalPrincipalMappings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issuer TEXT NOT NULL,
                global_subject TEXT NOT NULL,
                local_account_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen_at TIMESTAMP,
                disabled_at TIMESTAMP,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                UNIQUE(issuer, global_subject)
            );
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS GlobalAssertionJTIs (
                issuer TEXT NOT NULL,
                jti TEXT NOT NULL,
                global_subject TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                consumed_at TIMESTAMP NOT NULL,
                PRIMARY KEY (issuer, jti)
            );
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS GlobalLocalSessions (
                session_hash TEXT NOT NULL PRIMARY KEY,
                session_salt TEXT NOT NULL,
                mapping_id INTEGER NOT NULL,
                local_account_id INTEGER NOT NULL,
                issued_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                revoked_at TIMESTAMP
            );
            """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS GlobalCatalogState (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL DEFAULT 0,
                content_hash TEXT,
                published_at TIMESTAMP
            );
            """
        )
        self.db.commit()
        self.cursor.close()
        self.db.close()
        self.lock = threading.RLock()

    # ---- principal mappings ----------------------------------------

    @db_connection
    def get_mapping(self, *, issuer: str, global_subject: str) -> Optional[PrincipalMapping]:
        self.cursor.execute(
            "SELECT id, issuer, global_subject, local_account_id, status, "
            "created_at, last_seen_at, disabled_at, metadata_json "
            "FROM GlobalPrincipalMappings WHERE issuer = ? AND global_subject = ?",
            (issuer, global_subject),
        )
        row = self.cursor.fetchone()
        return PrincipalMapping(*row) if row else None

    @db_connection
    def get_or_create_mapping(
        self, *, issuer: str, global_subject: str, local_account_id: int
    ) -> PrincipalMapping:
        """
        Atomic get-or-create: relies on the UNIQUE(issuer, global_subject)
        constraint for correctness under concurrent first logins for the
        same subject — the loser of the race hits an IntegrityError and
        simply re-reads the winner's row instead of creating a duplicate
        account.
        """
        now = datetime.now()
        try:
            self.cursor.execute(
                "INSERT INTO GlobalPrincipalMappings "
                "(issuer, global_subject, local_account_id, status, created_at, last_seen_at) "
                "VALUES (?, ?, ?, 'active', ?, ?)",
                (issuer, global_subject, local_account_id, now, now),
            )
            mapping_id = int(self.cursor.lastrowid)
        except sqlite3.IntegrityError:
            pass

        self.cursor.execute(
            "SELECT id, issuer, global_subject, local_account_id, status, "
            "created_at, last_seen_at, disabled_at, metadata_json "
            "FROM GlobalPrincipalMappings WHERE issuer = ? AND global_subject = ?",
            (issuer, global_subject),
        )
        row = self.cursor.fetchone()
        assert row is not None
        return PrincipalMapping(*row)

    @db_connection
    def list_mappings(self) -> list[PrincipalMapping]:
        self.cursor.execute(
            "SELECT id, issuer, global_subject, local_account_id, status, "
            "created_at, last_seen_at, disabled_at, metadata_json "
            "FROM GlobalPrincipalMappings ORDER BY id"
        )
        return [PrincipalMapping(*row) for row in self.cursor.fetchall()]

    @db_connection
    def touch_last_seen(self, *, mapping_id: int) -> None:
        self.cursor.execute(
            "UPDATE GlobalPrincipalMappings SET last_seen_at = ? WHERE id = ?",
            (datetime.now(), mapping_id),
        )

    @db_connection
    def set_mapping_status(self, *, global_subject: str, status: str) -> bool:
        assert status in ("active", "disabled")
        disabled_at = datetime.now() if status == "disabled" else None
        self.cursor.execute(
            "UPDATE GlobalPrincipalMappings SET status = ?, disabled_at = ? "
            "WHERE global_subject = ?",
            (status, disabled_at, global_subject),
        )
        return self.cursor.rowcount > 0

    # ---- assertion replay guard -------------------------------------

    @db_connection
    def consume_jti(
        self, *, issuer: str, jti: str, global_subject: str, expires_at: datetime
    ) -> bool:
        """Returns True if this (issuer, jti) is fresh (now consumed);
        False if it was already used (replay)."""
        self._prune_expired_jtis_locked()
        try:
            self.cursor.execute(
                "INSERT INTO GlobalAssertionJTIs "
                "(issuer, jti, global_subject, expires_at, consumed_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (issuer, jti, global_subject, expires_at, datetime.now()),
            )
            return True
        except sqlite3.IntegrityError:
            return False

    def _prune_expired_jtis_locked(self) -> None:
        self.cursor.execute(
            "DELETE FROM GlobalAssertionJTIs WHERE expires_at < ?", (datetime.now(),)
        )

    # ---- local sessions ----------------------------------------------

    @db_connection
    def create_session(
        self, *, mapping_id: int, local_account_id: int, minutes: int
    ) -> tuple[str, datetime]:
        salt, hashed, token = generate_token(length=32)
        now = datetime.now()
        from datetime import timedelta

        expires_at = now + timedelta(minutes=minutes)
        self.cursor.execute(
            "INSERT INTO GlobalLocalSessions "
            "(session_hash, session_salt, mapping_id, local_account_id, issued_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (hashed, salt, mapping_id, local_account_id, now, expires_at),
        )
        return token, expires_at

    @db_connection
    def validate_session(self, *, token: str) -> Optional[dict]:
        now = datetime.now()
        self.cursor.execute(
            "SELECT session_salt, session_hash, mapping_id, local_account_id, "
            "expires_at, revoked_at FROM GlobalLocalSessions "
            "WHERE revoked_at IS NULL AND expires_at > ?",
            (now,),
        )
        for salt, hashed, mapping_id, local_account_id, expires_at, _ in self.cursor.fetchall():
            if validate_token(salt, hashed, token):
                return {
                    "mapping_id": mapping_id,
                    "local_account_id": local_account_id,
                    "expires_at": expires_at,
                }
        return None

    @db_connection
    def revoke_sessions_for_mapping(self, *, mapping_id: int) -> int:
        self.cursor.execute(
            "UPDATE GlobalLocalSessions SET revoked_at = ? "
            "WHERE mapping_id = ? AND revoked_at IS NULL",
            (datetime.now(), mapping_id),
        )
        return self.cursor.rowcount

    # ---- catalog version state -----------------------------------------

    @db_connection
    def get_catalog_state(self) -> tuple[int, Optional[str]]:
        self.cursor.execute(
            "SELECT version, content_hash FROM GlobalCatalogState WHERE id = 1"
        )
        row = self.cursor.fetchone()
        if row is None:
            return 0, None
        return int(row[0]), row[1]

    @db_connection
    def set_catalog_state(self, *, version: int, content_hash: str) -> None:
        self.cursor.execute(
            "INSERT INTO GlobalCatalogState (id, version, content_hash, published_at) "
            "VALUES (1, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET version = excluded.version, "
            "content_hash = excluded.content_hash, published_at = excluded.published_at",
            (version, content_hash, datetime.now()),
        )


_GLOBAL_DB_LOCK = threading.Lock()
_GLOBAL_DB: Optional[GlobalDB] = None


def get_global_db() -> GlobalDB:
    """Process-wide singleton, lazily created — mirrors the existing
    `perms = perms_db()`/`reservation_handler = ReservationHandler()`
    module-level singleton pattern, but constructed lazily so importing
    this module never touches disk when Global is disabled."""
    global _GLOBAL_DB
    if _GLOBAL_DB is None:
        with _GLOBAL_DB_LOCK:
            if _GLOBAL_DB is None:
                _GLOBAL_DB = GlobalDB()
    return _GLOBAL_DB
