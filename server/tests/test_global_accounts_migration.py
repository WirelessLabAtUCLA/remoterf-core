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
Covers the one existing-table schema change this feature makes
(Accounts.auth_type) and the additive login_user/create_external_account
behavior in reservation.py. Every ReservationHandler here is a fresh
instance backed by an isolated temp-dir sqlite file (get_db_dir patched at
construction time only) — the process-wide `reservation_handler` singleton
elsewhere in the codebase is never touched by these tests.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from remoteRF_server.common.utils.api_token import hash_token
from remoteRF_server.server.global_access.db import GlobalDB
from remoteRF_server.server.reservation import ReservationHandler


class AccountsMigrationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db_dir = Path(self._tmp.name)

        # Seed a pre-v1.0 Accounts table (no auth_type column at all).
        conn = sqlite3.connect(self.db_dir / "reservations.db")
        conn.execute(
            """
            CREATE TABLE Accounts (
                acc_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                pass_salt TEXT NOT NULL,
                pass_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        salt, hashed = hash_token("correct horse battery staple")
        conn.execute(
            "INSERT INTO Accounts (username, email, pass_salt, pass_hash) VALUES (?, ?, ?, ?)",
            ("alice", "alice@example.com", salt, hashed),
        )
        conn.commit()
        conn.close()

    def _open_handler(self) -> ReservationHandler:
        with patch("remoteRF_server.server.reservation.get_db_dir", return_value=self.db_dir):
            return ReservationHandler()

    def test_existing_account_row_is_preserved(self):
        rh = self._open_handler()
        usernames = [row[1] for row in rh.get_all_accounts()]
        self.assertIn("alice", usernames)

    def test_existing_account_defaults_to_local_password_auth_type(self):
        rh = self._open_handler()
        self.assertEqual(rh.get_auth_type("alice"), "local_password")

    def test_migration_is_idempotent_across_multiple_opens(self):
        self._open_handler()
        rh2 = self._open_handler()  # would raise "duplicate column name" if not guarded
        self.assertEqual(rh2.get_auth_type("alice"), "local_password")
        self.assertEqual(len(rh2.get_all_accounts()), 1)

    def test_existing_password_login_still_works_after_migration(self):
        rh = self._open_handler()
        result = rh.login_user("alice", "correct horse battery staple")
        self.assertEqual(result.get("UC").string_value, "alice")

    def test_wrong_password_still_rejected_after_migration(self):
        rh = self._open_handler()
        result = rh.login_user("alice", "wrong password")
        self.assertIn("UE", result)


class ExternalAccountAndSessionLoginTests(unittest.TestCase):
    """
    Exercises reservation.py's create_external_account/login_user('remoterf_global')
    branch together with a real (temp-dir-backed) GlobalDB session — this is
    the mechanism GlobalAuthV1.ExchangeAssertion relies on to authenticate a
    Global-derived shadow account against the existing, unmodified `login`/
    `get_res`/etc. RPC surface.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db_dir = Path(self._tmp.name)
        with patch("remoteRF_server.server.reservation.get_db_dir", return_value=self.db_dir):
            self.rh = ReservationHandler()
        self.gdb = GlobalDB(db_dir=self.db_dir)

    def test_external_account_has_remoterf_global_auth_type(self):
        self.rh.create_external_account(username="global-test1")
        self.assertEqual(self.rh.get_auth_type("global-test1"), "remoterf_global")

    def test_external_account_cannot_login_with_any_password(self):
        self.rh.create_external_account(username="global-test1")
        # No password was ever set for this account by anyone — any guess,
        # including an empty string, must be rejected. Patched so the
        # (unmatched) session-token lookup never touches the real,
        # process-wide global.db singleton.
        with patch("remoteRF_server.server.global_access.db.get_global_db", return_value=self.gdb):
            for guess in ("", "password", "global-test1", "admin"):
                with self.subTest(guess=guess):
                    result = self.rh.login_user("global-test1", guess)
                    self.assertIn("UE", result)

    def test_valid_session_token_authenticates_the_shadow_account(self):
        acc_id = self.rh.create_external_account(username="global-test1")
        token, _expires_at = self.gdb.create_session(
            mapping_id=1, local_account_id=acc_id, minutes=5
        )
        with patch("remoteRF_server.server.global_access.db.get_global_db", return_value=self.gdb):
            result = self.rh.login_user("global-test1", token)
        self.assertEqual(result.get("UC").string_value, "global-test1")

    def test_expired_session_token_is_rejected(self):
        acc_id = self.rh.create_external_account(username="global-test1")
        token, _ = self.gdb.create_session(mapping_id=1, local_account_id=acc_id, minutes=-1)
        with patch("remoteRF_server.server.global_access.db.get_global_db", return_value=self.gdb):
            result = self.rh.login_user("global-test1", token)
        self.assertIn("UE", result)

    def test_session_token_for_a_different_account_is_rejected(self):
        acc_id_1 = self.rh.create_external_account(username="global-test1")
        self.rh.create_external_account(username="global-test2")
        token, _ = self.gdb.create_session(mapping_id=1, local_account_id=acc_id_1, minutes=5)
        with patch("remoteRF_server.server.global_access.db.get_global_db", return_value=self.gdb):
            result = self.rh.login_user("global-test2", token)
        self.assertIn("UE", result)

    def test_concurrent_create_external_account_converges_on_one_row(self):
        id1 = self.rh.create_external_account(username="global-dup")
        id2 = self.rh.create_external_account(username="global-dup")
        self.assertEqual(id1, id2)
        usernames = [row[1] for row in self.rh.get_all_accounts()]
        self.assertEqual(usernames.count("global-dup"), 1)


if __name__ == "__main__":
    unittest.main()
