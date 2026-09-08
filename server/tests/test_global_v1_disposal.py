from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from remoteRF_server.server.federation.legacy_state import (
    DisposalError,
    apply_disposal,
    build_preflight,
    write_preflight,
)
from remoteRF_server.server.federation.migrations import check_gate_c_ready

DEPLOYMENT = "11111111-1111-4111-8111-111111111111"


def seed(root: Path, *, mapped_auth="remoterf_global", orphan=False):
    with sqlite3.connect(root / "reservations.db") as conn:
        conn.executescript(
            """
            CREATE TABLE Accounts (
              acc_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE,
              email TEXT UNIQUE, pass_salt TEXT NOT NULL, pass_hash TEXT NOT NULL,
              created_at TIMESTAMP, auth_type TEXT NOT NULL DEFAULT 'local_password');
            CREATE TABLE Reservations (
              res_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, device_id INTEGER,
              start_time TIMESTAMP, end_time TIMESTAMP, salt TEXT, hash TEXT);
            INSERT INTO Accounts VALUES
              (7,'native','native@example.com','ns','nh',CURRENT_TIMESTAMP,'local_password');
            INSERT INTO Reservations VALUES
              (70,'native',1,'2030-01-01','2030-01-02','native-s','native-h');
            """
        )
        conn.execute(
            "INSERT INTO Accounts VALUES (8,'global-old','old@global.invalid','gs','gh',"
            "CURRENT_TIMESTAMP,?)",
            (mapped_auth,),
        )
        conn.execute(
            "INSERT INTO Reservations VALUES "
            "(80,'global-old',2,'2030-01-01','2030-01-02','global-s','global-h')"
        )
    with sqlite3.connect(root / "usergroups.db") as conn:
        conn.executescript(
            """
            CREATE TABLE UserGroups (group_id INTEGER PRIMARY KEY, group_name TEXT UNIQUE,
              devices_whitelist TEXT, max_reservation_time_sec INTEGER,
              max_reservations INTEGER, lifetime_sec INTEGER, created_at TIMESTAMP);
            CREATE TABLE UsersLookup (user_id INTEGER, group_id INTEGER,
              PRIMARY KEY(user_id,group_id));
            CREATE TABLE EnrollmentCodes (code_id INTEGER PRIMARY KEY, code_name TEXT UNIQUE,
              group_id INTEGER, uses INTEGER, duration_sec INTEGER, created_at TIMESTAMP);
            INSERT INTO UserGroups VALUES (3,'shared','[]',1800,1,0,CURRENT_TIMESTAMP);
            INSERT INTO UsersLookup VALUES (7,3);
            INSERT INTO UsersLookup VALUES (8,3);
            INSERT INTO EnrollmentCodes VALUES (4,'keep-code',3,2,0,CURRENT_TIMESTAMP);
            """
        )
    with sqlite3.connect(root / "perms.db") as conn:
        conn.executescript(
            """
            CREATE TABLE Users (UserID INTEGER PRIMARY KEY, Username TEXT UNIQUE);
            CREATE TABLE PowerUsers (UserID INTEGER PRIMARY KEY, Username TEXT UNIQUE,
              MaxReservations INTEGER, MaxReservationTimeSec INTEGER, DevicesAllowed TEXT);
            CREATE TABLE Admins (AdminID INTEGER PRIMARY KEY, Username TEXT UNIQUE);
            INSERT INTO Users VALUES (7,'native');
            INSERT INTO Users VALUES (8,'global-old');
            """
        )
    with sqlite3.connect(root / "global.db") as conn:
        conn.executescript(
            """
            CREATE TABLE GlobalPrincipalMappings (id INTEGER PRIMARY KEY, issuer TEXT,
              global_subject TEXT, local_account_id INTEGER, status TEXT);
            CREATE TABLE GlobalAssertionJTIs (issuer TEXT,jti TEXT);
            CREATE TABLE GlobalLocalSessions (session_hash TEXT);
            CREATE TABLE GlobalCatalogState (id INTEGER);
            """
        )
        conn.execute(
            "INSERT INTO GlobalPrincipalMappings VALUES (1,'https://old','subject',?,'active')",
            (99 if orphan else 8,),
        )


class DisposalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_preflight_uses_mapping_ids_and_never_name_prefixes(self):
        seed(self.root)
        with sqlite3.connect(self.root / "reservations.db") as conn:
            conn.execute(
                "INSERT INTO Accounts VALUES "
                "(9,'global-looking-native','keep@example.com','s','h',CURRENT_TIMESTAMP,'local_password')"
            )
        result = build_preflight(self.root)
        self.assertEqual(result["blockers"], [])
        self.assertEqual([row["acc_id"] for row in result["candidates"]["accounts"]], [8])
        self.assertNotIn(9, [row["acc_id"] for row in result["candidates"]["accounts"]])
        self.assertTrue(all(row["delete"] is False for row in result["candidates"]["accounts"]))

    def test_native_collision_and_orphan_mapping_block(self):
        seed(self.root, mapped_auth="local_password")
        result = build_preflight(self.root)
        self.assertTrue(any("protected/non-v1" in item for item in result["blockers"]))
        with tempfile.TemporaryDirectory() as other:
            other_root = Path(other)
            seed(other_root, orphan=True)
            result = build_preflight(other_root)
            self.assertTrue(any("missing account" in item for item in result["blockers"]))

    def test_apply_requires_review_and_unchanged_sources(self):
        seed(self.root)
        manifest_path = self.root.parent / (self.root.name + "-manifest.json")
        self.addCleanup(lambda: manifest_path.unlink(missing_ok=True))
        write_preflight(self.root, manifest_path)
        with self.assertRaises(DisposalError):
            apply_disposal(
                manifest_path,
                archive_dir=self.root.parent / (self.root.name + "-archive-a"),
                deployment_id=DEPLOYMENT,
            )
        value = json.loads(manifest_path.read_text())
        value["reviewed"] = True
        for rows in value["candidates"].values():
            for row in rows:
                row["delete"] = True
        manifest_path.write_text(json.dumps(value))
        with sqlite3.connect(self.root / "reservations.db") as conn:
            conn.execute("UPDATE Accounts SET email='changed@example.com' WHERE acc_id=7")
        with self.assertRaises(DisposalError):
            apply_disposal(
                manifest_path,
                archive_dir=self.root.parent / (self.root.name + "-archive-b"),
                deployment_id=DEPLOYMENT,
            )

    def test_review_cannot_inject_a_native_candidate(self):
        seed(self.root)
        manifest_path = self.root.parent / (self.root.name + "-manifest.json")
        archive = self.root.parent / (self.root.name + "-archive")
        self.addCleanup(lambda: manifest_path.unlink(missing_ok=True))
        self.addCleanup(lambda: shutil.rmtree(archive, ignore_errors=True))
        write_preflight(self.root, manifest_path)
        value = json.loads(manifest_path.read_text())
        value["reviewed"] = True
        for rows in value["candidates"].values():
            for row in rows:
                row["delete"] = True
        value["candidates"]["reservations"].append(
            {
                "res_id": 70,
                "acc_id": 7,
                "username": "native",
                "device_id": 1,
                "start_time": "2030-01-01",
                "end_time": "2030-01-02",
                "delete": True,
            }
        )
        manifest_path.write_text(json.dumps(value))
        with self.assertRaises(DisposalError, msg="tampered candidates must fail"):
            apply_disposal(
                manifest_path, archive_dir=archive, deployment_id=DEPLOYMENT
            )
        self.assertFalse(archive.exists())
        with sqlite3.connect(self.root / "reservations.db") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM Reservations").fetchone()[0], 2)

    def test_reviewed_apply_archives_and_preserves_native_state(self):
        seed(self.root)
        manifest_path = self.root.parent / (self.root.name + "-manifest.json")
        archive = self.root.parent / (self.root.name + "-archive")
        self.addCleanup(lambda: manifest_path.unlink(missing_ok=True))
        self.addCleanup(lambda: shutil.rmtree(archive, ignore_errors=True))
        write_preflight(self.root, manifest_path)
        value = json.loads(manifest_path.read_text())
        value["reviewed"] = True
        for rows in value["candidates"].values():
            for row in rows:
                row["delete"] = True
        manifest_path.write_text(json.dumps(value))
        result = apply_disposal(
            manifest_path, archive_dir=archive, deployment_id=DEPLOYMENT
        )
        self.assertEqual(result["accounts_removed"], 1)
        self.assertTrue((archive / "global.db").exists())
        self.assertFalse((self.root / "global.db").exists())
        with sqlite3.connect(self.root / "reservations.db") as conn:
            self.assertEqual(conn.execute("SELECT acc_id,username FROM Accounts").fetchall(), [(7,"native")])
            self.assertEqual(conn.execute("SELECT res_id,username FROM Reservations").fetchall(), [(70,"native")])
            subject = conn.execute(
                "SELECT subject_id FROM LocalAccountSubjects WHERE local_account_id=7"
            ).fetchone()[0]
            self.assertEqual(len(subject), 36)
        with sqlite3.connect(self.root / "usergroups.db") as conn:
            self.assertEqual(conn.execute("SELECT user_id,group_id FROM UsersLookup").fetchall(), [(7,3)])
            self.assertEqual(conn.execute("SELECT code_name FROM EnrollmentCodes").fetchone()[0], "keep-code")
        check_gate_c_ready(self.root)
