from __future__ import annotations

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import UUID, uuid4, uuid5

from remoterf_federation_core import federated_proxy_adapter
from remoteRF_server.common.utils.api_token import hash_token
from remoteRF_server.server.acc_perms import perms_db
from remoteRF_server.server.federation.migrations import SchemaNotReady
from remoteRF_server.server.federation.identity import (
    DeploymentState,
    init_identity,
    load_private_key,
    save_state,
)
from remoteRF_server.server.federation.runtime import (
    build_configured_server_federation,
)
from remoteRF_server.server.reservation import (
    FEDERATED_PASSWORD_HASH,
    FEDERATED_PASSWORD_SALT,
    ReservationHandler,
)
from remoteRF_server.server.user_group_handler import UserGroupHandler

DEPLOYMENT = "11111111-1111-4111-8111-111111111111"
ISSUER = "22222222-2222-4222-8222-222222222222"
SUBJECT = "33333333-3333-4333-8333-333333333333"


class GateCFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for target in (
            "remoteRF_server.server.reservation.get_db_dir",
            "remoteRF_server.server.acc_perms.get_db_dir",
            "remoteRF_server.server.user_group_handler.get_db_dir",
        ):
            item = patch(target, return_value=self.root)
            item.start()
            self.addCleanup(item.stop)
        self.perms = perms_db()
        self.groups = UserGroupHandler()
        self.reservations = ReservationHandler()
        for target, value in (
            ("remoteRF_server.server.reservation.perms", self.perms),
            ("remoteRF_server.server.reservation.user_group_handler", self.groups),
        ):
            item = patch(target, value)
            item.start()
            self.addCleanup(item.stop)

    def native(self, name="alice", email="alice@example.com", password="native-secret"):
        salt, hashed = hash_token(password)
        with sqlite3.connect(self.root / "reservations.db") as conn:
            conn.execute(
                "INSERT INTO Accounts "
                "(username,email,pass_salt,pass_hash,created_at,auth_type) "
                "VALUES (?,?,?,?,CURRENT_TIMESTAMP,'local_password')",
                (name, email, salt, hashed),
            )
            return int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])


class NativeSubjectTests(GateCFixture):
    def test_existing_native_id_hash_and_deterministic_subject_are_preserved(self):
        account_id = self.native()
        with sqlite3.connect(self.root / "reservations.db") as conn:
            before = conn.execute(
                "SELECT acc_id,pass_salt,pass_hash FROM Accounts WHERE acc_id=?", (account_id,)
            ).fetchone()
        first = self.reservations.initialize_native_subjects(DEPLOYMENT)
        second = self.reservations.initialize_native_subjects(DEPLOYMENT)
        self.assertEqual(first, second)
        self.assertEqual(
            first[account_id], str(uuid5(UUID(DEPLOYMENT), f"account:{account_id}"))
        )
        with sqlite3.connect(self.root / "reservations.db") as conn:
            after = conn.execute(
                "SELECT acc_id,pass_salt,pass_hash FROM Accounts WHERE acc_id=?", (account_id,)
            ).fetchone()
        self.assertEqual(after, before)

    def test_rename_does_not_change_subject_and_raw_subject_update_fails(self):
        account_id = self.native()
        subject = self.reservations.initialize_native_subjects(DEPLOYMENT)[account_id]
        with sqlite3.connect(self.root / "reservations.db") as conn:
            conn.execute(
                "UPDATE Accounts SET username='renamed', email='renamed@example.com' "
                "WHERE acc_id=?",
                (account_id,),
            )
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    "UPDATE LocalAccountSubjects SET subject_id=? WHERE local_account_id=?",
                    (str(uuid4()), account_id),
                )
        self.assertEqual(self.reservations.get_native_subject(account_id), subject)

    def test_new_native_account_gets_uuid4_and_recreation_gets_another_subject(self):
        group_id = self.groups.create_user_group(
            group_name="native", devices_whitelist=[], max_reservation_time_sec=1800,
            max_reservations=1, lifetime_sec=0,
        )
        code = "native-code"
        self.groups.create_enrollment_codes(
            code_names=[code], group_id=group_id, uses=2, duration_sec=0
        )
        args = {"un": "fresh", "pw": "secret", "em": "fresh@example.com", "ec": code}
        from remoteRF_server.common.utils import map_arg

        mapped = {key: map_arg(value) for key, value in args.items()}
        self.assertIn("UC", self.reservations.create_user(**mapped))
        first_id = self.reservations.get_uid("fresh")
        first = self.reservations.get_native_subject(first_id)
        self.assertEqual(UUID(first).version, 4)
        self.reservations.remove_user(username="fresh")
        args["em"] = "fresh2@example.com"
        mapped = {key: map_arg(value) for key, value in args.items()}
        self.assertIn("UC", self.reservations.create_user(**mapped))
        second = self.reservations.get_native_subject(
            self.reservations.get_uid("fresh")
        )
        self.assertNotEqual(first, second)


class StockFederationRuntimeTests(GateCFixture):
    def test_stock_runtime_rejects_replaced_private_identity_key(self):
        identity_dir = self.root / "identity"
        init_identity(identity_dir)
        replacement_dir = self.root / "replacement"
        init_identity(replacement_dir)
        (identity_dir / "deployment-private.pem").write_bytes(
            (replacement_dir / "deployment-private.pem").read_bytes()
        )
        with self.assertRaisesRegex(
            RuntimeError, "private/public key binding mismatch"
        ):
            load_private_key(identity_dir)

    def test_explicit_config_builds_complete_server_federation_runtime(self):
        identity_dir = self.root / "identity"
        init_identity(identity_dir)
        save_state(
            identity_dir,
            DeploymentState(
                deployment_id=DEPLOYMENT,
                display_name="Configured Server",
                protocol_version="2",
            ),
        )
        config = self.root / "federation.yml"
        config.write_text(
            "protocol_version: '2'\n"
            f"identity_dir: {identity_dir}\n"
            "display_name: Configured Server\n"
            "broker:\n"
            "  origin: https://broker.example\n"
            "  deployment_id: 99999999-9999-4999-8999-999999999999\n"
            "databases:\n"
            f"  reservations: {self.root / 'reservations.db'}\n"
            f"  usergroups: {self.root / 'usergroups.db'}\n"
            f"  permissions: {self.root / 'perms.db'}\n",
            encoding="utf-8",
        )
        with (
            patch.dict(
                "os.environ",
                {
                    "REMOTERF_FEDERATION_ENABLED": "1",
                    "REMOTERF_FEDERATION_CONFIG_PATH": str(config),
                },
            ),
            patch("remoteRF_server.server.acc_perms.perms", self.perms),
            patch(
                "remoteRF_server.server.user_group_handler.user_group_handler",
                self.groups,
            ),
        ):
            runtime = build_configured_server_federation(self.reservations)
        assert runtime.executor is not None
        assert runtime.enroller.outbound is runtime.permissions.outbound
        assert runtime.permissions.local_deployment_id == DEPLOYMENT
        runtime.permissions.close()


class FederatedProxyTests(GateCFixture):
    def test_concurrent_resolution_converges_on_one_account_and_principal(self):
        handlers = [ReservationHandler() for _ in range(6)]
        with ThreadPoolExecutor(max_workers=6) as pool:
            principals = list(
                pool.map(
                    lambda handler: handler.resolve_federated_principal(
                        issuer_deployment_id=ISSUER,
                        remote_subject_id=SUBJECT,
                        display_metadata={"display_name": "Concurrent"},
                    ),
                    handlers,
                )
            )
        self.assertEqual(len({item.id for item in principals}), 1)
        self.assertEqual(len({item.local_account_id for item in principals}), 1)
        with sqlite3.connect(self.root / "reservations.db") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM FederatedAccountBindings").fetchone()[0], 1)
        with sqlite3.connect(self.root / "usergroups.db") as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM FederatedPrincipals").fetchone()[0], 1)

    def test_same_tuple_converges_and_same_subject_at_other_issuer_is_distinct(self):
        first = self.reservations.resolve_federated_account(
            issuer_deployment_id=ISSUER, remote_subject_id=SUBJECT
        )
        again = self.reservations.resolve_federated_account(
            issuer_deployment_id=ISSUER, remote_subject_id=SUBJECT
        )
        other = self.reservations.resolve_federated_account(
            issuer_deployment_id=DEPLOYMENT, remote_subject_id=SUBJECT
        )
        self.assertEqual(first, again)
        self.assertNotEqual(first, other)
        username, email = federated_proxy_adapter(ISSUER, SUBJECT)
        with sqlite3.connect(self.root / "reservations.db") as conn:
            row = conn.execute(
                "SELECT username,email,pass_salt,pass_hash,auth_type FROM Accounts "
                "WHERE acc_id=?",
                (first,),
            ).fetchone()
        self.assertEqual(
            row, (username, email, FEDERATED_PASSWORD_SALT, FEDERATED_PASSWORD_HASH, "federated")
        )

    def test_username_or_email_collision_fails_closed_without_adoption(self):
        username, email = federated_proxy_adapter(ISSUER, SUBJECT)
        for native_name, native_email in (
            (username, "native@example.com"),
            ("native-user", email),
        ):
            with self.subTest(native_name=native_name):
                salt, hashed = hash_token("native-secret")
                with sqlite3.connect(self.root / "reservations.db") as conn:
                    conn.execute(
                        "INSERT INTO Accounts "
                        "(username,email,pass_salt,pass_hash,created_at,auth_type) "
                        "VALUES (?,?,?,?,CURRENT_TIMESTAMP,'local_password')",
                        (native_name, native_email, salt, hashed),
                    )
                with self.assertRaises(ValueError):
                    self.reservations.resolve_federated_account(
                        issuer_deployment_id=ISSUER, remote_subject_id=SUBJECT
                    )
                with sqlite3.connect(self.root / "reservations.db") as conn:
                    conn.execute("DELETE FROM Accounts")

    def test_federated_and_unknown_auth_never_reach_password_verifier(self):
        account_id = self.reservations.resolve_federated_account(
            issuer_deployment_id=ISSUER, remote_subject_id=SUBJECT
        )
        username, _ = federated_proxy_adapter(ISSUER, SUBJECT)
        salt, hashed = hash_token("copied-native-password")
        with sqlite3.connect(self.root / "reservations.db") as conn:
            # Model corrupt/out-of-band state after bypassing the database's
            # normal immutability defense; runtime must still fail closed.
            conn.execute("DROP TRIGGER Accounts_federated_adapter_immutable")
            conn.execute(
                "UPDATE Accounts SET pass_salt=?,pass_hash=? WHERE acc_id=?",
                (salt, hashed, account_id),
            )
        with patch(
            "remoteRF_server.server.reservation.validate_token",
            side_effect=AssertionError("password verifier reached"),
        ):
            for guess in (
                "anything", FEDERATED_PASSWORD_SALT, FEDERATED_PASSWORD_HASH,
                "copied-native-password",
            ):
                self.assertIn("UE", self.reservations.login_user(username, guess))

        native_id = self.native(name="mystery", email="mystery@example.com")
        with sqlite3.connect(self.root / "reservations.db") as conn:
            conn.execute("PRAGMA ignore_check_constraints=ON")
            conn.execute("DROP TRIGGER Accounts_auth_type_immutable")
            conn.execute("DROP TRIGGER Accounts_auth_type_insert")
            conn.execute("UPDATE Accounts SET auth_type='unknown' WHERE acc_id=?", (native_id,))
        with patch(
            "remoteRF_server.server.reservation.validate_token",
            side_effect=AssertionError("password verifier reached"),
        ):
            self.assertIn("UE", self.reservations.login_user("mystery", "native-secret"))

    def test_retry_never_resets_an_existing_role(self):
        account_id = self.reservations.resolve_federated_account(
            issuer_deployment_id=ISSUER, remote_subject_id=SUBJECT
        )
        username = self.reservations.get_username_by_acc_id(account_id)
        with sqlite3.connect(self.root / "perms.db") as conn:
            conn.execute("DELETE FROM Users WHERE Username=?", (username,))
            conn.execute("INSERT INTO Admins (Username) VALUES (?)", (username,))
        self.reservations.resolve_federated_account(
            issuer_deployment_id=ISSUER, remote_subject_id=SUBJECT
        )
        self.assertEqual(self.perms.get_perms(username)[0][0], "Admin")

    def test_principal_is_generic_local_state_and_metadata_is_bounded(self):
        first = self.reservations.resolve_federated_principal(
            issuer_deployment_id=ISSUER,
            remote_subject_id=SUBJECT,
            display_metadata={"display_name": "Same Name"},
        )
        again = self.reservations.resolve_federated_principal(
            issuer_deployment_id=ISSUER,
            remote_subject_id=SUBJECT,
            display_metadata={"display_name": "Renamed"},
        )
        self.assertEqual(first.id, again.id)
        self.assertEqual(first.local_account_id, again.local_account_id)
        self.assertEqual(again.display_metadata, {"display_name": "Renamed"})
        with self.assertRaises(ValueError):
            self.reservations.resolve_federated_principal(
                issuer_deployment_id=ISSUER,
                remote_subject_id=SUBJECT,
                display_metadata={"display_name": "x" * 257},
            )

    def test_proxy_is_denied_before_server_role_bypass_or_token_mint(self):
        account_id = self.reservations.resolve_federated_account(
            issuer_deployment_id=ISSUER, remote_subject_id=SUBJECT
        )
        username = self.reservations.get_username_by_acc_id(account_id)
        with patch.object(
            self.perms,
            "validate_reservation_request",
            side_effect=AssertionError("role check reached"),
        ):
            result = self.reservations.reserve_device(
                username,
                1,
                datetime.now() + timedelta(minutes=1),
                datetime.now() + timedelta(minutes=12),
                is_server=True,
            )
        self.assertIn("ace", result)

    def test_out_of_band_proxy_reservation_is_not_materialized(self):
        account_id = self.reservations.resolve_federated_account(
            issuer_deployment_id=ISSUER, remote_subject_id=SUBJECT
        )
        username = self.reservations.get_username_by_acc_id(account_id)
        token_salt, token_hash = hash_token("proxy-token")
        with sqlite3.connect(self.root / "reservations.db") as conn:
            conn.execute(
                "INSERT INTO Reservations "
                "(username,device_id,start_time,end_time,salt,hash) VALUES (?,?,?,?,?,?)",
                (
                    username, 7, datetime.now() - timedelta(minutes=1),
                    datetime.now() + timedelta(minutes=10), token_salt, token_hash,
                ),
            )
        with (
            patch("remoteRF_server.server.reservation.get_all_devices", return_value={7: object()}),
            patch("remoteRF_server.server.reservation.set_device") as set_device,
        ):
            self.reservations.update_devices()
        set_device.assert_called_once_with("7", "", "")

        # Supported proxy retirement quarantines the residual row in the same
        # transaction, so it cannot later fall through as a legacy accountless
        # native reservation.
        self.reservations.remove_user(username=username)
        with sqlite3.connect(self.root / "reservations.db") as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT COUNT(*) FROM Reservations WHERE username=?", (username,)
                ).fetchone()[0],
                0,
            )
        with (
            patch("remoteRF_server.server.reservation.get_all_devices", return_value={7: object()}),
            patch("remoteRF_server.server.reservation.set_device") as set_device,
        ):
            self.reservations.update_devices()
        set_device.assert_called_once_with("7", "", "")

    def test_legacy_accountless_native_reservation_still_materializes(self):
        token_salt, token_hash = hash_token("accountless-native-token")
        with sqlite3.connect(self.root / "reservations.db") as conn:
            conn.execute(
                "INSERT INTO Reservations "
                "(username,device_id,start_time,end_time,salt,hash) VALUES (?,?,?,?,?,?)",
                (
                    "historical-accountless",
                    8,
                    datetime.now() - timedelta(minutes=1),
                    datetime.now() + timedelta(minutes=10),
                    token_salt,
                    token_hash,
                ),
            )
        with (
            patch("remoteRF_server.server.reservation.get_all_devices", return_value={8: object()}),
            patch("remoteRF_server.server.reservation.set_device") as set_device,
        ):
            self.reservations.update_devices()
        set_device.assert_called_once_with("8", token_salt, token_hash)


class LegacyAuthTypeReadinessTests(unittest.TestCase):
    def test_pre_global_schema_migrates_additively_and_native_login_is_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            salt, hashed = hash_token("existing-password")
            with sqlite3.connect(root / "reservations.db") as conn:
                conn.executescript(
                    """
                    CREATE TABLE Accounts (
                        acc_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        email TEXT NOT NULL UNIQUE,
                        pass_salt TEXT NOT NULL,
                        pass_hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE Reservations (
                        res_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL, device_id INTEGER NOT NULL,
                        start_time TIMESTAMP NOT NULL, end_time TIMESTAMP NOT NULL,
                        salt TEXT NOT NULL, hash TEXT NOT NULL
                    );
                    """
                )
                conn.execute(
                    "INSERT INTO Accounts VALUES "
                    "(77,'existing','existing@example.com',?,?,CURRENT_TIMESTAMP)",
                    (salt, hashed),
                )
            patches = [
                patch(target, return_value=root)
                for target in (
                    "remoteRF_server.server.reservation.get_db_dir",
                    "remoteRF_server.server.acc_perms.get_db_dir",
                    "remoteRF_server.server.user_group_handler.get_db_dir",
                )
            ]
            for item in patches:
                item.start()
                self.addCleanup(item.stop)
            local_perms = perms_db()
            local_groups = UserGroupHandler()
            with (
                patch("remoteRF_server.server.reservation.perms", local_perms),
                patch(
                    "remoteRF_server.server.reservation.user_group_handler",
                    local_groups,
                ),
            ):
                handler = ReservationHandler()
                self.assertIn("UC", handler.login_user("existing", "existing-password"))
                subject = handler.initialize_native_subjects(DEPLOYMENT)[77]
            with sqlite3.connect(root / "reservations.db") as conn:
                row = conn.execute(
                    "SELECT acc_id,pass_salt,pass_hash,auth_type FROM Accounts"
                ).fetchone()
            # A legacy sha256 row is rehashed with the password KDF on login.
            self.assertEqual((row[0], row[3]), (77, "local_password"))
            self.assertTrue(row[2].startswith("pbkdf2$"), row[2])
            self.assertEqual(subject, str(uuid5(UUID(DEPLOYMENT), "account:77")))

    def test_remoterf_global_and_unknown_rows_block_runtime_migration(self):
        for auth_type in ("remoterf_global", "mystery"):
            with self.subTest(auth_type=auth_type), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with sqlite3.connect(root / "reservations.db") as conn:
                    conn.execute(
                        "CREATE TABLE Accounts (acc_id INTEGER PRIMARY KEY, username TEXT UNIQUE, "
                        "email TEXT UNIQUE, pass_salt TEXT, pass_hash TEXT, created_at TIMESTAMP, "
                        "auth_type TEXT NOT NULL)"
                    )
                    conn.execute(
                        "INSERT INTO Accounts VALUES (1,'legacy','legacy@example.com','s','h',"
                        "CURRENT_TIMESTAMP,?)",
                        (auth_type,),
                    )
                with patch(
                    "remoteRF_server.server.reservation.get_db_dir", return_value=root
                ), self.assertRaises(SchemaNotReady):
                    ReservationHandler()
