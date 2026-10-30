"""Account handling: generic errors, login/enrollment limiter, password KDF, get_res masking."""

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock


class AccountHardeningTests(unittest.TestCase):
    def setUp(self):
        from remoteRF_server.server import acc_perms, reservation, user_group_handler as ugh
        from remoteRF_server.common.utils import map_arg, unmap_arg

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for target in (reservation, acc_perms, ugh):
            patch = mock.patch.object(target, "get_db_dir", return_value=root)
            patch.start()
            self.addCleanup(patch.stop)
        self.perms = acc_perms.perms_db() if hasattr(acc_perms, "perms_db") else acc_perms.Perms()
        self.groups = ugh.UserGroupHandler()
        self.h = reservation.ReservationHandler()
        for name, value in (("perms", self.perms), ("user_group_handler", self.groups)):
            patch = mock.patch.object(reservation, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.reservation = reservation
        reservation._failures.clear()
        self.addCleanup(reservation._failures.clear)
        gid = self.groups.create_user_group(
            group_name="g", devices_whitelist=[7], max_reservation_time_sec=3600,
            max_reservations=5, lifetime_sec=0,
        )
        self.groups.create_enrollment_codes(code_names=["C1"], group_id=gid, uses=10, duration_sec=0)
        self.map, self.unmap = map_arg, unmap_arg
        self.assertIn("UC", self.create("alice", "a@x.org"))

    def create(self, username, email, code="C1", password="password1"):
        return self.h.create_user(
            un=self.map(username), pw=self.map(password), em=self.map(email), ec=self.map(code)
        )

    def call(self, function_name, **args):
        result = self.h.handle_call(function_name=function_name, args={k: self.map(v) for k, v in args.items()})
        return {k: self.unmap(v) for k, v in result.items()}

    def account_row(self, username):
        with sqlite3.connect(self.h.filepath) as con:
            return con.execute(
                "SELECT pass_salt, pass_hash FROM Accounts WHERE username = ?", (username,)
            ).fetchone()

    def test_unexpected_error_is_a_generic_ace(self):
        result = self.call("login", pw="password1")  # no 'un' -> KeyError inside handle_call
        self.assertEqual(set(result), {"ace"})
        self.assertIn("Internal server error", result["ace"])

    def test_duplicate_username_or_email_gives_one_generic_message(self):
        expected = "That username or email is already registered."
        self.assertEqual(self.unmap(self.create("alice", "other@x.org")["UE"]), expected)
        self.assertEqual(self.unmap(self.create("bob", "a@x.org")["UE"]), expected)
        self.assertIsNone(self.account_row("bob"))

    def test_login_limiter_locks_after_ten_failures_and_unlocks_after_window(self):
        self.assertIn("UC", self.create("bob", "b@x.org"))
        time = self.reservation.time
        base = time.monotonic()
        with mock.patch.object(time, "monotonic", return_value=base):
            for _ in range(10):
                self.assertIn("UE", self.h.login_user("alice", "wrong"))
            locked = self.h.login_user("alice", "password1")
            self.assertEqual(self.unmap(locked["UE"]), "Invalid login details.")
            self.assertIn("UC", self.h.login_user("bob", "password1"))  # per-username, not global
        with mock.patch.object(time, "monotonic", return_value=base + 301):
            self.assertIn("UC", self.h.login_user("alice", "password1"))
            self.assertNotIn("login:alice", self.reservation._failures)

    def test_enrollment_limiter_uses_a_global_bucket(self):
        for _ in range(60):
            self.assertEqual(
                self.unmap(self.create("dave", "d@x.org", code="nope")["UE"]),
                "Invalid or expired enrollment code.",
            )
        self.assertEqual(
            self.unmap(self.create("carol", "c@x.org")["UE"]), "Invalid or expired enrollment code."
        )
        self.assertIn(
            "Invalid or expired code",
            self.call("set_enroll", un="alice", pw="password1", ec="C1")["UE"],
        )

    def test_legacy_sha256_password_logs_in_and_is_rehashed(self):
        from remoteRF_server.common.utils import hash_token
        from remoteRF_server.common.utils.api_token import PASSWORD_HASH_PREFIX

        self.assertTrue(self.account_row("alice")[1].startswith(PASSWORD_HASH_PREFIX))
        with sqlite3.connect(self.h.filepath) as con:
            con.execute(
                "UPDATE Accounts SET pass_salt = ?, pass_hash = ? WHERE username = 'alice'",
                hash_token("password1"),
            )
        self.assertFalse(self.account_row("alice")[1].startswith(PASSWORD_HASH_PREFIX))
        self.assertIn("UE", self.h.login_user("alice", "wrong"))
        self.assertIn("UC", self.h.login_user("alice", "password1"))
        self.assertTrue(self.account_row("alice")[1].startswith(PASSWORD_HASH_PREFIX))
        self.assertIn("UC", self.h.login_user("alice", "password1"))
        self.assertIn("UE", self.h.login_user("alice", "wrong"))

    def test_get_res_masks_other_users_but_keeps_field_layout(self):
        self.assertIn("UC", self.create("bob", "b@x.org"))
        start = datetime.now() + timedelta(hours=1)
        end = start + timedelta(minutes=30)
        with sqlite3.connect(self.h.filepath) as con:
            for user in ("alice", "bob"):
                con.execute(
                    "INSERT INTO Reservations (username, device_id, start_time, end_time, salt, hash) "
                    "VALUES (?, 7, ?, ?, 's', 'h')",
                    (user, start, end),
                )
        rows = [v.split(",") for v in self.call("get_res", un="alice", pw="password1").values()]
        self.assertEqual(len(rows), 2)
        self.assertEqual(sorted(r[0] for r in rows), ["alice", "reserved"])
        for r in rows:
            self.assertEqual(len(r), 4)
            self.assertEqual(r[1], "7")
            self.assertEqual(r[2], str(start))
            self.assertEqual(r[3], str(end))


if __name__ == "__main__":
    unittest.main()
