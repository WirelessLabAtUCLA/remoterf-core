"""Stay-logged-in tokens for the deployment protocol."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock


class ClientSessionTests(unittest.TestCase):
    def setUp(self):
        from remoteRF_server.server import acc_perms, reservation, user_group_handler as ugh

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
        gid = self.groups.create_user_group(
            group_name="g", devices_whitelist=[], max_reservation_time_sec=60,
            max_reservations=1, lifetime_sec=0,
        )
        self.groups.create_enrollment_codes(code_names=["C1"], group_id=gid, uses=1, duration_sec=0)
        from remoteRF_server.common.utils import map_arg
        created = self.h.create_user(un=map_arg("alice"), pw=map_arg("password1"), em=map_arg("a@x.org"), ec=map_arg("C1"))
        self.assertIn("UC", created, created)
        self.map = map_arg

    def login(self, secret, remember=False):
        from remoteRF_server.common.utils import unmap_arg
        args = {"un": self.map("alice"), "pw": self.map(secret)}
        if remember:
            args["remember"] = self.map(True)
        result = self.h.handle_call(function_name="login", args=args)
        return {k: unmap_arg(v) for k, v in result.items()}

    def test_token_replaces_the_password_and_logout_revokes_it(self):
        plain = self.login("password1")
        self.assertEqual(plain, {"UC": "alice"})           # no token unless asked
        remembered = self.login("password1", remember=True)
        token = remembered["token"]
        self.assertGreaterEqual(len(token), 40)
        self.assertEqual(self.login(token), {"UC": "alice"})   # token works as the secret
        self.assertNotIn("token", self.login(token))           # and never mints another
        # Only a hash is stored.
        with mock.patch.object(self.h, "filepath", self.h.filepath):
            import sqlite3
            rows = sqlite3.connect(self.h.filepath).execute("SELECT token_hash FROM ClientSessions").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertNotIn(token, rows[0][0])
        # Wrong user, garbage, and a revoked token all fail.
        self.assertIn("UE", self.h.login_user("bob", token))
        self.assertIn("UE", self.login("x" * 43))
        self.h.handle_call(function_name="logout", args={"un": self.map("alice"), "pw": self.map(token)})
        self.assertIn("UE", self.login(token))
        self.assertEqual(self.login("password1"), {"UC": "alice"})

    def test_removing_the_user_revokes_sessions(self):
        token = self.login("password1", remember=True)["token"]
        self.h.remove_user(username="alice")
        self.assertIn("UE", self.h.login_user("alice", token))


    def test_direct_offer_needs_the_session_secret(self):
        """ACC:direct_offer is authenticated like every other account call."""
        from remoteRF_server.common.utils import unmap_arg

        token = self.login("password1", remember=True)["token"]
        with mock.patch("remoteRF_server.server.direct_path.offer", return_value={"ice": self.map("{}")}) as offer:
            for secret in ("wrong", "x" * 43, ""):
                result = self.h.handle_call(
                    function_name="direct_offer",
                    args={"un": self.map("alice"), "pw": self.map(secret), "ice": self.map("{}")},
                )
                self.assertEqual(unmap_arg(result["ace"]), "Invalid login credentials.", secret)
            offer.assert_not_called()
            result = self.h.handle_call(
                function_name="direct_offer",
                args={"un": self.map("alice"), "pw": self.map(token), "ice": self.map('{"id": "p1"}')},
            )
            self.assertIn("ice", result)
            offer.assert_called_once_with(self.h._session_hash(token), "alice", '{"id": "p1"}')
        # A revoked session cannot offer either.
        self.h.handle_call(function_name="logout", args={"un": self.map("alice"), "pw": self.map(token)})
        result = self.h.handle_call(
            function_name="direct_offer",
            args={"un": self.map("alice"), "pw": self.map(token), "ice": self.map("{}")},
        )
        self.assertEqual(unmap_arg(result["ace"]), "Invalid login credentials.")

if __name__ == "__main__":
    unittest.main()
