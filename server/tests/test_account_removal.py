"""Deleting an account leaves no row the cluster tick or a group would still act on."""

import os
import sqlite3
import tempfile
import unittest
from unittest import mock


class AccountRemovalTests(unittest.TestCase):
    def test_remove_user_drops_every_row_keyed_by_the_account(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("REMOTERF_", "XDG_"))}
        env.update(XDG_CONFIG_HOME=tmp.name, XDG_DATA_HOME=tmp.name + "/data")
        with mock.patch.dict("os.environ", env, clear=True):
            from remoteRF_server.common.utils import map_arg
            from remoteRF_server.server import acc_perms, reservation
            from remoteRF_server.server import user_group_handler as ugh
            from remoteRF_server.server.federation import cluster

            groups, h = ugh.UserGroupHandler(), reservation.ReservationHandler()
            perms = acc_perms.perms_db() if hasattr(acc_perms, "perms_db") else acc_perms.Perms()
            res_db = reservation.get_db_dir() / "reservations.db"
            with mock.patch.object(reservation, "perms", perms), mock.patch.object(reservation, "user_group_handler", groups):
                gid = groups.create_user_group(group_name="g", devices_whitelist=[], max_reservation_time_sec=60,
                                               max_reservations=1, lifetime_sec=0)
                groups.create_enrollment_codes(code_names=["C1"], group_id=gid, uses=1, duration_sec=0)
                created = h.create_user(un=map_arg("alice"), pw=map_arg("password1"), em=map_arg("a@x.org"), ec=map_arg("C1"))
                self.assertIn("UC", created, created)
                uid = h.get_uid("alice")
                with cluster._usergroups() as conn:
                    conn.execute("INSERT INTO ClusterAccounts(cluster_name,local_account_id,kind,joined_at) "
                                 "VALUES ('open',?,'local',0)", (uid,))
                with sqlite3.connect(res_db) as conn:
                    conn.execute("CREATE TABLE IF NOT EXISTS FederatedEnrollments "
                                 "(local_account_id INTEGER, destination_deployment_id TEXT, enrolled_at INTEGER)")
                    conn.execute("INSERT INTO FederatedEnrollments VALUES (?, 'lab', 0)", (uid,))
                    self.assertEqual(conn.execute("SELECT COUNT(*) FROM LocalAccountSubjects WHERE local_account_id=?",
                                                  (uid,)).fetchone()[0], 1)
                h.remove_user(username="alice")
            with sqlite3.connect(res_db) as conn:
                for table, col in (("Accounts", "acc_id"), ("LocalAccountSubjects", "local_account_id"),
                                   ("FederatedEnrollments", "local_account_id")):
                    self.assertEqual(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {col}=?", (uid,)).fetchone()[0], 0, table)
            with cluster._usergroups() as conn:
                for table, col in (("UsersLookup", "user_id"), ("ClusterAccounts", "local_account_id")):
                    self.assertEqual(conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {col}=?", (uid,)).fetchone()[0], 0, table)


if __name__ == "__main__":
    unittest.main()
