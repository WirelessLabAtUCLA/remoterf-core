"""A lab active on Global proposes a contract with Global's account home and
sees it through to active once the home accepts; the home side is played here
with the same cluster primitives the real home agent mirrors."""

import contextlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from remoteRF_server.server import global_onboarding as g
from remoteRF_server.server.federation import cluster, global_home
from test_cluster import FakeBroker

A = "8a2e3f10-0000-4000-8000-00000000000a"   # the lab
B = "8a2e3f10-0000-4000-8000-00000000000b"
C = "8a2e3f10-0000-4000-8000-00000000000c"
H = "8a2e3f10-0000-4000-8000-00000000000e"   # Global's account home


class GlobalHomeContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.broker = FakeBroker()
        patch = mock.patch.object(g, "call", self.broker.call)
        patch.start()
        self.addCleanup(patch.stop)
        self.notes = []

    @contextlib.contextmanager
    def server(self, deployment_id):
        root = Path(self.tmp.name) / deployment_id[-1]
        env = {k: v for k, v in os.environ.items() if not k.startswith(("REMOTERF_", "XDG_"))}
        env.update(XDG_CONFIG_HOME=str(root / "config"), XDG_DATA_HOME=str(root / "data"))
        with mock.patch.dict("os.environ", env, clear=True):
            if not g.participating():
                g.update(GLOBAL_CONSENT="yes", GLOBAL_NAME=deployment_id[-1], GLOBAL_DISPLAY_NAME="Lab",
                         GLOBAL_EMAIL="lab@example.edu", GLOBAL_STATE="unregistered")
                g.ensure_identity()
                g._apply_me({"status": "active", "deployment_id": deployment_id, "name": deployment_id[-1], "relay": None})
            self.broker.caller = deployment_id
            yield

    def test_lab_proposes_and_the_contract_goes_active_once_global_accepts(self):
        with self.server(H):
            home_identity = cluster._identity()
        with self.server(A), mock.patch.object(global_home, "fetch_identity", return_value=home_identity):
            global_home.tick(self.notes.append)
            party = global_home.load()["party"]
            self.assertEqual(party["state"], "proposed")
            self.assertTrue(party["contract_id"])
            self.assertIsNone(global_home.contract_id())
            lab_identity = cluster._identity()
        # Global's home: pin the lab on the broker's word, adopt the proposal, accept, activate, publish.
        with self.server(H):
            cluster._pin(lab_identity, source="broker_candidate")
            cluster._pin_self()
            home_party = {"state": "created"}
            directory = g.call("GET", "/v2/broker/contracts")["contracts"]
            cluster._advance(home_party, A, directory, label="lab", notify=self.notes.append, is_member=True)
            self.assertEqual(home_party["contract_id"], party["contract_id"])
        with self.server(A), mock.patch.object(global_home, "fetch_identity", side_effect=AssertionError("cached")):
            global_home.tick(self.notes.append)
            self.assertEqual(global_home.load()["party"]["state"], "active")
            self.assertEqual(global_home.contract_id(), party["contract_id"])
        self.assertIn("[cluster] RemoteRF Global is active", self.notes)

    def _standing(self, lab, home_identity):
        """The lab proposes its standing contract; the home accepts; the lab sees it active."""
        with self.server(lab), mock.patch.object(global_home, "fetch_identity", return_value=home_identity):
            global_home.tick(self.notes.append)
            lab_identity = cluster._identity()
        with self.server(H):
            cluster._pin(lab_identity, source="broker_candidate")
            cluster._pin_self()
            directory = g.call("GET", "/v2/broker/contracts")["contracts"]
            cluster._advance({"state": "created"}, lab, directory, label=lab, notify=self.notes.append, is_member=True)
        with self.server(lab), mock.patch.object(global_home, "fetch_identity", return_value=home_identity):
            global_home.tick(self.notes.append)
            self.assertIsNotNone(global_home.contract_id())

    def test_every_lab_walks_into_the_one_global_cluster_and_shares_its_public_groups(self):
        with self.server(H):
            home_identity = cluster._identity()
            cluster._public_note(cluster.GLOBAL, "open")
        with self.server(A):
            cluster._public_note("theirs", "open")  # a lab's own open door is not Global's: ignored
        for lab in (B, C):
            with self.server(lab):
                cluster.tick(self.notes.append)
                self.assertEqual(cluster.load(), {})  # no standing contract yet: wait
            self._standing(lab, home_identity)
            with self.server(lab):
                cluster.tick(self.notes.append)
                self.assertEqual(sorted(cluster.load()), [cluster.GLOBAL])  # nobody typed anything
                item = cluster.load()[cluster.GLOBAL]
                self.assertEqual((item["peer"], item["contract_id"], item["state"]),
                                 (H, global_home.contract_id(), "active"))
                with self.assertRaises(cluster.ClusterError):
                    cluster.remove(cluster.GLOBAL)
        # The home signs the member list; B and C mesh by it.
        with self.server(H):
            cluster._publish_roster(cluster.GLOBAL, {"members": {
                lab: {"state": "active", "display_name": "Lab " + lab[-1].upper()} for lab in (B, C)}})
        for _ in range(3):
            for lab in (B, C):
                with self.server(lab):
                    cluster.tick(self.notes.append)
        with self.server(B):
            (item,) = cluster.list_clusters()
            self.assertEqual((item["state"], [(p["deployment_id"], p["state"]) for p in item["peers"]]),
                             ("active", [(C, "active")]))
            # A group marked public is what the other labs see.
            with cluster._usergroups() as conn:
                conn.execute("INSERT INTO UserGroups(group_name,devices_whitelist,max_reservation_time_sec,"
                             "max_reservations,lifetime_sec) VALUES ('bench','[1,2,3]',3600,5,0)")
            cluster.attach_group(cluster.GLOBAL, "bench")
            cluster.tick(self.notes.append)
        with self.server(C):
            cluster.tick(self.notes.append)
            self.assertEqual(cluster.load()[cluster.GLOBAL]["peers"][B]["sharing"]["devices"], 3)

    def test_a_group_made_public_before_the_lab_walks_in_is_shared_when_it_does(self):
        with self.server(H):
            home_identity = cluster._identity()
            cluster._public_note(cluster.GLOBAL, "open")
        with self.server(B):
            with cluster._usergroups() as conn:
                conn.execute("INSERT INTO UserGroups(group_name,devices_whitelist,max_reservation_time_sec,"
                             "max_reservations,lifetime_sec) VALUES ('bench','[1]',3600,5,0)")
            cluster.attach_group(cluster.GLOBAL, "bench")
            (group_id,) = global_home.load()["public_groups"]
            self.assertEqual(cluster.shared_with(group_id), [cluster.GLOBAL])
        self._standing(B, home_identity)
        with self.server(B):
            cluster.tick(self.notes.append)
            self.assertEqual(cluster.load()[cluster.GLOBAL]["groups"], [group_id])
            self.assertNotIn("public_groups", global_home.load())


if __name__ == "__main__":
    unittest.main()
