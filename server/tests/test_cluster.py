"""Two deployments form a cluster from one invite code, through a relay that
holds no secret. The broker is faked; the trust store and contract state
machine underneath are the real ones."""

import contextlib
import hashlib
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from remoteRF_server.server import global_onboarding as g
from remoteRF_server.server.federation import cluster


class FakeBroker:
    """The four broker endpoints the cluster flow uses, minus signatures --
    every event is re-verified by the importing ContractStore anyway."""

    def __init__(self):
        self.invites = {}
        self.contracts = {}
        self.rosters = {}
        self.statuses = {}
        self.public = {}  # (owner, cluster_name) -> {deployment_id: (identity, state)}
        self.caller = None

    def call(self, method, path, payload=None, **_):
        if path == "/v2/broker/invites" and method == "POST":
            self.invites[payload["invite_id"]] = {**payload, "joiner": None}
            return {}
        if path == "/v2/broker/invites/join":
            row = self.invites.get(payload["invite_id"])
            if row is None or row["secret_sha256"] != payload["secret_sha256"]:
                raise g.GlobalError("invite_not_found")
            row["joiner"] = {"identity": payload["identity"], "tag": payload["tag"]}
            return {"invite": self._view(row)}
        if path == "/v2/broker/invites":
            return {"invites": [self._view(row) for row in self.invites.values()]}
        if path == "/v2/broker/contracts/events":
            key = payload["terms"]["contract_id"]
            entry = self.contracts.setdefault(key, {"contract_id": key, "version": 1, "terms": payload["terms"], "events": []})
            entry["events"].append(payload["signed_event"])
            return {}
        if path == "/v2/broker/contracts":
            # Like the real relay, no promise about event order within a contract.
            return {"contracts": [{**c, "events": list(reversed(c["events"]))} for c in self.contracts.values()]}
        if path == "/v2/broker/clusters/roster" and method == "POST" and "public" in payload:
            note = payload["public"]
            key, me = (note["owner"], note["cluster_name"]), note["identity"]["deployment_id"]
            if note["state"] == "gone":
                self.public.pop(key, None)
            elif note["state"] == "closed":
                self.public.get(key, {}).pop(me, None)
            else:
                if note["state"] == "joined" and note["owner"] not in self.public.get(key, {}):
                    raise g.GlobalError("pool_not_found")
                self.public.setdefault(key, {})[me] = (note["identity"], note["state"])
            return {}
        if path == "/v2/broker/clusters/roster" and method == "POST":
            if "status" in payload:
                status = payload["status"]
                self.statuses[(status["owner"], status["cluster_name"], status["deployment_id"])] = {
                    "status": status, "signature": payload["signature"]}
                return {}
            roster = payload["roster"]
            self.rosters[(roster["owner"], roster["cluster_name"])] = {"roster": roster, "signature": payload["signature"]}
            return {}
        if path == "/v2/broker/clusters/roster":
            # The real broker filters to the caller; every side ignores its own.
            pools, joins = [], []
            for (owner, name), rows in self.public.items():
                for lab, (identity, state) in rows.items():
                    entry = {"identity": identity, "display_name": "Lab " + lab[-1].upper()}
                    if lab == owner and owner != self.caller:
                        pools.append({"cluster_name": name, "owner": entry,
                                      "state": rows.get(self.caller, (None, None))[1]})
                    elif owner == self.caller and lab != owner and state == "joined":
                        joins.append({"cluster_name": name, **entry})
            return {"rosters": list(self.rosters.values()), "statuses": list(self.statuses.values()),
                    "pools": pools, "joins": joins}
        raise AssertionError(path)

    @staticmethod
    def _view(row):
        return {
            "invite_id": row["invite_id"],
            "cluster_name": row["cluster_name"],
            "owner": {"identity": row["identity"], "tag": row["tag"],
                      "display_name": "Lab " + row["identity"]["deployment_id"][-1].upper()},
            "joiner": row["joiner"] and {**row["joiner"],
                                          "display_name": "Lab " + row["joiner"]["identity"]["deployment_id"][-1].upper()},
        }


class ClusterFlowTests(unittest.TestCase):
    A = "8a2e3f10-0000-4000-8000-00000000000a"
    B = "8a2e3f10-0000-4000-8000-00000000000b"

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

    def state(self, name, peer=None):
        """Member: the row's state. Owner: the named (or only) member's state,
        or 'invited'/'created' when nobody has joined yet."""
        item = {item["name"]: item for item in cluster.list_clusters()}[name]
        if item["role"] != "owner":
            return item["state"]
        members = [m for m in item["members"] if peer is None or m["deployment_id"] == peer]
        if members:
            return members[0]["state"]
        return "invited" if item["open_invites"] else "created"

    def test_invite_join_activates_on_both_sides(self):
        with self.server(self.A):
            cluster.create("lab")
            code = cluster.invite("lab")
            self.assertEqual(self.state("lab"), "invited")
        self.assertEqual(len(code.replace("-", "")), 40)

        with self.server(self.B):
            with self.assertRaises(cluster.ClusterError):
                cluster.join("not-a-code")
            with self.assertRaises(g.GlobalError):
                cluster.join(cluster.encode_code("00" * 5, b"\0" * 20))
            self.assertEqual(cluster.join(code), "lab")
            self.assertEqual(self.state("lab"), "joined")

        with self.server(self.A):
            # The invite code was the approval: the owner's tick pins the
            # joiner and proposes the contract with no further step.
            cluster.tick(self.notes.append)
            self.assertEqual(self.state("lab"), "proposed")

        with self.server(self.B):
            cluster.tick(self.notes.append)
            self.assertEqual(self.state("lab"), "accepted")  # our activation intent is in; owner's is not

        with self.server(self.A):
            cluster.tick(self.notes.append)
            self.assertEqual(self.state("lab"), "active")

        with self.server(self.B):
            cluster.tick(self.notes.append)
            self.assertEqual(self.state("lab"), "active")
            contract = cluster._contracts().list()[0]
            self.assertEqual(contract["state"], "active")
            self.assertEqual(contract["terms"]["allowed_capabilities"], sorted(cluster.CAPABILITIES))
        self.assertTrue(any("is active" in note for note in self.notes))

    def test_a_join_without_the_secret_is_ignored_by_the_owner(self):
        with self.server(self.A):
            cluster.create("lab")
            code = cluster.invite("lab")
        invite_id, _ = cluster.decode_code(code)
        row = self.broker.invites[invite_id]
        with self.server(self.B):
            forged = cluster._identity()
        # A relay (or attacker at the relay) that knows the hash but not the secret.
        row["joiner"] = {"identity": forged, "tag": hashlib.sha256(b"guess").hexdigest()}
        with self.server(self.A):
            cluster.tick(self.notes.append)
            self.assertIn("without the invite secret", self.notes[-1])
            self.assertEqual(cluster.load()["lab"], {**cluster.load()["lab"], "members": {}, "invites": {}})



    def test_invite_reuses_a_key_already_pinned_with_a_validity_window(self):
        """A Gate D import pinned our own key with real dates; inviting must
        advertise the same window instead of failing with trusted_key_conflict."""
        with self.server(self.A):
            me = cluster._identity()
            cluster._pin({**me, "valid_from": 1_000, "valid_until": 2_000}, source="manual_offline")
            cluster.create("lab")
            cluster.invite("lab")
            (invite_id,) = cluster.load()["lab"]["invites"]
            advertised = self.broker.invites[invite_id]["identity"]
        self.assertEqual((advertised["valid_from"], advertised["valid_until"]), (1_000, 2_000))

    def test_remove_revokes_the_contract_and_the_peer_sees_it(self):
        with self.server(self.A):
            cluster.create("lab")
            code = cluster.invite("lab")
        with self.server(self.B):
            cluster.join(code)
        for who in (self.A, self.B, self.A, self.B):
            with self.server(who):
                cluster.tick(self.notes.append)
        with self.server(self.A):
            self.assertEqual(self.state("lab"), "active")
            self.assertEqual(cluster.remove("lab"), "removed")
            self.assertEqual(cluster.load(), {})
            self.assertEqual(cluster._contracts().list()[0]["state"], "revoked")
        with self.server(self.B):
            cluster.tick(self.notes.append)
            self.assertEqual(self.state("lab"), "revoked")
            self.assertEqual(cluster.remove("lab"), "removed")
            self.assertEqual(cluster.load(), {})


    C = "8a2e3f10-0000-4000-8000-00000000000c"

    def test_an_owner_holds_several_members_each_on_its_own_contract(self):
        with self.server(self.A):
            cluster.create("lab")
            code_b, code_c = cluster.invite("lab"), cluster.invite("lab")
            self.assertEqual(cluster.list_clusters()[0]["open_invites"], 2)
        with self.server(self.B):
            cluster.join(code_b)
        with self.server(self.C):
            cluster.join(code_c)
        for who in (self.A, self.B, self.C, self.A, self.B, self.C):
            with self.server(who):
                cluster.tick(self.notes.append)
        with self.server(self.A):
            (item,) = cluster.list_clusters()
            self.assertEqual(item["open_invites"], 0)
            self.assertEqual(
                [(m["display_name"], m["state"]) for m in item["members"]],
                [("Lab B", "active"), ("Lab C", "active")],
            )
            contracts = {c["terms"]["contract_id"] for c in cluster._contracts().list()}
            self.assertEqual(len(contracts), 2)  # bilateral: one per member, never shared
        with self.server(self.B):
            (item,) = cluster.list_clusters()
            self.assertEqual((item["peer_name"], item["state"]), ("Lab A", "active"))
            # Only the owner hands out codes.
            with self.assertRaises(cluster.ClusterError):
                cluster.invite("lab")

    def _settle(self, *labs, rounds=4):
        for _ in range(rounds):
            for who in labs:
                with self.server(who):
                    cluster.tick(self.notes.append)

    def test_members_mesh_through_the_owner_signed_roster(self):
        with self.server(self.A):
            cluster.create("lab")
            code_b, code_c = cluster.invite("lab"), cluster.invite("lab")
        with self.server(self.B):
            cluster.join(code_b)
        with self.server(self.C):
            cluster.join(code_c)
        self._settle(self.A, self.B, self.C)
        for who, other in ((self.B, self.C), (self.C, self.B)):
            with self.server(who):
                (item,) = cluster.list_clusters()
                self.assertEqual(item["state"], "active")
                self.assertEqual([(p["deployment_id"], p["display_name"], p["state"]) for p in item["peers"]],
                                 [(other, "Lab " + other[-1].upper(), "active")])
                # B<->C is one contract, distinct from either owner contract.
                states = {c["terms"]["contract_id"]: c["state"] for c in cluster._contracts().list()}
                self.assertEqual(sorted(states.values()), ["active", "active"])
        # A roster the owner did not sign is ignored.
        key = (self.A, "lab")
        forged = dict(self.broker.rosters[key]); forged["signature"] = "AAAA"
        self.broker.rosters[key] = forged
        with self.server(self.B):
            cluster.tick(self.notes.append)
            self.assertIn("not signed by the owner", self.notes[-1])
        # C leaves: the owner republishes without it, and B revokes B<->C.
        with self.server(self.C):
            cluster.remove("lab")
        self._settle(self.A, self.B, rounds=2)
        with self.server(self.B):
            (item,) = cluster.list_clusters()
            self.assertEqual(item["peers"], [])
            self.assertTrue(any("left" in note for note in self.notes))

    def test_partners_learn_what_a_lab_shares_from_its_signed_note(self):
        with self.server(self.A):
            cluster.create("lab")
            code = cluster.invite("lab")
        with self.server(self.B):
            cluster.join(code)
            with cluster._usergroups() as conn:
                conn.execute("INSERT INTO UserGroups(group_name,devices_whitelist,max_reservation_time_sec,"
                             "max_reservations,lifetime_sec) VALUES ('bench','[1,2,3]',3600,5,0)")
            cluster.attach_group("lab", "bench")
        self._settle(self.A, self.B)
        with self.server(self.A):
            (item,) = cluster.list_clusters()
            sharing = item["members"][0]["sharing"]
            self.assertEqual((sharing["groups"], sharing["devices"]), (1, 3))
            (group,) = sharing["detail"]
            self.assertEqual((group["name"], group["max_reservation_time_sec"], group["max_reservations"]),
                             ("bench", 3600, 5))
            self.assertEqual(group["devices"], [])  # ids 1-3 are not devices this test process knows
            self.assertEqual(item["groups"], [])
        with self.server(self.B):
            (item,) = cluster.list_clusters()
            self.assertEqual(item["peer_sharing"], {"groups": 0, "devices": 0, "detail": []})
            self.assertEqual(item["groups"][0]["devices"], [1, 2, 3])
        # A note the lab did not sign is ignored.
        key = (self.A, "lab", self.B)
        self.broker.statuses[key] = {**self.broker.statuses[key], "signature": "AAAA"}
        self.broker.statuses[key]["status"] = {**self.broker.statuses[key]["status"], "groups": 99}
        with self.server(self.A):
            cluster.tick(self.notes.append)
            self.assertEqual(cluster.list_clusters()[0]["members"][0]["sharing"]["groups"], 1)

    def test_attached_groups_follow_cluster_accounts(self):
        with self.server(self.A):
            cluster.create("lab")
            with cluster._usergroups() as conn:
                for name in ("sdr", "pluto"):
                    conn.execute("INSERT INTO UserGroups(group_name,max_reservation_time_sec,max_reservations,"
                                 "lifetime_sec) VALUES (?,3600,5,0)", (name,))
            self.assertEqual(cluster.attach_group("lab", "sdr"), "sdr")
            with self.assertRaises(cluster.ClusterError):
                cluster.attach_group("lab", "sdr")
            (code,) = cluster.mint_codes("lab", uses=1, duration_sec=0)
            self.assertTrue(code.startswith("cluster."))
            self.assertEqual(cluster.list_codes()[0]["cluster_name"], "lab")
            self.assertIsNone(cluster.redeem_code(7, "cluster.nope"))
            self.assertEqual(cluster.redeem_code(7, code), "lab")
            self.assertIsNone(cluster.redeem_code(8, code))  # single use
            # A group attached later reaches accounts already in the cluster;
            # detaching takes it away again.
            cluster.attach_group("lab", "pluto")

            def groups():
                with cluster._usergroups() as conn:
                    return sorted(r[0] for r in conn.execute("SELECT group_id FROM UsersLookup WHERE user_id=7"))

            self.assertEqual(groups(), [1, 2])
            cluster.detach_group("lab", "1")
            self.assertEqual(groups(), [2])
            # A membership a group code granted is the group's, not the
            # cluster's: un-sharing and disbanding leave it alone.
            with cluster._usergroups() as conn:
                conn.execute("INSERT INTO UsersLookup(user_id,group_id) VALUES (7,1)")
            cluster.attach_group("lab", "1")
            cluster.detach_group("lab", "1")
            self.assertEqual(groups(), [1, 2])
            cluster.remove("lab")
            self.assertEqual(groups(), [1])
            with cluster._usergroups() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM ClusterAccounts").fetchone()[0], 0)

    def test_labs_can_form_a_new_cluster_after_disbanding_one(self):
        """The directory keeps the revoked contract; adopting the new proposal
        must step over it instead of failing the tick."""
        for _ in range(2):
            with self.server(self.A):
                cluster.create("lab")
                code = cluster.invite("lab")
            with self.server(self.B):
                cluster.join(code)
            self._settle(self.A, self.B)
            for who in (self.A, self.B):
                with self.server(who):
                    self.assertEqual(self.state("lab"), "active")
                    cluster.remove("lab")

    def test_first_shape_state_file_is_upgraded_in_place(self):
        with self.server(self.A):
            cluster.save({"old": {"role": "owner", "state": "active", "created_at": 5, "peer": self.B,
                                  "contract_id": "c-1", "published": ["e1"]},
                          "pending": {"role": "owner", "state": "invited", "created_at": 6,
                                      "invite_id": "ab" * 5, "secret": "00" * 20, "auto": False}})
            clusters = cluster.load()
        self.assertEqual(clusters["old"]["members"], {self.B: {
            "display_name": None, "contract_id": "c-1", "state": "active", "published": ["e1"], "joined_at": 5}})
        self.assertEqual(clusters["pending"]["invites"], {"ab" * 5: {"secret": "00" * 20, "auto": False, "created_at": 6}})
        for cluster_state in clusters.values():
            self.assertNotIn("peer", cluster_state)


if __name__ == "__main__":
    unittest.main()

    # A public cluster swaps the invite code for an open door. What bounds it
    # is the per-lab cap and `kick`.

    def _open(self):
        with self.server(self.A):
            cluster.create("open")
            cluster.set_public("open", True)

    def _accounts(self, *rows):
        """Accounts as the reservation handler keeps them: (acc_id, auth_type)."""
        path = cluster._db_path().with_name("reservations.db")
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS Accounts (acc_id INTEGER PRIMARY KEY, auth_type TEXT)")
            conn.executemany("INSERT INTO Accounts VALUES (?,?)", rows)

    def _in_cluster(self, name="open"):
        with cluster._usergroups() as conn:
            return sorted(conn.execute(
                "SELECT local_account_id,kind FROM ClusterAccounts WHERE cluster_name=?", (name,)).fetchall())

    def test_any_lab_on_global_walks_in_without_a_code(self):
        self._open()
        with self.server(self.A):
            (item,) = cluster.list_clusters()
            self.assertEqual((item["public"], item["lab_cap"], item["members"]), ("open", cluster.PUBLIC_LAB_CAP, []))
            with self.assertRaises(cluster.ClusterError):
                cluster.set_public("nope", True)
        with self.server(self.B):
            cluster.tick(self.notes.append)  # nobody typed anything on B
            self.assertEqual(self.state("open"), "joined")
            self.assertIn("joined public cluster open from Lab A", self.notes[-1])
            with self.assertRaises(cluster.ClusterError):
                cluster.set_public("open", False)  # not the owner
        self._settle(self.A, self.B)
        for who in (self.A, self.B):
            with self.server(who):
                self.assertEqual(self.state("open"), "active")
        with self.server(self.A):
            self.assertEqual(cluster.list_clusters()[0]["members"][0]["display_name"], "Lab B")
            self.assertEqual(cluster.lab_cap(self.B), cluster.PUBLIC_LAB_CAP)
        with self.server(self.B):
            (item,) = cluster.list_clusters()
            self.assertEqual((item["public"], item["lab_cap"], item["peer_name"]), (True, cluster.PUBLIC_LAB_CAP, "Lab A"))

    def test_every_native_account_is_in_and_enrolled_only_where_something_is_shared(self):
        self._open()
        with self.server(self.B):
            self._accounts((1, "local_password"), (2, "local_password"), (3, "federated"))
            cluster.tick(self.notes.append)
            self.assertEqual(self._in_cluster(), [(1, "local"), (2, "local")])  # no code; the proxy (3) is not a student
            self._accounts((4, "local_password"))
            cluster.tick(self.notes.append)  # an account made later follows on the next pass
            self.assertEqual([a for a, _ in self._in_cluster()], [1, 2, 4])
        self._settle(self.A, self.B)

        calls = []

        class Plane:
            enrolled_at = {}
            def enrolled(self, account):
                return self.enrolled_at.setdefault(account, set())
            def record_enrollment(self, *, local_account_id, destination_deployment_id):
                self.enrolled_at.setdefault(local_account_id, set()).add(destination_deployment_id)

        from types import SimpleNamespace
        home = SimpleNamespace(
            federation_devices=Plane(),
            federation_enroller=SimpleNamespace(outbound=SimpleNamespace(
                execute=lambda **kw: calls.append((kw["local_account_id"], kw["destination_deployment_id"])))))
        with self.server(self.B):
            cluster.enroll_students(home)
            self.assertEqual(calls, [])  # A shares nothing yet: it gets none of B's accounts
        with self.server(self.A):
            with cluster._usergroups() as conn:
                conn.execute("INSERT INTO UserGroups(group_name,devices_whitelist,max_reservation_time_sec,"
                             "max_reservations,lifetime_sec) VALUES ('community','[1,2,3]',3600,1,0)")
            cluster.attach_group("open", "community")
        self._settle(self.A, self.B, rounds=2)
        with self.server(self.B):
            cluster.enroll_students(home)
            self.assertEqual(sorted(calls), [(1, self.A), (2, self.A), (4, self.A)])

    def test_the_owners_own_accounts_get_the_shared_groups_too(self):
        """Overlap, not priority: local students may reserve the community
        devices like anyone else, next to whatever their own groups hold."""
        self._open()
        with self.server(self.A):
            self._accounts((7, "local_password"))
            with cluster._usergroups() as conn:
                conn.execute("INSERT INTO UserGroups(group_name,devices_whitelist,max_reservation_time_sec,"
                             "max_reservations,lifetime_sec) VALUES ('community','[1,2,3]',3600,1,0)")
            cluster.attach_group("open", "community")
            cluster.tick(self.notes.append)
            self.assertEqual(self._in_cluster(), [(7, "local")])
            with cluster._usergroups() as conn:
                self.assertEqual(conn.execute("SELECT group_id FROM UsersLookup WHERE user_id=7").fetchall(), [(1,)])

    def test_a_lab_that_leaves_stays_out_until_it_asks_back_in(self):
        self._open()
        self._settle(self.B, self.A)
        with self.server(self.B):
            self.assertEqual(self.state("open"), "active")
            self.assertEqual(cluster.remove("open"), "removed")
            cluster.tick(self.notes.append)
            self.assertEqual(cluster.load(), {})  # the door is open, and B does not walk back in
        with self.server(self.A):
            cluster.tick(self.notes.append)
            self.assertEqual(self.state("open"), "revoked")
        with self.server(self.B):
            self.assertEqual(cluster.join("open"), "open")  # by name: no code
        self._settle(self.A, self.B)
        for who in (self.A, self.B):
            with self.server(who):
                self.assertEqual(self.state("open"), "active")

    def test_closing_the_door_keeps_the_labs_already_in(self):
        self._open()
        self._settle(self.B, self.A)
        with self.server(self.A):
            with self.assertRaises(cluster.ClusterError):
                cluster.create("plain") and cluster.set_public("plain", False)  # never was public
            cluster.set_public("open", False)
            self.assertEqual(cluster.list_clusters()[0]["public"], "closed")
        with self.server(self.C):
            cluster.tick(self.notes.append)
            self.assertEqual(cluster.load(), {})
            with self.assertRaises(cluster.ClusterError):
                cluster.join("open")
        self._settle(self.A, self.B, rounds=1)
        for who in (self.A, self.B):
            with self.server(who):
                self.assertEqual(self.state("open"), "active")
        # Disbanding withdraws the door altogether.
        with self.server(self.A):
            cluster.set_public("open", True)
            cluster.remove("open")
        self.assertNotIn((self.A, "open"), self.broker.public)

    def test_kick_puts_one_lab_out_and_leaves_the_rest(self):
        self._open()
        self._settle(self.B, self.C, self.A)
        with self.server(self.A):
            self.assertEqual([m["state"] for m in cluster.list_clusters()[0]["members"]], ["active", "active"])
            contract_b = cluster.load()["open"]["members"][self.B]["contract_id"]
            # B's visitor: a proxy in the cluster's group, holding a reservation under B's contract.
            with cluster._usergroups() as conn:
                conn.execute("INSERT INTO UserGroups(group_name,devices_whitelist,max_reservation_time_sec,"
                             "max_reservations,lifetime_sec) VALUES ('community','[1]',3600,1,0)")
                for account, lab in ((50, self.B), (60, self.C)):
                    conn.execute(
                        "INSERT INTO FederatedPrincipals(id,issuer_deployment_id,remote_subject_id,local_account_id,"
                        "status,created_at) VALUES (?,?,?,?,'active',1)",
                        (f"p{account}", lab, f"00000000-0000-4000-8000-0000000000{account}", account))
                    cluster.join_account(conn, "open", cluster.load()["open"], account, kind="proxy")
            cluster.attach_group("open", "community")
            path = cluster._db_path().with_name("reservations.db")
            with sqlite3.connect(path) as conn:
                conn.execute("CREATE TABLE Reservations (res_id INTEGER PRIMARY KEY, username TEXT)")
                conn.execute("CREATE TABLE FederatedReservations (res_id INTEGER PRIMARY KEY, contract_id TEXT)")
                conn.executemany("INSERT INTO Reservations VALUES (?,?)", [(1, "b-visitor"), (2, "c-visitor"), (3, "native")])
                conn.executemany("INSERT INTO FederatedReservations VALUES (?,?)", [(1, contract_b), (2, "other-contract")])

            for nobody in ("Lab Z", self.B[:8] + "…"):  # unknown; an id prefix two labs share
                with self.assertRaises(cluster.ClusterError):
                    cluster.kick("open", nobody)
            self.assertEqual(cluster.kick("open", "lab b"), "Lab B")
            (item,) = cluster.list_clusters()
            self.assertEqual(([m["display_name"] for m in item["members"]], item["kept_out"]), (["Lab C"], 1))
            self.assertEqual(cluster._contracts().show(contract_b, 1)["state"], "revoked")
            self.assertEqual(self._in_cluster(), [(60, "proxy")])
            with cluster._usergroups() as conn:
                self.assertEqual(conn.execute("SELECT user_id FROM UsersLookup").fetchall(), [(60,)])
            with sqlite3.connect(path) as conn:
                self.assertEqual(conn.execute("SELECT res_id FROM Reservations").fetchall(), [(2,), (3,)])
                self.assertEqual(conn.execute("SELECT res_id FROM FederatedReservations").fetchall(), [(2,)])
            self.assertIsNone(cluster.lab_cap(self.B))  # no longer a party to anything here

        # The door is still open and B's row still says joined: A does not let it back in.
        self._settle(self.A, self.B, self.C, rounds=2)
        with self.server(self.A):
            self.assertEqual([m["display_name"] for m in cluster.list_clusters()[0]["members"]], ["Lab C"])
        with self.server(self.B):
            self.assertEqual(self.state("open"), "revoked")
        with self.server(self.C):
            (item,) = cluster.list_clusters()
            self.assertEqual((item["state"], item["peers"]), ("active", []))  # C dropped its contract with B

        # A code handed to B by the owner is the way back in.
        with self.server(self.B):
            cluster.remove("open")
            cluster.tick(self.notes.append)
            self.assertEqual(cluster.load(), {})  # kicked: it does not walk back in on its own either
        with self.server(self.A):
            code = cluster.invite("open")
        with self.server(self.B):
            cluster.join(code)
        self._settle(self.A, self.B)
        with self.server(self.A):
            (item,) = cluster.list_clusters()
            self.assertEqual((sorted(m["display_name"] for m in item["members"]), item["kept_out"]),
                             (["Lab B", "Lab C"], 0))

    def test_the_cap_is_the_most_generous_among_shared_clusters(self):
        self._open()
        self._settle(self.B, self.A)
        with self.server(self.A):
            self.assertEqual(cluster.lab_cap(self.B), cluster.PUBLIC_LAB_CAP)
            self.assertIsNone(cluster.lab_cap(self.C))  # in no cluster: a contract made by hand is not capped
            cluster.set_cap("open", 9)
            self.assertEqual(cluster.lab_cap(self.B), 9)
            with self.assertRaises(cluster.ClusterError):
                cluster.set_cap("open", -1)
            # A partner chosen by hand, in a cluster with no cap, is not held to the public one.
            cluster.create("partners")
            code = cluster.invite("partners")
        with self.server(self.B):
            cluster.join(code)
        self._settle(self.A, self.B)
        with self.server(self.A):
            self.assertIsNone(cluster.lab_cap(self.B))
            cluster.set_cap("partners", 20)
            self.assertEqual(cluster.lab_cap(self.B), 20)
            cluster.set_cap("open", 0)  # 0 lifts it, and reopening does not bring the default back
            cluster.set_public("open", True)
            self.assertIsNone(cluster.lab_cap(self.B))
