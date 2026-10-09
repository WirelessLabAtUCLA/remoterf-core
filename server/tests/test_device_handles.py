"""Device handles: a device's name, as typed (spaces and '_' alike), which its
holder can trade (logged in) for a token bound to their own live reservation
(ACC:device_token)."""

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yaml

from remoteRF_server.common.grpc import grpc_host_pb2, grpc_pb2
from remoteRF_server.common.utils import map_arg, unmap_arg
from remoteRF_server.server import device_manager as dm

GID = 4300
WHY = "no active reservation of yours on Pluto_A right now"


class _Dev:
    device_type = "fake"

    def dispatch(self, method_name, args):
        return method_name


def _state(origin="local", name="dev", salt="", hsh=""):
    return dm._DeviceState(
        dev=_Dev() if origin == "local" else dm.VirtualDevice(gid=0, host_id="h", device_id="0"),
        origin=origin, online=True, salt=salt, hsh=hsh, name=name, ident="X", dtype="fake",
        handle=dm._name_handle(name),
    )


class _Devices(unittest.TestCase):
    """A private device table, so the module's real inventory is untouched."""

    def setUp(self):
        for patcher in (
            mock.patch.dict(dm._devices, clear=True),
            mock.patch.dict(dm._bridge_tokens, clear=True),
            mock.patch.object(dm, "_reservation_end_callbacks", []),
            mock.patch.object(dm, "_get_host_registry", return_value=None),
            mock.patch.object(dm, "_reset_if_pending"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)


class HandleTableTests(_Devices):
    def test_a_name_is_its_handle_with_spaces_and_underscores_alike(self):
        dm._devices[7] = _state(name="pluto A")
        for typed in ("pluto A", "pluto_A", " pluto\tA ", "pluto__A"):
            self.assertEqual(dm.find_device_id_by_handle(typed), 7, typed)
        self.assertIsNone(dm.find_device_id_by_handle("Pluto_A"))  # case-sensitive
        self.assertEqual([dm._name_handle(n) for n in ("a@b", "a:b", "rfg_x", "bridge-x", " _ ")], [""] * 5)

    def test_duplicates_go_to_local_first_then_the_lowest_id(self):
        dm._devices.update({
            10: _state("host", "A"), 11: _state("local", "A"),
            12: _state("local", "B"), 13: _state("local", "B"), 14: _state("local", "a@b"),
        })
        self.assertEqual(dm.find_device_id_by_handle("A"), 11)
        self.assertEqual(dm.find_device_id_by_handle("B"), 12)
        self.assertIsNone(dm.find_device_id_by_handle("b"))  # exact, case-sensitive
        self.assertIsNone(dm.find_device_id_by_handle(""))
        self.assertEqual(dm.handle_report(), {
            10: "A ignored (duplicate name)", 11: "A", 12: "B", 13: "B ignored (duplicate name)",
        })
        labels = dm._local_devices_str_snapshot()
        self.assertEqual((labels[12], labels[13]), ("B (online)", "B (online)"))
        described = {d["id"]: d.get("handle") for d in dm.describe_devices([11, 12, 13, 14])}
        self.assertEqual(described, {11: "A", 12: "B", 13: None, 14: None})
        inventory = dm.device_inventory_snapshot()
        self.assertEqual([inventory[g]["handle"] for g in (10, 11, 13)], ["", "A", ""])

    def test_host_sync_takes_the_handle_from_the_label_not_the_handle_field(self):
        snap = {
            "20": ("nuc", grpc_host_pb2.DeviceInfo(label="X", handle="PlutoH"), True),
            "21": ("nuc", grpc_host_pb2.DeviceInfo(label="Y@lab"), True),
        }
        reg = SimpleNamespace(device_directory_cached=lambda ttl_ms: snap, list_devices=lambda: {})
        with mock.patch.object(dm, "_get_host_registry", return_value=reg):
            dm._sync_host_devices(force=True)
            self.assertEqual((dm._devices[20].handle, dm._devices[21].handle), ("X", ""))
            self.assertEqual(dm._host_devices_str_snapshot()[20], "X (online)")
            snap.pop("20")  # renumbered away: the stale entry gives its handle up
            dm._sync_host_devices(force=True)
            self.assertEqual((dm._devices[20].online, dm._devices[20].handle), (False, ""))

    def test_a_device_removed_from_a_host_frees_its_handle_for_another(self):
        from remoteRF_server.host import host_tunnel_server as hts

        def dev(gid, label):
            return grpc_host_pb2.DeviceInfo(device_id=str(gid), local_id=gid, label=label)

        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"REMOTERF_CONFIG_DIR": tmp}):
            reg = hts.HostTunnelRegistry()
            reg._hosts["lab-host"] = SimpleNamespace(alive=True)
            with mock.patch.object(dm, "_get_host_registry", return_value=reg):
                reg.announce_devices("lab-host", [dev(502, "PlutoB"), dev(503, "d503")], full_snapshot=True)
                dm._sync_host_devices(force=True)
                self.assertEqual(dm.find_device_id_by_handle("PlutoB"), 502)
                # the Host drops 502 and renames 503 PlutoB (its announce is a full snapshot)
                reg.announce_devices("lab-host", [dev(503, "PlutoB")], full_snapshot=True)
                dm._sync_host_devices(force=True)
        self.assertEqual(dm.find_device_id_by_handle("PlutoB"), 503)
        self.assertEqual(dm.handle_report(), {503: "PlutoB"})
        self.assertFalse(dm._devices[502].online)
        self.assertFalse(reg.is_host_device("502"))


class BridgeTokenTests(_Devices):
    def setUp(self):
        super().setUp()
        dm._devices[GID] = _state(salt="a1", hsh="h1")

    def test_expect_refuses_a_changed_reservation(self):
        with self.assertRaises(RuntimeError):
            dm.reservation_bridge_token(GID, expect=("b2", "h2"))
        token = dm.reservation_bridge_token(GID, expect=("a1", "h1"))
        self.assertTrue(token.startswith(f"bridge-{GID}-"))

    def test_acquire_device_honours_a_bound_token_until_the_holder_changes(self):
        token = dm.reservation_bridge_token(GID)
        with dm.acquire_device(token) as (gid, dev):
            self.assertEqual(gid, GID)
        dm.set_device(GID, "b2", "h2")
        with self.assertRaisesRegex(RuntimeError, "invalid token"):
            with dm.acquire_device(token):
                pass

    def test_a_bound_token_drives_the_device_over_the_direct_path(self):
        from remoteRF_server.server import direct_path

        token = dm.reservation_bridge_token(GID)
        request = grpc_pb2.GenericRPCRequest(function_name="fake:rx_lo:GET", args={"a": map_arg(token)})
        with mock.patch("remoteRF_server.server.global_onboarding.detected_lan_ip", return_value="10.0.0.1"):
            results = direct_path._dispatch(request, "10.0.0.2")
        self.assertEqual(unmap_arg(results["rx_lo"]), "get_rx_lo")


class DeviceTokenExchangeTests(_Devices):
    def setUp(self):
        super().setUp()
        from remoteRF_server.server import acc_perms, reservation, user_group_handler as ugh

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        for target in (reservation, acc_perms, ugh):
            patcher = mock.patch.object(target, "get_db_dir", return_value=Path(tmp.name))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.groups = ugh.UserGroupHandler()
        self.h = reservation.ReservationHandler()
        for name, value in (("perms", acc_perms.perms_db()), ("user_group_handler", self.groups)):
            patcher = mock.patch.object(reservation, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        group = self.groups.create_user_group(
            group_name="g", devices_whitelist=[], max_reservation_time_sec=60,
            max_reservations=1, lifetime_sec=0,
        )
        self.groups.create_enrollment_codes(code_names=["C1", "C2"], group_id=group, uses=1, duration_sec=0)
        for user, code in (("alice", "C1"), ("bob", "C2")):
            created = self.h.create_user(un=map_arg(user), pw=map_arg("password1"),
                                         em=map_arg(f"{user}@example.org"), ec=map_arg(code))
            self.assertIn("UC", created, created)
        dm._devices[GID] = _state(name="Pluto A")
        self.reservation = reservation

    def _reserve(self, username, salt="s1", hsh="h1", end="2099-01-01 00:00:00"):
        with sqlite3.connect(self.h.filepath) as conn:
            res_id = conn.execute(
                "INSERT INTO Reservations (username, device_id, start_time, end_time, salt, hash) "
                "VALUES (?, ?, '2026-01-01 00:00:00', ?, ?, ?)",
                (username, GID, end, salt, hsh),
            ).lastrowid
        dm.set_device(GID, salt, hsh)
        return res_id

    def _exchange(self, h, user="alice", pw="password1"):
        result = self.h.handle_call(function_name="device_token",
                                    args={"un": map_arg(user), "pw": map_arg(pw), "h": map_arg(h)})
        return {k: unmap_arg(v) for k, v in result.items()}

    def test_the_holder_gets_a_token_bound_to_their_reservation(self):
        res_id = self._reserve("alice")
        reply = self._exchange("Pluto_A")
        self.assertEqual(set(reply), {"Token", "res_id"})
        self.assertTrue(reply["Token"].startswith("bridge-"))
        self.assertEqual(reply["res_id"], res_id)
        self.assertEqual(dm.resolve_gid_for_token(reply["Token"]), GID)
        self.assertEqual(self._exchange("Pluto A")["Token"], reply["Token"])

    def test_anything_that_is_not_a_handle_comes_back_unchanged(self):
        self._reserve("alice")
        for h in ("pluto A", "Ab3__xY9-kLm_", "bridge-1-x"):  # a miss is never rewritten
            self.assertEqual(self._exchange(h), {"Token": h})

    def test_a_super_token_passes_through_to_the_device_plane(self):
        self._reserve("alice")  # held: only the _force form takes it over
        with mock.patch.object(dm, "_get_master_token", return_value="SuperTok"):
            for t in (f"SuperTok_{GID}_force", f"SuperTok-{GID}", "SuperTok"):
                self.assertEqual(self._exchange(t), {"Token": t})
            with dm.acquire_device(f"SuperTok_{GID}_force") as (gid, _dev):
                self.assertEqual(gid, GID)

    def test_refusals_are_identical_and_never_name_the_holder(self):
        self.assertEqual(self._exchange("Pluto_A"), {"Token": "Pluto_A", "why": WHY})  # unreserved
        self._reserve("bob")
        self.assertEqual(self._exchange("Pluto_A"), {"Token": "Pluto_A", "why": WHY})  # someone else's
        self.assertIn("Token", self._exchange("Pluto_A", user="bob"))
        self.assertEqual(self._exchange("Pluto_A", pw="wrong"), {"ace": "Invalid login credentials."})

    def test_an_offline_device_or_an_expired_pair_gets_the_refusal(self):
        self._reserve("alice", end="2026-01-01 00:01:00")  # ended; the pair outlived it
        self.assertEqual(self._exchange("Pluto_A"), {"Token": "Pluto_A", "why": WHY})
        self._reserve("alice", salt="s2", hsh="h2")
        dm._devices[GID].dev = None  # offline local device
        self.assertEqual(self._exchange("Pluto_A"), {"Token": "Pluto_A", "why": WHY})

    def test_the_activity_log_never_records_the_handle_or_token(self):
        entry = self.reservation._activity_log_entry(
            function_name="device_token",
            args={"un": map_arg("alice"), "pw": map_arg("password1"), "h": map_arg("Zq81_secret")},
            result={"Token": map_arg("Zq81_secret")},
        )
        self.assertEqual(list(entry["details"]["args"]), ["un"])
        self.assertNotIn("Zq81_secret", json.dumps(entry, default=str))

    def test_federated_listing_carries_only_effective_handles(self):
        inventory = {
            1: {"name": "a", "device_type": "fake", "online": True, "handle": "PlutoA"},
            2: {"name": "b", "device_type": "fake", "online": True, "handle": ""},
        }
        with mock.patch.object(self.reservation, "device_inventory_snapshot", return_value=inventory), \
                mock.patch.object(self.h, "_permitted_device_ids_locked", return_value=None), \
                mock.patch.object(self.h, "_device_block_seconds_locked", return_value=60):
            entries = self.h.federated_visible_devices(local_account_id=self.h.get_uid("alice"))
        self.assertEqual([e.get("handle") for e in entries], ["PlutoA", None])


class StatusNoteTests(_Devices):
    def test_the_sharing_detail_carries_the_handle(self):
        from remoteRF_server.server.federation import cluster

        dm._devices.update({1: _state(name="PlutoA"), 2: _state(name="x@y")})
        group = {"group_name": "g", "max_reservation_time_sec": 60, "max_reservations": 1,
                 "lifetime_sec": 0, "max_horizon_sec": 0, "devices": [1, 2]}
        with mock.patch.object(cluster, "groups", return_value=[group]):
            devices = cluster._sharing("c")["detail"][0]["devices"]
        self.assertEqual([d.get("handle") for d in devices], ["PlutoA", None])


class CliHandleTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"REMOTERF_CONFIG_DIR": tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.yml = Path(tmp.name, "devices.yml")
        from remoteRF_server import serverrf_cli

        self.cli = serverrf_cli

    def _yml(self):
        return {d["device_id"]: d for d in yaml.safe_load(self.yml.read_text())["devices"]}

    def test_add_writes_no_handle_and_round_trips_through_rename_and_remove(self):
        cli = self.cli
        self.assertEqual(cli.cmd_devices_add(["pluto", "Pluto A", "--serial", "S1"]), 0)
        self.assertEqual(cli._legacy_main(["--device", "--add", "--pluto", "5:b:S2"]), 0)
        self.assertEqual(cli.cmd_devices_add(["pluto", "c", "--serial", "S3"]), 0)
        self.assertEqual(list(self._yml()[0]), ["device_id", "device_type", "name", "init"])
        self.assertEqual(cli.cmd_devices_rename(["0", "Pluto_A"]), 0)  # its own name, typed another way
        self.assertEqual(cli.cmd_devices_rename(["5", "Pluto", "B"]), 0)  # unquoted words join
        self.assertEqual(cli._device_remove("6"), 0)
        self.assertEqual({g: d["name"] for g, d in self._yml().items()}, {0: "Pluto_A", 5: "Pluto B"})

    def test_a_name_that_reads_as_a_handle_is_refused(self):
        cli = self.cli
        self.assertEqual(cli.cmd_devices_add(["pluto", "Bench [B1]", "--serial", "S1"]), 2)
        self.assertEqual(cli._legacy_main(["--device", "--add", "--pluto", "5:Bench [B1]:S2"]), 2)
        self.assertEqual(cli.cmd_devices_add(["pluto", "Pluto SDR (OTA) [two words]", "--serial", "S3"]), 0)
        self.assertEqual(list(self._yml()), [0])
        self.assertEqual(cli.cmd_devices_rename(["0", "Bench [B1]"]), 2)
        self.assertEqual(self._yml()[0]["name"], "Pluto SDR (OTA) [two words]")

    def test_a_taken_or_unaddressable_name_adds_nothing(self):
        cli = self.cli
        self.assertEqual(cli.cmd_devices_add(["pluto", "Pluto A", "--serial", "S1"]), 0)
        for bad, why in (("Pluto_A", "a device named 'Pluto A' already exists (#0)"), ("Pluto__A ", "already exists"),
                         ("a@b", "can't contain '@'"), ("a:b", "can't contain"), ("rfg_x", "can't start with"),
                         ("bridge-x", "can't start with")):
            with mock.patch("sys.stderr") as err:
                self.assertEqual(cli.cmd_devices_add(["pluto", bad, "--serial", "S2"]), 2, bad)
            self.assertIn(why, "".join(c.args[0] for c in err.write.call_args_list), bad)
        with mock.patch("sys.stderr"):
            self.assertEqual(cli._legacy_main(["--device", "--add", "--pluto", "7:Pluto_A:S2"]), 2)
        self.assertEqual(cli.cmd_devices_add(["pluto", "b", "--serial", "S2"]), 0)
        with mock.patch("sys.stderr"):
            self.assertEqual(cli.cmd_devices_rename(["1", "Pluto", "A"]), 2)
            self.assertEqual(cli._legacy_main(["--device", "--edit-name", "1", "a@b"]), 2)
        self.assertEqual({g: d["name"] for g, d in self._yml().items()}, {0: "Pluto A", 1: "b"})

    def test_show_marks_a_hand_edited_duplicate(self):
        self.yml.write_text(yaml.safe_dump({"devices": [
            {"device_id": 1, "device_type": "adalm_pluto", "name": "Pluto A", "init": {"serial": "1"}},
            {"device_id": 2, "device_type": "adalm_pluto", "name": "Pluto_A", "handle": "H", "init": {"serial": "2"}},
            {"device_id": 3, "device_type": "adalm_pluto", "name": "a@b", "init": {"serial": "3"}},
        ]}))
        with mock.patch("remoteRF_server.common.utils.panel.print_table") as table:
            self.assertEqual(self.cli._device_show(), 0)
        rows = table.call_args.args[1]
        self.assertEqual([r["handle"] for r in rows], ["Pluto_A", "Pluto_A ignored (duplicate name)", "-"])
        self.assertEqual(self.cli._device_remove("1"), 0)  # a duplicate never blocks remove
        self.assertNotIn("handle", self._yml()[2])  # a legacy handle: key is dropped


if __name__ == "__main__":
    unittest.main()
