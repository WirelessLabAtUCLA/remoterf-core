# Copyright (C) 2026 RemoteRF
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import io
import unittest
from contextlib import redirect_stdout

from remoteRF_server.server.user_group_cli import edit_user_group_local


class _Session:
    def __init__(self, responses: list[str]):
        self.responses = iter(responses)
        self.prompts: list[str] = []

    def prompt(self, message: str) -> str:
        self.prompts.append(message)
        return next(self.responses)


class EditUserGroupCliTests(unittest.TestCase):
    def test_all_is_refused_and_an_explicit_list_is_required(self) -> None:
        session = _Session([
            "1",       # group ID
            "",        # group name unchanged
            "all",     # no longer an option
            "0,1",     # an explicit list
            "",        # max reservation time unchanged
            "",        # max reservations unchanged
            "",        # lifetime unchanged
            "",        # LAN only unchanged
            "n",       # do not persist the edit
        ])
        output = io.StringIO()
        with redirect_stdout(output):
            edit_user_group_local(session)
        self.assertIn("List the device ids this group may use", output.getvalue())
        self.assertIn("devices_whitelist       : 0,1", output.getvalue())

    def test_enter_leaves_the_whitelist_unchanged(self) -> None:
        session = _Session(["1", "renamed", "", "", "", "", "", "n"])
        output = io.StringIO()
        with redirect_stdout(output):
            edit_user_group_local(session)
        self.assertIn("devices_whitelist       : (unchanged)", output.getvalue())


class WhitelistSemanticsTests(unittest.TestCase):
    """An empty whitelist grants every device, including ones added later."""

    def setUp(self) -> None:
        import tempfile
        from pathlib import Path
        from unittest import mock

        from remoteRF_server.server import user_group_handler as m

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = mock.patch.object(m, "get_db_dir", return_value=Path(tmp.name))
        root.start()
        self.addCleanup(root.stop)
        self.m = m
        self.h = m.UserGroupHandler()
        self.gid = int(self.h.create_user_group(
            group_name="dev", devices_whitelist=[], max_reservation_time_sec=600,
            max_reservations=1, lifetime_sec=0,
        ))
        self.h.create_enrollment_codes(
            code_names=["T1"], group_id=self.gid, uses=1, duration_sec=0
        )
        self.assertTrue(self.h.enroll_user_with_code(uid=7, code_name="T1"))

    def test_empty_whitelist_is_unrestricted(self) -> None:
        from unittest import mock

        self.assertTrue(self.m.whitelist_allows([], 16))
        self.assertFalse(self.m.whitelist_allows([3], 16))
        with mock.patch(
            "remoteRF_server.server.device_manager.get_all_devices_str",
            return_value={16: "pluto", 4: "rtl"},
        ):
            self.assertEqual(self.h.get_users_devices(uid=7), [4, 16])
        self.assertEqual(self.h.get_users_max_reservation_time(uid=7, device_id=16), (True, 600))
        self.assertEqual(self.h.get_users_max_reservations(uid=7, device_id=999), (True, 1))
        self.assertEqual(
            self.h.get_group_quota_for_device(uid=7, device_id=16, reserved_device_ids=[4])[:3],
            (True, 1, 1),
        )

    def test_a_listed_whitelist_still_restricts(self) -> None:
        self.h.edit_user_group(group_id=self.gid, devices_whitelist=[4])
        self.assertEqual(self.h.get_users_devices(uid=7), [4])
        self.assertEqual(self.h.get_users_max_reservation_time(uid=7, device_id=16), (False, 0))


class LanOnlyGroupTests(unittest.TestCase):
    """A LAN-only group does not exist to a call that came through the relay."""

    def setUp(self) -> None:
        import tempfile
        from pathlib import Path
        from unittest import mock

        from remoteRF_server.server import user_group_handler as m

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = mock.patch.object(m, "get_db_dir", return_value=Path(tmp.name))
        root.start()
        self.addCleanup(root.stop)
        self.m = m
        self.h = m.UserGroupHandler()
        self.gid = int(self.h.create_user_group(
            group_name="lab-only", devices_whitelist=[16], max_reservation_time_sec=600,
            max_reservations=1, lifetime_sec=0, lan_only=True,
        ))
        self.h.create_enrollment_codes(code_names=["LAN1"], group_id=self.gid, uses=5, duration_sec=0)

    def relayed(self):
        from remoteRF_server.server.global_onboarding import RELAYED

        class _Ctx:
            def __enter__(_self):
                _self.token = RELAYED.set(True)
            def __exit__(_self, *exc):
                RELAYED.reset(_self.token)
        return _Ctx()

    def test_codes_and_membership_only_work_on_the_lan(self) -> None:
        h = self.h
        self.assertTrue(h.code_is_lan_only(code_name="LAN1"))
        with self.relayed():
            self.assertFalse(h.validate_enrollment_code(code_name="LAN1"))
            self.assertFalse(h.enroll_user_with_code(uid=7, code_name="LAN1"))
        self.assertTrue(h.validate_enrollment_code(code_name="LAN1"))
        self.assertTrue(h.enroll_user_with_code(uid=7, code_name="LAN1"))
        self.assertEqual(h.get_users_devices(uid=7), [16])
        self.assertTrue(h.user_is_lan_only(uid=7))
        with self.relayed():
            self.assertEqual(h.get_users_devices(uid=7), [])
            self.assertEqual(h.get_users_max_reservation_time(uid=7, device_id=16), (False, 0))
        self.assertTrue(h.edit_user_group(group_id=self.gid, lan_only=False))
        self.assertFalse(h.user_is_lan_only(uid=7))
        with self.relayed():
            self.assertEqual(h.get_users_devices(uid=7), [16])
        self.assertEqual(h.get_all_user_groups(include_users=False)[0]["lan_only"], False)

    def test_relay_peers_are_the_tunnel_target(self) -> None:
        from unittest import mock

        from remoteRF_server.server import global_onboarding as g

        with mock.patch.object(g, "local_bind_host", return_value="164.67.195.210"):
            self.assertTrue(g.is_relayed("ipv4:164.67.195.210:41234"))
            self.assertTrue(g.is_relayed("ipv6:[::ffff:164.67.195.210]:41234"))
            self.assertTrue(g.is_relayed("ipv4:127.0.0.1:5"))
            self.assertFalse(g.is_relayed("ipv4:164.67.195.77:41234"))
            self.assertFalse(g.is_relayed("ipv6:[2607:f010::1]:41234"))


if __name__ == "__main__":
    unittest.main()
