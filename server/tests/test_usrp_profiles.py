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

from __future__ import annotations

import json
import unittest

from remoteRF_server.drivers.usrp.profiles import (
    GENERIC_UHD,
    QUALIFIED_NATIVE,
    USRP_PROFILES,
    get_usrp_profile,
    infer_inventory_profile,
    inventory_for_profile,
    profile_definitions,
    resolve_live_profile,
    validate_profile_inventory,
)


class USRPProfileTests(unittest.TestCase):
    def test_qualified_profiles_are_explicit(self):
        qualified = {
            profile.profile_id
            for profile in USRP_PROFILES
            if profile.support_level == QUALIFIED_NATIVE
        }
        self.assertEqual(qualified, {"usrp2901", "b205mini", "n210"})
        self.assertEqual(get_usrp_profile("usrp-2901").profile_id, "usrp2901")
        self.assertEqual(get_usrp_profile("b205i").profile_id, "b205mini")
        self.assertEqual(
            get_usrp_profile("usrp-b205-mini").profile_id,
            "b205mini",
        )
        self.assertEqual(get_usrp_profile("usrp2").profile_id, "n2xx")
        self.assertEqual(get_usrp_profile("x310").profile_id, "x3xx")
        self.assertEqual(get_usrp_profile("x310").support_level, GENERIC_UHD)

    def test_inventory_building_is_profile_driven(self):
        self.assertEqual(
            inventory_for_profile("usrp2901", "31A2B3C"),
            {
                "profile": "usrp2901",
                "type": "b200",
                "serial": "31A2B3C",
            },
        )
        self.assertEqual(
            inventory_for_profile("b205mini", "31E9F48"),
            {
                "profile": "b205mini",
                "type": "b200",
                "serial": "31E9F48",
            },
        )
        self.assertEqual(
            inventory_for_profile("n210", "192.168.137.21"),
            {
                "profile": "n210",
                "type": "usrp2",
                "addr": "192.168.137.21",
            },
        )
        self.assertEqual(
            inventory_for_profile("x310", "192.168.10.2"),
            {
                "profile": "x3xx",
                "type": "x300",
                "addr": "192.168.10.2",
            },
        )

    def test_legacy_inventory_inference_remains_compatible(self):
        self.assertEqual(
            infer_inventory_profile({"serial": "31A2B3C"}).profile_id,
            "usrp2901",
        )
        self.assertEqual(
            infer_inventory_profile({"addr": "192.168.137.21"}).profile_id,
            "n210",
        )
        self.assertEqual(
            infer_inventory_profile({
                "type": "usrp2",
                "addr": "192.168.137.21",
            }).profile_id,
            "n210",
        )
        self.assertEqual(
            infer_inventory_profile({"type": "x300"}).profile_id,
            "x3xx",
        )

    def test_explicit_profile_rejects_conflicting_inventory(self):
        profile = get_usrp_profile("n210")
        with self.assertRaisesRegex(ValueError, "requires UHD type 'usrp2'"):
            validate_profile_inventory(
                profile,
                {"type": "b200", "addr": "192.168.10.2"},
            )
        with self.assertRaisesRegex(ValueError, "requires selector 'address'"):
            validate_profile_inventory(profile, {"serial": "30FB628"})
        with self.assertRaisesRegex(ValueError, "requires UHD type 'e3xx'"):
            validate_profile_inventory(
                get_usrp_profile("e320"),
                {"args": "type=x300,addr=192.168.20.2"},
            )

    def test_native_identity_wins_and_detects_profile_mismatch(self):
        profile, resolution = resolve_live_profile(
            {"profile": "n210", "type": "usrp2", "addr": "192.168.10.2"},
            "X310",
            "X310",
        )
        self.assertEqual(profile.profile_id, "x3xx")
        self.assertEqual(resolution["source"], "native_identity")
        self.assertFalse(resolution["requested_profile_matches"])

        profile, resolution = resolve_live_profile(
            {"profile": "usrp2901", "serial": "31A2B3C"},
            "NI2901",
            "B210",
        )
        self.assertEqual(profile.profile_id, "usrp2901")
        self.assertTrue(resolution["requested_profile_matches"])

        profile, resolution = resolve_live_profile(
            {"profile": "usrp2901", "type": "b200", "serial": "31E9F48"},
            "B205mini",
            "B205mini",
        )
        self.assertEqual(profile.profile_id, "b205mini")
        self.assertEqual(resolution["source"], "native_identity")
        self.assertFalse(resolution["requested_profile_matches"])

    def test_profile_definitions_are_json_safe_and_extensible(self):
        definitions = profile_definitions()
        json.dumps(definitions)
        by_id = {item["profile_id"]: item for item in definitions}
        self.assertEqual(by_id["n210"]["transport"], "ethernet")
        self.assertIn("n210", by_id["n210"]["identity_terms"])
        self.assertEqual(by_id["usrp2901"]["support_level"], QUALIFIED_NATIVE)
        self.assertEqual(by_id["b205mini"]["support_level"], QUALIFIED_NATIVE)
        self.assertEqual(by_id["b205mini"]["transport"], "usb")
        self.assertIn("x4xx", by_id)
        self.assertIn("generic_usrp", by_id)


if __name__ == "__main__":
    unittest.main()
