"""Opt-in, RX-safe B205-mini qualification checks for UHD 4.10.

Run with:
    REMOTERF_TEST_USRP_B205MINI_SERIAL=31E9F48 python -m unittest discover \
        -s tests -p test_usrp_b205mini_uhd410_hardware.py -v

These tests never create a TX streamer, call a TX setter, or issue an RX
stream command. Capability discovery only constructs inactive RX streamers to
probe supported over-the-wire formats.
"""
from __future__ import annotations

import os
import unittest

from remoteRF_server.drivers.usrp.uhd_manifest import (
    TARGET_UHD_VERSION,
    is_supported_uhd_version,
)


SERIAL = os.getenv("REMOTERF_TEST_USRP_B205MINI_SERIAL", "").strip()
if SERIAL:
    from remoteRF_server.drivers.usrp.usrp_schema import UsrpSchema
else:
    UsrpSchema = None


@unittest.skipUnless(
    SERIAL,
    "set REMOTERF_TEST_USRP_B205MINI_SERIAL for B205-mini hardware tests",
)
class UHD410USRPB205miniHardwareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = UsrpSchema()
        cls.schema.bind_inventory({
            "profile": "b205mini",
            "type": "b200",
            "serial": SERIAL,
        })
        cls.schema.bind(cls.schema.open_native_device())

    @classmethod
    def tearDownClass(cls):
        cls.schema.close_native_device()

    def test_identity_versions_and_single_channel_usb_capabilities(self):
        capabilities = self.schema.build_session_metadata_v2()
        self.assertEqual(capabilities["hardware_profile"], "b205mini")
        self.assertEqual(
            capabilities["device_profile"]["support_level"],
            "qualified_native",
        )
        self.assertTrue(
            capabilities["profile_resolution"]["requested_profile_matches"]
        )
        identity = " ".join((
            capabilities["native_product"],
            capabilities["native_name"],
        )).lower()
        self.assertIn("b205mini", identity)
        self.assertEqual(capabilities["native_serial"], SERIAL)
        self.assertTrue(is_supported_uhd_version(capabilities["uhd_version"]))
        self.assertEqual(TARGET_UHD_VERSION, "4.10.0.0")
        self.assertTrue(capabilities["uhd_abi"])
        self.assertTrue(capabilities["firmware_version"])
        self.assertTrue(capabilities["fpga_version"])
        self.assertEqual(capabilities["transport_type"], "usb")
        self.assertTrue(capabilities["usb_speed"])
        self.assertEqual(capabilities["rx_channel_count"], 1)
        self.assertEqual(capabilities["tx_channel_count"], 1)
        self.assertEqual(
            capabilities["stream_format_capabilities"]["rx"]["status"],
            "runtime_probed",
        )
        self.assertIn("sc16", capabilities["supported_otw_formats"])

    def test_read_only_frequency_ranges_cover_normal_b205mini_operation(self):
        device = self.schema.device
        rx_range = device.get_rx_freq_range(0)
        tx_range = device.get_tx_freq_range(0)
        for frequency_range in (rx_range, tx_range):
            self.assertLessEqual(frequency_range.start(), 100e6)
            self.assertGreaterEqual(frequency_range.stop(), 6e9)


if __name__ == "__main__":
    unittest.main()
