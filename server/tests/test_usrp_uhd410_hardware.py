"""Opt-in, RX-safe qualification checks for the pinned UHD target.

Run with:
    REMOTERF_TEST_USRP_SERIAL=32A0D07 python -m unittest discover \
        -s tests -p test_usrp_uhd410_hardware.py -v

These tests never create a TX streamer or call a TX setter.
"""
from __future__ import annotations

import os
import unittest

from remoteRF_server.drivers.usrp.uhd_manifest import (
    TARGET_UHD_VERSION,
    is_supported_uhd_version,
)
from remoteRF_server.server.dynamic_v2 import snapshot_native


SERIAL = os.getenv("REMOTERF_TEST_USRP_SERIAL", "").strip()
if SERIAL:
    from remoteRF_server.drivers.usrp.usrp_schema import UsrpSchema, _construct
else:
    UsrpSchema = None
    _construct = None


@unittest.skipUnless(SERIAL, "set REMOTERF_TEST_USRP_SERIAL for hardware tests")
class UHD410USRP2901HardwareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = UsrpSchema()
        cls.schema.bind_inventory({"serial": SERIAL})
        cls.schema.bind(cls.schema.open_native_device())

    @classmethod
    def tearDownClass(cls):
        cls.schema.close_native_device()

    def test_identity_versions_and_transport_capabilities(self):
        capabilities = self.schema.build_session_metadata_v2()
        self.assertEqual(capabilities["hardware_profile"], "usrp2901")
        self.assertEqual(
            capabilities["device_profile"]["support_level"],
            "qualified_native",
        )
        self.assertTrue(
            capabilities["profile_resolution"]["requested_profile_matches"]
        )
        self.assertEqual(capabilities["native_product"], "B210")
        self.assertEqual(capabilities["native_name"], "NI2901")
        self.assertEqual(capabilities["native_serial"], SERIAL)
        self.assertTrue(is_supported_uhd_version(capabilities["uhd_version"]))
        self.assertEqual(TARGET_UHD_VERSION, "4.10.0.0")
        self.assertTrue(capabilities["uhd_abi"])
        self.assertTrue(capabilities["firmware_version"])
        self.assertTrue(capabilities["fpga_version"])
        self.assertEqual(capabilities["transport_type"], "usb")
        self.assertTrue(capabilities["usb_speed"])
        self.assertEqual(capabilities["rx_channel_count"], 2)
        self.assertEqual(capabilities["tx_channel_count"], 2)
        self.assertEqual(
            capabilities["stream_format_capabilities"]["rx"]["status"],
            "runtime_probed",
        )
        self.assertIn("sc16", capabilities["supported_otw_formats"])
        self.assertTrue(
            capabilities["advanced_interfaces"]["property_tree"]
        )
        for name in (
            "radio_control",
            "mboard_controller",
            "dboard_iface",
            "user_settings_iface",
        ):
            self.assertFalse(capabilities["advanced_interfaces"][name])

    def test_advanced_interface_unavailability_matches_native_b210(self):
        device = self.schema.device
        for method in (
            "get_radio_control",
            "get_mb_controller",
            "get_rx_dboard_iface",
            "get_tx_dboard_iface",
        ):
            with self.subTest(method=method):
                with self.assertRaises(RuntimeError):
                    getattr(device, method)(0)
        self.assertIsNone(device.get_user_settings_iface(0))

    def test_required_positional_getters_match_native_uhd(self):
        device = self.schema.device
        for method in (
            "get_clock_source",
            "get_clock_sources",
            "get_time_source",
            "get_time_sources",
            "get_sync_source",
            "get_sync_sources",
            "get_gpio_banks",
            "get_rx_filter_names",
            "get_tx_filter_names",
        ):
            with self.subTest(method=method):
                with self.assertRaises(TypeError):
                    getattr(device, method)()
                native = getattr(device, method)(0)
                remote_path = self.schema.invoke_native(
                    method,
                    {},
                    positional_args=[0],
                )
                self.assertEqual(
                    snapshot_native(remote_path),
                    snapshot_native(native),
                )

    def test_read_only_value_codecs_cover_b210_results(self):
        device = self.schema.device
        checks = (
            ("get_rx_freq_range", {"chan": 0}, "MetaRange"),
            ("get_tx_freq_range", {"chan": 0}, "MetaRange"),
            ("get_rx_gain_range", {"chan": 0}, "MetaRange"),
            ("get_tx_gain_range", {"chan": 0}, "MetaRange"),
            ("get_rx_subdev_spec", {"mboard": 0}, "SubdevSpec"),
            ("get_sync_source", {}, "DeviceAddr"),
        )
        for method, arguments, expected_type in checks:
            with self.subTest(method=method):
                positional = [0] if method == "get_sync_source" else []
                result = self.schema.invoke_native(
                    method,
                    arguments,
                    positional_args=positional,
                )
                snapshot = snapshot_native(result)
                self.assertEqual(snapshot["__uhd_type__"], expected_type)

        for direction in ("rx", "tx"):
            with self.subTest(direction=direction):
                names = getattr(
                    device,
                    f"get_{direction}_filter_names",
                )(0)
                original = getattr(device, f"get_{direction}_filter")(
                    names[0],
                    0,
                )
                original_snapshot = snapshot_native(original)
                reconstructed = _construct(original_snapshot)
                reconstructed_snapshot = snapshot_native(reconstructed)
                for field in (
                    "native_class",
                    "filter_type",
                    "bypassed",
                    "position",
                ):
                    self.assertEqual(
                        reconstructed_snapshot[field],
                        original_snapshot[field],
                    )
                self.assertEqual(
                    reconstructed_snapshot.get("taps"),
                    original_snapshot.get("taps"),
                )


if __name__ == "__main__":
    unittest.main()
