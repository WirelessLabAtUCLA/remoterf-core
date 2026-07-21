from __future__ import annotations

import sys
import types
import unittest
from unittest.mock import call, patch

import numpy as np

sys.modules.setdefault("adi", types.ModuleType("adi"))

from remoteRF_server.common.idl.pluto_schema import PlutoSchema
from remoteRF_server.common.utils import map_arg, unmap_arg
from remoteRF_server.drivers.adalm_pluto.pluto_remote_server import PlutoServer
from remoteRF_server.server import device_manager


class FakePluto:
    def __init__(self):
        self.sample_rate = 1_000_000
        self.rx_hardwaregain_chan0 = 12.5
        self.dds_frequencies = [100_000, 100_000]
        self.dds_scales = [0.25, 0.25]
        self.dds_phases = [0, 90_000]
        self.dds_enabled = [True, True]
        self.rx_enabled_channels = [0]
        self.tx_enabled_channels = [0]
        self.rx_annotated = False
        self.rx_output_type = "raw"
        self.rx_channel_names = ["voltage0", "voltage1"]
        self.tx_channel_names = ["voltage0", "voltage1"]
        self.single_tone_args = None
        self.dual_tone_args = None
        self.tx_samples = None
        self.rx_samples = np.array([1 + 2j, 3 + 4j], dtype=np.complex64)

    def rx(self):
        return self.rx_samples

    def tx(self, samples):
        self.tx_samples = samples

    def dds_single_tone(self, frequency, scale, channel=0):
        self.single_tone_args = (frequency, scale, channel)

    def dds_dual_tone(
        self,
        frequency1,
        scale1,
        frequency2,
        scale2,
        channel=0,
    ):
        self.dual_tone_args = (
            frequency1,
            scale1,
            frequency2,
            scale2,
            channel,
        )


class PlutoCompatTests(unittest.TestCase):
    def setUp(self) -> None:
        self.device = FakePluto()

    def handle(self, function_name: str, args: dict):
        with patch(
            "remoteRF_server.drivers.adalm_pluto.pluto_remote_server.device_pluto",
            return_value=self.device,
        ):
            return PlutoServer.handle_call(function_name=function_name, args=args)

    def test_get_and_set_still_use_legacy_token_paths(self) -> None:
        response = self.handle("Pluto:sample_rate:GET", {"a": map_arg("token")})
        self.assertEqual(unmap_arg(response["sample_rate"]), 1_000_000)

        response = self.handle(
            "Pluto:sample_rate:SET",
            {"a": map_arg("token"), "sample_rate": map_arg(2_000_000)},
        )
        self.assertEqual(response, {})
        self.assertEqual(self.device.sample_rate, 2_000_000)

    def test_call0_and_call1_still_use_existing_wire_shape(self) -> None:
        response = self.handle("Pluto:rx:CALL0", {"a": map_arg("token")})
        np.testing.assert_allclose(unmap_arg(response["rx"]), self.device.rx_samples)

        samples = np.array([5 + 6j, 7 + 8j], dtype=np.complex64)
        response = self.handle(
            "Pluto:tx:CALL1",
            {"a": map_arg("token"), "arg1": map_arg(samples)},
        )
        self.assertEqual(unmap_arg(response["tx"]), "None")
        np.testing.assert_allclose(self.device.tx_samples, samples)

    def test_schema_dispatch_preserves_pluto_get_set_call0_and_call1(self) -> None:
        schema = PlutoSchema()
        schema.bind(self.device)

        idl = schema.get_idl()
        self.assertEqual(idl["calls"]["call_rx"]["args"], [])
        self.assertEqual(idl["calls"]["call_tx"]["args"][0]["name"], "value")
        self.assertTrue(idl["calls"]["call_tx"]["args"][0]["required"])

        self.assertEqual(schema.dispatch("get_sample_rate", {}), 1_000_000)
        schema.dispatch("set_sample_rate", {"value": 2_000_000})
        self.assertEqual(self.device.sample_rate, 2_000_000)

        np.testing.assert_allclose(schema.dispatch("call_rx", {}), self.device.rx_samples)
        samples = np.array([9 + 1j, 10 + 2j], dtype=np.complex64)
        self.assertIsNone(schema.dispatch("call_tx", {"value": samples}))
        np.testing.assert_allclose(self.device.tx_samples, samples)

    def test_schema_rx_hardware_gain_uses_pyadi_property_name(self) -> None:
        schema = PlutoSchema()
        schema.bind(self.device)

        self.assertEqual(schema.dispatch("get_rx_hardwaregain_chan0", {}), 12.5)
        schema.dispatch("set_rx_hardwaregain_chan0", {"value": 24.0})
        self.assertEqual(self.device.rx_hardwaregain_chan0, 24.0)

    def test_schema_exposes_dds_generation_and_controls(self) -> None:
        schema = PlutoSchema()
        schema.bind(self.device)

        idl = schema.get_idl()
        single_args = idl["calls"]["call_dds_single_tone"]["args"]
        dual_args = idl["calls"]["call_dds_dual_tone"]["args"]
        self.assertEqual(
            [arg["name"] for arg in single_args],
            ["frequency", "scale", "channel"],
        )
        self.assertEqual(single_args[-1]["default"], 0)
        self.assertEqual(
            [arg["name"] for arg in dual_args],
            ["frequency1", "scale1", "frequency2", "scale2", "channel"],
        )
        self.assertEqual(dual_args[-1]["default"], 0)

        schema.dispatch(
            "call_dds_single_tone",
            {"frequency": 125_000, "scale": 0.5},
        )
        self.assertEqual(self.device.single_tone_args, (125_000, 0.5, 0))
        schema.dispatch(
            "call_dds_dual_tone",
            {
                "frequency1": 100_000,
                "scale1": 0.25,
                "frequency2": -200_000,
                "scale2": 0.4,
                "channel": 1,
            },
        )
        self.assertEqual(
            self.device.dual_tone_args,
            (100_000, 0.25, -200_000, 0.4, 1),
        )

        controls = {
            "dds_frequencies": [200_000, 200_000],
            "dds_scales": [0.5, 0.5],
            "dds_phases": [90_000, 0],
            "dds_enabled": [False, True],
        }
        for name, value in controls.items():
            schema.dispatch(f"set_{name}", {"value": value})
            self.assertEqual(schema.dispatch(f"get_{name}", {}), value)

    def test_schema_exposes_channel_selection_and_receive_formatting(self) -> None:
        schema = PlutoSchema()
        schema.bind(self.device)

        # Numeric lists use ndarray transport in the legacy codec. The schema
        # restores the integer list shape required by pyadi-iio.
        encoded_channels = unmap_arg(map_arg([0]))
        schema.dispatch("set_rx_enabled_channels", {"value": encoded_channels})
        self.assertEqual(self.device.rx_enabled_channels, [0])
        self.assertIs(type(self.device.rx_enabled_channels[0]), int)

        schema.dispatch("set_tx_enabled_channels", {"value": ["voltage0"]})
        self.assertEqual(self.device.tx_enabled_channels, ["voltage0"])
        schema.dispatch("set_rx_annotated", {"value": True})
        schema.dispatch("set_rx_output_type", {"value": "SI"})
        self.assertTrue(schema.dispatch("get_rx_annotated", {}))
        self.assertEqual(schema.dispatch("get_rx_output_type", {}), "SI")

    def test_schema_exposes_channel_metadata_as_read_only(self) -> None:
        schema = PlutoSchema()
        schema.bind(self.device)

        idl = schema.get_idl()
        self.assertEqual(
            schema.dispatch("get_rx_channel_names", {}),
            ["voltage0", "voltage1"],
        )
        self.assertEqual(
            schema.dispatch("get_tx_channel_names", {}),
            ["voltage0", "voltage1"],
        )
        self.assertNotIn("set_rx_channel_names", idl["setters"])
        self.assertNotIn("set_tx_channel_names", idl["setters"])

    def test_legacy_pluto_inventory_type_resolves_to_packaged_schema(self) -> None:
        with patch.object(PlutoSchema, "make_device", return_value=self.device):
            schema, ident, dtype = device_manager._connect_from_record(
                {
                    "TYPE": "pluto",
                    "IDENT": "104473f6",
                    "INIT": {"serial": "104473f6"},
                }
            )

        self.assertIsInstance(schema, PlutoSchema)
        self.assertEqual(ident, "104473f6")
        self.assertEqual(dtype, "adalm_pluto")

    def test_legacy_builtin_pluto_schema_is_registered_for_auto_upgrade(self) -> None:
        expected_hash = (
            "a3697eeef55827e0db7705685f8fe64b615468dd26057211de8b5805b9ecf583"
        )
        self.assertIn(expected_hash, device_manager._LEGACY_PLUTO_SCHEMA_HASHES)

        with patch.object(device_manager, "_seed_default_driver") as seed:
            device_manager._seed_default_pluto_drivers()

        self.assertEqual(
            seed.call_args_list,
            [
                call(
                    "pluto_schema.py",
                    "adalm_pluto",
                    legacy_hashes=device_manager._LEGACY_PLUTO_SCHEMA_HASHES,
                ),
                call("pluto_mimo_schema.py", "adalm_pluto_mimo"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
