from __future__ import annotations

import sys
import types
import unittest
from unittest.mock import patch

import numpy as np

sys.modules.setdefault("adi", types.ModuleType("adi"))

from remoteRF_host.common.idl.pluto_schema import PlutoSchema
from remoteRF_host.common.utils import map_arg, unmap_arg
from remoteRF_host.drivers.adalm_pluto.pluto_remote_server import PlutoServer


class FakePluto:
    def __init__(self):
        self.sample_rate = 1_000_000
        self.ip = "ip:192.168.2.1"
        self.tx_samples = None
        self.rx_samples = np.array([1 + 2j, 3 + 4j], dtype=np.complex64)

    def rx(self):
        return self.rx_samples

    def tx(self, samples):
        self.tx_samples = samples


class PlutoCompatTests(unittest.TestCase):
    def setUp(self) -> None:
        self.device = FakePluto()

    def handle(self, function_name: str, args: dict):
        with patch(
            "remoteRF_host.drivers.adalm_pluto.pluto_remote_server.get_device",
            return_value=self.device,
        ):
            return PlutoServer.handle_call(function_name=function_name, args=args)

    def test_get_and_set_still_use_legacy_pluto_idl_paths(self) -> None:
        response = self.handle("Pluto:sample_rate:GET", {"g": map_arg(7)})
        self.assertEqual(unmap_arg(response["sample_rate"]), 1_000_000)

        response = self.handle(
            "Pluto:sample_rate:SET",
            {"g": map_arg(7), "sample_rate": map_arg(2_000_000)},
        )
        self.assertEqual(unmap_arg(response["sample_rate"]), "None")
        self.assertEqual(self.device.sample_rate, 2_000_000)

    def test_call0_still_supports_methods_and_property_fallback(self) -> None:
        response = self.handle("Pluto:rx:CALL0", {"g": map_arg(7)})
        np.testing.assert_allclose(unmap_arg(response["rx"]), self.device.rx_samples)

        response = self.handle("Pluto:ip:CALL0", {"g": map_arg(7)})
        self.assertEqual(unmap_arg(response["ip"]), "ip:192.168.2.1")

    def test_call1_still_forwards_arg1_to_tx(self) -> None:
        samples = np.array([5 + 6j, 7 + 8j], dtype=np.complex64)
        response = self.handle(
            "Pluto:tx:CALL1",
            {"g": map_arg(7), "arg1": map_arg(samples)},
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


if __name__ == "__main__":
    unittest.main()
