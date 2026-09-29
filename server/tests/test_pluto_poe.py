from __future__ import annotations

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.modules.setdefault("adi", types.ModuleType("adi"))

from remoteRF_server.common.idl.pluto_schema import PlutoSchema
from remoteRF_server.drivers.adalm_pluto import poe

SERIAL = "104473b80a160019efff2c005a01be9b75"


class FakePluto:
    def __init__(self, uri, serial=SERIAL):
        self.uri = uri
        self._ctx = types.SimpleNamespace(attrs={"hw_serial": serial})
        self.rx_lo = 0


class PoePlutoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.poe_calls = []
        root = Path(tempfile.mkdtemp())
        (root / "poe_switch_password").write_text("secret\n")
        self.opened = []
        self.serial_seen = SERIAL
        for p in (
            patch.object(poe, "set_poe", side_effect=lambda **kw: self.poe_calls.append((kw["port"], kw["on"], kw["password"]))),
            patch.object(poe, "_iiod_up", return_value=True),
            patch.object(poe, "get_remoterf_root", return_value=root),
            patch.object(poe.time, "sleep"),
            patch.object(sys.modules["adi"], "Pluto", side_effect=self._open, create=True),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _open(self, uri):
        self.opened.append(uri)
        return FakePluto(uri, self.serial_seen)

    def schema(self, **init):
        schema = PlutoSchema()
        schema.bind(PlutoSchema.make_device(serial=SERIAL, **init))
        return schema

    def test_a_poe_pluto_starts_off_and_its_first_command_powers_it_up(self) -> None:
        schema = self.schema(poe=True, ip="192.168.4.101", poe_port="ether5")
        self.assertEqual(self.poe_calls, [("ether5", False, "secret")])
        self.assertEqual(schema.dispatch("call_ip", {}), "ip:192.168.4.101")
        self.assertEqual(self.opened, [])

        schema.dispatch("set_rx_lo", {"value": 915_000_000})
        self.assertEqual(self.poe_calls[-1], ("ether5", True, "secret"))
        self.assertEqual(schema.dispatch("get_rx_lo", {}), 915_000_000)
        self.assertEqual(self.opened, ["ip:192.168.4.101"])

    def test_the_end_of_a_reservation_powers_it_off_until_the_next_command(self) -> None:
        schema = self.schema(POE=True, ip="192.168.4.101", poe_port="ether5")
        schema.dispatch("call_power_up", {})
        schema.reset_for_next_holder()
        self.assertEqual(self.poe_calls[-1], ("ether5", False, "secret"))
        schema.dispatch("get_rx_lo", {})
        self.assertEqual(self.poe_calls[-1], ("ether5", True, "secret"))
        self.assertEqual(len(self.opened), 2)

    def test_power_cycle_and_shutdown(self) -> None:
        schema = self.schema(poe=True, ip="192.168.4.101", poe_port="ether5")
        schema.dispatch("call_power_cycle", {})
        self.assertEqual([on for _, on, _ in self.poe_calls], [False, False, True])
        schema.device.close()
        self.assertEqual(self.poe_calls[-1][1], False)

    def test_a_different_pluto_at_that_address_is_refused_and_switched_off(self) -> None:
        schema = self.schema(poe=True, ip="192.168.4.101", poe_port="ether5")
        self.serial_seen = "10447392da110010f9ff1500612ff8ecb0"
        with self.assertRaisesRegex(RuntimeError, "expected"):
            schema.dispatch("call_power_up", {})
        self.assertEqual(self.poe_calls[-1][1], False)

    def test_a_poe_pluto_without_its_address_and_port_is_not_created(self) -> None:
        with self.assertRaises(ValueError):
            PlutoSchema.make_device(serial=SERIAL, poe=True, ip="192.168.4.101")

    def test_power_commands_do_nothing_on_a_usb_pluto(self) -> None:
        schema = PlutoSchema()
        usb = FakePluto("usb:1.2.5")
        schema.bind(usb)
        for name in ("call_power_up", "call_power_down", "call_power_cycle"):
            self.assertIsNone(schema.dispatch(name, {}))
        self.assertEqual(self.poe_calls, [])
        self.assertIs(schema.device, usb)


if __name__ == "__main__":
    unittest.main()
