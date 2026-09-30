from __future__ import annotations

import itertools
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.modules.setdefault("adi", types.ModuleType("adi"))

from remoteRF_server.common.idl.pluto_schema import PlutoSchema
from remoteRF_server.drivers.adalm_pluto import poe
from remoteRF_server.server import device_manager

SERIAL = "104473b80a160019efff2c005a01be9b75"
real_port_running = poe.port_running  # setUp replaces the module attribute


class FakePluto:
    def __init__(self, uri, serial=SERIAL):
        self.uri = uri
        self._ctx = types.SimpleNamespace(attrs={"hw_serial": serial})
        self.rx_lo = 0
        self.rx_buffer_size = 1024
        self.destroyed = 0

    def rx_destroy_buffer(self):
        self.destroyed += 1


class PoePlutoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.poe_calls = []
        root = Path(tempfile.mkdtemp())
        (root / "poe_switch_password").write_text("secret\n")
        self.opened = []
        self.serial_seen = SERIAL
        self.link = True
        self.logged = []
        for p in (
            patch.object(poe, "set_poe", side_effect=lambda **kw: self.poe_calls.append((kw["port"], kw["on"], kw["password"]))),
            patch.object(poe, "port_running", side_effect=lambda **kw: self.link),
            patch.object(poe, "printf", side_effect=lambda msg, sty: self.logged.append(msg)),
            patch.object(poe, "_iiod_up", return_value=True),
            patch.object(poe, "get_remoterf_root", return_value=root),
            patch.object(poe.time, "sleep"),
            patch.object(sys.modules["adi"], "Pluto", side_effect=self._open, create=True),
        ):
            p.start()
        self.addCleanup(patch.stopall)

    def _open(self, uri):
        self.opened.append(uri)
        return FakePluto(uri, self.serial_seen)

    def schema(self, **init):
        schema = PlutoSchema()
        schema.bind(PlutoSchema.make_device(serial=SERIAL, **init))
        return schema

    def listed(self, schema, name="pluto02", salt=""):
        device_manager._devices[999] = device_manager._DeviceState(
            dev=schema, origin="local", online=True, salt=salt, hsh="", name=name, ident="X", dtype="adalm_pluto",
        )
        self.addCleanup(device_manager._devices.pop, 999, None)
        with patch.object(device_manager, "_sync_host_devices"):
            return (
                device_manager._local_devices_str_snapshot()[999],
                device_manager.describe_devices([999])[0]["online"],
                device_manager.device_inventory_snapshot()[999]["online"],
            )

    def stuck_boot(self, step_s=10):
        # IIOD never answers; each poll of the clock advances step_s.
        self.stuck = [
            patch.object(poe, "_iiod_up", return_value=False),
            patch.object(poe.time, "monotonic", side_effect=itertools.count(0, step_s)),
        ]
        for p in self.stuck:
            p.start()

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

    def test_no_ethernet_link_fails_fast_sets_fault_and_recovers_on_the_next_command(self) -> None:
        schema = self.schema(poe=True, ip="192.168.4.101", poe_port="ether5")
        self.stuck_boot()
        self.link = False
        with self.assertRaisesRegex(RuntimeError, "PoE on ether5 but no Ethernet link after 30 s") as cm:
            schema.dispatch("get_rx_lo", {})
        self.assertEqual(self.poe_calls[-1][1], False)
        self.assertEqual(schema.device.fault, str(cm.exception))
        self.assertEqual(schema.device.power_state, "fault")
        self.assertEqual(len(self.logged), 1)
        self.assertRegex(self.logged[0], r"^\d\d:\d\d:\d\d Pluto ip:192.168.4.101: PoE on ether5")
        self.assertEqual(self.listed(schema)[0], f"pluto02 (offline: {cm.exception})")
        self.assertEqual(self.listed(schema)[1:], (False, False))

        for p in self.stuck:
            p.stop()
        schema.dispatch("get_rx_lo", {})
        self.assertIsNone(schema.device.fault)
        self.assertEqual(schema.device.power_state, "on")

    def test_an_unreachable_switch_keeps_waiting_until_the_boot_timeout(self) -> None:
        schema = self.schema(poe=True, ip="192.168.4.101", poe_port="ether5")
        self.stuck_boot()
        patch.object(poe, "port_running", side_effect=OSError("switch down")).start()
        with self.assertRaisesRegex(RuntimeError, "did not boot within 45 s"):
            schema.dispatch("call_power_up", {})
        self.assertEqual(self.poe_calls[-1][1], False)
        self.assertEqual(schema.device.power_state, "fault")

    def test_power_state_and_listing(self) -> None:
        schema = self.schema(poe=True, ip="192.168.4.101", poe_port="ether5")
        self.assertEqual(schema.device.power_state, "standby")
        self.assertEqual(self.listed(schema), ("pluto02 (online, standby)", True, True))
        schema.dispatch("call_power_up", {})
        self.assertEqual(schema.device.power_state, "on")
        self.assertEqual(self.listed(schema)[0], "pluto02 (online, on)")
        self.assertEqual(self.listed(schema, salt="s")[0], "pluto02 (online, on, reserved)")
        schema.reset_for_next_holder()
        self.assertEqual(schema.device.power_state, "standby")

        usb = PlutoSchema()
        usb.bind(FakePluto("usb:1.2.5"))
        self.assertEqual(self.listed(usb, name="pluto01"), ("pluto01 (online)", True, True))

    def test_changing_rx_buffer_size_drops_the_buffer_only_when_the_value_changes(self) -> None:
        schema = PlutoSchema()
        dev = FakePluto("usb:1.2.5")
        schema.bind(dev)
        schema.dispatch("set_rx_buffer_size", {"value": 1024})
        self.assertEqual(dev.destroyed, 0)
        schema.dispatch("set_rx_buffer_size", {"value": 4096})
        schema.dispatch("set_rx_buffer_size", {"value": 4096})
        self.assertEqual((dev.destroyed, dev.rx_buffer_size), (1, 4096))

    def test_port_running_parses_the_switch_reply(self) -> None:
        class FakeRouterOS:
            replies = [["!re", "=name=ether5", "=running=false"], ["!done"]]

            def __init__(self, *a, **kw):
                pass

            def cmd(self, *words):
                self.words = words
                return self.replies

            def close(self):
                pass

        with patch.object(poe, "RouterOS", FakeRouterOS):
            self.assertFalse(real_port_running(switch="s", user="u", password="p", port="ether5"))
            FakeRouterOS.replies = [["!re", "=name=ether5", "=running=true"], ["!done"]]
            self.assertTrue(real_port_running(switch="s", user="u", password="p", port="ether5"))
            FakeRouterOS.replies = [["!done"]]
            with self.assertRaises(RuntimeError):
                real_port_running(switch="s", user="u", password="p", port="ether5")

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
