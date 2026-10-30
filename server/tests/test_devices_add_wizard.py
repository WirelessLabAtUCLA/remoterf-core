"""`devices add` wizard with fakes only: no USB, iio, switch or radio is touched.

Every record it writes is read back by the server's own loader and handed to
_connect_from_record, so a wizard answer always lands on init: keys the driver reads.
"""

import contextlib
import inspect
import io
import os
import sqlite3
import stat
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

import yaml

sys.modules.setdefault("adi", types.ModuleType("adi"))

from remoteRF_server import serverrf_cli as cli
from remoteRF_server.common.idl import pluto_schema
from remoteRF_server.drivers.adalm_pluto import poe
from remoteRF_server.drivers.adalm_pluto.pluto_mimo_schema import connect_pluto_mimo
from remoteRF_server.drivers.rtl_sdr.rtl_sdr_schema import _connect_rtl_sdr
from remoteRF_server.drivers.ti_mmwave.ti_mmwave_schema import connect_ti_mmwave
from remoteRF_server.drivers.usrp.usrp_schema import _usrp_args
from remoteRF_server.server import device_manager as dm

USB = {  # sysfs port -> (vid, pid, serial)
    "1-1": ("0bda", "2838", "00000101"),
    "1-2": ("1d50", "6089", "0000000000000000a1b2"),
    "1-3": ("2500", "0020", "31AB4C5"),
    "1-4": ("10c4", "ea70", "00F1E2D3"),
    "1-5": ("0456", "b673", "1044cc"),
}

# The init keys each driver's make_device / bind_inventory reads (contrib: from its source).
CONTRIB_KEYS = {"gps": {"port", "baud", "timeout"}, "bluetooth": {"adapter", "allow_fallback"}}


def _fake_driver(dtype):
    session_scoped = dtype in ("usrp", "usrp_phaser")

    class Fake:
        seen = []

        def __init__(self):
            pass

        @staticmethod
        def make_device(**kwargs):
            Fake.seen.append(kwargs)
            return object()

        def bind(self, dev):
            pass

        def bind_inventory(self, init):
            Fake.seen.append(dict(init))

    Fake.session_scoped = session_scoped
    return Fake


class WizardTests(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        self.cfg = tmp / "cfg"
        self.xdg = tmp / "xdg"
        self.cfg.mkdir()
        patcher = mock.patch.dict(os.environ, {"REMOTERF_CONFIG_DIR": str(self.cfg), "XDG_CONFIG_HOME": str(self.xdg)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.root = self.xdg / "remoterf"
        sysfs = tmp / "usb"
        for port, (vid, pid, serial) in USB.items():
            (sysfs / port).mkdir(parents=True)
            (sysfs / port / "idVendor").write_text(vid + "\n")
            (sysfs / port / "idProduct").write_text(pid + "\n")
            (sysfs / port / "serial").write_text(serial + "\n")
        (sysfs / "1-1:1.0").mkdir()  # an interface, not a device
        by_id = tmp / "by-id"
        by_id.mkdir()
        (by_id / "usb-u-blox_GNSS_Receiver-if00").touch()
        bt = tmp / "bt"
        (bt / "hci0").mkdir(parents=True)
        (bt / "hci1").mkdir()
        self.scan = [("usb:1.5.5", "1044aa"), ("ip:192.168.4.60", "1044dd")]
        self.poe_calls = []
        for p in (
            mock.patch.object(cli, "_SYSFS_USB", sysfs),
            mock.patch.object(cli, "_SERIAL_BY_ID", by_id),
            mock.patch.object(cli, "_SYSFS_BT", bt),
            mock.patch.object(cli, "_iio_scan", side_effect=lambda: list(self.scan)),
            mock.patch.object(poe, "set_poe", side_effect=lambda **kw: self.poe_calls.append((kw["port"], kw["on"], kw["password"]))),
            mock.patch.object(poe, "_iiod_up", return_value=True),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.yml = self.cfg / "devices.yml"

    def wizard(self, answers, argv=(), secret=()):
        it = iter(answers)
        self.prompts = []

        def fake_input(prompt=""):
            self.prompts.append(prompt)
            try:
                return next(it)
            except StopIteration:
                raise AssertionError(f"unexpected prompt {prompt!r}; asked so far: {self.prompts}")

        out = io.StringIO()
        with mock.patch("builtins.input", fake_input), \
                mock.patch.object(cli.getpass, "getpass", side_effect=list(secret)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = cli.cmd_devices_add(list(argv))
        self.assertEqual(list(it), [], f"unused answers; output:\n{out.getvalue()}")
        return rc, out.getvalue()

    def devices(self):
        return {d["device_id"]: d for d in yaml.safe_load(self.yml.read_text())["devices"]}

    def loaded(self, gid, dtype):
        """The record through the server's loader and _connect_from_record (a fake driver)."""
        rec = dm._load_device_records()[gid]
        fake = _fake_driver(dtype)
        with mock.patch.object(dm, "get_driver_class", return_value=fake):
            schema, _, got_type = dm._connect_from_record(rec)
        self.assertIsNotNone(schema)
        self.assertEqual(got_type, dtype)
        self.assertEqual(fake.seen, [rec["INIT"]])
        return rec["INIT"]

    # --- every type ---------------------------------------------------------

    def test_every_type_round_trips_through_the_loader_and_its_driver(self):
        (self.root / "drivers").mkdir(parents=True)
        (self.root / "drivers" / "sim_schema.py").write_text('@idl_register("sim_sdr")\nclass S: pass\n')
        cases = [
            ("rtl_sdr", ["1", ""], {"serial": "00000101"}),
            ("rtl_sdr", ["2", "3"], {"device_index": 3}),
            ("hackrf", ["1", ""], {"serial": "0000000000000000a1b2"}),
            ("hackrf", ["2", ""], {"device_index": 0}),
            ("usrp", ["1", ""], {"profile": "usrp2901", "type": "b200", "serial": "31AB4C5"}),
            ("usrp", ["n210", "192.168.10.2"], {"profile": "n210", "type": "usrp2", "addr": "192.168.10.2"}),
            ("usrp", ["generic_usrp", "type=x300,addr=192.168.40.2"],
             {"profile": "generic_usrp", "args": "type=x300,addr=192.168.40.2"}),
            ("usrp_phaser", ["b205mini", "", ""],
             {"profile": "b205mini", "type": "b200", "serial": "31AB4C5", "phaser_uri": "ip:localhost"}),
            ("ti_mmwave", [""], {"serial": "00F1E2D3", "firmware_profile": "xwr68xx_oob_sdk3", "cli_baud": 115200,
                                 "data_baud": 921600, "frame_queue_depth": 8}),
            ("adalm_pluto_mimo", ["1", ""], {"serial": "1044aa", "rx_enabled_channels": [0, 1],
                                             "tx_enabled_channels": [0, 1]}),
            ("adalm_pluto_mimo", ["2", ""], {"usb_port": "1-5", "rx_enabled_channels": [0, 1],
                                             "tx_enabled_channels": [0, 1]}),
            ("gps", ["1", ""], {"port": str(cli._SERIAL_BY_ID / "usb-u-blox_GNSS_Receiver-if00"), "baud": 9600}),
            ("gps", ["", "4800"], {"baud": 4800}),
            ("bluetooth", ["", ""], {}),
            ("bluetooth", ["", "y"], {"allow_fallback": True}),
            ("bluetooth", ["2"], {"adapter": "hci1"}),
            ("sim_sdr", ["gain=10", "label=bench", ""], {"gain": 10, "label": "bench"}),
        ]
        for i, (dtype, answers, expected) in enumerate(cases):
            with self.subTest(dtype=dtype, answers=answers):
                self.yml.unlink(missing_ok=True)
                rc, out = self.wizard([dtype, "", f"dev-{i}", *answers, ""])
                self.assertEqual(rc, 0, out)
                self.assertEqual(self.devices()[0]["device_type"], dtype)
                init = self.loaded(0, dtype)
                self.assertEqual(init, expected)
                self._driver_accepts(dtype, init)

    def _driver_accepts(self, dtype, init):
        """The real driver entry points take exactly these keys (no hardware opened)."""
        if dtype == "rtl_sdr":
            inspect.signature(_connect_rtl_sdr).bind(**init)
        elif dtype == "hackrf":
            self.assertLessEqual(set(init), {"serial", "device_index"})
        elif dtype == "ti_mmwave":
            self.assertLessEqual(set(init), set(inspect.signature(connect_ti_mmwave).parameters))
        elif dtype == "adalm_pluto_mimo":
            params = set(inspect.signature(connect_pluto_mimo).parameters) - {"initial_settings"}
            self.assertLessEqual(set(init), params)
        elif dtype in ("usrp", "usrp_phaser"):
            uhd = {k: v for k, v in init.items() if k != "phaser_uri"}
            args = _usrp_args(**uhd)
            self.assertTrue(init.get("serial", init.get("addr", init.get("args"))) in args, args)
        elif dtype in CONTRIB_KEYS:
            self.assertLessEqual(set(init), CONTRIB_KEYS[dtype])

    def test_contrib_driver_not_installed_is_noted_but_written(self):
        rc, out = self.wizard(["gps", "", "gps-1", "", "", ""])
        self.assertEqual(rc, 0, out)
        self.assertIn("gps driver is not installed", out)

    def test_type_menu_lists_every_type_with_a_description(self):
        rc, out = self.wizard(["c"])
        self.assertEqual(rc, 1)
        for dtype in cli._WIZARD_TYPES:
            self.assertIn(dtype, out)
        self.assertIn("Cancelled; nothing written.", out)
        self.assertFalse(self.yml.exists() and self.yml.read_text().strip())

    # --- Pluto ----------------------------------------------------------------

    def test_pluto_over_usb_picks_a_detected_serial(self):
        rc, out = self.wizard(["", "pluto-lab-1", "1", "", "", ""], argv=["pluto"])
        self.assertEqual(rc, 0, out)
        init = self.loaded(0, "adalm_pluto")
        self.assertEqual(init, {"serial": "1044aa"})
        opened = []
        with mock.patch.object(pluto_schema, "connect_pluto", side_effect=lambda **kw: opened.append(kw)):
            pluto_schema.PlutoSchema.make_device(**init)
        self.assertEqual(opened, [{"serial": "1044aa", "ip": None}])

    def test_pluto_over_ethernet_opens_its_ip_and_checks_the_serial(self):
        rc, out = self.wizard(["adalm_pluto", "", "pluto-lab-2", "2", "192.168.4.50", "1044ee", "", ""])
        self.assertEqual(rc, 0, out)
        init = self.loaded(0, "adalm_pluto")
        self.assertEqual(init, {"ip": "192.168.4.50", "serial": "1044ee"})
        fake = types.SimpleNamespace(_ctx=types.SimpleNamespace(attrs={"hw_serial": "1044ee"}))
        with mock.patch.object(pluto_schema.adi, "Pluto", return_value=fake, create=True) as pluto:
            self.assertIs(pluto_schema.PlutoSchema.make_device(**init), fake)
        pluto.assert_called_once_with("ip:192.168.4.50")
        fake._ctx.attrs["hw_serial"] = "other"
        with mock.patch.object(pluto_schema.adi, "Pluto", return_value=fake, create=True), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(pluto_schema.PlutoSchema.make_device(**init))

    def test_pluto_ip_picked_from_the_network_scan_defaults_its_serial(self):
        rc, out = self.wizard(["adalm_pluto", "", "pluto-lab-3", "2", "1", "", "", ""])
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.devices()[0]["init"], {"ip": "192.168.4.60", "serial": "1044dd"})

    def test_poe_pluto_with_power_cycling_asks_the_switch_once_and_hides_the_password(self):
        rc, out = self.wizard(
            ["adalm_pluto", "", "pluto-lab-4", "3", "192.168.4.51", "1044bb", "ether7", "", "", "", "y", ""],
            secret=["pw-test"],
        )
        self.assertEqual(rc, 0, out)
        self.assertNotIn("pw-test", out + "".join(self.prompts))
        init = self.loaded(0, "adalm_pluto")
        self.assertEqual(init, {"ip": "192.168.4.51", "serial": "1044bb", "poe": True, "poe_port": "ether7",
                                "poe_switch": "192.168.88.1", "poe_user": "admin"})
        self.assertEqual(self.poe_calls, [("ether7", True, "pw-test"), ("ether7", False, "pw-test")])
        pw = self.root / "poe_switch_password"
        self.assertEqual(pw.read_text(), "pw-test\n")
        self.assertEqual(stat.S_IMODE(pw.stat().st_mode), 0o600)
        # The real driver builds a switched-off PoePluto from it.
        self.poe_calls.clear()
        with mock.patch.object(poe, "get_remoterf_root", return_value=self.root):
            dev = pluto_schema.PlutoSchema.make_device(**init)
        self.assertIsInstance(dev, poe.PoePluto)
        self.assertEqual((dev.uri, dev._port, dev._serial), ("ip:192.168.4.51", "ether7", "1044bb"))
        self.assertEqual(self.poe_calls, [("ether7", False, "pw-test")])

        # A second PoE Pluto reuses the switch and password: no switch questions, no password.
        rc, out = self.wizard(["adalm_pluto", "", "pluto-lab-5", "3", "192.168.4.52", "", "ether8", "", "", ""])
        self.assertEqual(rc, 0, out)
        self.assertIn("same as the other PoE Plutos", out)
        self.assertEqual(self.devices()[1]["init"]["poe_port"], "ether8")

    def test_poe_pluto_without_power_cycling_is_an_always_on_ip_pluto(self):
        rc, out = self.wizard(["adalm_pluto", "", "pluto-lab-6", "3", "192.168.4.53", "", "ether9", "n", "y", ""])
        self.assertEqual(rc, 0, out)
        init = self.loaded(0, "adalm_pluto")
        self.assertEqual(init, {"ip": "192.168.4.53", "poe": False, "poe_port": "ether9"})
        self.assertEqual(self.poe_calls, [])  # tested over IIOD only: the switch is never touched
        self.assertIn("keep its PoE output on", out)
        with mock.patch.object(pluto_schema.adi, "Pluto", return_value=object(), create=True) as pluto, \
                contextlib.redirect_stdout(io.StringIO()):
            pluto_schema.PlutoSchema.make_device(**init)
        pluto.assert_called_once_with("ip:192.168.4.53")

    def test_a_failed_test_asks_before_writing(self):
        poe._iiod_up.return_value = False
        rc, out = self.wizard(["adalm_pluto", "", "pluto-lab-7", "2", "192.168.4.54", "", "y", "n"])
        self.assertEqual(rc, 1)
        self.assertIn("does not answer", out)
        self.assertFalse(self.yml.exists() and self.yml.read_text().strip())

    def test_configured_pluto_ip_is_not_offered_and_dash_clears_the_serial(self):
        self.yml.write_text(yaml.safe_dump({"devices": [
            {"device_id": 0, "device_type": "adalm_pluto", "name": "pluto-lab-1", "init": {"ip": "192.168.4.60"}}]}))
        self.scan.append(("ip:192.168.4.61", "1044ee"))
        rc, out = self.wizard(["adalm_pluto", "", "pluto-lab-2", "2", "1", "-", "", ""])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("192.168.4.60  (serial", out)
        self.assertEqual(self.devices()[1]["init"], {"ip": "192.168.4.61"})

    # --- validation, cancel ----------------------------------------------------

    def test_taken_index_adapter_and_argv_id_alias_and_help(self):
        self.yml.write_text(yaml.safe_dump({"devices": [
            {"device_id": 0, "device_type": "rtl_sdr", "name": "rtl-0", "init": {"device_index": 0}},
            {"device_id": 1, "device_type": "bluetooth", "name": "bt-1", "init": {"adapter": "hci0"}}]}))
        rc, out = self.wizard(["rtl_sdr", "", "rtl-2", "2", "0", "", ""])
        self.assertEqual(rc, 0, out)
        self.assertIn("index 0 is already device #0", out)
        self.assertEqual(self.devices()[2]["init"], {"device_index": 1})
        rc, out = self.wizard(["", "bt-3", "hci0", "1", ""], argv=["bluetooth"])
        self.assertEqual(rc, 0, out)
        self.assertIn("adapter hci0 is already device #1", out)
        self.assertEqual(self.devices()[3]["init"], {"adapter": "hci1"})
        rc, out = self.wizard(["", "usrp-n210-1", "", "192.168.10.2", ""], argv=["usrp-n210", "--id", "7"])
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.devices()[7]["init"]["addr"], "192.168.10.2")
        rc, out = self.wizard([], argv=["-h"])
        self.assertEqual(rc, 0)
        self.assertIn("--profile P --selector S", out)

    def test_generic_fields_keep_serials_as_text_and_survive_bad_yaml(self):
        answers = iter(["serial=00000001", "rate=2.5", "note=@lab", ""])
        with mock.patch("builtins.input", lambda _="": next(answers)):
            self.assertEqual(cli._ask_generic({}, {}), {"serial": "00000001", "rate": 2.5, "note": "@lab"})

    def test_unreadable_reservations_db_still_asks(self):
        (self.root / "db").mkdir(parents=True)
        (self.root / "db" / "reservations.db").write_text("not a database")
        rc, out = self.wizard(["hackrf", "", "hackrf-1", "1", "", "", "no"])
        self.assertEqual(rc, 1)
        self.assertIn("Could not read reservations.db", out)

    def test_taken_ids_names_addresses_and_ports_are_asked_again(self):
        self.yml.write_text(yaml.safe_dump({"devices": [
            {"device_id": 4, "device_type": "adalm_pluto", "name": "pluto-lab-1",
             "init": {"ip": "192.168.4.50", "poe": True, "poe_port": "ether7"}},
        ]}))
        (self.root / "poe_switch_password").parent.mkdir(parents=True, exist_ok=True)
        (self.root / "poe_switch_password").write_text("x\n")
        rc, out = self.wizard(["adalm_pluto", "4", "-1", "", "pluto-lab-1", "bad@name", "pluto-lab-2",
                               "3", "not-an-ip", "192.168.4.50", "192.168.4.55", "", "ether7", "ether 8", "ether8",
                               "", "", ""])
        self.assertEqual(rc, 0, out)
        for problem in ("id 4 is taken", "whole number", "already exists", "cannot be typed as a handle",
                        "IPv4 or IPv6", "address 192.168.4.50 is already device #4",
                        "port ether7 is already device #4", "RouterOS interface name"):
            self.assertIn(problem, out)
        self.assertEqual(self.devices()[5]["name"], "pluto-lab-2")  # the id defaulted to the next free one

    def test_cancel_at_any_prompt_and_on_eof_writes_nothing(self):
        self.yml.write_text("devices: []\n")
        before = self.yml.read_text()
        for answers in (["c"], ["hackrf", "c"], ["hackrf", "", "c"], ["hackrf", "", "h-1", "C"],
                        ["adalm_pluto", "", "p-1", "3", "192.168.4.56", "", "c"], ["hackrf", "", "h-1", "1", "", "n"]):
            with self.subTest(answers=answers):
                rc, out = self.wizard(answers)
                self.assertEqual(rc, 1, out)
                self.assertIn("Cancelled; nothing written.", out)
                self.assertEqual(self.yml.read_text(), before)
        with mock.patch("builtins.input", side_effect=EOFError), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.cmd_devices_add([]), 1)
        self.assertEqual(self.yml.read_text(), before)

    # --- writing ------------------------------------------------------------

    def test_write_keeps_other_records_backs_up_and_is_atomic(self):
        original = "# bench inventory\ndevices:\n- device_id: 2\n  device_type: sim_sdr\n  name: SimSDR-2\n  init: {}\n"
        self.yml.write_text(original)
        rc, out = self.wizard(["hackrf", "", "hackrf-1", "1", "", ""])
        self.assertEqual(rc, 0, out)
        self.assertEqual(sorted(self.devices()), [2, 3])
        self.assertEqual(self.devices()[2]["init"], {})
        backups = list(self.cfg.glob("devices.yml.*.bak"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), original)
        self.assertIn(str(backups[0]), out)
        self.assertEqual(list(self.cfg.glob(".devices.yml.tmp")), [])

        now = self.yml.read_text()
        with mock.patch.object(cli.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                cli._write_device_records({9: {"TYPE": "hackrf", "NAME": "x", "INIT": {}}})
        self.assertEqual(self.yml.read_text(), now)
        self.assertEqual(list(self.cfg.glob(".devices.yml.tmp")), [])
        self.yml.chmod(0o600)
        cli._write_device_records(cli._read_device_records())
        self.assertEqual(stat.S_IMODE(self.yml.stat().st_mode), 0o600)

    def test_a_rename_keeps_wizard_init_fields(self):
        self.wizard(["adalm_pluto", "", "pluto-lab-8", "3", "192.168.4.57", "1044ff", "ether3", "", "", "", "", ""],
                    secret=[""])
        before = self.devices()[0]["init"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.cmd_devices_rename(["0", "pluto-lab-9"]), 0)
        self.assertEqual(self.devices()[0]["init"], before)

    # --- reservations ----------------------------------------------------------

    def _reservation(self):
        db = self.root / "db"
        db.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(db / "reservations.db") as conn:
            conn.execute("CREATE TABLE Reservations (res_id INTEGER PRIMARY KEY, username TEXT, device_id INTEGER,"
                         " start_time TIMESTAMP, end_time TIMESTAMP, salt TEXT, hash TEXT)")
            now = datetime.now()
            for start, end in ((now - timedelta(minutes=5), now + timedelta(minutes=5)),
                               (now + timedelta(hours=1), now + timedelta(hours=2))):
                conn.execute("INSERT INTO Reservations (username, device_id, start_time, end_time, salt, hash)"
                             " VALUES ('jdoe@lab', 1, ?, ?, '', '')", (start.isoformat(" "), end.isoformat(" ")))

    def test_an_active_reservation_needs_confirmation(self):
        self._reservation()
        rc, out = self.wizard(["hackrf", "", "hackrf-1", "1", "", "", "no"])
        self.assertEqual(rc, 1)
        self.assertIn("1 reservation(s) are running now", out)
        self.assertFalse(self.yml.exists() and self.yml.read_text().strip())
        rc, out = self.wizard(["hackrf", "", "hackrf-1", "1", "", "", "reload"])
        self.assertEqual(rc, 0, out)
        rc, out = self.wizard(["hackrf", "", "hackrf-2", "2", "1", ""], argv=["-y"])
        self.assertEqual(rc, 0, out)
        # The argv form is guarded too, and -y skips the question.
        rc, out = self.wizard(["no"], argv=["hackrf", "hackrf-3", "--serial", "75b1"])
        self.assertEqual(rc, 1)
        rc, out = self.wizard([], argv=["hackrf", "hackrf-3", "--serial", "75b1", "-y"])
        self.assertEqual(rc, 0, out)


if __name__ == "__main__":
    unittest.main()
