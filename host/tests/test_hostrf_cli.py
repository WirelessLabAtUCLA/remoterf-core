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

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from remoteRF_host import hostrf_cli


class HostRfCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.root = Path(self.tmp.name)
        self.host_dir = self.root / "host"
        self.drivers_dir = self.root / "drivers"

    def run_cli(self, *args: str, tty_input: str | None = None, tty_stdout: bool = True) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        stdin = io.StringIO(tty_input or "")
        stdin.isatty = lambda: tty_input is not None  # type: ignore[method-assign]
        stdout.isatty = lambda: tty_stdout  # type: ignore[method-assign]
        env = {
            "REMOTERF_CONFIG_DIR": str(self.host_dir),
            "REMOTERF_DRIVERS_DIR": str(self.drivers_dir),
            "XDG_CONFIG_HOME": str(self.root),
        }

        with patch.dict(os.environ, env, clear=False):
            with patch.object(hostrf_cli.sys, "argv", ["hostrf", *args]), \
                    patch.object(hostrf_cli.sys, "stdin", stdin):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = hostrf_cli.main()

        return rc, stdout.getvalue(), stderr.getvalue()

    def test_no_args_matches_server_style_error(self) -> None:
        rc, out, err = self.run_cli()
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("invalid args, expect hostrf <args>", err)

    def test_host_mode_set_and_show(self) -> None:
        rc, out, err = self.run_cli("--host", "--set", "lab-host-01", "secret1234")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertIn("Configured host:", out)

        rc, out, err = self.run_cli("--host", "--show")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertIn("HOST_ID=lab-host-01", out)
        self.assertIn("HOST_TOKEN=secr...1234", out)
        self.assertNotIn("HOST_TOKEN=secret1234", out)

        rc, out, err = self.run_cli("--host", "--show", "--secrets")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertIn("HOST_TOKEN=secret1234", out)

    def test_legacy_config_host_alias_still_works(self) -> None:
        rc, out, err = self.run_cli("-c", "-h", "legacy-host", "abcd1234")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertIn("Configured host:", out)

        host_env = self.host_dir / "host.env"
        self.assertTrue(host_env.exists())
        self.assertIn("HOST_ID=legacy-host", host_env.read_text(encoding="utf-8"))

    def test_device_mode_add_show_and_wipe(self) -> None:
        rc, out, err = self.run_cli("--device", "--add", "--pluto", "10:pluto_0:104473")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertIn("Added device: 10", out)

        rc, out, err = self.run_cli("--device", "--show")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertIn("10: type=adalm_pluto name=pluto_0 iio_serial=104473", out)

        devices_yml = self.host_dir / "devices.yml"
        self.assertTrue(devices_yml.exists())
        self.assertIn('"device_id": 10', devices_yml.read_text(encoding="utf-8"))

        rc, out, err = self.run_cli("--device", "--wipe", "-y")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertIn("Wiped device config", out)
        self.assertFalse(devices_yml.exists())

    def test_device_add_with_handle_round_trips(self) -> None:
        rc, out, err = self.run_cli(
            "--device", "--add", "--pluto", "0:pluto_a:123123", "--handle", "PlutoA"
        )
        self.assertEqual((rc, err), (0, ""))
        self.assertIn("Set device handle: 0 handle=PlutoA", out)
        rc, _, err = self.run_cli("--device", "--add", "--pluto", "1:pluto_b:456456")
        self.assertEqual((rc, err), (0, ""))

        # rename and removing another device keep the handle
        self.assertEqual(self.run_cli("--device", "--edit-name", "0", "pluto_x")[0], 0)
        self.assertEqual(self.run_cli("--device", "--remove", "1")[0], 0)

        devices_yml = self.host_dir / "devices.yml"
        self.assertEqual(
            json.loads(devices_yml.read_text(encoding="utf-8"))["devices"],
            [{
                "device_id": 0,
                "device_type": "adalm_pluto",
                "name": "pluto_x",
                "handle": "PlutoA",
                "init": {"serial": "123123"},
            }],
        )
        rc, out, _ = self.run_cli("--device", "--show")
        self.assertIn("0: type=adalm_pluto name=pluto_x iio_serial=123123 handle=PlutoA", out)

    def test_a_name_that_reads_as_a_handle_is_refused(self) -> None:
        rc, out, err = self.run_cli("--device", "--add", "--pluto", "3:Bench [B1]:789789")
        self.assertEqual(rc, 2)
        self.assertIn("device lists show a handle that way", err + out)
        self.assertNotIn("Added device", out)
        self.assertEqual(self.run_cli("--device", "--add", "--pluto", "3:bench:789789")[0], 0)
        rc, _, err = self.run_cli("--device", "--edit-name", "3", "Bench [B1]")
        self.assertEqual(rc, 2)
        self.assertIn("device lists show a handle that way", err)

    def test_device_add_rejects_bad_or_duplicate_handle(self) -> None:
        for bad in ("", "a@lab", "uuid:1", "two words", "rfg_x", "bridge-1", "tab\tx", "Pluto\u200bA", "\u202ePlutoA"):
            rc, out, err = self.run_cli(
                "--device", "--add", "--pluto", "3:pluto_c:789789", "--handle", bad
            )
            self.assertEqual(rc, 2, bad)
            self.assertIn(f"ERROR: invalid handle {bad!r}", err)
            self.assertNotIn("Added device", out)

        self.run_cli("--device", "--add", "--pluto", "0:pluto_a:123123", "--handle", "PlutoA")
        rc, out, err = self.run_cli(
            "--device", "--add", "--pluto", "1:pluto_b:456456", "--handle", "PlutoA"
        )
        self.assertEqual(rc, 2)
        self.assertIn("ERROR: handle 'PlutoA' is already used by global_id=0", err)
        records = json.loads((self.host_dir / "devices.yml").read_text(encoding="utf-8"))
        self.assertEqual([d["device_id"] for d in records["devices"]], [0])

        # exact match: a different case is a different handle
        rc, _, err = self.run_cli(
            "--device", "--add", "--pluto", "1:pluto_b:456456", "--handle", "plutoa"
        )
        self.assertEqual((rc, err), (0, ""))

    def handles(self) -> dict[int, str | None]:
        records = json.loads((self.host_dir / "devices.yml").read_text(encoding="utf-8"))
        return {d["device_id"]: d.get("handle") for d in records["devices"]}

    def test_interactive_add_prompts_for_handle_until_valid(self) -> None:
        self.run_cli("--device", "--add", "--pluto", "0:pluto_a:123123", "--handle", "PlutoA")
        rc, out, err = self.run_cli(
            "--device", "--add", "--pluto", "1:pluto_b:456456",
            tty_input="bad handle\nPlutoA\nPlutoB\n",
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out.count("Handle (optional, e.g. PlutoA): "), 3)
        self.assertIn("ERROR: invalid handle 'bad handle'", err)
        self.assertIn("ERROR: handle 'PlutoA' is already used by global_id=0", err)
        self.assertEqual(self.handles(), {0: "PlutoA", 1: "PlutoB"})

        # Enter or EOF skips; --handle and non-TTY runs never prompt
        self.run_cli("--device", "--add", "--pluto", "2:pluto_c:1", tty_input="\n")
        self.run_cli("--device", "--add", "--pluto", "3:pluto_d:2", tty_input="")
        _, out, _ = self.run_cli("--device", "--add", "--pluto", "4:pluto_e:3", "--handle", "PlutoE", tty_input="")
        self.assertNotIn("Handle (optional", out)
        _, out, _ = self.run_cli("--device", "--add", "--pluto", "5:pluto_f:4")
        self.assertNotIn("Handle (optional", out)
        # stdout redirected: no prompt hidden in the output
        _, out, _ = self.run_cli("--device", "--add", "--pluto", "6:pluto_g:5", tty_input="PlutoG\n", tty_stdout=False)
        self.assertNotIn("Handle (optional", out)
        # '-' skips like Enter; Ctrl-C skips without a traceback
        self.run_cli("--device", "--add", "--pluto", "7:pluto_h:6", tty_input="-\n")
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            rc, _, _ = self.run_cli("--device", "--add", "--pluto", "8:pluto_i:7", tty_input="")
        self.assertEqual(rc, 0)
        self.assertEqual(
            self.handles(),
            {0: "PlutoA", 1: "PlutoB", 2: None, 3: None, 4: "PlutoE", 5: None, 6: None, 7: None, 8: None},
        )
        rc, _, err = self.run_cli("--device", "--add", "--pluto", "9:pluto_j:8", "--handle", "-")
        self.assertEqual(rc, 2)
        self.assertIn("'-' means no handle", err)
        self.assertNotIn(9, self.handles())

    def test_edit_handle_sets_validates_and_clears(self) -> None:
        self.run_cli("--device", "--add", "--pluto", "0:pluto_a:123123", "--handle", "PlutoA")
        self.run_cli("--device", "--add", "--pluto", "1:pluto_b:456456")

        rc, out, err = self.run_cli("--device", "--edit-handle", "1", "PlutoB")
        self.assertEqual((rc, err), (0, ""))
        self.assertIn("Set device handle: 1 handle=PlutoB", out)
        self.assertIn("when the host tunnel reconnects", out)
        # re-setting a device's own handle is not a duplicate
        self.assertEqual(self.run_cli("--device", "--edit-handle", "1", "PlutoB")[0], 0)

        for bad, msg in (("PlutoA", "already used by global_id=0"), ("a@lab", "invalid handle")):
            rc, _, err = self.run_cli("--device", "--edit-handle", "1", bad)
            self.assertEqual(rc, 2)
            self.assertIn(msg, err)
        rc, _, err = self.run_cli("--device", "--edit-handle", "9", "PlutoZ")
        self.assertEqual(rc, 2)
        self.assertIn("global_id 9 not present", err)

        rc, out, _ = self.run_cli("--device", "--edit-handle", "0", "-")
        self.assertEqual(rc, 0)
        self.assertIn("Cleared device handle: 0", out)
        self.assertEqual(self.handles(), {0: None, 1: "PlutoB"})

    def test_handle_without_add_is_rejected_even_with_wipe(self) -> None:
        self.run_cli("--device", "--add", "--pluto", "0:pluto_a:123123")
        rc, _, err = self.run_cli("--device", "--wipe", "-y", "--handle", "PlutoA")
        self.assertEqual(rc, 2)
        self.assertIn("ERROR: --handle is only valid with --device --add", err)
        self.assertTrue((self.host_dir / "devices.yml").exists())

    def test_device_mode_adds_serial_bound_usrp(self) -> None:
        rc, out, err = self.run_cli(
            "--device", "--add", "--usrp", "7:usrp2901_lab:31A2B3C"
        )
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertIn("Added device: 7 type=usrp", out)

        records = json.loads(
            (self.host_dir / "devices.yml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            records["devices"],
            [{
                "device_id": 7,
                "device_type": "usrp",
                "name": "usrp2901_lab",
                "init": {
                    "profile": "usrp2901",
                    "type": "b200",
                    "serial": "31A2B3C",
                },
            }],
        )

        rc, out, err = self.run_cli("--device", "--show")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertIn(
            "7: type=usrp name=usrp2901_lab serial=31A2B3C",
            out,
        )

    def test_device_mode_adds_all_new_host_radio_inventories(self) -> None:
        cases = (
            (
                "--usrp-b205-mini",
                "8:b205mini_lab:31E9F48",
                8,
                "usrp",
                {
                    "profile": "b205mini",
                    "type": "b200",
                    "serial": "31E9F48",
                },
            ),
            (
                "--usrp-n210",
                "9:n210_lab:192.168.10.2",
                9,
                "usrp",
                {
                    "profile": "n210",
                    "type": "usrp2",
                    "addr": "192.168.10.2",
                },
            ),
            (
                "--rtl-sdr",
                "10:rtl_fm:serial=00000001",
                10,
                "rtl_sdr",
                {"serial": "00000001"},
            ),
            (
                "--hackrf",
                "11:hackrf_lab:index=0",
                11,
                "hackrf",
                {"device_index": 0},
            ),
            (
                "--ti-mmwave",
                "12:ti_xwr68xx:00DF4F69",
                12,
                "ti_mmwave",
                {
                    "serial": "00DF4F69",
                    "firmware_profile": "xwr68xx_oob_sdk3",
                    "cli_baud": 115200,
                    "data_baud": 921600,
                    "frame_queue_depth": 8,
                },
            ),
        )

        for flag, spec, gid, device_type, expected_init in cases:
            with self.subTest(flag=flag):
                rc, _out, err = self.run_cli(
                    "--device", "--add", flag, spec
                )
                self.assertEqual(rc, 0)
                self.assertEqual(err, "")
                records = json.loads(
                    (self.host_dir / "devices.yml").read_text(encoding="utf-8")
                )["devices"]
                record = next(item for item in records if item["device_id"] == gid)
                self.assertEqual(record["device_type"], device_type)
                self.assertEqual(record["init"], expected_init)

        rc, out, err = self.run_cli("--device", "--show")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertIn("9: type=usrp name=n210_lab addr=192.168.10.2", out)
        self.assertIn("11: type=hackrf name=hackrf_lab device_index=0", out)
        self.assertIn("12: type=ti_mmwave name=ti_xwr68xx serial=00DF4F69", out)

    def test_n210_cli_rejects_non_ip_selector(self) -> None:
        rc, _out, err = self.run_cli(
            "--device", "--add", "--usrp-n210", "9:n210_lab:not-an-ip"
        )
        self.assertEqual(rc, 2)
        self.assertIn("addr must be an IPv4 or IPv6 address", err)

    def test_device_show_creates_empty_devices_config_on_first_run(self) -> None:
        devices_yml = self.host_dir / "devices.yml"
        pluto_schema = self.drivers_dir / "pluto_schema.py"
        pluto_mimo_schema = self.drivers_dir / "pluto_mimo_schema.py"
        self.assertFalse(devices_yml.exists())
        self.assertFalse(pluto_schema.exists())
        self.assertFalse(pluto_mimo_schema.exists())

        rc, out, err = self.run_cli("--device", "--show")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertTrue(devices_yml.exists())
        self.assertTrue(pluto_schema.exists())
        self.assertTrue(pluto_mimo_schema.exists())
        self.assertEqual(json.loads(devices_yml.read_text(encoding="utf-8")), {"devices": []})
        self.assertIn("class PlutoSchema", pluto_schema.read_text(encoding="utf-8"))
        self.assertIn("class PlutoMIMOSchema", pluto_mimo_schema.read_text(encoding="utf-8"))
        self.assertIn("Devices:", out)
        self.assertIn("  (none)", out)

    def test_device_show_does_not_overwrite_existing_pluto_schema(self) -> None:
        self.drivers_dir.mkdir(parents=True, exist_ok=True)
        pluto_schema = self.drivers_dir / "pluto_schema.py"
        pluto_schema.write_text("# custom pluto driver\n", encoding="utf-8")

        rc, out, err = self.run_cli("--device", "--show")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertEqual(pluto_schema.read_text(encoding="utf-8"), "# custom pluto driver\n")

    def test_legacy_config_device_alias_is_rejected(self) -> None:
        self.host_dir.mkdir(parents=True, exist_ok=True)
        (self.host_dir / "devices.yml").write_text('{"devices": []}\n', encoding="utf-8")

        rc, out, err = self.run_cli("-c", "-y", "-d", "--wipe")
        self.assertEqual(rc, 2)
        self.assertEqual(out, "")
        self.assertIn("--device cannot be combined with config/host commands", err)
        self.assertTrue((self.host_dir / "devices.yml").exists())

    def test_config_show_and_wipe(self) -> None:
        self.host_dir.mkdir(parents=True, exist_ok=True)
        (self.host_dir / "net.env").write_text(
            "REMOTERF_ADDR=1.2.3.4:61007\nREMOTERF_CA_CERT=./ca.crt\n",
            encoding="utf-8",
        )
        (self.host_dir / "ca.crt").write_text("dummy cert", encoding="utf-8")

        rc, out, err = self.run_cli("--config", "--show")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertIn("REMOTERF_ADDR=1.2.3.4:61007", out)
        self.assertIn("REMOTERF_CA_CERT=./ca.crt", out)

        rc, out, err = self.run_cli("--config", "--wipe", "-y")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertIn("Wiped address config", out)
        self.assertFalse((self.host_dir / "net.env").exists())
        self.assertFalse((self.host_dir / "ca.crt").exists())


if __name__ == "__main__":
    unittest.main()
