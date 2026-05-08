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

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        env = {
            "REMOTERF_CONFIG_DIR": str(self.host_dir),
            "REMOTERF_DRIVERS_DIR": str(self.drivers_dir),
            "XDG_CONFIG_HOME": str(self.root),
        }

        with patch.dict(os.environ, env, clear=False):
            with patch.object(hostrf_cli.sys, "argv", ["hostrf", *args]):
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
        self.assertIn("10: type=pluto name=pluto_0 iio_serial=104473", out)

        devices_yml = self.host_dir / "devices.yml"
        self.assertTrue(devices_yml.exists())
        self.assertIn('"device_id": 10', devices_yml.read_text(encoding="utf-8"))

        rc, out, err = self.run_cli("--device", "--wipe", "-y")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertIn("Wiped device config", out)
        self.assertFalse(devices_yml.exists())

    def test_device_show_creates_empty_devices_config_on_first_run(self) -> None:
        devices_yml = self.host_dir / "devices.yml"
        pluto_schema = self.drivers_dir / "pluto_schema.py"
        self.assertFalse(devices_yml.exists())
        self.assertFalse(pluto_schema.exists())

        rc, out, err = self.run_cli("--device", "--show")
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")
        self.assertTrue(devices_yml.exists())
        self.assertTrue(pluto_schema.exists())
        self.assertEqual(json.loads(devices_yml.read_text(encoding="utf-8")), {"devices": []})
        self.assertIn("class PlutoSchema", pluto_schema.read_text(encoding="utf-8"))
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
