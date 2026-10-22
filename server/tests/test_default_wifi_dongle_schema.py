# Copyright (C) 2026 RemoteRF
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from rssi import safety


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"


class DefaultWifiDongleSchemaTests(unittest.TestCase):
    def test_soft_blocked_radio_is_reported_after_unblock_attempt(self):
        with mock.patch.object(safety.subprocess, "run"), mock.patch.object(
            safety.subprocess,
            "check_output",
            side_effect=["default via 192.0.2.1 dev eth0\n", "disabled\n"],
        ):
            with self.assertRaisesRegex(RuntimeError, "sudo rfkill unblock wifi"):
                safety.verify_network_safety("wlan1")

    def test_fresh_server_seeds_schema_with_bundled_rssi_package(self):
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            config_root = temp / "xdg"
            env = dict(os.environ)
            env["HOME"] = str(temp / "home")
            env["XDG_CONFIG_HOME"] = str(config_root)
            env["PYTHONPATH"] = os.pathsep.join((str(SOURCE_ROOT), env.get("PYTHONPATH", "")))

            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    textwrap.dedent(
                        """
                        from remoteRF_server.common.idl.schema import get_driver_class
                        from remoteRF_server.common.utils import get_drivers_dir
                        from remoteRF_server.server import device_manager
                        from rssi.scanner import dbm_to_quality_percent, freq_to_channel

                        seeded = get_drivers_dir() / "wifi_dongle_schema.py"
                        assert seeded.is_file(), seeded
                        marker = get_drivers_dir() / ".wifi_dongle_schema.py.remoterf-managed"
                        assert marker.is_file(), marker

                        schema = get_driver_class("wifi_dongle")
                        assert schema.driver_version == "0.1.0"
                        assert freq_to_channel(2412) == 1
                        assert dbm_to_quality_percent(-75.0) == 50
                        print("DEFAULT_WIFI_DONGLE_SCHEMA_OK")
                        """
                    ),
                ],
                cwd=PROJECT_ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn("DEFAULT_WIFI_DONGLE_SCHEMA_OK", result.stdout)
        self.assertNotIn("wifi_dongle_schema.py: error", result.stdout)


if __name__ == "__main__":
    unittest.main()
