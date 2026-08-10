from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


class DeviceManagerRadioTests(unittest.TestCase):
    def test_inventory_loads_all_requested_radio_drivers_without_native_libraries(self):
        project_root = Path(__file__).resolve().parents[1]
        source_root = project_root / "src"
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            blocker = temp / "blocker"
            blocker.mkdir()
            for module_name in ("pyhackrf2", "rtlsdr", "serial", "uhd"):
                (blocker / f"{module_name}.py").write_text(
                    f"raise ImportError('{module_name} deliberately unavailable')\n",
                    encoding="utf-8",
                )

            host_root = temp / "host"
            drivers_root = temp / "drivers"
            host_root.mkdir()
            (host_root / "devices.yml").write_text(
                json.dumps(
                    {
                        "devices": [
                            {
                                "device_id": 1,
                                "device_type": "usrp",
                                "name": "usrp2901",
                                "init": {
                                    "profile": "usrp2901",
                                    "type": "b200",
                                    "serial": "SERIAL2901",
                                },
                            },
                            {
                                "device_id": 2,
                                "device_type": "usrp",
                                "name": "b205mini",
                                "init": {
                                    "profile": "b205mini",
                                    "type": "b200",
                                    "serial": "SERIALB205",
                                },
                            },
                            {
                                "device_id": 3,
                                "device_type": "usrp",
                                "name": "n210",
                                "init": {
                                    "profile": "n210",
                                    "type": "usrp2",
                                    "addr": "192.168.10.2",
                                },
                            },
                            {
                                "device_id": 4,
                                "device_type": "rtl_sdr",
                                "name": "rtl",
                                "init": {"device_index": 0},
                            },
                            {
                                "device_id": 5,
                                "device_type": "hackrf",
                                "name": "hackrf",
                                "init": {"serial": "HACKRF-SERIAL"},
                            },
                            {
                                "device_id": 6,
                                "device_type": "ti_mmwave",
                                "name": "ti-radar",
                                "init": {
                                    "serial": "00DF4F69",
                                    "firmware_profile": "xwr68xx_oob_sdk3",
                                    "cli_baud": 115200,
                                    "data_baud": 921600,
                                    "frame_queue_depth": 8,
                                },
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            env = dict(os.environ)
            env["REMOTERF_CONFIG_DIR"] = str(host_root)
            env["REMOTERF_DRIVERS_DIR"] = str(drivers_root)
            env["PYTHONPATH"] = os.pathsep.join((str(blocker), str(source_root)))
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    textwrap.dedent(
                        """
                        from remoteRF_host.common.idl.schema import get_driver_class
                        from remoteRF_host.server import device_manager

                        configured = device_manager.get_configured_devices()
                        assert set(configured) == {1, 2, 3, 4, 5, 6}
                        assert configured[3]["ident"] == "192.168.10.2"
                        assert configured[4]["ident"] == "0"

                        for filename in (
                            "usrp_schema.py",
                            "rtl_sdr_schema.py",
                            "hackrf_schema.py",
                            "ti_mmwave_schema.py",
                        ):
                            assert (device_manager.get_drivers_dir() / filename).is_file()

                        for device_type, client_class in (
                            ("usrp", "MultiUSRP"),
                            ("rtl_sdr", "RtlSdr"),
                            ("hackrf", "HackRF"),
                            ("ti_mmwave", "TiMmWave"),
                        ):
                            schema = get_driver_class(device_type)()
                            assert schema.get_idl()["client_class"] == client_class

                        for gid, profile in (
                            (1, "usrp2901"),
                            (2, "b205mini"),
                            (3, "n210"),
                        ):
                            context = device_manager.get_local_device_context(gid)
                            assert context["schema"]._inventory["profile"] == profile

                        print("HOST_RADIO_INVENTORY_OK")
                        """
                    ),
                ],
                cwd=project_root,
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
        self.assertIn("HOST_RADIO_INVENTORY_OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
