from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"


class DefaultRtlSdrSchemaTests(unittest.TestCase):
    def test_fresh_server_seeds_schema_without_native_rtlsdr(self):
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            blocker = temp / "blocker"
            blocker.mkdir()
            (blocker / "rtlsdr.py").write_text(
                "raise ImportError('RTL-SDR deliberately unavailable in test')\n",
                encoding="utf-8",
            )
            config_root = temp / "xdg"
            env = dict(os.environ)
            env["HOME"] = str(temp / "home")
            env["XDG_CONFIG_HOME"] = str(config_root)
            env["PYTHONPATH"] = os.pathsep.join((str(blocker), str(SOURCE_ROOT)))

            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    textwrap.dedent(
                        """
                        from remoteRF_server.common.idl.schema import get_driver_class
                        from remoteRF_server.common.utils import get_drivers_dir
                        from remoteRF_server.server import device_manager

                        seeded = get_drivers_dir() / "rtl_sdr_schema.py"
                        assert seeded.is_file(), seeded
                        marker = get_drivers_dir() / ".rtl_sdr_schema.py.remoterf-managed"
                        assert marker.is_file(), marker

                        schema = get_driver_class("rtl_sdr")()
                        idl = schema.get_idl()
                        assert idl["client_class"] == "RtlSdr"
                        assert "call_read_samples" in idl["calls"]
                        assert "call_read_bytes" in idl["calls"]
                        assert "get_center_freq" in idl["getters"]

                        try:
                            schema.make_device(device_index=0)
                        except RuntimeError as exc:
                            assert "pyrtlsdr" in str(exc).lower()
                        else:
                            raise AssertionError("native open should require PyRtlSdr")

                        print("DEFAULT_RTL_SDR_SCHEMA_OK")
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
        self.assertIn("DEFAULT_RTL_SDR_SCHEMA_OK", result.stdout)
        self.assertNotIn("Driver load rtl_sdr_schema.py: error", result.stdout)


if __name__ == "__main__":
    unittest.main()
