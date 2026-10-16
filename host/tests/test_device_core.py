from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run(cfg: Path, code: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, REMOTERF_CONFIG_DIR=str(cfg), REMOTERF_DRIVERS_DIR=str(cfg / "drivers"),
               PYTHONPATH=str(PROJECT_ROOT / "src"))
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code)], env=env,
                          capture_output=True, text=True, timeout=120)


class DeviceCoreTests(unittest.TestCase):
    def test_host_builtins_report_the_lab_manifest_hashes(self):
        with tempfile.TemporaryDirectory() as raw:
            result = _run(Path(raw), """
                import json, sys, types
                sys.modules.setdefault("adi", types.ModuleType("adi"))  # no libiio needed for the interface
                from remoterf_device_core import manifest
                from remoteRF_host.common.idl import get_driver_class
                from remoteRF_host.server import device_manager
                for module in manifest.BUILTIN_MODULES:
                    __import__(module)
                out = {row["device_type"]: get_driver_class(row["device_type"])().get_idl_hash() == row["v1"]
                       for row in manifest.load()}
                print(json.dumps(out))
            """)
            self.assertEqual(result.returncode, 0, result.stderr)
            matched = json.loads(result.stdout.strip().splitlines()[-1])
            self.assertTrue(matched and all(matched.values()), matched)

    def test_a_released_pluto_copy_is_refreshed_and_an_edited_one_kept(self):
        with tempfile.TemporaryDirectory() as raw:
            cfg = Path(raw)
            drivers = cfg / "drivers"
            drivers.mkdir()
            stale = b"# a pluto_schema.py some hostrf release copied here\n"
            legacy = hashlib.sha256(stale).hexdigest()
            (drivers / "pluto_schema.py").write_bytes(stale)
            (drivers / "pluto_mimo_schema.py").write_text("# edited by the admin\n")
            result = _run(cfg, f"""
                from remoteRF_host.common.idl import host_drivers
                host_drivers._LEGACY_PLUTO_SCHEMA_HASHES += ("{legacy}",)
                host_drivers.ensure_default_driver_files()
            """)
            self.assertEqual(result.returncode, 0, result.stderr)
            import remoterf_device_core.drivers as core_drivers

            source = Path(core_drivers.__file__).parent / "adalm_pluto" / "pluto_schema.py"
            self.assertEqual((drivers / "pluto_schema.py").read_bytes(), source.read_bytes())
            self.assertTrue((drivers / ".pluto_schema.py.remoterf-managed").exists())
            self.assertEqual((drivers / "pluto_mimo_schema.py").read_text(), "# edited by the admin\n")


if __name__ == "__main__":
    unittest.main()
