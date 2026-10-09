"""An inventory reload closes the previous instance before opening it again."""

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

_FAKE_DRIVER = """
import os
from remoteRF_host.common.idl import DeviceSchema, idl_register

def _log(line):
    with open(os.environ["FAKE_LOG"], "a") as f:
        f.write(line + "\\n")

class _Native:
    def __init__(self, n):
        self.n = n

    def close(self):
        _log(f"close{self.n}")

@idl_register("fake_reload")
class FakeReloadSchema(DeviceSchema):
    device_type = "fake_reload"
    driver_version = "0.0.1"

    @staticmethod
    def make_device(**kwargs):
        n = open(os.environ["FAKE_LOG"]).read().count("make") + 1 if os.path.exists(os.environ["FAKE_LOG"]) else 1
        _log(f"make{n}")
        return _Native(n)
"""

_CHILD = """
from pathlib import Path
import os
from remoteRF_host.server import device_manager as dm

yml = Path(os.environ["REMOTERF_CONFIG_DIR"], "devices.yml")
yml.write_text(yml.read_text().replace("name: gps", "name: gps2"))
assert dm.reload_devices()
print(open(os.environ["FAKE_LOG"]).read().split())
"""


class DeviceReloadTests(unittest.TestCase):
    def test_reload_closes_before_reopening(self):
        source_root = Path(__file__).resolve().parents[1] / "src"
        with tempfile.TemporaryDirectory() as tmp:
            host_root, drivers = Path(tmp, "host"), Path(tmp, "drivers")
            host_root.mkdir()
            drivers.mkdir()
            (drivers / "fake_reload_schema.py").write_text(_FAKE_DRIVER)
            (host_root / "devices.yml").write_text(textwrap.dedent("""\
                devices:
                  - device_id: 7
                    device_type: fake_reload
                    name: gps
                    init: {port: /dev/ttyACM0}
                """))
            env = dict(os.environ, REMOTERF_CONFIG_DIR=str(host_root), REMOTERF_DRIVERS_DIR=str(drivers),
                       FAKE_LOG=str(Path(tmp, "log")), PYTHONPATH=str(source_root))
            proc = subprocess.run([sys.executable, "-c", _CHILD], env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip().splitlines()[-1], "['make1', 'close1', 'make2']")


if __name__ == "__main__":
    unittest.main()
