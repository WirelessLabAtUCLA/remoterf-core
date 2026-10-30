"""Local devices are opened by the server at startup and on reload, never on import."""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from remoteRF_server.server import device_manager as dm


class ReloadTests(unittest.TestCase):
    def setUp(self):
        for table in (dm._devices, dm.devices_info, dm.device_serialization):
            patcher = mock.patch.dict(table, clear=True)
            patcher.start()
            self.addCleanup(patcher.stop)
        events = self.events = []

        class Native:
            def __init__(self, n):
                self.n = n

            def close(self):
                events.append(f"close{self.n}")

        class Schema:
            device = None

            @staticmethod
            def make_device(**init):
                n = sum(e.startswith("make") for e in events) + 1
                events.append(f"make{n}")
                return Native(n)

            def bind(self, dev):
                self.device = dev

        records = {3: {"TYPE": "gps", "NAME": "gps", "IDENT": "/dev/ttyACM0", "INIT": {"port": "/dev/ttyACM0"}}}
        for patcher in (
            mock.patch.object(dm, "_load_device_records", return_value=records),
            mock.patch.object(dm, "get_driver_class", return_value=Schema),
            mock.patch.object(dm, "_sync_host_devices"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_reload_closes_the_previous_instance_once_before_reopening(self):
        dm._devices[50] = dm._DeviceState(dev=dm.VirtualDevice(50, "h", "50"), origin="host", online=True,
                                          salt="", hsh="", name="remote", ident="", dtype="")
        dm.reload_devices()  # startup
        self.assertEqual(self.events, ["make1"])
        dm._devices[3].salt, dm._devices[3].hsh = "s", "h"

        dm.reload_devices()  # devices add/remove/rename/wipe
        self.assertEqual(self.events, ["make1", "close1", "make2"])
        st = dm._devices[3]
        self.assertEqual((st.salt, st.hsh, st.handle), ("s", "h", "gps"))
        self.assertIn(50, dm._devices)

        self.assertEqual(dm.close_local_devices(), 1)
        self.assertEqual(self.events, ["make1", "close1", "make2", "close2"])


_FAKE_DRIVER = """
import os
from remoteRF_server.common.idl import DeviceSchema, idl_register

@idl_register("fake_init")
class FakeInitSchema(DeviceSchema):
    device_type = "fake_init"
    driver_version = "0.0.1"

    @staticmethod
    def make_device(**kwargs):
        with open(os.environ["FAKE_MAKE_LOG"], "a") as f:
            f.write("make\\n")
        return object()
"""

_CHILD = """
import json, os
from remoteRF_server.server import device_manager as dm
log = os.environ["FAKE_MAKE_LOG"]
out = {"after_import": os.path.exists(log), "listed": dm.describe_devices([7])}
dm.reload_devices()
out["makes"] = open(log).read().count("make")
out["after_reload"] = dm.describe_devices([7])
print(json.dumps(out))
"""


class ImportTests(unittest.TestCase):
    def test_import_reads_records_but_opens_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp, "config", "remoterf")
            (cfg / "drivers").mkdir(parents=True)
            (cfg / "drivers" / "fake_init_schema.py").write_text(_FAKE_DRIVER)
            (cfg / "devices.yml").write_text(textwrap.dedent("""\
                devices:
                  - device_id: 7
                    device_type: fake_init
                    name: gps
                    init: {port: /dev/ttyACM0}
                """))
            env = dict(os.environ, XDG_CONFIG_HOME=str(cfg.parent), XDG_DATA_HOME=str(Path(tmp, "data")),
                       REMOTERF_CONFIG_DIR=str(cfg), FAKE_MAKE_LOG=str(Path(tmp, "makes.log")))
            proc = subprocess.run([sys.executable, "-c", _CHILD], env=env, capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = json.loads(proc.stdout.strip().splitlines()[-1])

        self.assertFalse(out["after_import"])
        self.assertEqual(out["listed"], [{"id": 7, "name": "gps", "type": "fake_init", "online": False, "handle": "gps"}])
        self.assertEqual(out["makes"], 1)
        self.assertTrue(out["after_reload"][0]["online"])


if __name__ == "__main__":
    unittest.main()
