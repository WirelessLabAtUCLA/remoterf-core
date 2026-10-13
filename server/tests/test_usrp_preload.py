import os
import subprocess
import threading
import types
import unittest
from unittest.mock import patch

from remoteRF_server.drivers.usrp import usrp_schema


class UsrpPreloadTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.child_rc = 0
        self.release = threading.Event()
        self.release.set()

        def multi_usrp(args):
            self.events.append(("open", args))
            return types.SimpleNamespace(args=args)

        def run(cmd, **kwargs):
            self.events.append(("child", cmd[-1]))
            self.release.wait(5)
            self.events.append(("child_done", cmd[-1]))
            return subprocess.CompletedProcess(cmd, self.child_rc)

        usrp_schema._preloaded.clear()
        usrp_schema._preload_locks.clear()
        for p in (
            patch.object(usrp_schema, "uhd", types.SimpleNamespace(usrp=types.SimpleNamespace(MultiUSRP=multi_usrp))),
            patch.object(usrp_schema.subprocess, "run", run),
            patch.dict(os.environ, {"REMOTERF_USRP_PRELOAD": "1"}),
        ):
            p.start()
            self.addCleanup(p.stop)

    def schema(self):
        schema = usrp_schema.UsrpSchema()
        schema.bind_inventory({"serial": "31A2B3C"})
        return schema

    def test_the_first_open_loads_the_image_in_a_child_once(self):
        args = "type=b200,serial=31A2B3C,num_recv_frames=256"
        usrp_schema._connect_usrp(serial="31A2B3C")
        usrp_schema._connect_usrp(serial="31A2B3C")
        self.assertEqual(
            self.events,
            [("child", args), ("child_done", args), ("open", args), ("open", args)],
        )

    def test_an_open_waits_for_a_reservation_start_preload(self):
        self.release.clear()
        schema = self.schema()
        preload = threading.Thread(target=schema.prepare_for_holder)
        preload.start()
        while not self.events:
            threading.Event().wait(0.01)
        opener = threading.Thread(target=schema.open_native_device)
        opener.start()
        opener.join(0.2)
        self.assertTrue(opener.is_alive())  # still waiting for the child
        self.release.set()
        preload.join(5)
        opener.join(5)
        self.assertEqual([kind for kind, _ in self.events], ["child", "child_done", "open"])

    def test_a_failed_child_still_opens_in_process_then_counts_as_warm(self):
        self.child_rc = 1
        schema = self.schema()
        schema.open_native_device()
        schema.prepare_for_holder()
        schema.open_native_device()
        self.assertEqual([kind for kind, _ in self.events], ["child", "child_done", "open", "open"])

    def test_it_can_be_turned_off(self):
        with patch.dict(os.environ, {"REMOTERF_USRP_PRELOAD": "0"}):
            self.schema().prepare_for_holder()
            self.schema().open_native_device()
        self.assertEqual([kind for kind, _ in self.events], ["open"])


if __name__ == "__main__":
    unittest.main()
