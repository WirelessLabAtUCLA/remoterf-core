import unittest
import sys
import types

sys.modules.setdefault("adi", types.ModuleType("adi"))

from remoteRF_server.common.utils.process_arg import map_arg, unmap_arg
from remoteRF_server.server.rpc_manager import RpcManager


class FakeDevice:
    def __init__(self, result=None):
        self.result = result
        self.seen = None

    def dispatch(self, method_name, args):
        self.seen = (method_name, args)
        return self.result if self.result is not None else {"method": method_name, "args": args}


class RpcManagerCallNTests(unittest.TestCase):
    def test_calln_unmaps_named_args_and_filters_transport_keys(self):
        dev = FakeDevice()
        result = RpcManager()._dispatch_local_schema(
            function_name="Fake:configure:CALLN",
            args={
                "a": map_arg("token"),
                "g": map_arg(123),
                "device_id": map_arg(123),
                "freq": map_arg(2.4e9),
                "options": map_arg({"mode": "fast"}),
            },
            dev=dev,
        )

        self.assertEqual(
            dev.seen,
            ("call_configure", {"freq": 2.4e9, "options": {"mode": "fast"}}),
        )
        self.assertEqual(
            unmap_arg(result["configure"]),
            {"method": "call_configure", "args": {"freq": 2.4e9, "options": {"mode": "fast"}}},
        )

    def test_existing_call0_and_call1_paths_still_work(self):
        dev = FakeDevice(result="ok")
        manager = RpcManager()

        self.assertEqual(
            unmap_arg(manager._dispatch_local_schema(
                function_name="Fake:ping:CALL0",
                args={"a": map_arg("token")},
                dev=dev,
            )["ping"]),
            "ok",
        )
        self.assertEqual(dev.seen, ("call_ping", {}))

        self.assertEqual(
            unmap_arg(manager._dispatch_local_schema(
                function_name="Fake:echo:CALL1",
                args={"a": map_arg("token"), "arg1": map_arg(42)},
                dev=dev,
            )["echo"]),
            "ok",
        )
        self.assertEqual(dev.seen, ("call_echo", {"value": 42}))


if __name__ == "__main__":
    unittest.main()
