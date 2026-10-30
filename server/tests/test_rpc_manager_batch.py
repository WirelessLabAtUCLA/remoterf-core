import sys
import threading
import time
import types
import unittest
from unittest.mock import patch

sys.modules.setdefault("adi", types.ModuleType("adi"))

from remoteRF_server.common.grpc import grpc_pb2
from remoteRF_server.common.utils.process_arg import map_arg, unmap_arg
from remoteRF_server.server import device_manager
from remoteRF_server.server import rpc_manager as rpc_module
from remoteRF_server.server.device_manager import VirtualDevice, _DeviceState
from remoteRF_server.server.rpc_manager import RpcManager


class FakeSchema:
    device_type = "fake"

    def __init__(self, on_dispatch=None):
        self.calls = []
        self.values = {}
        self.on_dispatch = on_dispatch

    def dispatch(self, name, args):
        self.calls.append(name)
        if self.on_dispatch is not None:
            self.on_dispatch(name)
        if name == "call_boom":
            raise RuntimeError("boom")
        if name.startswith("set_"):
            self.values[name[4:]] = args["value"]
            return None
        if name.startswith("get_"):
            return self.values.get(name[4:])
        return "done"


def op(function_name, **args):
    request = grpc_pb2.GenericRPCRequest(function_name=function_name)
    for key, value in args.items():
        request.args[key].CopyFrom(map_arg(value))
    return map_arg(request.SerializeToString())


def batch(manager, dev, *ops, gid=1, **extra):
    args = {"a": map_arg("token"), **{f"op{i}": item for i, item in enumerate(ops)}, **extra}
    return manager._dispatch_acquired(function_name="Fake:batch:CALLN", args=args, gid=gid, dev=dev)


class BatchTests(unittest.TestCase):
    def test_ops_run_in_order_and_return_the_last_results(self):
        dev = FakeSchema()
        out = batch(RpcManager(), dev, op("Fake:freq:SET", freq=915e6), op("Fake:gain:SET", gain=10), op("Fake:freq:GET"))
        self.assertEqual(dev.calls, ["set_freq", "set_gain", "get_freq"])
        self.assertEqual(unmap_arg(out["freq"]), 915e6)
        self.assertEqual(unmap_arg(out["batch_done"]), 3)
        self.assertNotIn("batch_failed", out)

    def test_the_first_failure_stops_the_batch(self):
        dev = FakeSchema()
        out = batch(RpcManager(), dev, op("Fake:freq:SET", freq=1.0), op("Fake:boom:CALL0"), op("Fake:gain:SET", gain=1))
        self.assertEqual(dev.calls, ["set_freq", "call_boom"])
        self.assertEqual((unmap_arg(out["batch_done"]), unmap_arg(out["batch_failed"])), (1, 1))
        self.assertEqual(unmap_arg(out["batch_error"]), "boom")

    def test_a_drivers_own_batch_and_rx_n_calls_are_not_intercepted(self):
        dev = FakeSchema()
        dev.list_exposed = lambda: {"calls": ["call_batch", "call_rx", "call_rx_n"]}
        manager = RpcManager()
        out = manager._dispatch_acquired(
            function_name="Fake:batch:CALLN", args={"a": map_arg("token"), "count": map_arg(3)}, gid=1, dev=dev
        )
        self.assertEqual(unmap_arg(out["batch"]), "done")
        out = manager._dispatch_acquired(
            function_name="Fake:rx_n:CALL1", args={"a": map_arg("token"), "arg1": map_arg(2)}, gid=1, dev=dev
        )
        self.assertEqual(unmap_arg(out["rx_n"]), "done")
        self.assertEqual(dev.calls, ["call_batch", "call_rx_n"])

    def test_every_op_is_checked_before_any_runs(self):
        good = op("Fake:freq:SET", freq=1.0)
        bad_ops = [
            [],
            [good] * 65,
            [good, op("Fake:batch:CALLN")],
            [good, op("Other:freq:SET", freq=1.0)],
            [good, op("Fake:freq:SET", freq=1.0, a="other-token")],
            [good, op("Fake:freq:SET", freq=1.0, device_id=7)],
            [good, op("Fake:freq:POKE")],
            [good, op("Fake:freq")],
            [good, map_arg(b"\xff\xff")],
            [good, map_arg("Fake:freq:GET")],
        ]
        for i, ops in enumerate(bad_ops):
            dev = FakeSchema()
            with self.subTest(case=i), self.assertRaises(ValueError):
                batch(RpcManager(), dev, *ops)
            self.assertEqual(dev.calls, [])
        dev = FakeSchema()
        with self.assertRaises(ValueError):  # a gap in op indices
            RpcManager()._dispatch_acquired(
                function_name="Fake:batch:CALLN", args={"op0": good, "op2": good}, gid=1, dev=dev
            )
        self.assertEqual(dev.calls, [])

    def test_host_devices_expand_per_op_and_stop_at_an_error(self):
        sent = []

        def host(registry, *, host_id, device_id, function_name, args, timeout_sec):
            sent.append((function_name, sorted(args)))
            if function_name == "Fake:gain:SET":
                return {"gain": map_arg("None"), "Error": map_arg("gain out of range")}
            return {}

        dev = VirtualDevice(gid=5, host_id="host-1", device_id="d1", kind="fake")
        with patch.object(rpc_module.hts, "handle_host_device", host), \
                patch.object(rpc_module.hts, "get_tunnel_registry", lambda create=False: None):
            out = batch(RpcManager(), dev, op("Fake:freq:SET", freq=1.0), op("Fake:gain:SET", gain=99),
                        op("Fake:bw:SET", bw=1.0), gid=5)
        self.assertEqual(sent, [("Fake:freq:SET", ["freq", "g"]), ("Fake:gain:SET", ["g", "gain"])])
        self.assertEqual(unmap_arg(out["batch_failed"]), 1)
        self.assertEqual(unmap_arg(out["batch_error"]), "gain out of range")

    def test_the_io_lock_is_held_across_the_whole_batch(self):
        gid = 880_000
        order = []
        single = threading.Thread(
            target=lambda: manager.run_device_rpc_for_gid(gid=gid, function_name="Fake:freq:GET", args={})
        )

        def on_dispatch(name):
            order.append(name)
            if len(order) == 1:
                single.start()
                time.sleep(0.2)

        manager, dev = RpcManager(), FakeSchema(on_dispatch)
        state = _DeviceState(dev=dev, origin="local", online=True, salt="", hsh="", name="b", ident="", dtype="fake")
        with device_manager._state_lock:
            device_manager._devices[gid] = state
        try:
            manager.run_device_rpc_for_gid(
                gid=gid, function_name="Fake:batch:CALLN",
                args={"op0": op("Fake:freq:SET", freq=1.0), "op1": op("Fake:gain:SET", gain=2)},
            )
            single.join(5)
        finally:
            with device_manager._state_lock:
                device_manager._devices.pop(gid, None)
        self.assertEqual(order, ["set_freq", "set_gain", "get_freq"])


if __name__ == "__main__":
    unittest.main()
