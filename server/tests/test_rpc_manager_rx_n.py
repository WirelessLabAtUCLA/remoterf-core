import sys
import types
import unittest
from unittest.mock import patch

import numpy as np

sys.modules.setdefault("adi", types.ModuleType("adi"))

from remoteRF_server.common.utils.process_arg import map_arg, unmap_arg
from remoteRF_server.server import rpc_manager as rpc_module
from remoteRF_server.server.device_manager import VirtualDevice
from remoteRF_server.server.rpc_manager import RpcManager


class FakeRadio:
    device_type = "fake"

    def __init__(self, n=4, channels=1, fail_at=None, calls=("call_rx",)):
        self.n, self.channels, self.fail_at, self.calls = n, channels, fail_at, calls
        self.count = 0

    def list_exposed(self):
        return {"calls": list(self.calls)}

    def dispatch(self, name, args):
        if name != "call_rx":
            raise KeyError(f"'{name}' is not exposed on fake")
        if self.count == self.fail_at:
            raise RuntimeError("overflow")
        self.count += 1
        buffer = np.full(self.n, self.count, dtype=np.complex128) * (1 + 1j)
        return [buffer, -buffer] if self.channels == 2 else buffer


def rx_n(dev, k, gid=1, **extra):
    args = {"a": map_arg("token"), "arg1": map_arg(k), **{key: map_arg(v) for key, v in extra.items()}}
    return RpcManager()._dispatch_acquired(function_name="Fake:rx_n:CALL1", args=args, gid=gid, dev=dev)


class RxNTests(unittest.TestCase):
    def test_buffers_come_back_stacked_in_capture_order(self):
        out = unmap_arg(rx_n(FakeRadio(), 3)["rx_n"])
        self.assertEqual(out.shape, (3, 4))
        np.testing.assert_array_equal(out[:, 0], np.array([1, 2, 3]) * (1 + 1j))
        two = unmap_arg(rx_n(FakeRadio(channels=2), 2)["rx_n"])
        self.assertEqual(two.shape, (2, 2, 4))
        np.testing.assert_array_equal(two[1, 1], -np.full(4, 2 + 2j))

    def test_the_wire_flag_applies_to_the_stack(self):
        arg = rx_n(FakeRadio(), 2, wire="i16")["rx_n"]
        self.assertEqual(arg.ndarray_value.dtype, "ci16")
        self.assertEqual(list(arg.ndarray_value.shape), [2, 4])
        self.assertEqual(rx_n(FakeRadio(), 2, wire="c64")["rx_n"].ndarray_value.dtype, "<c8")

    def test_k_is_clamped_to_64_buffers_and_to_a_million_samples(self):
        self.assertEqual(unmap_arg(rx_n(FakeRadio(n=1), 500)["rx_n"]).shape, (64, 1))
        self.assertEqual(unmap_arg(rx_n(FakeRadio(n=1 << 18), 10)["rx_n"]).shape, (4, 1 << 18))
        self.assertEqual(unmap_arg(rx_n(FakeRadio(), 0)["rx_n"]).shape, (1, 4))

    def test_a_later_failure_returns_what_was_captured_a_first_one_raises(self):
        self.assertEqual(unmap_arg(rx_n(FakeRadio(fail_at=2), 5)["rx_n"]).shape, (2, 4))
        with self.assertRaisesRegex(RuntimeError, "overflow"):
            rx_n(FakeRadio(fail_at=0), 5)

    def test_a_device_without_rx_fails_exactly_as_before(self):
        with self.assertRaisesRegex(KeyError, "call_rx_n"):
            rx_n(FakeRadio(calls=("call_tx",)), 3)

    def test_host_devices_expand_into_plain_rx_calls(self):
        sent = []

        def host(registry, *, host_id, device_id, function_name, args, timeout_sec):
            sent.append((function_name, sorted(args)))
            if len(sent) == 3:
                return {"rx": map_arg("None"), "Error": map_arg("host overflow")}
            return {"rx": map_arg(np.full(4, len(sent), dtype=np.complex64))}

        dev = VirtualDevice(gid=5, host_id="host-1", device_id="d1", kind="fake")
        with patch.object(rpc_module.hts, "handle_host_device", host), \
                patch.object(rpc_module.hts, "get_tunnel_registry", lambda create=False: None):
            out = unmap_arg(rx_n(dev, 4, gid=5, wire="c64")["rx_n"])
            self.assertEqual(out.shape, (2, 4))
            self.assertEqual(sent[0], ("Fake:rx:CALL0", ["g", "wire"]))
            sent.clear()
            sent.append(None)
            sent.append(None)  # the next host rx answers with an Error first
            first_error = rx_n(dev, 4, gid=5)
        self.assertEqual(unmap_arg(first_error["a"]), "host overflow")


if __name__ == "__main__":
    unittest.main()
