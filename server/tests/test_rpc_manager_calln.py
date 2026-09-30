# Copyright (C) 2026 RemoteRF
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

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

    def test_rx_wire_flag_picks_the_sample_encoding(self):
        import numpy as np

        integer_iq = np.array([2047 - 2048j, 3 + 4j], dtype=np.complex128)
        fractional = np.array([0.5 + 0.25j, 1 + 1j], dtype=np.complex128)

        def rx(result, wire=None):
            args = {"a": map_arg("token")}
            if wire is not None:
                args["wire"] = map_arg(wire)
            out = RpcManager()._dispatch_local_schema(
                function_name="Fake:rx:CALL0", args=args, dev=FakeDevice(result)
            )
            return out["rx"]

        # No flag: exactly as before.
        arg = rx(integer_iq)
        self.assertEqual(arg.ndarray_value.dtype, "<c16")
        # c64 halves; i16 quarters integer IQ and sends anything else unchanged (lossless or nothing).
        self.assertEqual(rx(integer_iq, "c64").ndarray_value.dtype, "<c8")
        arg = rx(integer_iq, "i16")
        self.assertEqual(arg.ndarray_value.dtype, "ci16")
        np.testing.assert_array_equal(unmap_arg(arg), integer_iq.astype(np.complex64))
        self.assertEqual(rx(fractional, "i16").ndarray_value.dtype, "<c16")
        np.testing.assert_array_equal(unmap_arg(rx(fractional, "i16")), fractional)
        # Multi-channel rx returns a list of per-channel arrays: stacked to 2-D, shape kept.
        two_ch = [integer_iq, integer_iq * 2]
        arg = rx(two_ch, "i16")
        self.assertEqual(arg.ndarray_value.dtype, "ci16")
        np.testing.assert_array_equal(unmap_arg(arg), np.asarray(two_ch).astype(np.complex64))
        self.assertEqual(rx([fractional, fractional], "i16").ndarray_value.dtype, "<c16")
        self.assertEqual(rx(two_ch, "c64").ndarray_value.dtype, "<c8")
        self.assertEqual(list(rx(two_ch, "c64").ndarray_value.shape), [2, 2])
        # Unknown flags and non-complex results are left alone; CALLN never sees the flag.
        self.assertEqual(rx(integer_iq, "bogus").ndarray_value.dtype, "<c16")
        self.assertEqual(rx(np.array([1, 2], dtype=np.int16), "i16").ndarray_value.dtype, "<i2")
        dev = FakeDevice()
        RpcManager()._dispatch_local_schema(
            function_name="Fake:configure:CALLN",
            args={"a": map_arg("t"), "wire": map_arg("i16"), "freq": map_arg(1.0)}, dev=dev,
        )
        self.assertEqual(dev.seen, ("call_configure", {"freq": 1.0}))

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
