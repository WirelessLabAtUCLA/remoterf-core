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
from concurrent import futures

import grpc
import numpy as np

from remoteRF_server.common.grpc import grpc_host_pb2, grpc_pb2, grpc_pb2_grpc
from remoteRF_server.common.utils.process_arg import map_arg, unmap_arg


class ProcessArgTests(unittest.TestCase):
    def test_json_values_round_trip_dict_and_none(self):
        value = {"nested": {"x": 1}, "flag": True, "nothing": None}

        self.assertEqual(unmap_arg(map_arg(value)), value)
        self.assertIsNone(unmap_arg(map_arg(None)))

    def test_existing_scalar_values_still_round_trip(self):
        self.assertIs(unmap_arg(map_arg(True)), True)
        self.assertEqual(unmap_arg(map_arg(12)), 12)
        self.assertAlmostEqual(unmap_arg(map_arg(1.5)), 1.5)
        self.assertEqual(unmap_arg(map_arg("abc")), "abc")

    def test_arrays_and_list_values_still_round_trip_as_arrays(self):
        real = np.array([[1.0, 2.0], [3.0, 4.0]], dtype=np.float32)
        complex_value = np.array([1 + 2j, 3 + 4j], dtype=np.complex64)

        np.testing.assert_allclose(unmap_arg(map_arg(real)), real)
        np.testing.assert_allclose(unmap_arg(map_arg([1, 2, 3])), np.array([1, 2, 3]))
        np.testing.assert_allclose(unmap_arg(map_arg(complex_value)), complex_value)

    def test_numeric_arrays_use_compact_binary_encoding_and_preserve_metadata(self):
        values = [
            np.array(True, dtype=np.bool_),
            np.array([[-2, 3], [4, 5]], dtype=np.int16),
            np.array([1, 2**40], dtype=np.uint64),
            np.array([[1.25, -2.5]], dtype=np.float32),
            np.array([1.25, -2.5], dtype=np.float64),
            np.array([1 + 2j, -3 + 4j], dtype=np.complex64),
            np.array([[1 + 2j]], dtype=np.complex128),
            np.array([1.0, 2.0], dtype=">f4"),
            np.empty((0, 3), dtype=np.complex64),
        ]

        for original in values:
            with self.subTest(dtype=original.dtype, shape=original.shape):
                encoded = map_arg(original)
                self.assertEqual(encoded.WhichOneof("value"), "ndarray_value")
                self.assertEqual(encoded.ndarray_value.dtype, original.dtype.str)
                self.assertEqual(tuple(encoded.ndarray_value.shape), original.shape)
                self.assertEqual(
                    encoded.ndarray_value.data,
                    original.tobytes(order="C"),
                )

                decoded = unmap_arg(encoded)
                self.assertEqual(decoded.dtype, original.dtype)
                self.assertEqual(decoded.shape, original.shape)
                self.assertTrue(decoded.flags.owndata)
                np.testing.assert_array_equal(decoded, original)

    def test_iq16_wire_encoding_round_trips_integer_iq(self):
        from remoteRF_server.common.utils.process_arg import IQ16, fits_iq16, map_iq16

        samples = np.array([2047 - 2048j, -1 + 1j, 0j, 32767 + 0j], dtype=np.complex128)
        arg = map_iq16(samples)
        self.assertEqual(arg.ndarray_value.dtype, IQ16)
        self.assertEqual(list(arg.ndarray_value.shape), [4])
        self.assertEqual(len(arg.ndarray_value.data), 4 * 4)  # a quarter of complex128
        decoded = unmap_arg(arg)
        self.assertEqual(decoded.dtype, np.complex64)
        np.testing.assert_array_equal(decoded, samples.astype(np.complex64))
        # Not integer IQ, or out of int16 range: refused, so nothing is quantised silently.
        for bad in (np.array([0.5 + 0j]), np.array([40000 + 0j]), np.array([1.0, 2.0]), "x"):
            self.assertFalse(fits_iq16(np.asarray(bad) if not isinstance(bad, str) else bad))
        with self.assertRaises(ValueError):
            map_iq16(np.array([0.5 + 0j]))
        # A short payload is rejected exactly like any other ndarray.
        arg.ndarray_value.data = arg.ndarray_value.data[:-1]
        with self.assertRaises(ValueError):
            unmap_arg(arg)

    def test_noncontiguous_array_is_encoded_in_c_order(self):
        original = np.arange(24, dtype=np.float32).reshape(4, 6)[:, ::2]
        self.assertFalse(original.flags.c_contiguous)

        encoded = map_arg(original)

        self.assertEqual(
            encoded.ndarray_value.data,
            np.ascontiguousarray(original).tobytes(order="C"),
        )
        np.testing.assert_array_equal(unmap_arg(encoded), original)

    def test_iq_wire_size_is_close_to_the_raw_buffer_size(self):
        samples = np.zeros((2, 100_000), dtype=np.complex64)

        wire_size = len(map_arg(samples).SerializeToString())

        self.assertLess(wire_size, samples.nbytes + 128)

    def test_old_repeated_float_array_messages_still_decode(self):
        real = grpc_pb2.Argument()
        real.real_array.shape.dim.extend([2, 2])
        real.real_array.data.extend([1.0, 2.0, 3.0, 4.0])
        np.testing.assert_array_equal(
            unmap_arg(real),
            np.array([[1.0, 2.0], [3.0, 4.0]], dtype=np.float64),
        )

        complex_value = grpc_pb2.Argument()
        complex_value.complex_array.shape.dim.extend([2])
        for real_part, imaginary_part in ((1.0, 2.0), (3.0, 4.0)):
            item = complex_value.complex_array.data.add()
            item.real = real_part
            item.imag = imaginary_part
        np.testing.assert_array_equal(
            unmap_arg(complex_value),
            np.array([1 + 2j, 3 + 4j], dtype=np.complex64),
        )

    def test_malformed_binary_arrays_are_rejected(self):
        malformed = {
            "invalid dtype": grpc_pb2.Argument(
                ndarray_value=grpc_pb2.NDArrayValue(
                    dtype="not-a-dtype", shape=[1], data=b"\0"
                )
            ),
            "object dtype": grpc_pb2.Argument(
                ndarray_value=grpc_pb2.NDArrayValue(
                    dtype="|O8", shape=[1], data=b"\0" * 8
                )
            ),
            "negative shape": grpc_pb2.Argument(
                ndarray_value=grpc_pb2.NDArrayValue(
                    dtype="<f4", shape=[-1], data=b""
                )
            ),
            "too many dimensions": grpc_pb2.Argument(
                ndarray_value=grpc_pb2.NDArrayValue(
                    dtype="|u1", shape=[1] * 9, data=b"\0"
                )
            ),
            "oversized shape": grpc_pb2.Argument(
                ndarray_value=grpc_pb2.NDArrayValue(
                    dtype="|u1", shape=[64 * 1024 * 1024 + 1], data=b""
                )
            ),
            "byte mismatch": grpc_pb2.Argument(
                ndarray_value=grpc_pb2.NDArrayValue(
                    dtype="<f4", shape=[2], data=b"\0" * 4
                )
            ),
        }

        for name, encoded in malformed.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                unmap_arg(encoded)

        oversized = np.lib.stride_tricks.as_strided(
            np.zeros(1, dtype=np.uint8),
            shape=(64 * 1024 * 1024 + 1,),
            strides=(0,),
        )
        with self.assertRaisesRegex(ValueError, "exceeds"):
            map_arg(oversized)
        with self.assertRaisesRegex(ValueError, "invalid ndarray shape"):
            map_arg(np.zeros((1,) * 9, dtype=np.uint8))

    def test_binary_array_survives_the_host_tunnel_envelope(self):
        original = np.arange(32, dtype=np.float32).view(np.complex64)
        response = grpc_pb2.GenericRPCResponse()
        response.results["samples"].CopyFrom(map_arg(original))
        frame = grpc_host_pb2.HostFrame()
        frame.rpc_response.req_id = "request-1"
        frame.rpc_response.ok = True
        frame.rpc_response.response.CopyFrom(response)

        restored_frame = grpc_host_pb2.HostFrame.FromString(
            frame.SerializeToString()
        )
        restored = unmap_arg(
            restored_frame.rpc_response.response.results["samples"]
        )

        self.assertEqual(restored.dtype, original.dtype)
        np.testing.assert_array_equal(restored, original)

    def test_binary_array_round_trips_over_generic_grpc(self):
        class EchoServicer(grpc_pb2_grpc.GenericRPCServicer):
            def Call(self, request, context):
                response = grpc_pb2.GenericRPCResponse()
                response.results["samples"].CopyFrom(request.args["samples"])
                return response

        options = (
            ("grpc.max_send_message_length", 100 * 1024 * 1024),
            ("grpc.max_receive_message_length", 100 * 1024 * 1024),
        )
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=1), options=options)
        grpc_pb2_grpc.add_GenericRPCServicer_to_server(EchoServicer(), server)
        port = server.add_insecure_port("127.0.0.1:0")
        server.start()
        channel = grpc.insecure_channel(f"127.0.0.1:{port}", options=options)
        try:
            samples = np.arange(400_000, dtype=np.float32).view(np.complex64)
            request = grpc_pb2.GenericRPCRequest(function_name="echo")
            request.args["samples"].CopyFrom(map_arg(samples))

            response = grpc_pb2_grpc.GenericRPCStub(channel).Call(
                request, timeout=5.0
            )
            restored = unmap_arg(response.results["samples"])
        finally:
            channel.close()
            server.stop(0).wait()

        self.assertEqual(restored.dtype, samples.dtype)
        np.testing.assert_array_equal(restored, samples)

    def test_json_values_can_contain_arrays_and_mixed_return_tuples(self):
        samples = np.array([[1 + 2j, 3 + 4j]], dtype=np.complex64)
        value = (2, samples, {"error_code": "none"})

        count, restored_samples, metadata = unmap_arg(map_arg(value))

        self.assertEqual(count, 2)
        np.testing.assert_allclose(restored_samples, samples)
        self.assertEqual(metadata, {"error_code": "none"})

        nested = unmap_arg(map_arg({"samples": samples}))
        np.testing.assert_allclose(nested["samples"], samples)

    def test_values_numpy_makes_object_arrays_of_go_as_json(self):
        scan = [{"address": "AA:BB", "rssi": -60}, {"address": "CC:DD", "rssi": -70}]
        for value in (scan, scan[:1], [None, 1.5], np.array(scan, dtype=object)):
            with self.subTest(value=value):
                mapped = map_arg(value)
                self.assertEqual(mapped.WhichOneof("value"), "json_value")
                self.assertEqual(unmap_arg(mapped), list(value))
        self.assertEqual(unmap_arg(map_arg({"devices": np.array(scan, dtype=object)})), {"devices": scan})
        # Numeric lists and tuples stay compact ndarrays.
        self.assertEqual(map_arg((34.07, -118.44)).WhichOneof("value"), "ndarray_value")


if __name__ == "__main__":
    unittest.main()
