from __future__ import annotations

import unittest

import numpy as np

from remoteRF_host.common.grpc import grpc_pb2
from remoteRF_host.common.utils.process_arg import map_arg, unmap_arg


class ProcessArgTests(unittest.TestCase):
    def test_existing_primitive_values_still_round_trip(self) -> None:
        values = [True, 7, 2.5, "hello"]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(unmap_arg(map_arg(value)), value)

    def test_ndarray_and_list_array_compatibility(self) -> None:
        real = np.array([[1.0, 2.0], [3.0, 4.0]], dtype=np.float32)
        complex_arr = np.array([1 + 2j, 3 + 4j], dtype=np.complex64)

        np.testing.assert_allclose(unmap_arg(map_arg(real)), real)
        np.testing.assert_allclose(unmap_arg(map_arg(complex_arr)), complex_arr)
        np.testing.assert_allclose(unmap_arg(map_arg([1, 2, 3])), np.array([1, 2, 3]))

    def test_numeric_arrays_use_compact_binary_encoding_and_preserve_metadata(self) -> None:
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

    def test_noncontiguous_array_is_encoded_in_c_order(self) -> None:
        original = np.arange(24, dtype=np.float32).reshape(4, 6)[:, ::2]
        self.assertFalse(original.flags.c_contiguous)

        encoded = map_arg(original)

        self.assertEqual(
            encoded.ndarray_value.data,
            np.ascontiguousarray(original).tobytes(order="C"),
        )
        np.testing.assert_array_equal(unmap_arg(encoded), original)

    def test_iq_wire_size_is_close_to_the_raw_buffer_size(self) -> None:
        samples = np.zeros((2, 100_000), dtype=np.complex64)

        wire_size = len(map_arg(samples).SerializeToString())

        self.assertLess(wire_size, samples.nbytes + 128)

    def test_old_repeated_float_array_messages_still_decode(self) -> None:
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

    def test_malformed_binary_arrays_are_rejected(self) -> None:
        malformed = [
            grpc_pb2.Argument(
                ndarray_value=grpc_pb2.NDArrayValue(
                    dtype="not-a-dtype", shape=[1], data=b"\0"
                )
            ),
            grpc_pb2.Argument(
                ndarray_value=grpc_pb2.NDArrayValue(
                    dtype="|O8", shape=[1], data=b"\0" * 8
                )
            ),
            grpc_pb2.Argument(
                ndarray_value=grpc_pb2.NDArrayValue(
                    dtype="<f4", shape=[-1], data=b""
                )
            ),
            grpc_pb2.Argument(
                ndarray_value=grpc_pb2.NDArrayValue(
                    dtype="|u1", shape=[1] * 9, data=b"\0"
                )
            ),
            grpc_pb2.Argument(
                ndarray_value=grpc_pb2.NDArrayValue(
                    dtype="|u1", shape=[64 * 1024 * 1024 + 1], data=b""
                )
            ),
            grpc_pb2.Argument(
                ndarray_value=grpc_pb2.NDArrayValue(
                    dtype="<f4", shape=[2], data=b"\0" * 4
                )
            ),
        ]

        for encoded in malformed:
            with self.subTest(value=encoded.ndarray_value), self.assertRaises(ValueError):
                unmap_arg(encoded)

    def test_dict_and_explicit_none_use_json_value(self) -> None:
        payload = {
            "mode": "burst",
            "count": 3,
            "nested": {"enabled": True, "value": None},
        }

        mapped = map_arg(payload)
        self.assertTrue(mapped.HasField("json_value"))
        self.assertEqual(unmap_arg(mapped), payload)

        none_arg = map_arg(None)
        self.assertTrue(none_arg.HasField("json_value"))
        self.assertIsNone(unmap_arg(none_arg))

    def test_nested_arrays_and_mixed_tuples_use_json_value(self) -> None:
        samples = np.array([[1 + 1j, 2 + 2j], [3 + 3j, 4 + 4j]], dtype=np.complex64)
        payload = {"samples": samples, "meta": {"error_code": "none"}}

        unmapped = unmap_arg(map_arg(payload))
        self.assertEqual(unmapped["meta"], {"error_code": "none"})
        np.testing.assert_allclose(unmapped["samples"], samples)

        mixed = (4, samples, {"error_code": "none"})
        mixed_arg = map_arg(mixed)
        self.assertTrue(mixed_arg.HasField("json_value"))
        mixed_unmapped = unmap_arg(mixed_arg)
        self.assertEqual(mixed_unmapped[0], 4)
        np.testing.assert_allclose(mixed_unmapped[1], samples)
        self.assertEqual(mixed_unmapped[2], {"error_code": "none"})


if __name__ == "__main__":
    unittest.main()
