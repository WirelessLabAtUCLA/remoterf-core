from __future__ import annotations

import unittest

import numpy as np

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
