from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from remoteRF_host import hostrf_cli
from remoteRF_host.drivers.rtl_sdr.rtl_sdr_schema import (
    RtlSdrSchema,
    _MAX_COMPLEX64_SAMPLES,
    _MAX_REMOTE_PAYLOAD_BYTES,
    _RtlSdrAdapter,
    _connect_rtl_sdr,
)


class FakeRtlSdr:
    def __init__(self):
        self.center_freq = 100_000_000.0
        self.sample_rate = 2_048_000.0
        self.gain = 12.5
        self.valid_gains_db = [0.0, 12.5, 49.6]
        self.freq_correction = 1
        self.bandwidth = 0.0
        self.agc_mode = False
        self.bias_tee = False
        self.direct_sampling = 0
        self.offset_tuning = False
        self.dithering = True
        self.closed = False
        self.reset_count = 0

    def get_tuner_type(self):
        return "R820T"

    def set_agc_mode(self, enabled):
        self.agc_mode = enabled

    def set_bias_tee(self, enabled):
        self.bias_tee = enabled

    def get_direct_sampling(self):
        return self.direct_sampling

    def set_direct_sampling(self, value):
        self.direct_sampling = value

    def get_offset_tuning(self):
        return self.offset_tuning

    def set_offset_tuning(self, enabled):
        self.offset_tuning = enabled

    def set_dithering(self, enabled):
        self.dithering = enabled

    def reset_buffer(self):
        self.reset_count += 1

    def read_samples(self, count):
        return np.arange(count, dtype=np.float32).astype(np.complex64) + 1j

    def read_bytes(self, count):
        return bytes(index % 256 for index in range(count))

    def close(self):
        self.closed = True


def _bound_schema():
    native = FakeRtlSdr()
    adapter = _RtlSdrAdapter(
        native,
        device_index=2,
        serial_number="00000002",
        usb_strings=("Realtek", "RTL2838UHIDIR", "00000002"),
        test_mode_enabled=False,
        dithering_enabled=True,
    )
    schema = RtlSdrSchema()
    schema.bind(adapter)
    return schema, adapter, native


class RtlSdrSchemaTests(unittest.TestCase):
    def test_idl_publishes_rtlsdr_compatible_controls_and_receive_calls(self):
        idl = RtlSdrSchema().get_idl()

        self.assertEqual(idl["schema_version"], "1.0")
        self.assertEqual(idl["device_type"], "rtl_sdr")
        self.assertEqual(idl["client_class"], "RtlSdr")
        for name in (
            "get_center_freq",
            "get_sample_rate",
            "get_gain",
            "get_valid_gains_db",
            "get_freq_correction",
            "get_bandwidth",
            "get_tuner_type",
            "get_agc_mode",
            "get_bias_tee",
            "get_direct_sampling",
            "get_offset_tuning",
            "get_dithering",
        ):
            self.assertIn(name, idl["getters"])
        for name in ("call_read_samples", "call_read_bytes", "call_reset_buffer"):
            self.assertIn(name, idl["calls"])
        self.assertNotIn("call_get_capabilities", idl["calls"])
        self.assertEqual(
            idl["calls"]["call_read_samples"]["args"][0]["default"],
            1024,
        )

    def test_dispatch_controls_and_returns_wire_safe_iq(self):
        schema, _adapter, native = _bound_schema()

        schema.dispatch("set_center_freq", {"value": 101_100_000})
        schema.dispatch("set_sample_rate", {"value": 1_024_000})
        schema.dispatch("set_gain", {"value": "auto"})
        schema.dispatch("set_freq_correction", {"value": -3})
        schema.dispatch("set_bandwidth", {"value": 200_000})
        schema.dispatch("set_agc_mode", {"value": True})
        schema.dispatch("set_bias_tee", {"value": False})
        schema.dispatch("set_direct_sampling", {"value": 2})
        schema.dispatch("set_offset_tuning", {"value": True})
        schema.dispatch("set_dithering", {"value": False})

        self.assertEqual(schema.dispatch("get_center_freq", {}), 101_100_000.0)
        self.assertEqual(schema.dispatch("get_sample_rate", {}), 1_024_000.0)
        self.assertEqual(native.gain, "auto")
        self.assertEqual(schema.dispatch("get_freq_correction", {}), -3)
        self.assertEqual(schema.dispatch("get_bandwidth", {}), 200_000.0)
        self.assertTrue(schema.dispatch("get_agc_mode", {}))
        self.assertFalse(schema.dispatch("get_bias_tee", {}))
        self.assertEqual(schema.dispatch("get_direct_sampling", {}), 2)
        self.assertTrue(schema.dispatch("get_offset_tuning", {}))
        self.assertFalse(schema.dispatch("get_dithering", {}))

        samples = schema.dispatch("call_read_samples", {"num_samples": 16})
        self.assertEqual(samples.dtype, np.dtype(np.complex64))
        self.assertEqual(samples.shape, (16,))
        self.assertTrue(samples.flags.c_contiguous)
        self.assertEqual(len(schema.dispatch("call_read_bytes", {"num_bytes": 17})), 17)
        schema.dispatch("call_reset_buffer", {})
        self.assertEqual(native.reset_count, 1)

    def test_capture_limits_prevent_unbounded_rpc_payloads(self):
        schema, _adapter, _native = _bound_schema()

        for value in (0, -1, _MAX_COMPLEX64_SAMPLES + 1):
            with self.subTest(samples=value), self.assertRaises(ValueError):
                schema.dispatch("call_read_samples", {"num_samples": value})
        with self.assertRaises(ValueError):
            schema.dispatch(
                "call_read_bytes",
                {"num_bytes": _MAX_REMOTE_PAYLOAD_BYTES + 1},
            )

    def test_connector_resolves_serial_before_opening_device(self):
        class ConstructorFake(FakeRtlSdr):
            opened_with = None

            @staticmethod
            def get_device_index_by_serial(serial):
                return 3 if serial == "SERIAL3" else -1

            @staticmethod
            def get_device_usb_strings(index):
                return ("Realtek", "RTL2838", f"SERIAL{index}")

            def __init__(self, **kwargs):
                super().__init__()
                type(self).opened_with = kwargs

        with patch(
            "remoteRF_host.drivers.rtl_sdr.rtl_sdr_schema._require_rtlsdr",
            return_value=ConstructorFake,
        ):
            adapter = _connect_rtl_sdr(serial="SERIAL3", dithering_enabled=False)

        self.assertEqual(adapter.device_index, 3)
        self.assertEqual(adapter.serial_number, "SERIAL3")
        self.assertEqual(
            ConstructorFake.opened_with,
            {
                "device_index": 3,
                "test_mode_enabled": False,
                "dithering_enabled": False,
            },
        )
        adapter.close()
        self.assertTrue(adapter.native is None)

    def test_connector_omits_dithering_for_older_pyrtlsdr_constructor(self):
        class OlderConstructorFake(FakeRtlSdr):
            opened_with = None

            @staticmethod
            def get_device_index_by_serial(serial):
                return 0

            def __init__(
                self,
                device_index=0,
                test_mode_enabled=False,
                serial_number=None,
            ):
                super().__init__()
                type(self).opened_with = {
                    "device_index": device_index,
                    "test_mode_enabled": test_mode_enabled,
                    "serial_number": serial_number,
                }

        with patch(
            "remoteRF_host.drivers.rtl_sdr.rtl_sdr_schema._require_rtlsdr",
            return_value=OlderConstructorFake,
        ):
            adapter = _connect_rtl_sdr(device_index=0, dithering_enabled=False)

        self.assertEqual(
            OlderConstructorFake.opened_with,
            {
                "device_index": 0,
                "test_mode_enabled": False,
                "serial_number": None,
            },
        )

    def test_cli_writes_serial_and_index_inventory(self):
        cases = (
            (
                "4:rtl_fm:serial=00000001",
                "serial",
                "00000001",
                {"serial": "00000001"},
            ),
            (
                "4:rtl_fm:index=0",
                "device_index",
                "0",
                {"device_index": 0},
            ),
        )
        for spec, kind, _ident, init in cases:
            with self.subTest(spec=spec), tempfile.TemporaryDirectory() as tmp:
                with patch.dict(
                    os.environ,
                    {"REMOTERF_CONFIG_DIR": tmp},
                    clear=False,
                ):
                    self.assertEqual(hostrf_cli._device_add_rtl_sdr(spec), 0)
                    record = hostrf_cli._read_device_records()[4]
                    self.assertEqual(record["device_type"], "rtl_sdr")
                    self.assertIn(kind, record["init"])
                    self.assertEqual(record["init"], init)
                    text = Path(tmp, "devices.yml").read_text(encoding="utf-8")
                    self.assertIn('"device_type": "rtl_sdr"', text)

    def test_cli_flag_routes_to_rtl_sdr_inventory_handler(self):
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch.dict(
                    os.environ,
                    {"REMOTERF_CONFIG_DIR": tmp},
                    clear=False,
                ),
                patch.object(
                    sys,
                    "argv",
                    [
                        "hostrf",
                        "--device",
                        "--add",
                        "--rtl-sdr",
                        "4:rtl_fm:index=0",
                    ],
                ),
            ):
                self.assertEqual(hostrf_cli.main(), 0)
                self.assertEqual(
                    hostrf_cli._read_device_records()[4]["device_type"],
                    "rtl_sdr",
                )


if __name__ == "__main__":
    unittest.main()
