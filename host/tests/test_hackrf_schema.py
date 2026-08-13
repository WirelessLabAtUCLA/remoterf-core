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

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from remoteRF_host.drivers.hackrf.hackrf_schema import (
    HackRFSchema,
    _MAX_COMPLEX64_SAMPLES,
    _correct_pyhackrf2_iq,
    connect_hackrf,
)


class FakeHackRF:
    def __init__(self):
        self.center_freq = 100_000_000
        self.sample_rate = 20_000_000
        self.filter_bandwidth = 15_000_000
        self._lna_gain = 16
        self.vga_gain = 16
        self.txvga_gain = 10
        self._amplifier_on = False
        self.bias_tee_on = False
        self.sample_count_limit = 0
        self.buffer = bytearray()
        self.tx_started = False
        self.tx_stop_count = 0

    @property
    def lna_gain(self):
        raise RecursionError("mirrors the broken pyhackrf2 1.0.3 getter")

    @lna_gain.setter
    def lna_gain(self, value):
        value = min(max(int(value), 0), 40)
        self._lna_gain = value - (value % 8)

    @property
    def amplifier_on(self):
        return self._amplifier_on

    @amplifier_on.setter
    def amplifier_on(self, _value):
        # pyhackrf2 1.0.3 sends the hardware command but forgets to track it.
        pass

    def read_samples(self, count):
        return np.arange(count, dtype=np.float32).astype(np.complex64) + 1j

    def get_serial_no(self):
        return "SERIAL0"

    def start_tx(self):
        self.tx_started = True

    def stop_tx(self):
        self.tx_started = False
        self.tx_stop_count += 1


def _bound_schema():
    native = FakeHackRF()
    schema = HackRFSchema()
    schema.bind(native)
    return schema, native


class HackRFSchemaTests(unittest.TestCase):
    def test_corrects_pyhackrf2_103_iq_dc_offset_only_for_affected_version(self):
        shifted = np.array([-1.5 - 0.5j, -0.75 - 1.25j], dtype=np.complex64)
        with patch(
            "remoteRF_host.drivers.hackrf.hackrf_schema.version",
            return_value="1.0.3",
        ):
            corrected = _correct_pyhackrf2_iq(shifted)
        np.testing.assert_allclose(corrected, shifted + np.complex64(1 + 1j))

        with patch(
            "remoteRF_host.drivers.hackrf.hackrf_schema.version",
            return_value="1.0.4",
        ):
            unchanged = _correct_pyhackrf2_iq(shifted)
        np.testing.assert_array_equal(unchanged, shifted)

    def test_idl_publishes_six_new_control_pairs(self):
        idl = HackRFSchema().get_idl()

        self.assertEqual(idl["schema_version"], "1.0")
        self.assertEqual(idl["device_type"], "hackrf")
        self.assertEqual(idl["client_class"], "HackRF")
        for name in (
            "center_freq",
            "sample_rate",
            "filter_bandwidth",
            "lna_gain",
            "vga_gain",
            "txvga_gain",
            "amplifier_on",
            "bias_tee_on",
            "sample_count_limit",
        ):
            self.assertIn(f"get_{name}", idl["getters"])
            self.assertIn(f"set_{name}", idl["setters"])
        for name in (
            "call_read_samples",
            "call_load_tx_iq",
            "call_start_tx",
            "call_stop_tx",
            "call_clear_buffer",
            "call_enumerate",
            "call_get_serial_no",
        ):
            self.assertIn(name, idl["calls"])
        self.assertNotIn("call_get_capabilities", idl["calls"])
        self.assertEqual(
            idl["calls"]["call_read_samples"]["args"][0]["name"],
            "num_samples",
        )

    def test_dispatch_controls_and_pyhackrf_tracking_workarounds(self):
        schema, native = _bound_schema()

        schema.dispatch("set_center_freq", {"value": "433200000"})
        schema.dispatch("set_sample_rate", {"value": 10_000_000})
        schema.dispatch("set_filter_bandwidth", {"value": 7_300_000})
        schema.dispatch("set_lna_gain", {"value": 23})
        schema.dispatch("set_vga_gain", {"value": 24})
        schema.dispatch("set_txvga_gain", {"value": 40})
        schema.dispatch("set_amplifier_on", {"value": "on"})
        schema.dispatch("set_bias_tee_on", {"value": True})
        schema.dispatch("set_sample_count_limit", {"value": 65_536})

        self.assertEqual(schema.dispatch("get_center_freq", {}), 433_200_000)
        self.assertEqual(schema.dispatch("get_sample_rate", {}), 10_000_000)
        self.assertEqual(schema.dispatch("get_filter_bandwidth", {}), 7_000_000)
        self.assertEqual(schema.dispatch("get_lna_gain", {}), 16)
        self.assertEqual(schema.dispatch("get_vga_gain", {}), 24)
        self.assertEqual(schema.dispatch("get_txvga_gain", {}), 40)
        self.assertTrue(schema.dispatch("get_amplifier_on", {}))
        self.assertTrue(schema.dispatch("get_bias_tee_on", {}))
        self.assertEqual(schema.dispatch("get_sample_count_limit", {}), 65_536)
        self.assertTrue(native._amplifier_on)

    def test_iq_calls_are_wire_safe_and_bounded(self):
        schema, native = _bound_schema()

        samples = schema.dispatch("call_read_samples", {"num_samples": 16})
        self.assertEqual(samples.dtype, np.dtype(np.complex64))
        self.assertEqual(samples.shape, (16,))
        self.assertTrue(samples.flags.c_contiguous)

        written = schema.dispatch(
            "call_load_tx_iq",
            {
                "samples": np.array(
                    [1 + 0j, 0 + 1j, -1 - 1j],
                    dtype=np.complex64,
                )
            },
        )
        self.assertEqual(written, 6)
        self.assertEqual(native.buffer, bytearray([127, 0, 0, 127, 129, 129]))

        self.assertEqual(schema.dispatch("call_start_tx", {}), 6)
        self.assertTrue(native.tx_started)
        self.assertIsNone(schema.dispatch("call_stop_tx", {}))
        self.assertFalse(native.tx_started)
        self.assertEqual(native.tx_stop_count, 1)
        self.assertEqual(schema.dispatch("call_clear_buffer", {}), 0)
        self.assertEqual(native.buffer, bytearray())

        for value in (0, -1, _MAX_COMPLEX64_SAMPLES + 1):
            with self.subTest(samples=value), self.assertRaises(ValueError):
                schema.dispatch("call_read_samples", {"num_samples": value})
        with self.assertRaises(ValueError):
            schema.dispatch("call_load_tx_iq", {"samples": np.array([], dtype=np.complex64)})
        with self.assertRaises(RuntimeError):
            schema.dispatch("call_start_tx", {})
        with self.assertRaises(ValueError):
            schema.dispatch("set_sample_count_limit", {"value": -1})
        with self.assertRaises(ValueError):
            schema.dispatch("set_amplifier_on", {"value": "sometimes"})

    def test_enumeration_identity_and_serial_connector(self):
        schema, _native = _bound_schema()

        class ConstructorFake(FakeHackRF):
            opened_with = None

            @staticmethod
            def enumerate():
                return ["SERIAL0", "SERIAL1"]

            def __init__(self, device_index=0):
                super().__init__()
                type(self).opened_with = device_index

        with patch(
            "remoteRF_host.drivers.hackrf.hackrf_schema._require_hackrf",
            return_value=ConstructorFake,
        ):
            connected = connect_hackrf(serial="SERIAL1")
            serials = json.loads(schema.dispatch("call_enumerate", {}))

        self.assertIsInstance(connected, ConstructorFake)
        self.assertEqual(ConstructorFake.opened_with, 1)
        self.assertEqual(serials, ["SERIAL0", "SERIAL1"])
        self.assertEqual(schema.dispatch("call_get_serial_no", {}), "SERIAL0")

        with patch(
            "remoteRF_host.drivers.hackrf.hackrf_schema._require_hackrf",
            return_value=ConstructorFake,
        ):
            with self.assertRaisesRegex(RuntimeError, "MISSING"):
                connect_hackrf(serial="MISSING")
            with self.assertRaisesRegex(ValueError, "either serial or device_index"):
                connect_hackrf(serial="SERIAL0", device_index=0)


class DefaultHackRFSchemaTests(unittest.TestCase):
    def test_configured_host_seeds_schema_without_native_pyhackrf(self):
        project_root = Path(__file__).resolve().parents[1]
        source_root = project_root / "src"
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            blocker = temp / "blocker"
            blocker.mkdir()
            (blocker / "pyhackrf2.py").write_text(
                "raise ImportError('HackRF deliberately unavailable in test')\n",
                encoding="utf-8",
            )
            config_root = temp / "host"
            drivers_root = temp / "drivers"
            env = dict(os.environ)
            env["HOME"] = str(temp / "home")
            env["REMOTERF_CONFIG_DIR"] = str(config_root)
            env["REMOTERF_DRIVERS_DIR"] = str(drivers_root)
            env["PYTHONPATH"] = os.pathsep.join((str(blocker), str(source_root)))

            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    textwrap.dedent(
                        """
                        import json
                        import os
                        from pathlib import Path

                        config_root = Path(os.environ["REMOTERF_CONFIG_DIR"])
                        config_root.mkdir(parents=True, exist_ok=True)
                        (config_root / "devices.yml").write_text(json.dumps({
                            "devices": [{
                                "device_id": 11,
                                "device_type": "hackrf",
                                "name": "hackrf-test",
                                "init": {"device_index": 0},
                            }]
                        }), encoding="utf-8")

                        from remoteRF_host.common.idl.schema import get_driver_class
                        from remoteRF_host.common.utils import get_drivers_dir
                        from remoteRF_host.server import device_manager

                        seeded = get_drivers_dir() / "hackrf_schema.py"
                        assert seeded.is_file(), seeded
                        marker = get_drivers_dir() / ".hackrf_schema.py.remoterf-managed"
                        assert marker.is_file(), marker

                        schema = get_driver_class("hackrf")()
                        idl = schema.get_idl()
                        assert idl["client_class"] == "HackRF"
                        assert "get_lna_gain" in idl["getters"]
                        assert "set_bias_tee_on" in idl["setters"]

                        try:
                            schema.make_device(device_index=0)
                        except RuntimeError as exc:
                            assert "pyhackrf2" in str(exc).lower()
                        else:
                            raise AssertionError("native open should require pyhackrf2")

                        print("DEFAULT_HACKRF_SCHEMA_OK")
                        """
                    ),
                ],
                cwd=project_root,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn("DEFAULT_HACKRF_SCHEMA_OK", result.stdout)
        self.assertNotIn("Driver load hackrf_schema.py: error", result.stdout)


if __name__ == "__main__":
    unittest.main()
