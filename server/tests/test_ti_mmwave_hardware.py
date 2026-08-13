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

"""Opt-in smoke test for a physically attached TI mmWave EVM.

Run with:
    REMOTERF_TI_MMWAVE_SERIAL=00DF4F69 \
      python -m unittest tests.test_ti_mmwave_hardware
"""
from __future__ import annotations

import os
import struct
import unittest
from pathlib import Path

from remoteRF_server.drivers.ti_mmwave.ti_mmwave_schema import (
    TI_FRAME_MAGIC,
    connect_ti_mmwave,
)


class TiMmWaveHardwareTests(unittest.TestCase):
    def _connect(self):
        return connect_ti_mmwave(
            serial=os.environ["REMOTERF_TI_MMWAVE_SERIAL"],
            cli_port=os.getenv("REMOTERF_TI_MMWAVE_CLI_PORT"),
            data_port=os.getenv("REMOTERF_TI_MMWAVE_DATA_PORT"),
        )

    @unittest.skipUnless(
        os.getenv("REMOTERF_TI_MMWAVE_SERIAL"),
        "set REMOTERF_TI_MMWAVE_SERIAL to run the attached-radar smoke test",
    )
    def test_open_identity_and_cli_version(self):
        device = self._connect()
        try:
            info = device.device_info()
            self.assertEqual(
                info["bridge_serial"],
                os.environ["REMOTERF_TI_MMWAVE_SERIAL"],
            )
            version = device.query_version(timeout=3.0)
            self.assertTrue(
                version.strip(),
                "the CLI returned an empty version response",
            )
            print(f"TI mmWave version response:\n{version}")
        finally:
            device.close()

    @unittest.skipUnless(
        os.getenv("REMOTERF_TI_MMWAVE_SERIAL")
        and os.getenv("REMOTERF_TI_MMWAVE_CONFIG"),
        "set REMOTERF_TI_MMWAVE_SERIAL and REMOTERF_TI_MMWAVE_CONFIG "
        "to run a configured frame capture",
    )
    def test_apply_config_and_receive_complete_frame(self):
        config_path = Path(os.environ["REMOTERF_TI_MMWAVE_CONFIG"])
        config_text = config_path.read_text(encoding="utf-8")
        frame_timeout = float(
            os.getenv("REMOTERF_TI_MMWAVE_FRAME_TIMEOUT", "5.0")
        )
        device = self._connect()
        try:
            result = device.apply_config(config_text, start=True)
            self.assertTrue(result["running"])
            packet = device.read_frame(timeout=frame_timeout)
            self.assertEqual(packet[:8], TI_FRAME_MAGIC)
            self.assertEqual(struct.unpack_from("<I", packet, 12)[0], len(packet))
            self.assertGreaterEqual(device.stream_stats()["frames_received"], 1)
            print(f"TI mmWave captured one complete {len(packet)}-byte frame")
        finally:
            if device.running:
                try:
                    device.stop(timeout=3.0)
                except Exception as exc:
                    print(f"Warning: sensorStop during cleanup failed: {exc}")
            device.close()


if __name__ == "__main__":
    unittest.main()
