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

import os
import struct
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from remoteRF_server import serverrf_cli
from remoteRF_server.drivers.ti_mmwave.ti_mmwave_schema import (
    CP2105_PRODUCT_ID,
    CP2105_VENDOR_ID,
    TI_FRAME_MAGIC,
    PortSelection,
    TiFrameAccumulator,
    TiMmWaveDevice,
    TiMmWaveSchema,
    discover_ti_mmwave_ports,
)


def _packet(*, frame_number: int = 1, payload: bytes = b"") -> bytes:
    total = 40 + len(payload)
    return struct.pack(
        "<8s8I",
        TI_FRAME_MAGIC,
        0x03060000,
        total,
        0xA6843,
        frame_number,
        12345,
        0,
        0,
        0,
    ) + payload


def _port(device: str, serial: str, interface: str):
    return SimpleNamespace(
        device=device,
        vid=CP2105_VENDOR_ID,
        pid=CP2105_PRODUCT_ID,
        serial_number=serial,
        interface=interface,
        description=f"CP2105 {interface}",
        product="CP2105 Dual USB to UART Bridge Controller",
        name=device.rsplit("/", 1)[-1],
    )


class _FakeSerialHandle:
    def __init__(self, module, *, port, baudrate, **_kwargs):
        self.module = module
        self.port = port
        self.baudrate = baudrate
        self.closed = False
        self.writes: list[bytes] = []
        self.pending = bytearray()
        self.reset_count = 0

    def write(self, value):
        payload = bytes(value)
        self.writes.append(payload)
        command = payload.decode().strip()
        response = self.module.responses.get(command, "Done")
        self.pending.extend(
            f"{command}\r\n{response}\r\nmmwDemo:/>".encode()
        )
        return len(payload)

    def read(self, count):
        if not self.pending:
            return b""
        chunk = bytes(self.pending[:count])
        del self.pending[:count]
        return chunk

    def flush(self):
        return None

    def reset_input_buffer(self):
        self.pending.clear()
        self.reset_count += 1

    def close(self):
        self.closed = True


class _FakeSerialModule:
    EIGHTBITS = 8
    PARITY_NONE = "N"
    STOPBITS_ONE = 1

    def __init__(self):
        self.handles = []
        self.responses = {"version": "mmWave SDK 03.06.00.00"}

    def Serial(self, **kwargs):
        handle = _FakeSerialHandle(self, **kwargs)
        self.handles.append(handle)
        return handle


def _device(*, queue_depth=8):
    module = _FakeSerialModule()
    device = TiMmWaveDevice(
        PortSelection(
            cli_port="/dev/cu.enhanced",
            data_port="/dev/cu.standard",
            bridge_serial="00DF4F69",
        ),
        serial_module=module,
        start_reader=False,
        frame_queue_depth=queue_depth,
    )
    return device, module


class TiMmWaveDiscoveryTests(unittest.TestCase):
    def test_discovers_enhanced_and_standard_by_bridge_serial(self):
        ports = [
            _port("/dev/cu.cli", "00DF4F69", "Enhanced Com Port"),
            _port("/dev/cu.data", "00DF4F69", "Standard Com Port"),
            _port("/dev/cu.other", "OTHER", "Enhanced Com Port"),
        ]

        selected = discover_ti_mmwave_ports(serial="00DF4F69", ports=ports)

        self.assertEqual(selected.cli_port, "/dev/cu.cli")
        self.assertEqual(selected.data_port, "/dev/cu.data")
        self.assertEqual(selected.bridge_serial, "00DF4F69")

    def test_requires_overrides_when_interface_names_are_missing(self):
        ports = [
            _port("/dev/cu.1", "00DF4F69", ""),
            _port("/dev/cu.2", "00DF4F69", ""),
        ]
        with self.assertRaisesRegex(RuntimeError, "cli_port and data_port explicitly"):
            discover_ti_mmwave_ports(serial="00DF4F69", ports=ports)

        selected = discover_ti_mmwave_ports(
            serial="00DF4F69",
            cli_port="/dev/cu.1",
            data_port="/dev/cu.2",
            ports=ports,
        )
        self.assertEqual(selected.cli_port, "/dev/cu.1")


class TiFrameAccumulatorTests(unittest.TestCase):
    def test_recovers_split_frames_and_resynchronizes_after_noise(self):
        first = _packet(frame_number=1)
        second = _packet(frame_number=2)
        parser = TiFrameAccumulator()

        self.assertEqual(parser.feed(b"noise" + first[:13]), [])
        frames = parser.feed(first[13:] + second)

        self.assertEqual(frames, [first, second])
        self.assertEqual(parser.discarded_bytes, 5)

    def test_rejects_implausible_length_then_finds_next_packet(self):
        invalid = TI_FRAME_MAGIC + b"\0\0\0\0" + struct.pack("<I", 10)
        valid = _packet(frame_number=3)
        parser = TiFrameAccumulator()

        frames = parser.feed(invalid + valid)

        self.assertEqual(frames, [valid])
        self.assertEqual(parser.invalid_headers, 1)


class TiMmWaveDeviceTests(unittest.TestCase):
    def test_commands_config_state_and_version(self):
        device, module = _device()
        self.addCleanup(device.close)

        version = device.query_version()
        result = device.apply_config(
            "% comment\nflushCfg\nprofileCfg 0 60 7\nsensorStart\n"
        )

        self.assertEqual(version, "mmWave SDK 03.06.00.00")
        self.assertTrue(result["running"])
        self.assertEqual(result["commands_sent"], 3)
        self.assertEqual(
            module.handles[0].writes,
            [
                b"version\n",
                b"flushCfg\n",
                b"profileCfg 0 60 7\n",
                b"sensorStart\n",
            ],
        )

        response = device.stop()
        self.assertEqual(response, "Done")
        self.assertFalse(device.device_info()["running"])

    def test_config_fails_fast_on_cli_error(self):
        device, module = _device()
        self.addCleanup(device.close)
        module.responses["badCfg"] = "Error -1"

        with self.assertRaisesRegex(RuntimeError, "badCfg"):
            device.apply_config("flushCfg\nbadCfg\nsensorStart")
        self.assertEqual(module.handles[0].writes[-1], b"badCfg\n")

    def test_start_option_does_not_duplicate_an_existing_start(self):
        device, module = _device()
        self.addCleanup(device.close)

        result = device.apply_config(
            "sensorStart\nprofileCfg 0 60 7",
            start=True,
        )

        self.assertEqual(result["commands_sent"], 2)
        self.assertEqual(len(module.handles[0].writes), 2)
        self.assertTrue(device.running)

    def test_rejects_non_finite_and_out_of_range_timeouts(self):
        device, _module = _device()
        self.addCleanup(device.close)

        for timeout in (float("nan"), float("inf"), -1, 31):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                device.read_frame(timeout=timeout)

    def test_frame_queue_is_bounded_and_keeps_latest(self):
        device, _module = _device(queue_depth=1)
        self.addCleanup(device.close)
        first = _packet(frame_number=1)
        second = _packet(frame_number=2)

        device._ingest_data(first + second)

        self.assertEqual(device.read_frame(timeout=0), second)
        stats = device.stream_stats()
        self.assertEqual(stats["frames_received"], 2)
        self.assertEqual(stats["frames_dropped"], 1)
        with self.assertRaises(TimeoutError):
            device.read_frame(timeout=0)

    def test_close_releases_both_serial_ports(self):
        device, module = _device()
        device.close()
        device.close()

        self.assertTrue(all(handle.closed for handle in module.handles))
        with self.assertRaisesRegex(RuntimeError, "closed"):
            device.flush_frames()


class TiMmWaveSchemaTests(unittest.TestCase):
    def test_schema_contract_and_dispatch(self):
        idl = TiMmWaveSchema().get_idl()
        self.assertEqual(idl["schema_version"], "1.0")
        self.assertEqual(idl["device_type"], "ti_mmwave")
        self.assertEqual(idl["client_class"], "TiMmWave")
        self.assertEqual(
            idl["client_modules"],
            {"ti_mmwave": "remoteRF.drivers.support.ti_mmwave"},
        )
        for name in ("device_info", "stream_stats", "firmware_profile", "is_running"):
            self.assertIn(f"get_{name}", idl["getters"])
        for name in (
            "send_command",
            "apply_config",
            "start",
            "stop",
            "query_version",
            "read_frame",
            "flush_frames",
        ):
            self.assertIn(f"call_{name}", idl["calls"])

        device, _module = _device()
        self.addCleanup(device.close)
        schema = TiMmWaveSchema()
        schema.bind(device)
        self.assertEqual(
            schema.dispatch("call_query_version", {"timeout": 1}),
            "mmWave SDK 03.06.00.00",
        )

    def test_server_cli_writes_canonical_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.dict(os.environ, {"REMOTERF_CONFIG_DIR": temp}):
                self.assertEqual(
                    serverrf_cli._device_add_ti_mmwave(
                        "20:lab_ti_radar:00DF4F69"
                    ),
                    0,
                )
                record = serverrf_cli._read_device_records()[20]

            self.assertEqual(record["TYPE"], "ti_mmwave")
            self.assertEqual(record["INIT"]["serial"], "00DF4F69")
            self.assertEqual(record["INIT"]["cli_baud"], 115200)
            self.assertEqual(record["INIT"]["data_baud"], 921600)
            text = Path(temp, "devices.yml").read_text(encoding="utf-8")
            self.assertIn("firmware_profile: xwr68xx_oob_sdk3", text)


class DefaultTiMmWaveSchemaTests(unittest.TestCase):
    def test_fresh_server_seeds_schema_without_pyserial(self):
        project_root = Path(__file__).resolve().parents[1]
        source_root = project_root / "src"
        with tempfile.TemporaryDirectory() as raw_temp:
            temp = Path(raw_temp)
            blocker = temp / "blocker" / "serial"
            blocker.mkdir(parents=True)
            (blocker / "__init__.py").write_text(
                "raise ImportError('pyserial deliberately unavailable in test')\n",
                encoding="utf-8",
            )
            config_root = temp / "xdg"
            env = dict(os.environ)
            env.pop("REMOTERF_CONFIG_DIR", None)
            env["HOME"] = str(temp / "home")
            env["XDG_CONFIG_HOME"] = str(config_root)
            env["PYTHONPATH"] = os.pathsep.join(
                (str(temp / "blocker"), str(source_root))
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    textwrap.dedent(
                        """
                        from remoteRF_server.common.idl.schema import get_driver_class
                        from remoteRF_server.common.utils import get_drivers_dir
                        from remoteRF_server.server import device_manager

                        seeded = get_drivers_dir() / "ti_mmwave_schema.py"
                        assert seeded.is_file(), seeded
                        marker = (
                            get_drivers_dir()
                            / ".ti_mmwave_schema.py.remoterf-managed"
                        )
                        assert marker.is_file(), marker

                        schema = get_driver_class("ti_mmwave")()
                        idl = schema.get_idl()
                        assert idl["client_class"] == "TiMmWave"
                        assert "call_read_frame" in idl["calls"]
                        assert "get_stream_stats" in idl["getters"]

                        try:
                            schema.make_device(serial="00DF4F69")
                        except RuntimeError as exc:
                            assert "pyserial" in str(exc).lower()
                        else:
                            raise AssertionError("native open should require pyserial")

                        print("DEFAULT_TI_MMWAVE_SCHEMA_OK")
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
        self.assertIn("DEFAULT_TI_MMWAVE_SCHEMA_OK", result.stdout)
        self.assertNotIn(
            "Driver load ti_mmwave_schema.py: error",
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()
