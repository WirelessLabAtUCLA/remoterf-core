from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace
from unittest import mock

from remoteRF_host.drivers.ti_mmwave.ti_mmwave_schema import (
    CP2105_PRODUCT_ID,
    CP2105_VENDOR_ID,
    TI_FRAME_MAGIC,
    TiFrameAccumulator,
    TiMmWaveSchema,
    discover_ti_mmwave_ports,
)


def _port(device: str, interface: str):
    return SimpleNamespace(
        device=device,
        vid=CP2105_VENDOR_ID,
        pid=CP2105_PRODUCT_ID,
        serial_number="00DF4F69",
        interface=interface,
        description=f"CP2105 {interface}",
        product="CP2105",
        name=device,
    )


def _frame(number: int, payload: bytes = b"") -> bytes:
    total = 40 + len(payload)
    return struct.pack(
        "<8s8I",
        TI_FRAME_MAGIC,
        0x03050000,
        total,
        0xA6843,
        number,
        0,
        0,
        0,
        0,
    ) + payload


class TiMmWaveHostSchemaTests(unittest.TestCase):
    def test_cp2105_interfaces_are_resolved_by_serial_and_role(self) -> None:
        selected = discover_ti_mmwave_ports(
            serial="00DF4F69",
            ports=[
                _port("/dev/cu.SLAB_USBtoUART", "Standard Com Port"),
                _port("/dev/cu.SLAB_USBtoUART3", "Enhanced Com Port"),
            ],
        )
        self.assertEqual(selected.cli_port, "/dev/cu.SLAB_USBtoUART3")
        self.assertEqual(selected.data_port, "/dev/cu.SLAB_USBtoUART")

    def test_accumulator_recovers_frames_across_arbitrary_chunks(self) -> None:
        first = _frame(7)
        second = _frame(8)
        accumulator = TiFrameAccumulator()
        self.assertEqual(accumulator.feed(b"noise" + first[:17]), [])
        self.assertEqual(accumulator.feed(first[17:] + second), [first, second])
        self.assertEqual(accumulator.discarded_bytes, 5)

    def test_schema_publishes_client_decoder_and_bounded_calls(self) -> None:
        idl = TiMmWaveSchema().get_idl()
        self.assertEqual(idl["device_type"], "ti_mmwave")
        self.assertEqual(idl["client_class"], "TiMmWave")
        self.assertEqual(
            idl["client_modules"],
            {"ti_mmwave": "remoteRF.drivers.support.ti_mmwave"},
        )
        self.assertIn("call_query_version", idl["calls"])
        self.assertIn("call_read_frame", idl["calls"])

    def test_make_device_forwards_inventory_to_connector(self) -> None:
        sentinel = object()
        with mock.patch(
            "remoteRF_host.drivers.ti_mmwave.ti_mmwave_schema.connect_ti_mmwave",
            return_value=sentinel,
        ) as connect:
            result = TiMmWaveSchema.make_device(
                serial="00DF4F69",
                cli_baud=115200,
                data_baud=921600,
                firmware_profile="xwr68xx_oob_sdk3",
                frame_queue_depth=8,
            )
        self.assertIs(result, sentinel)
        connect.assert_called_once_with(
            serial="00DF4F69",
            bridge_serial=None,
            cli_port=None,
            data_port=None,
            cli_baud=115200,
            data_baud=921600,
            firmware_profile="xwr68xx_oob_sdk3",
            frame_queue_depth=8,
        )


if __name__ == "__main__":
    unittest.main()
