"""Opt-in real N210 test through client, localhost gRPC, and server."""
from __future__ import annotations

import os
import sys
import unittest
from concurrent import futures
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import grpc
import numpy as np

from remoteRF_server.common.grpc import grpc_pb2_grpc as server_grpc
from remoteRF_server.drivers.usrp.policy import USRPPolicy
from remoteRF_server.server import dynamic_v2 as server_v2


ADDRESS = os.getenv("REMOTERF_TEST_USRP_N210_ADDR", "").strip()


def _add_client_source() -> None:
    configured = os.getenv("REMOTERF_CLIENT_SRC", "").strip()
    candidates = []
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates.append(
        Path(__file__).resolve().parents[2] / "RemoteRF-Client" / "src"
    )
    for candidate in candidates:
        if (candidate / "remoteRF").is_dir():
            sys.path.insert(0, str(candidate.resolve()))
            return


_add_client_source()
try:
    from remoteRF.common.grpc import grpc_pb2_grpc as client_grpc
    from remoteRF.core.dynamic_v2_transport import DynamicV2Transport
    from remoteRF.drivers.dynamic_v2 import build_uhd_bindings
except (ImportError, RuntimeError) as exc:
    _CLIENT_IMPORT_ERROR = exc
else:
    _CLIENT_IMPORT_ERROR = None


@unittest.skipUnless(
    ADDRESS,
    "set REMOTERF_TEST_USRP_N210_ADDR for N210 hardware tests",
)
@unittest.skipIf(
    _CLIENT_IMPORT_ERROR is not None,
    f"RemoteRF client source is unavailable: {_CLIENT_IMPORT_ERROR}",
)
class USRPN210ClientServerHardwareTests(unittest.TestCase):
    def test_single_channel_rx_through_localhost_client_server(self):
        from remoteRF_server.drivers.usrp.usrp_schema import UsrpSchema

        inventory = UsrpSchema()
        inventory.bind_inventory({"type": "usrp2", "addr": ADDRESS})
        device_context = {
            "schema": inventory,
            "dtype": "usrp",
            "ident": ADDRESS,
            "name": "usrp_n210_client_server_hardware_test",
        }
        manager = server_v2.SessionManager()
        grpc_server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=8)
        )
        server_grpc.add_DynamicControlV2Servicer_to_server(
            server_v2.DynamicControlV2Servicer(),
            grpc_server,
        )
        server_grpc.add_SampleDataV1Servicer_to_server(
            server_v2.SampleDataV1Servicer(),
            grpc_server,
        )
        port = grpc_server.add_insecure_port("127.0.0.1:0")
        self.assertNotEqual(port, 0)

        channel = None
        device = None
        baseline = None
        with ExitStack() as stack:
            stack.enter_context(
                patch.object(server_v2, "resolve_gid_for_token", return_value=8)
            )
            stack.enter_context(
                patch.object(
                    server_v2,
                    "get_local_device_context",
                    return_value=device_context,
                )
            )
            stack.enter_context(
                patch.object(server_v2, "token_matches_device", return_value=True)
            )
            stack.enter_context(
                patch.object(
                    server_v2.USRPPolicy,
                    "load",
                    return_value=USRPPolicy({}),
                )
            )
            stack.enter_context(patch.object(server_v2, "session_manager", manager))
            grpc_server.start()
            try:
                channel = grpc.insecure_channel(f"127.0.0.1:{port}")
                grpc.channel_ready_future(channel).result(timeout=5)
                transport = DynamicV2Transport(
                    control_stub=client_grpc.DynamicControlV2Stub(channel),
                    sample_stub=client_grpc.SampleDataV1Stub(channel),
                )
                schema = transport.get_schema("n210-hardware-test-token")
                uhd, MultiUSRP = build_uhd_bindings(
                    schema,
                    transport_factory=lambda: transport,
                )
                device = MultiUSRP("n210-hardware-test-token")
                capabilities = device.remoterf_capabilities
                self.assertEqual(capabilities["hardware_profile"], "n210")
                self.assertEqual(
                    capabilities["device_profile"]["support_level"],
                    "qualified_native",
                )
                self.assertTrue(
                    capabilities["profile_resolution"][
                        "requested_profile_matches"
                    ]
                )
                self.assertEqual(capabilities["transport_type"], "ethernet")
                self.assertEqual(capabilities["transport_address"], ADDRESS)
                self.assertEqual(capabilities["native_product"], "N210r4")
                self.assertEqual(capabilities["rx_channel_count"], 1)
                self.assertEqual(capabilities["tx_channel_count"], 1)
                self.assertIn("sc16", capabilities["supported_otw_formats"])
                self.assertNotIn("sc12", capabilities["supported_otw_formats"])
                format_capabilities = capabilities["stream_format_capabilities"]
                self.assertEqual(
                    format_capabilities["rx"]["status"],
                    "runtime_probed",
                )
                self.assertTrue(
                    format_capabilities["rx"]["default"]["supported"]
                )
                self.assertEqual(
                    {
                        item["otw_format"]: item["supported"]
                        for item in format_capabilities["rx"]["formats"]
                    },
                    {"sc16": True, "sc12": False, "sc8": True},
                )
                self.assertEqual(
                    format_capabilities["tx"]["status"],
                    "not_probed",
                )

                baseline = {
                    "rate": device.get_rx_rate(0),
                    "freq": device.get_rx_freq(0),
                    "gain": device.get_rx_gain(0),
                    "antenna": device.get_rx_antenna(0),
                }
                device.set_rx_rate(1e6, 0)
                device.set_rx_freq(100e6, 0)
                device.set_rx_gain(0.0, 0)
                self.assertEqual(device.get_rx_rate(0), 1e6)
                self.assertEqual(device.get_rx_freq(0), 100e6)
                self.assertLessEqual(device.get_rx_freq_range(0).start(), 100e6)
                self.assertGreaterEqual(device.get_rx_freq_range(0).stop(), 100e6)

                stream_args = uhd.usrp.StreamArgs("fc32", "sc16")
                stream_args.channels = [0]
                with device.get_rx_stream(stream_args) as streamer:
                    stream_cmd = uhd.types.StreamCMD(
                        uhd.types.StreamMode.num_done
                    )
                    stream_cmd.num_samps = 8192
                    stream_cmd.stream_now = True
                    streamer.issue_stream_cmd(stream_cmd)
                    samples = np.empty((1, 8192), dtype=np.complex64)
                    metadata = uhd.types.RXMetadata()
                    count = streamer.recv(samples, metadata, 2.0)

                self.assertEqual(count, 8192, msg=metadata.error_code_repr)
                self.assertEqual(metadata.error_code.value, "none")
                self.assertTrue(np.isfinite(samples).all())
                self.assertGreater(np.count_nonzero(samples), 0)
            finally:
                try:
                    if device is not None and baseline is not None:
                        device.set_rx_rate(baseline["rate"], 0)
                        device.set_rx_freq(baseline["freq"], 0)
                        device.set_rx_gain(baseline["gain"], 0)
                        device.set_rx_antenna(baseline["antenna"], 0)
                finally:
                    try:
                        if device is not None:
                            device.close()
                    finally:
                        if channel is not None:
                            channel.close()
                        grpc_server.stop(0).wait()
                        manager.close_all()


if __name__ == "__main__":
    unittest.main()
