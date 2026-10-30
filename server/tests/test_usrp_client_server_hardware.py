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

"""Opt-in real USRP-2901 test through client, localhost gRPC, and server."""
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


SERIAL = os.getenv("REMOTERF_TEST_USRP_SERIAL", "").strip()


def _add_client_source() -> None:
    configured = os.getenv("REMOTERF_CLIENT_SRC", "").strip()
    candidates = []
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates.append(
        Path(__file__).resolve().parents[2] / "client" / "src"
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
    SERIAL,
    "set REMOTERF_TEST_USRP_SERIAL for hardware tests",
)
@unittest.skipIf(
    _CLIENT_IMPORT_ERROR is not None,
    f"RemoteRF client source is unavailable: {_CLIENT_IMPORT_ERROR}",
)
class USRPClientServerHardwareTests(unittest.TestCase):
    def test_two_channel_rx_through_localhost_client_server(self):
        from remoteRF_server.drivers.usrp.usrp_schema import UsrpSchema

        inventory = UsrpSchema()
        inventory.bind_inventory({"serial": SERIAL})
        device_context = {
            "schema": inventory,
            "dtype": "usrp",
            "ident": SERIAL,
            "name": "usrp2901_client_server_hardware_test",
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
                patch.object(
                    server_v2,
                    "resolve_gid_for_token",
                    return_value=7,
                )
            )
            stack.enter_context(
                patch.object(
                    server_v2,
                    "get_local_device_context",
                    return_value=device_context,
                )
            )
            stack.enter_context(
                patch.object(
                    server_v2,
                    "token_matches_device",
                    return_value=True,
                )
            )
            stack.enter_context(
                patch.object(
                    server_v2.USRPPolicy,
                    "load",
                    return_value=USRPPolicy({}),
                )
            )
            stack.enter_context(
                patch.object(server_v2, "session_manager", manager)
            )
            grpc_server.start()
            try:
                channel = grpc.insecure_channel(f"127.0.0.1:{port}")
                grpc.channel_ready_future(channel).result(timeout=5)
                transport = DynamicV2Transport(
                    control_stub=client_grpc.DynamicControlV2Stub(channel),
                    sample_stub=client_grpc.SampleDataV1Stub(channel),
                )
                schema = transport.get_schema("hardware-test-token")
                uhd, MultiUSRP = build_uhd_bindings(
                    schema,
                    transport_factory=lambda: transport,
                )
                device = MultiUSRP("hardware-test-token")
                self.assertEqual(
                    device.remoterf_capabilities["hardware_profile"],
                    "usrp2901",
                )
                baseline = {
                    "rate": [
                        device.get_rx_rate(channel_index)
                        for channel_index in range(2)
                    ],
                    "freq": [
                        device.get_rx_freq(channel_index)
                        for channel_index in range(2)
                    ],
                    "gain": [
                        device.get_rx_gain(channel_index)
                        for channel_index in range(2)
                    ],
                    "bandwidth": [
                        device.get_rx_bandwidth(channel_index)
                        for channel_index in range(2)
                    ],
                    "antenna": [
                        device.get_rx_antenna(channel_index)
                        for channel_index in range(2)
                    ],
                }
                for channel_index in range(2):
                    device.set_rx_rate(1e6, channel_index)
                    device.set_rx_freq(100e6, channel_index)
                    device.set_rx_gain(10.0, channel_index)
                    device.set_rx_bandwidth(1e6, channel_index)

                stream_args = uhd.usrp.StreamArgs("fc32", "sc16")
                stream_args.channels = [0, 1]
                with device.get_rx_stream(stream_args) as streamer:
                    stream_cmd = uhd.types.StreamCMD(
                        uhd.types.StreamMode.num_done
                    )
                    stream_cmd.num_samps = 4096
                    stream_cmd.stream_now = False
                    stream_cmd.time_spec = device.get_time_now() + 0.5
                    streamer.issue_stream_cmd(stream_cmd)

                    samples = np.empty(
                        (2, 4096),
                        dtype=np.complex64,
                    )
                    metadata = uhd.types.RXMetadata()
                    count = streamer.recv(samples, metadata, 2.0)

                self.assertGreater(count, 0, msg=metadata.error_code_repr)
                self.assertLessEqual(count, samples.shape[-1])
                self.assertEqual(metadata.error_code.value, "none")
                self.assertTrue(
                    np.isfinite(samples[:, :count]).all()
                )
            finally:
                try:
                    if device is not None and baseline is not None:
                        for channel_index in range(2):
                            device.set_rx_rate(
                                baseline["rate"][channel_index],
                                channel_index,
                            )
                            device.set_rx_freq(
                                baseline["freq"][channel_index],
                                channel_index,
                            )
                            device.set_rx_gain(
                                baseline["gain"][channel_index],
                                channel_index,
                            )
                            device.set_rx_bandwidth(
                                baseline["bandwidth"][channel_index],
                                channel_index,
                            )
                            device.set_rx_antenna(
                                baseline["antenna"][channel_index],
                                channel_index,
                            )
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
