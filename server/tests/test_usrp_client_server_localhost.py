"""Client/server Dynamic v2 regression test over a real localhost gRPC socket."""
from __future__ import annotations

import os
import sys
import types
import unittest
from concurrent import futures
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import grpc
import numpy as np

from remoteRF_server.common.grpc import grpc_pb2_grpc as server_grpc
from remoteRF_server.drivers.usrp.policy import USRPPolicy
from remoteRF_server.drivers.usrp.uhd_manifest import (
    TARGET_UHD_VERSION,
    build_usrp_schema_v2,
)
from remoteRF_server.server import dynamic_v2 as server_v2


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


class _FakeRXStreamer:
    def get_max_num_samps(self):
        return 256

    def recv(self, buffer, metadata, timeout):
        self.last_timeout = timeout
        buffer[..., :2] = np.array(
            [1 + 2j, 3 + 4j],
            dtype=buffer.dtype,
        )
        metadata.error_code = "none"
        metadata.has_time_spec = False
        return 2


class _FakeRXMetadata:
    def __init__(self):
        self.error_code = "none"
        self.has_time_spec = False
        self.time_spec = None
        self.more_fragments = False
        self.fragment_offset = 0
        self.out_of_sequence = False


class _FakeLiveSchema:
    def __init__(self):
        self.device = object()
        self.closed = False

    def build_session_metadata_v2(self, policy_restrictions=None):
        return {
            "hardware_profile": "usrp2901",
            "uhd_version": TARGET_UHD_VERSION,
            "uhd_abi": "localhost-test",
            "policy_restrictions": dict(policy_restrictions or {}),
        }

    def invoke_native(self, method, args, positional_args=None):
        if method == "get_rx_stream":
            return _FakeRXStreamer()
        if method == "get_time_now":
            return 1.5
        return None

    def close_native_device(self):
        self.closed = True


class _FakeInventorySchema:
    device = None

    def __init__(self):
        self.live = None

    def get_idl_v2(self):
        return build_usrp_schema_v2()

    def create_session_schema(self):
        self.live = _FakeLiveSchema()
        return self.live


@unittest.skipIf(
    _CLIENT_IMPORT_ERROR is not None,
    f"RemoteRF client source is unavailable: {_CLIENT_IMPORT_ERROR}",
)
class USRPClientServerLocalhostTests(unittest.TestCase):
    def test_control_handle_binary_rx_and_cleanup_cross_the_grpc_boundary(self):
        inventory = _FakeInventorySchema()
        device_context = {
            "schema": inventory,
            "dtype": "usrp",
            "ident": "LOCALHOST-SERIAL",
            "name": "usrp2901_localhost_test",
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

        fake_usrp_schema = types.ModuleType(
            "remoteRF_server.drivers.usrp.usrp_schema"
        )
        fake_usrp_schema._construct = lambda value: value

        channel = None
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
            stack.enter_context(
                patch.object(
                    server_v2.SampleDataV1Servicer,
                    "_metadata_object",
                    return_value=_FakeRXMetadata(),
                )
            )
            stack.enter_context(
                patch.dict(
                    sys.modules,
                    {
                        "remoteRF_server.drivers.usrp.usrp_schema":
                            fake_usrp_schema,
                    },
                )
            )
            grpc_server.start()
            try:
                channel = grpc.insecure_channel(f"127.0.0.1:{port}")
                grpc.channel_ready_future(channel).result(timeout=5)
                transport = DynamicV2Transport(
                    control_stub=client_grpc.DynamicControlV2Stub(channel),
                    sample_stub=client_grpc.SampleDataV1Stub(channel),
                )
                schema = transport.get_schema("localhost-token")
                uhd, MultiUSRP = build_uhd_bindings(
                    schema,
                    transport_factory=lambda: transport,
                )

                with MultiUSRP("localhost-token") as device:
                    self.assertEqual(
                        device.remoterf_capabilities["hardware_profile"],
                        "usrp2901",
                    )
                    device.set_rx_rate(1e6)
                    stream_args = uhd.usrp.StreamArgs("fc32", "sc16")
                    stream_args.channels = [0]
                    with device.get_rx_stream(stream_args) as streamer:
                        self.assertEqual(
                            streamer.get_max_num_samps(),
                            64 * 1024,
                        )
                        samples = np.full(
                            4,
                            99 + 0j,
                            dtype=np.complex64,
                        )
                        metadata = uhd.types.RXMetadata()
                        count = streamer.recv(
                            samples,
                            metadata,
                            0.25,
                        )

                self.assertEqual(count, 4)
                np.testing.assert_array_equal(
                    samples[:count],
                    np.array(
                        [1 + 2j, 3 + 4j, 1 + 2j, 3 + 4j],
                        dtype=np.complex64,
                    ),
                )
                self.assertEqual(metadata.error_code.value, "none")
                self.assertEqual(manager.metrics()["sessions"], 0)
                self.assertTrue(inventory.live.closed)
            finally:
                if channel is not None:
                    channel.close()
                grpc_server.stop(0).wait()


if __name__ == "__main__":
    unittest.main()
