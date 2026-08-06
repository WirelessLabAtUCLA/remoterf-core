from __future__ import annotations

import unittest
from unittest.mock import patch

import numpy as np

from remoteRF_host.common.grpc import grpc_pb2
from remoteRF_host.common.grpc.v2_codec import decode_value
from remoteRF_host.common.utils import map_arg, unmap_arg
from remoteRF_host.drivers.usrp.uhd_manifest import (
    TARGET_UHD_VERSION,
    build_usrp_schema_v2,
)
from remoteRF_host.server.dynamic_v2 import session_manager
from remoteRF_host.server.dynamic_v2_bridge import run_bridge


class FakeRXMetadata:
    def __init__(self):
        self.error_code = "none"
        self.has_time_spec = False
        self.time_spec = None
        self.more_fragments = False
        self.fragment_offset = 0
        self.out_of_sequence = False


class FakeRXStreamer:
    def __init__(self):
        self.calls = 0

    def recv(self, buffer, metadata, timeout):
        self.calls += 1
        if self.calls > 1:
            return 0
        buffer[..., :2] = np.array([1 + 2j, 3 + 4j], dtype=buffer.dtype)
        metadata.error_code = "none"
        return 2


class FakeLiveSchema:
    def __init__(self):
        self.device = object()
        self.closed = False

    def build_session_metadata_v2(self, policy_restrictions=None):
        return {
            "hardware_profile": "usrp2901",
            "uhd_version": TARGET_UHD_VERSION,
            "uhd_abi": "test",
            "policy_restrictions": dict(policy_restrictions or {}),
        }

    def invoke_native(self, method, args, positional_args=None):
        if method == "get_time_now":
            return 1.5
        return None

    def close_native_device(self):
        self.closed = True


class FakeInventorySchema:
    device = None

    def __init__(self):
        self.live = None

    def get_idl_v2(self):
        return build_usrp_schema_v2()

    def create_session_schema(self):
        self.live = FakeLiveSchema()
        return self.live


class DynamicV2BridgeTests(unittest.TestCase):
    def setUp(self):
        session_manager.close_all()
        self.inventory = FakeInventorySchema()
        self.patches = [
            patch(
                "remoteRF_host.server.dynamic_v2.resolve_gid_for_token",
                return_value=7,
            ),
            patch(
                "remoteRF_host.server.dynamic_v2.get_local_device_context",
                return_value={
                    "gid": 7,
                    "schema": self.inventory,
                    "dtype": "usrp",
                    "ident": "31A2B3C",
                    "name": "usrp2901_lab",
                    "reserved": True,
                },
            ),
            patch(
                "remoteRF_host.server.dynamic_v2.token_matches_device",
                return_value=True,
            ),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(session_manager.close_all)

    @staticmethod
    def call(operation, request, response_type):
        result = run_bridge(
            operation=operation,
            args={"wire": map_arg(request.SerializeToString())},
            gid=7,
        )
        wire = unmap_arg(result["wire"])
        return response_type.FromString(wire)

    def open_session(self):
        response = self.call(
            "OpenSession",
            grpc_pb2.OpenSessionRequest(
                token="server-owned-reservation-token",
                control_protocol_version="2.0",
                streaming_protocol_version="1.0",
            ),
            grpc_pb2.OpenSessionResponse,
        )
        self.assertFalse(response.error.code)
        self.assertTrue(response.session_id)
        self.assertTrue(response.device_handle)
        return response

    def test_control_requests_round_trip_as_serialized_v2_messages(self):
        schema = self.call(
            "GetSchema",
            grpc_pb2.GetSchemaRequest(
                token="server-owned-reservation-token",
                schema_versions=["2.0"],
            ),
            grpc_pb2.GetSchemaResponse,
        )
        self.assertFalse(schema.error.code)
        self.assertEqual(schema.schema_version, "2.0")

        opened = self.open_session()
        invoked = self.call(
            "Invoke",
            grpc_pb2.InvokeRequest(
                session_id=opened.session_id,
                handle=opened.device_handle,
                method="get_time_now",
                overload_id="default",
            ),
            grpc_pb2.InvokeResponse,
        )
        self.assertFalse(invoked.error.code)
        self.assertEqual(decode_value(invoked.result), 1.5)

        closed = self.call(
            "CloseSession",
            grpc_pb2.CloseSessionRequest(session_id=opened.session_id),
            grpc_pb2.CloseResponse,
        )
        self.assertTrue(closed.closed)
        self.assertTrue(self.inventory.live.closed)

    def test_rx_sample_frames_keep_binary_payloads_across_tunnel_calls(self):
        opened = self.open_session()
        session = session_manager.get(opened.session_id)
        streamer = session_manager.register_handle(
            session,
            FakeRXStreamer(),
            "uhd.usrp.RXStreamer",
            parent=opened.device_handle,
        )
        streamer.cpu_format = "fc32"
        common = {
            "session_id": opened.session_id,
            "handle": streamer.handle,
            "generation": streamer.generation,
            "operation_id": "rx-operation",
            "direction": grpc_pb2.SAMPLE_DIRECTION_RX,
        }

        opened_stream = self.call(
            "SampleFrame",
            grpc_pb2.SampleFrame(
                **common,
                sequence=0,
                kind=grpc_pb2.SAMPLE_FRAME_OPEN,
                credits=1,
            ),
            grpc_pb2.SampleFrame,
        )
        self.assertEqual(opened_stream.kind, grpc_pb2.SAMPLE_FRAME_RESULT)

        with patch(
            "remoteRF_host.drivers.usrp.usrp_schema._construct",
            return_value=FakeRXMetadata(),
        ):
            received = self.call(
                "SampleFrame",
                grpc_pb2.SampleFrame(
                    **common,
                    sequence=1,
                    kind=grpc_pb2.SAMPLE_FRAME_REQUEST,
                    dtype=np.dtype(np.complex64).str,
                    shape=[4],
                    channels=[0],
                    sample_count=4,
                    timeout_sec=1.0,
                    metadata_json="{}",
                ),
                grpc_pb2.SampleFrame,
            )

        self.assertEqual(received.kind, grpc_pb2.SAMPLE_FRAME_DATA)
        self.assertEqual(received.sample_count, 2)
        samples = np.frombuffer(received.payload, dtype=np.complex64)
        np.testing.assert_array_equal(
            samples,
            np.array([1 + 2j, 3 + 4j], dtype=np.complex64),
        )


if __name__ == "__main__":
    unittest.main()
