"""Dynamic v2 for a partner lab's caller.

The owner runs ``DynamicV2:<Operation>:WIRE`` through its own servicers with a
token bound to the device's current reservation, which retires with it.
"""

import json
import unittest
from unittest.mock import patch

import numpy as np

from remoteRF_server.common.grpc import grpc_pb2
from remoteRF_server.common.grpc.v2_codec import decode_value, encode_value
from remoteRF_server.common.utils import map_arg, unmap_arg
from remoteRF_server.drivers.usrp.policy import USRPPolicy
from remoteRF_server.server import device_manager
from remoteRF_server.server import dynamic_v2_bridge as bridge
from remoteRF_server.server.dynamic_v2 import (
    CONTROL_PROTOCOL_VERSION,
    SCHEMA_VERSION,
    STREAMING_PROTOCOL_VERSION,
    SampleDataV1Servicer,
    session_manager,
)
from remoteRF_server.server.rpc_manager import RpcManager

from test_dynamic_v2 import FakeInventorySchema, FakeRXMetadata

GID = 4242


def _run(operation, request, response_type, gid=GID):
    results = bridge.run_bridge(
        operation=operation, args={"wire": map_arg(request.SerializeToString())}, gid=gid
    )
    return response_type.FromString(unmap_arg(results["wire"]))


def _device(dev, salt="a1", hsh="h1"):
    device_manager._devices[GID] = device_manager._DeviceState(
        dev=dev, origin="local", online=True, salt=salt, hsh=hsh, name="dev", ident="X", dtype="usrp",
    )


class FederatedBridgeTests(unittest.TestCase):
    def setUp(self):
        _device(FakeInventorySchema())
        self.addCleanup(device_manager._devices.pop, GID, None)
        for patcher in (
            patch("remoteRF_server.server.dynamic_v2.USRPPolicy.load", return_value=USRPPolicy({})),
            patch.object(SampleDataV1Servicer, "_metadata_object", return_value=FakeRXMetadata()),
            patch.object(device_manager, "_reservation_end_callbacks", [session_manager.close_gid]),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(session_manager.close_gid, GID)

    def _open(self):
        schema = _run(
            "GetSchema",
            grpc_pb2.GetSchemaRequest(schema_versions=[SCHEMA_VERSION]),
            grpc_pb2.GetSchemaResponse,
        )
        self.assertFalse(schema.error.code, schema.error.message)
        opened = _run(
            "OpenSession",
            grpc_pb2.OpenSessionRequest(
                requested_schema_hash=schema.schema_hash,
                control_protocol_version=CONTROL_PROTOCOL_VERSION,
                streaming_protocol_version=STREAMING_PROTOCOL_VERSION,
            ),
            grpc_pb2.OpenSessionResponse,
        )
        self.assertFalse(opened.error.code, opened.error.message)
        return opened

    def _invoke(self, opened, method, gid=GID, positional=None):
        request = grpc_pb2.InvokeRequest(
            session_id=opened.session_id, handle=opened.device_handle, method=method, overload_id="default",
        )
        if positional is not None:
            request.args.add(name="__args__", value=encode_value(positional))
        return _run("Invoke", request, grpc_pb2.InvokeResponse, gid=gid)

    def test_a_session_streams_for_the_reservation_and_ends_with_it(self):
        opened = self._open()
        limits = json.loads(opened.capabilities_json)["remote_resource_limits"]
        self.assertEqual(limits["maximum_sample_payload_bytes"], bridge.FEDERATED_SAMPLE_PAYLOAD_BYTES)

        streamer = decode_value(self._invoke(opened, "get_rx_stream", positional=[{}]).result)
        common = dict(
            session_id=opened.session_id, handle=streamer["__remoterf_handle__"],
            generation=streamer["generation"], operation_id="op", direction=grpc_pb2.SAMPLE_DIRECTION_RX,
        )
        opened_frame = _run(
            "SampleFrame",
            grpc_pb2.SampleFrame(**common, sequence=0, kind=grpc_pb2.SAMPLE_FRAME_OPEN, credits=1),
            grpc_pb2.SampleFrame,
        )
        self.assertEqual(opened_frame.kind, grpc_pb2.SAMPLE_FRAME_RESULT)
        data = _run(
            "SampleFrame",
            grpc_pb2.SampleFrame(
                **common, sequence=1, kind=grpc_pb2.SAMPLE_FRAME_REQUEST, dtype=np.dtype(np.complex64).str,
                shape=[4], sample_count=4, timeout_sec=0.1, metadata_json="{}",
            ),
            grpc_pb2.SampleFrame,
        )
        self.assertEqual(data.kind, grpc_pb2.SAMPLE_FRAME_DATA, data.error.message)
        samples = np.frombuffer(data.payload, dtype=np.complex64)
        self.assertEqual(samples[:2].tolist(), [1 + 2j, 3 + 4j])

        # Pinned to its device: the same session is not another device's.
        other = self._invoke(opened, "get_time_now", gid=GID + 1)
        self.assertIn("does not belong to this device", other.error.message)

        # The reservation ends: its session and its bridge token go with it.
        token = device_manager.reservation_bridge_token(GID)
        device_manager.set_device(GID, "", "")
        self.assertIsNone(device_manager.resolve_gid_for_token(token))
        after = self._invoke(opened, "get_time_now")
        self.assertTrue(after.error.code)

    def test_without_a_reservation_the_bridge_refuses_typed(self):
        device_manager.set_device(GID, "", "")
        schema = _run(
            "GetSchema",
            grpc_pb2.GetSchemaRequest(schema_versions=[SCHEMA_VERSION]),
            grpc_pb2.GetSchemaResponse,
        )
        self.assertIn("no active reservation", schema.error.message)

    def test_a_bridge_token_lives_exactly_as_long_as_its_reservation(self):
        token = device_manager.reservation_bridge_token(GID)
        device_manager.set_device(GID, "a1", "h1")  # the same reservation, refreshed
        self.assertEqual(device_manager.resolve_gid_for_token(token), GID)
        self.assertEqual(device_manager.reservation_bridge_token(GID), token)
        device_manager.set_device(GID, "b2", "h2")  # a back-to-back one takes over
        self.assertIsNone(device_manager.resolve_gid_for_token(token))
        self.assertNotEqual(device_manager.reservation_bridge_token(GID), token)

    def test_the_bound_device_rpc_routes_dynamic_v2_to_the_bridge(self):
        request = grpc_pb2.NegotiateRequest(
            schema_versions=[SCHEMA_VERSION],
            control_protocol_versions=[CONTROL_PROTOCOL_VERSION],
            streaming_protocol_versions=[STREAMING_PROTOCOL_VERSION],
        )
        results = RpcManager().run_device_rpc_for_gid(
            gid=GID, function_name="DynamicV2:Negotiate:WIRE",
            args={"wire": map_arg(request.SerializeToString())},
        )
        response = grpc_pb2.NegotiateResponse.FromString(unmap_arg(results["wire"]))
        self.assertEqual(response.control_protocol_version, CONTROL_PROTOCOL_VERSION)


if __name__ == "__main__":
    unittest.main()
