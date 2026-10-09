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

import sys
import threading
import time
import types
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
from remoteRF_host.server.dynamic_v2 import (
    HandleEntry,
    SampleDataV1Servicer,
    SessionManager,
    session_manager,
    snapshot_native,
)
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


class FakeMetaRange:
    def __iter__(self):
        raise TypeError("this PyUHD build does not expose range iteration")

    def start(self):
        return 42e6

    def stop(self):
        return 6.008e9

    def step(self):
        return 0.25


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

    def test_reopen_releases_a_leftover_session_even_if_its_close_fails(self):
        first = session_manager.open("token")
        first_live = self.inventory.live
        first_live.close_native_device = lambda: (
            setattr(first_live, "closed", True),
            (_ for _ in ()).throw(RuntimeError("native close failed")),
        )
        second = session_manager.open("token")
        self.assertNotEqual(first.session_id, second.session_id)
        self.assertTrue(first_live.closed)
        self.assertEqual(session_manager._opening_gids, set())
        self.assertEqual(session_manager.metrics()["sessions"], 1)

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

    def test_non_iterable_meta_range_preserves_aggregate_interval(self):
        snapshot = snapshot_native(FakeMetaRange())

        self.assertEqual(snapshot["__uhd_type__"], "MetaRange")
        self.assertEqual(snapshot["start"], 42e6)
        self.assertEqual(snapshot["stop"], 6.008e9)
        self.assertEqual(snapshot["step"], 0.25)
        self.assertEqual(
            snapshot["ranges"],
            [
                {
                    "__uhd_type__": "Range",
                    "start": 42e6,
                    "stop": 6.008e9,
                    "step": 0.25,
                }
            ],
        )

    def test_usrp_stream_args_reconstruct_tagged_device_addr(self):
        from remoteRF_host.drivers.usrp import usrp_schema

        class DeviceAddr:
            def __init__(self, value=""):
                self.value = value

        class StreamArgs:
            def __init__(self, cpu_format, otw_format):
                self.cpu_format = cpu_format
                self.otw_format = otw_format
                self.args = ""
                self.channels = []

        fake_uhd = types.SimpleNamespace(
            types=types.SimpleNamespace(DeviceAddr=DeviceAddr),
            usrp=types.SimpleNamespace(StreamArgs=StreamArgs),
        )
        with patch.object(usrp_schema, "uhd", fake_uhd):
            for items, expected in (({}, ""), ({"spp": "512"}, "spp=512")):
                with self.subTest(items=items):
                    stream_args = usrp_schema._construct({
                        "__uhd_type__": "StreamArgs",
                        "cpu_format": "fc32",
                        "otw_format": "sc16",
                        "args": {
                            "__uhd_type__": "DeviceAddr",
                            "items": items,
                        },
                        "channels": [0, 1],
                    })

                    self.assertIsInstance(stream_args.args, DeviceAddr)
                    self.assertEqual(stream_args.args.value, expected)
                    self.assertEqual(stream_args.channels, [0, 1])

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


    def test_closed_session_errors_stay_typed_across_the_tunnel(self):
        invoked = self.call(
            "Invoke",
            grpc_pb2.InvokeRequest(
                session_id="gone",
                handle="h",
                method="get_time_now",
            ),
            grpc_pb2.InvokeResponse,
        )
        self.assertEqual(invoked.error.code, "RemoteRFSessionExpiredError")

        closed = self.call(
            "CloseSession",
            grpc_pb2.CloseSessionRequest(session_id="gone"),
            grpc_pb2.CloseResponse,
        )
        self.assertEqual(closed.error.code, "RemoteRFSessionExpiredError")

        frame = self.call(
            "SampleFrame",
            grpc_pb2.SampleFrame(
                session_id="gone",
                handle="h",
                operation_id="op",
                direction=grpc_pb2.SAMPLE_DIRECTION_RX,
                kind=grpc_pb2.SAMPLE_FRAME_OPEN,
            ),
            grpc_pb2.SampleFrame,
        )
        self.assertEqual(frame.kind, grpc_pb2.SAMPLE_FRAME_ERROR)
        self.assertEqual(frame.error.code, "RemoteRFSessionExpiredError")
        self.assertEqual(frame.operation_id, "op")

    def test_session_of_another_device_is_refused_typed(self):
        opened = self.open_session()
        result = run_bridge(
            operation="Invoke",
            args={
                "wire": map_arg(
                    grpc_pb2.InvokeRequest(
                        session_id=opened.session_id,
                        handle=opened.device_handle,
                        method="get_time_now",
                    ).SerializeToString()
                )
            },
            gid=8,
        )
        invoked = grpc_pb2.InvokeResponse.FromString(unmap_arg(result["wire"]))
        self.assertEqual(invoked.error.code, "RemoteRFProtocolError")

    def test_unknown_operation_is_still_a_tunnel_error(self):
        with self.assertRaises(Exception):
            run_bridge(operation="Nope", args={"wire": map_arg(b"")}, gid=7)

    def test_rx_prefetch_serves_sample_frames_across_tunnel_calls(self):
        class StreamingRX:
            threads = set()

            def recv(self, buffer, metadata, timeout):
                self.threads.add(threading.current_thread().name)
                buffer[...] = 5 + 6j
                metadata.error_code = "none"
                metadata.time_spec = types.SimpleNamespace(get_real_secs=lambda: 2.5)
                time.sleep(0.001)
                return buffer.shape[-1]

        opened = self.open_session()
        session = session_manager.get(opened.session_id)
        streamer = session_manager.register_handle(
            session,
            StreamingRX(),
            "uhd.usrp.RXStreamer",
            parent=opened.device_handle,
        )
        streamer.cpu_format = "fc32"
        streamer.stream_channels = [0]
        fake_uhd = types.SimpleNamespace(
            types=types.SimpleNamespace(RXMetadata=FakeRXMetadata)
        )
        with patch.dict(sys.modules, {"uhd": fake_uhd}):
            session_manager._start_rx_prefetch(session, streamer)
        self.assertTrue(streamer.rx_worker.is_alive())

        common = {
            "session_id": opened.session_id,
            "handle": streamer.handle,
            "generation": streamer.generation,
            "direction": grpc_pb2.SAMPLE_DIRECTION_RX,
        }
        for index in range(3):
            operation = f"rx-{index}"
            self.call(
                "SampleFrame",
                grpc_pb2.SampleFrame(
                    **common,
                    operation_id=operation,
                    sequence=2 * index + 1,
                    kind=grpc_pb2.SAMPLE_FRAME_OPEN,
                    credits=1,
                ),
                grpc_pb2.SampleFrame,
            )
            with patch(
                "remoteRF_host.drivers.usrp.usrp_schema._construct",
                return_value=FakeRXMetadata(),
            ):
                received = self.call(
                    "SampleFrame",
                    grpc_pb2.SampleFrame(
                        **common,
                        operation_id=operation,
                        sequence=2 * index + 2,
                        kind=grpc_pb2.SAMPLE_FRAME_REQUEST,
                        dtype=np.dtype(np.complex64).str,
                        shape=[1000],
                        channels=[0],
                        sample_count=1000,
                        timeout_sec=1.0,
                        metadata_json="{}",
                    ),
                    grpc_pb2.SampleFrame,
                )
            self.assertEqual(received.kind, grpc_pb2.SAMPLE_FRAME_DATA, received.error)
            self.assertEqual(received.sample_count, 1000)
            samples = np.frombuffer(received.payload, dtype=np.complex64)
            self.assertTrue(np.all(samples == np.complex64(5 + 6j)))

        self.assertTrue(all("rx-prefetch" in name for name in StreamingRX.threads))
        worker = streamer.rx_worker
        self.call(
            "CloseSession",
            grpc_pb2.CloseSessionRequest(session_id=opened.session_id),
            grpc_pb2.CloseResponse,
        )
        worker.join(timeout=1.0)
        self.assertFalse(worker.is_alive())


    def test_prefetch_recv_in_flight_does_not_delay_sample_frames(self):
        in_recv = threading.Event()

        class SlowRX:
            def recv(self, buffer, metadata, timeout):
                in_recv.set()
                time.sleep(0.5)
                metadata.error_code = "none"
                return buffer.shape[-1]

        opened = self.open_session()
        session = session_manager.get(opened.session_id)
        streamer = session_manager.register_handle(
            session, SlowRX(), "uhd.usrp.RXStreamer", parent=opened.device_handle
        )
        streamer.cpu_format = "fc32"
        streamer.stream_channels = [0]
        fake_uhd = types.SimpleNamespace(
            types=types.SimpleNamespace(RXMetadata=FakeRXMetadata)
        )
        with patch.dict(sys.modules, {"uhd": fake_uhd}):
            session_manager._start_rx_prefetch(session, streamer)
        self.assertTrue(in_recv.wait(1.0))
        started = time.monotonic()
        frame = self.call(
            "SampleFrame",
            grpc_pb2.SampleFrame(
                session_id=opened.session_id,
                handle=streamer.handle,
                generation=streamer.generation,
                operation_id="rx",
                direction=grpc_pb2.SAMPLE_DIRECTION_RX,
                sequence=1,
                kind=grpc_pb2.SAMPLE_FRAME_OPEN,
                credits=1,
            ),
            grpc_pb2.SampleFrame,
        )
        self.assertEqual(frame.kind, grpc_pb2.SAMPLE_FRAME_RESULT)
        self.assertLess(time.monotonic() - started, 0.2)

class RXPrefetchTests(unittest.TestCase):
    @staticmethod
    def entry(**kwargs):
        return HandleEntry(
            handle="rx",
            type_id="uhd.rx_streamer.RXStreamer",
            value=kwargs.pop("value", object()),
            parent=None,
            generation=1,
            **kwargs,
        )

    def test_coalesces_batches_and_preserves_remainder(self):
        entry = self.entry()
        entry.rx_prefetch.put(
            (np.array([[1, 2, 3]], dtype=np.complex64), {"error_code": "none"})
        )
        entry.rx_prefetch.put(
            (np.array([[4, 5]], dtype=np.complex64), {"error_code": "none"})
        )
        first = np.empty((1, 4), dtype=np.complex64)
        count, metadata = SampleDataV1Servicer._recv_prefetched(entry, first, 0.1)
        self.assertEqual(count, 4)
        self.assertEqual(metadata["error_code"], "none")
        np.testing.assert_array_equal(first, [[1, 2, 3, 4]])

        second = np.empty((1, 1), dtype=np.complex64)
        count, metadata = SampleDataV1Servicer._recv_prefetched(entry, second, 0.1)
        self.assertEqual(count, 1)
        np.testing.assert_array_equal(second, [[5]])

    def test_empty_queue_reports_timeout(self):
        buffer = np.empty((1, 4), dtype=np.complex64)
        count, metadata = SampleDataV1Servicer._recv_prefetched(self.entry(), buffer, 0.01)
        self.assertEqual(count, 0)
        self.assertEqual(metadata["error_code"], "timeout")

    def test_reports_queue_overflow_once(self):
        entry = self.entry()
        entry.rx_prefetch.put(
            (np.array([[1]], dtype=np.complex64), {"error_code": "none"})
        )
        entry.rx_prefetch_overflowed = True
        buffer = np.empty((1, 1), dtype=np.complex64)
        count, metadata = SampleDataV1Servicer._recv_prefetched(entry, buffer, 0.1)
        self.assertEqual(count, 1)
        self.assertEqual(metadata["error_code"], "overflow")
        self.assertFalse(entry.rx_prefetch_overflowed)

    def test_worker_drains_native_stream_until_stopped(self):
        class StreamingRX:
            def __init__(self):
                self.calls = 0

            def recv(self, buffer, metadata, timeout):
                self.calls += 1
                buffer[...] = self.calls
                metadata.error_code = "none"
                time.sleep(0.001)
                return buffer.shape[-1]

        streamer = StreamingRX()
        entry = self.entry(value=streamer, stream_channels=[0], cpu_format="fc32")
        session = types.SimpleNamespace(closed=False)
        fake_uhd = types.SimpleNamespace(
            types=types.SimpleNamespace(RXMetadata=FakeRXMetadata)
        )
        manager = SessionManager()
        with patch.dict(sys.modules, {"uhd": fake_uhd}):
            manager._start_rx_prefetch(session, entry)
            deadline = time.monotonic() + 1.0
            while entry.rx_prefetch.empty() and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertFalse(entry.rx_prefetch.empty())
            manager._stop_rx_prefetch(entry)
        self.assertIsNone(entry.rx_worker)
        self.assertTrue(entry.rx_prefetch.empty())

    def test_a_restart_never_overlaps_native_recvs_with_a_slow_worker(self):
        guard, active, peak = threading.Lock(), [0], [0]
        in_recv, release = threading.Event(), threading.Event()

        class SlowRX:
            def recv(self, buffer, metadata, timeout):
                with guard:
                    active[0] += 1
                    peak[0] = max(peak[0], active[0])
                in_recv.set()
                release.wait(2.0)
                with guard:
                    active[0] -= 1
                metadata.error_code = "none"
                return buffer.shape[-1]

        entry = self.entry(value=SlowRX(), stream_channels=[0], cpu_format="fc32")
        session = types.SimpleNamespace(closed=False)
        fake_uhd = types.SimpleNamespace(
            types=types.SimpleNamespace(RXMetadata=FakeRXMetadata)
        )
        manager = SessionManager()
        with patch.dict(sys.modules, {"uhd": fake_uhd}):
            manager._start_rx_prefetch(session, entry)
            try:
                self.assertTrue(in_recv.wait(1.0))
                in_recv.clear()
                # The first worker's recv outlasts the 0.5 s stop join.
                manager._start_rx_prefetch(session, entry)
                in_recv.wait(0.2)
            finally:
                release.set()
                manager._stop_rx_prefetch(entry)
        self.assertEqual(peak[0], 1)


if __name__ == "__main__":
    unittest.main()
