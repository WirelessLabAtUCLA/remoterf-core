import json
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
import yaml

from remoteRF_server import serverrf_cli
from remoteRF_server.common.grpc import grpc_pb2
from remoteRF_server.common.grpc.v2_codec import decode_value, encode_value
from remoteRF_server.common.idl.v2 import validate_schema
from remoteRF_server.drivers.usrp.policy import USRPPolicy
from remoteRF_server.drivers.usrp.usrp_schema import _configure_uhd_console_logging
from remoteRF_server.drivers.usrp.uhd_manifest import (
    MULTIUSRP_METHODS,
    TARGET_UHD_VERSION,
    assert_release_coverage,
    build_usrp_schema_v2,
    canonical_uhd_version,
    is_supported_uhd_version,
)
from remoteRF_server.server.dynamic_v2 import (
    DynamicControlV2Servicer,
    HandleEntry,
    SampleDataV1Servicer,
    SessionManager,
    snapshot_native,
)
from remoteRF_server.server.v2_errors import (
    RemoteRFOverloadError,
    RemoteRFProtocolError,
    RemoteRFServerOverloadedError,
    RemoteRFSessionExpiredError,
    RemoteRFStaleHandleError,
)


class FakeRXStreamer:
    def get_max_num_samps(self):
        return 256

    def recv(self, buffer, metadata, timeout):
        self.last_timeout = timeout
        buffer[..., :2] = np.array([1 + 2j, 3 + 4j], dtype=buffer.dtype)
        metadata.error_code = "none"
        metadata.has_time_spec = False
        return 2


class FakeRXMetadata:
    def __init__(self):
        self.error_code = "none"
        self.has_time_spec = False
        self.time_spec = None
        self.more_fragments = False
        self.fragment_offset = 0
        self.out_of_sequence = False


class FakeNativeDevice:
    pass


class Fake_meta_range:
    def __iter__(self):
        raise TypeError("this PyUHD build does not expose range iteration")

    def start(self):
        return 42e6

    def stop(self):
        return 6.008e9

    def step(self):
        return 0.25


class FakeProperty:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def get_desired(self):
        return self.value

    def set(self, value):
        self.value = value

    def set_coerced(self, value):
        self.value = value


class FakePropertyTree:
    def __init__(self):
        self.integer = FakeProperty(3)

    def exists(self, path):
        return path == "/value"

    def list(self, path):
        return ["value"]

    def subtree(self, path):
        return self

    def access_int(self, path):
        return self.integer


class FakeLiveSchema:
    def __init__(self):
        self.device = FakeNativeDevice()
        self.closed = False
        self.calls = []
        self.tree = FakePropertyTree()

    def get_capabilities_v2(self, policy_restrictions=None):
        return {
            "hardware_profile": "usrp2901",
            "uhd_version": TARGET_UHD_VERSION,
            "uhd_abi": "test",
            "policy_restrictions": dict(policy_restrictions or {}),
        }

    def invoke_native(self, method, args, positional_args=None):
        self.calls.append((method, args, list(positional_args or ())))
        if method == "get_rx_stream":
            return FakeRXStreamer()
        if method == "get_tree":
            return self.tree
        if method == "get_time_now":
            return 1.5
        return None

    def close_native_device(self):
        self.closed = True


class FakeInventorySchema:
    def __init__(self):
        self.live = None

    def get_idl_v2(self):
        return build_usrp_schema_v2()

    def create_session_schema(self):
        self.live = FakeLiveSchema()
        return self.live


class DynamicV2ServerTests(unittest.TestCase):
    def test_non_iterable_meta_range_preserves_aggregate_interval(self):
        snapshot = snapshot_native(Fake_meta_range())

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

    def test_usrp_console_logging_is_forced_off_without_remoterf_opt_in(self):
        with patch.dict(
            os.environ,
            {"UHD_LOG_CONSOLE_LEVEL": "debug"},
            clear=True,
        ):
            _configure_uhd_console_logging()
            self.assertEqual(os.environ["UHD_LOG_CONSOLE_LEVEL"], "off")

        with patch.dict(
            os.environ,
            {"REMOTERF_UHD_CONSOLE_LEVEL": "warning"},
            clear=True,
        ):
            _configure_uhd_console_logging()
            self.assertEqual(os.environ["UHD_LOG_CONSOLE_LEVEL"], "warning")

    def test_usrp2901_manifest_is_valid_and_has_no_deferred_reachable_api(self):
        schema = build_usrp_schema_v2()
        validate_schema(schema)
        self.assertEqual(schema["schema_version"], "2.0")
        self.assertGreaterEqual(len(schema["methods"]), 140)
        self.assertIn("usrp2901", schema["hardware_profiles"])
        self.assertIn("n210", schema["hardware_profiles"])
        definitions = {
            item["profile_id"]: item
            for item in schema["hardware_profile_definitions"]
        }
        self.assertEqual(
            definitions["usrp2901"]["support_level"],
            "qualified_native",
        )
        self.assertEqual(
            definitions["n210"]["support_level"],
            "qualified_native",
        )
        self.assertEqual(definitions["x3xx"]["support_level"], "generic_uhd")
        self.assertIn("device_profile", schema["capability_fields"])
        self.assertIn("profile_resolution", schema["capability_fields"])
        self.assertIn("transport_address", schema["capability_fields"])
        self.assertIn("stream_format_capabilities", schema["capability_fields"])
        self.assertNotIn("deferred", schema["coverage"].values())
        self.assertIn(
            "unsupported_by_hardware_native_equivalent",
            schema["coverage"].values(),
        )
        object_paths = {
            item["python_path"] for item in schema["objects"]
        }
        self.assertIn("uhd.filters.AnalogFilterLP", object_paths)
        self.assertIn("uhd.filters.DigitalFilterFIRI16", object_paths)
        self.assertIn("uhd.filters.FilterType", object_paths)
        self.assertIn("uhd.dsp", object_paths)
        self.assertIn("uhd.dsp.signals", object_paths)
        self.assertEqual(
            schema["coverage"]["uhd.dsp.signals.get_continuous_tone"],
            "implemented",
        )
        self.assertEqual(
            schema["coverage"]["uhd.usrp.RXStreamer.get_max_num_samps"],
            "implemented_with_documented_remote_difference",
        )
        assert_release_coverage(schema)

    def test_promoted_signatures_preserve_native_defaults_and_parameter_kinds(self):
        schema = build_usrp_schema_v2()
        methods = {
            (item["owner"], item["name"]): item
            for item in schema["methods"]
        }
        owner = "uhd.usrp.MultiUSRP"
        rx_rate = methods[(owner, "set_rx_rate")]["overloads"][0]
        self.assertEqual(rx_rate["parameters"][1]["default"], (1 << 64) - 1)

        clock = methods[(owner, "get_clock_source")]["overloads"][0]
        self.assertEqual(clock["parameters"][0]["kind"], "positional_only")
        self.assertTrue(clock["parameters"][0]["required"])

        receive = methods[(owner, "recv_num_samps")]["overloads"][0]
        receive_params = {
            item["name"]: item for item in receive["parameters"]
        }
        self.assertEqual(receive_params["rate"]["default"], 1_000_000.0)
        self.assertEqual(receive_params["channels"]["default"], [0])
        self.assertIsNone(receive_params["streamer"]["default"])
        self.assertEqual(
            methods[(owner, "send_waveform")]["overloads"][0]["returns"],
            "int",
        )

    def test_manifest_uses_native_uhd_410_names_and_accepts_package_suffix(self):
        self.assertIn("set_normalized_rx_gain", MULTIUSRP_METHODS)
        self.assertIn("get_normalized_tx_gain", MULTIUSRP_METHODS)
        self.assertIn("has_rx_power_reference", MULTIUSRP_METHODS)
        self.assertIn("get_gpio_srcs", MULTIUSRP_METHODS)
        self.assertNotIn("set_rx_normalized_gain", MULTIUSRP_METHODS)
        self.assertNotIn("get_rx_agc", MULTIUSRP_METHODS)
        self.assertNotIn("set_tx_spp", MULTIUSRP_METHODS)

        packaged = "4.10.0.0-0ubuntu1~noble1"
        self.assertEqual(canonical_uhd_version(packaged), TARGET_UHD_VERSION)
        self.assertTrue(is_supported_uhd_version(packaged))
        self.assertTrue(is_supported_uhd_version("UHD 4.10.0.0-0-gabcdef"))
        self.assertEqual(
            canonical_uhd_version("4.10.0.main-release"),
            TARGET_UHD_VERSION,
        )
        self.assertTrue(is_supported_uhd_version("4.10.0.main-release"))
        self.assertFalse(is_supported_uhd_version("4.10.0.1"))
        self.assertFalse(is_supported_uhd_version("4.9.0.0"))

    def test_dynamic_value_ndarray_is_binary_and_exact(self):
        original = np.array([[1 + 2j, 3 + 4j]], dtype=np.complex64)
        encoded = encode_value(original)
        self.assertEqual(encoded.WhichOneof("value"), "ndarray_value")
        self.assertEqual(encoded.ndarray_value.data, original.tobytes())
        decoded = decode_value(encoded)
        self.assertEqual(decoded.dtype, original.dtype)
        np.testing.assert_array_equal(decoded, original)
        all_indexes = (1 << 64) - 1
        encoded_integer = encode_value(all_indexes)
        self.assertEqual(encoded_integer.WhichOneof("value"), "json_value")
        self.assertEqual(decode_value(encoded_integer), all_indexes)

    def test_negotiation_requires_mutually_supported_versions(self):
        servicer = DynamicControlV2Servicer()
        accepted = servicer.Negotiate(
            grpc_pb2.NegotiateRequest(
                schema_versions=["2.0"],
                control_protocol_versions=["2.0"],
                streaming_protocol_versions=["1.0"],
            ),
            None,
        )
        self.assertEqual(accepted.schema_version, "2.0")
        self.assertFalse(accepted.error.code)

        rejected = servicer.Negotiate(
            grpc_pb2.NegotiateRequest(
                schema_versions=["9.0"],
                control_protocol_versions=["2.0"],
                streaming_protocol_versions=["1.0"],
            ),
            None,
        )
        self.assertEqual(rejected.error.code, "RemoteRFProtocolError")

    def test_policy_compatibility_shim_allows_all_operations(self):
        policy = USRPPolicy({"tx_enabled": False, "max_tx_gain_db": 0})
        self.assertTrue(policy.tx_enabled)
        self.assertEqual(policy.restrictions, {})
        policy.check_control("set_tx_freq", {"tune_request": 2.4e9})
        policy.check_control("set_tx_gain", {"gain": 100})
        policy.check_control("set_gpio_attr", {"bank": "FP0", "mask": 0xFFFFFFFF})
        policy.check_tx_duration(3600)
        policy.check_handle_call(
            "uhd.property_tree",
            "set",
            {"__args__": ["/mboards/0/unsafe", 1]},
        )

    def test_sessions_use_opaque_typed_generation_checked_handles(self):
        inventory = FakeInventorySchema()
        context = {
            "schema": inventory,
            "dtype": "usrp",
            "ident": "SERIAL",
            "name": "test",
        }
        policy = USRPPolicy({})
        manager = SessionManager()
        with (
            patch(
                "remoteRF_server.server.dynamic_v2.resolve_gid_for_token",
                return_value=7,
            ),
            patch(
                "remoteRF_server.server.dynamic_v2.get_local_device_context",
                return_value=context,
            ),
            patch(
                "remoteRF_server.server.dynamic_v2.token_matches_device",
                return_value=True,
            ),
            patch(
                "remoteRF_server.server.dynamic_v2.USRPPolicy.load",
                return_value=policy,
            ),
        ):
            session = manager.open("token")
            self.assertTrue(session.session_id.startswith("sess_"))
            self.assertTrue(session.root_handle.startswith("dev_"))
            self.assertNotIn("rx:1", session.root_handle)
            manager.invoke(
                session.session_id,
                session.root_handle,
                "set_tx_freq",
                {"tune_request": 2.4e9},
                overload_id="default",
            )
            manager.invoke(
                session.session_id,
                session.root_handle,
                "set_gpio_attr",
                {"bank": "FP0", "attr": "OUT", "value": 1},
                overload_id="default",
            )
            result, _ = manager.invoke(
                session.session_id,
                session.root_handle,
                "get_rx_stream",
                {},
                positional_args=[{}],
            )
            handle = result["__remoterf_handle__"]
            self.assertTrue(handle.startswith("rx_"))
            entry = manager.get_handle(
                session,
                handle,
                expected_type="uhd.usrp.RXStreamer",
                generation=result["generation"],
            )
            with self.assertRaises(RemoteRFStaleHandleError):
                manager.get_handle(
                    session,
                    handle,
                    generation=entry.generation + 1,
                )
            manager.invoke(
                session.session_id,
                session.root_handle,
                "recv_num_samps",
                {
                    "num_samps": 1,
                    "freq": 100e6,
                    "streamer": {
                        "__remoterf_handle_arg__": handle,
                        "type_id": "uhd.usrp.RXStreamer",
                        "generation": entry.generation,
                    },
                },
                overload_id="default",
            )
            native_streamer = inventory.live.calls[-1][1]["streamer"]
            self.assertIsInstance(native_streamer, FakeRXStreamer)
            tree, _ = manager.invoke(
                session.session_id,
                session.root_handle,
                "get_tree",
                {},
                overload_id="default",
            )
            exists, _ = manager.invoke(
                session.session_id,
                tree["__remoterf_handle__"],
                "exists",
                {"path": "/value"},
                overload_id="default",
            )
            self.assertTrue(exists)
            prop, _ = manager.invoke(
                session.session_id,
                tree["__remoterf_handle__"],
                "access_int",
                {},
                positional_args=["/value"],
                overload_id="default",
            )
            value, _ = manager.invoke(
                session.session_id,
                prop["__remoterf_handle__"],
                "get",
                {},
                overload_id="default",
            )
            self.assertEqual(value, 3)
            manager.invoke(
                session.session_id,
                prop["__remoterf_handle__"],
                "set",
                {},
                positional_args=[4],
                overload_id="default",
            )
            updated, _ = manager.invoke(
                session.session_id,
                prop["__remoterf_handle__"],
                "get",
                {},
                overload_id="default",
            )
            self.assertEqual(updated, 4)
            with self.assertRaises(RemoteRFProtocolError):
                manager.invoke(
                    session.session_id,
                    tree["__remoterf_handle__"],
                    "set",
                    {"path": "/mboards/0/unsafe", "value": 1},
                    overload_id="native",
                )
            with self.assertRaises(RemoteRFOverloadError):
                manager.invoke(
                    session.session_id,
                    session.root_handle,
                    "set_rx_gain",
                    {"gain": 1.0, "chan": 0},
                )
            self.assertTrue(manager.close_handle(session.session_id, handle))
            self.assertFalse(manager.close_handle(session.session_id, handle))
            self.assertTrue(manager.close(session.session_id))
            self.assertTrue(inventory.live.closed)

    def test_binary_rx_stream_coalesces_native_packets(self):
        inventory = FakeInventorySchema()
        context = {
            "schema": inventory,
            "dtype": "usrp",
            "ident": "SERIAL",
            "name": "test",
        }
        manager = SessionManager()
        with (
            patch(
                "remoteRF_server.server.dynamic_v2.resolve_gid_for_token",
                return_value=7,
            ),
            patch(
                "remoteRF_server.server.dynamic_v2.get_local_device_context",
                return_value=context,
            ),
            patch(
                "remoteRF_server.server.dynamic_v2.token_matches_device",
                return_value=True,
            ),
            patch(
                "remoteRF_server.server.dynamic_v2.USRPPolicy.load",
                return_value=USRPPolicy({}),
            ),
        ):
            session = manager.open("token")
            result, _ = manager.invoke(
                session.session_id,
                session.root_handle,
                "get_rx_stream",
                {},
                positional_args=[{}],
                overload_id="default",
            )
            handle = result["__remoterf_handle__"]
            generation = result["generation"]
            frames = [
                grpc_pb2.SampleFrame(
                    session_id=session.session_id,
                    handle=handle,
                    generation=generation,
                    operation_id="op",
                    sequence=0,
                    direction=grpc_pb2.SAMPLE_DIRECTION_RX,
                    kind=grpc_pb2.SAMPLE_FRAME_OPEN,
                    credits=1,
                ),
                grpc_pb2.SampleFrame(
                    session_id=session.session_id,
                    handle=handle,
                    generation=generation,
                    operation_id="op",
                    sequence=1,
                    direction=grpc_pb2.SAMPLE_DIRECTION_RX,
                    kind=grpc_pb2.SAMPLE_FRAME_REQUEST,
                    dtype=np.dtype(np.complex64).str,
                    shape=[4],
                    sample_count=4,
                    timeout_sec=0.1,
                    metadata_json="{}",
                ),
            ]
            with (
                patch(
                    "remoteRF_server.server.dynamic_v2.session_manager",
                    manager,
                ),
                patch(
                    "remoteRF_server.server.dynamic_v2.token_matches_device",
                    return_value=True,
                ),
                patch.object(
                    SampleDataV1Servicer,
                    "_metadata_object",
                    return_value=FakeRXMetadata(),
                ),
            ):
                responses = list(
                    SampleDataV1Servicer().SampleStream(iter(frames), None)
                )
                bad_frames = [
                    grpc_pb2.SampleFrame(
                        session_id=session.session_id,
                        handle=handle,
                        generation=generation,
                        operation_id="bad",
                        sequence=2,
                        direction=grpc_pb2.SAMPLE_DIRECTION_RX,
                        kind=grpc_pb2.SAMPLE_FRAME_OPEN,
                    ),
                    grpc_pb2.SampleFrame(
                        session_id=session.session_id,
                        handle=handle,
                        generation=generation,
                        operation_id="bad",
                        sequence=3,
                        direction=grpc_pb2.SAMPLE_DIRECTION_RX,
                        kind=grpc_pb2.SAMPLE_FRAME_REQUEST,
                        dtype=np.dtype(object).str,
                        shape=[1],
                        sample_count=1,
                    ),
                ]
                malformed = list(
                    SampleDataV1Servicer().SampleStream(iter(bad_frames), None)
                )
            data = responses[-1]
            self.assertEqual(data.kind, grpc_pb2.SAMPLE_FRAME_DATA)
            self.assertEqual(data.sample_count, 4)
            self.assertEqual(len(data.payload), 4 * np.dtype(np.complex64).itemsize)
            np.testing.assert_array_equal(
                np.frombuffer(data.payload, dtype=np.complex64),
                np.array(
                    [1 + 2j, 3 + 4j, 1 + 2j, 3 + 4j],
                    dtype=np.complex64,
                ),
            )
            self.assertEqual(json.loads(data.metadata_json)["error_code"], "none")
            self.assertGreater(
                manager.get_handle(session, handle).value.last_timeout,
                0.0,
            )
            self.assertLessEqual(
                manager.get_handle(session, handle).value.last_timeout,
                0.1,
            )
            self.assertEqual(
                malformed[-1].error.code,
                "RemoteRFProtocolError",
            )
            manager.close(session.session_id)

    def test_rx_prefetch_coalesces_batches_and_preserves_remainder(self):
        entry = HandleEntry(
            handle="rx",
            type_id="uhd.rx_streamer.RXStreamer",
            value=object(),
            parent=None,
            generation=1,
        )
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
        self.assertEqual(metadata["error_code"], "none")
        np.testing.assert_array_equal(second, [[5]])

    def test_rx_prefetch_reports_server_queue_overflow(self):
        entry = HandleEntry(
            handle="rx",
            type_id="uhd.rx_streamer.RXStreamer",
            value=object(),
            parent=None,
            generation=1,
        )
        entry.rx_prefetch.put(
            (np.array([[1]], dtype=np.complex64), {"error_code": "none"})
        )
        entry.rx_prefetch_overflowed = True
        buffer = np.empty((1, 1), dtype=np.complex64)
        count, metadata = SampleDataV1Servicer._recv_prefetched(entry, buffer, 0.1)
        self.assertEqual(count, 1)
        self.assertEqual(metadata["error_code"], "overflow")
        self.assertIn("prefetch queue", metadata["error_code_repr"])
        self.assertFalse(entry.rx_prefetch_overflowed)

    def test_rx_prefetch_worker_drains_native_stream_until_stopped(self):
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
        entry = HandleEntry(
            handle="rx",
            type_id="uhd.rx_streamer.RXStreamer",
            value=streamer,
            parent=None,
            generation=1,
            stream_channels=[0],
            cpu_format="fc32",
        )
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
            self.assertGreater(streamer.calls, 0)
            manager._stop_rx_prefetch(entry)
        self.assertIsNone(entry.rx_worker)
        self.assertTrue(entry.rx_prefetch_stop.is_set())
        self.assertTrue(entry.rx_prefetch.empty())

    def test_reservation_loss_closes_session(self):
        inventory = FakeInventorySchema()
        context = {
            "schema": inventory,
            "dtype": "usrp",
            "ident": "SERIAL",
            "name": "test",
        }
        manager = SessionManager()
        with (
            patch(
                "remoteRF_server.server.dynamic_v2.resolve_gid_for_token",
                return_value=7,
            ),
            patch(
                "remoteRF_server.server.dynamic_v2.get_local_device_context",
                return_value=context,
            ),
            patch(
                "remoteRF_server.server.dynamic_v2.USRPPolicy.load",
                return_value=USRPPolicy({}),
            ),
        ):
            session = manager.open("token")
        with patch(
            "remoteRF_server.server.dynamic_v2.token_matches_device",
            return_value=False,
        ):
            with self.assertRaises(RemoteRFSessionExpiredError):
                manager.get(session.session_id)
        self.assertTrue(inventory.live.closed)

    def test_resource_limits_metrics_and_close_all_are_bounded(self):
        inventory = FakeInventorySchema()
        context = {
            "schema": inventory,
            "dtype": "usrp",
            "ident": "SERIAL",
            "name": "test",
        }
        manager = SessionManager()
        with (
            patch(
                "remoteRF_server.server.dynamic_v2.resolve_gid_for_token",
                return_value=7,
            ),
            patch(
                "remoteRF_server.server.dynamic_v2.get_local_device_context",
                return_value=context,
            ),
            patch(
                "remoteRF_server.server.dynamic_v2.token_matches_device",
                return_value=True,
            ),
            patch(
                "remoteRF_server.server.dynamic_v2.USRPPolicy.load",
                return_value=USRPPolicy({}),
            ),
            patch(
                "remoteRF_server.server.dynamic_v2._MAX_HANDLES_PER_SESSION",
                3,
            ),
        ):
            session = manager.open("token")
            manager.register_handle(
                session,
                object(),
                "test.handle",
                parent=session.root_handle,
            )
            manager.register_handle(
                session,
                object(),
                "test.handle",
                parent=session.root_handle,
            )
            with self.assertRaises(RemoteRFServerOverloadedError):
                manager.register_handle(
                    session,
                    object(),
                    "test.handle",
                    parent=session.root_handle,
                )
            self.assertEqual(
                manager.metrics(),
                {
                    "sessions": 1,
                    "opening_sessions": 0,
                    "handles": 3,
                    "async_queue_depth": 0,
                    "async_queue_overflows": 0,
                    "rx_prefetch_queue_depth": 0,
                    "rx_prefetch_queue_overflows": 0,
                },
            )
            self.assertEqual(manager.close_all(), 1)
            self.assertEqual(manager.close_all(), 0)
            self.assertEqual(manager.metrics()["sessions"], 0)
            self.assertEqual(manager.metrics()["handles"], 0)
            self.assertTrue(inventory.live.closed)

    def test_stream_limits_reject_oversize_and_concurrent_operations(self):
        inventory = FakeInventorySchema()
        context = {
            "schema": inventory,
            "dtype": "usrp",
            "ident": "SERIAL",
            "name": "test",
        }
        manager = SessionManager()
        with (
            patch(
                "remoteRF_server.server.dynamic_v2.resolve_gid_for_token",
                return_value=7,
            ),
            patch(
                "remoteRF_server.server.dynamic_v2.get_local_device_context",
                return_value=context,
            ),
            patch(
                "remoteRF_server.server.dynamic_v2.token_matches_device",
                return_value=True,
            ),
            patch(
                "remoteRF_server.server.dynamic_v2.USRPPolicy.load",
                return_value=USRPPolicy({}),
            ),
        ):
            session = manager.open("token")
            result, _ = manager.invoke(
                session.session_id,
                session.root_handle,
                "get_rx_stream",
                {},
                positional_args=[{}],
                overload_id="default",
            )
            handle = result["__remoterf_handle__"]
            generation = result["generation"]
            common = {
                "session_id": session.session_id,
                "handle": handle,
                "generation": generation,
                "direction": grpc_pb2.SAMPLE_DIRECTION_RX,
            }
            with (
                patch(
                    "remoteRF_server.server.dynamic_v2.session_manager",
                    manager,
                ),
                patch(
                    "remoteRF_server.server.dynamic_v2.token_matches_device",
                    return_value=True,
                ),
                patch.object(
                    SampleDataV1Servicer,
                    "_metadata_object",
                    return_value=FakeRXMetadata(),
                ),
            ):
                credit_response = list(
                    SampleDataV1Servicer().SampleStream(
                        iter(
                            [
                                grpc_pb2.SampleFrame(
                                    **common,
                                    operation_id="credits",
                                    sequence=0,
                                    kind=grpc_pb2.SAMPLE_FRAME_OPEN,
                                    credits=999,
                                )
                            ]
                        ),
                        None,
                    )
                )
                self.assertEqual(credit_response[0].credits, 64)

                oversize = list(
                    SampleDataV1Servicer().SampleStream(
                        iter(
                            [
                                grpc_pb2.SampleFrame(
                                    **common,
                                    operation_id="oversize",
                                    sequence=1,
                                    kind=grpc_pb2.SAMPLE_FRAME_OPEN,
                                ),
                                grpc_pb2.SampleFrame(
                                    **common,
                                    operation_id="oversize",
                                    sequence=2,
                                    kind=grpc_pb2.SAMPLE_FRAME_REQUEST,
                                    dtype=np.dtype(np.complex64).str,
                                    shape=[524289],
                                    sample_count=524289,
                                ),
                            ]
                        ),
                        None,
                    )
                )
                self.assertEqual(
                    oversize[-1].error.code,
                    "RemoteRFProtocolError",
                )

                invalid_dtypes = (
                    "",
                    "object",
                    "O",
                    ">c8",
                    "[('sample','<c8')]",
                )
                sequence = 3
                for index, dtype in enumerate(invalid_dtypes):
                    operation_id = f"bad-dtype-{index}"
                    malformed = list(
                        SampleDataV1Servicer().SampleStream(
                            iter(
                                [
                                    grpc_pb2.SampleFrame(
                                        **common,
                                        operation_id=operation_id,
                                        sequence=sequence,
                                        kind=grpc_pb2.SAMPLE_FRAME_OPEN,
                                    ),
                                    grpc_pb2.SampleFrame(
                                        **common,
                                        operation_id=operation_id,
                                        sequence=sequence + 1,
                                        kind=grpc_pb2.SAMPLE_FRAME_REQUEST,
                                        dtype=dtype,
                                        shape=[1],
                                        sample_count=1,
                                    ),
                                ]
                            ),
                            None,
                        )
                    )
                    self.assertEqual(
                        malformed[-1].error.code,
                        "RemoteRFProtocolError",
                    )
                    sequence += 2

                zero_timeout = list(
                    SampleDataV1Servicer().SampleStream(
                        iter(
                            [
                                grpc_pb2.SampleFrame(
                                    **common,
                                    operation_id="zero-timeout",
                                    sequence=sequence,
                                    kind=grpc_pb2.SAMPLE_FRAME_OPEN,
                                ),
                                grpc_pb2.SampleFrame(
                                    **common,
                                    operation_id="zero-timeout",
                                    sequence=sequence + 1,
                                    kind=grpc_pb2.SAMPLE_FRAME_REQUEST,
                                    dtype="<c8",
                                    shape=[2],
                                    sample_count=2,
                                    timeout_sec=0.0,
                                    metadata_json="{}",
                                ),
                            ]
                        ),
                        None,
                    )
                )
                self.assertFalse(
                    zero_timeout[-1].error.code,
                    (
                        zero_timeout[-1].error.message,
                        zero_timeout[-1].error.native_exception,
                    ),
                )
                self.assertEqual(
                    manager.get_handle(session, handle).value.last_timeout,
                    0.0,
                )

                entry = manager.get_handle(session, handle)
                entry.active_operation = "already-running"
                concurrent = list(
                    SampleDataV1Servicer().SampleStream(
                        iter(
                            [
                                grpc_pb2.SampleFrame(
                                    **common,
                                    operation_id="concurrent",
                                    sequence=sequence + 2,
                                    kind=grpc_pb2.SAMPLE_FRAME_OPEN,
                                )
                            ]
                        ),
                        None,
                    )
                )
                self.assertEqual(
                    concurrent[-1].error.code,
                    "RemoteRFServerOverloadedError",
                )
                entry.active_operation = ""
            manager.close_all()

    def test_usrp_cli_writes_only_canonical_yaml_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(
                os.environ,
                {"REMOTERF_CONFIG_DIR": tmp},
                clear=False,
            ):
                self.assertEqual(
                    serverrf_cli._device_add_usrp("7:lab_usrp:31A2B3C"),
                    0,
                )
                inventory = Path(tmp, "devices.yml")
                self.assertTrue(inventory.exists())
                text = inventory.read_text(encoding="utf-8")
                self.assertIn("device_type: usrp", text)
                self.assertIn("serial: 31A2B3C", text)
                records = serverrf_cli._read_device_records()
                self.assertEqual(records[7]["TYPE"], "usrp")
                self.assertEqual(records[7]["IDENT"], "31A2B3C")
                self.assertFalse(Path(tmp, "devices.env").exists())

    def test_usrp2901_cli_flag_and_legacy_usrp_alias_share_the_same_handler(self):
        for option in ("--usrp-2901", "--usrp2901", "--usrp"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as tmp:
                with (
                    patch.dict(
                        os.environ,
                        {"REMOTERF_CONFIG_DIR": tmp},
                        clear=False,
                    ),
                    patch.object(
                        sys,
                        "argv",
                        [
                            "serverrf",
                            "--device",
                            "--add",
                            option,
                            "7:lab_usrp:31A2B3C",
                        ],
                    ),
                ):
                    self.assertEqual(serverrf_cli.main(), 0)
                    record = serverrf_cli._read_device_records()[7]
                    self.assertEqual(record["TYPE"], "usrp")
                    self.assertEqual(record["IDENT_KIND"], "serial")
                    self.assertEqual(record["IDENT"], "31A2B3C")
                    self.assertEqual(record["INIT"]["profile"], "usrp2901")

    def test_n210_cli_writes_address_bound_usrp_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(
                os.environ,
                {"REMOTERF_CONFIG_DIR": tmp},
                clear=False,
            ):
                self.assertEqual(
                    serverrf_cli._device_add_usrp_n210(
                        "8:lab_n210:192.168.137.21"
                    ),
                    0,
                )
                inventory = Path(tmp, "devices.yml")
                text = inventory.read_text(encoding="utf-8")
                self.assertIn("device_type: usrp", text)
                self.assertIn("type: usrp2", text)
                self.assertIn("addr: 192.168.137.21", text)
                self.assertNotIn("serial:", text)
                records = serverrf_cli._read_device_records()
                self.assertEqual(records[8]["TYPE"], "usrp")
                self.assertEqual(records[8]["IDENT_KIND"], "address")
                self.assertEqual(records[8]["IDENT"], "192.168.137.21")
                self.assertEqual(
                    records[8]["INIT"],
                    {
                        "profile": "n210",
                        "type": "usrp2",
                        "addr": "192.168.137.21",
                    },
                )

    def test_generic_usrp_profile_cli_writes_structured_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(
                os.environ,
                {"REMOTERF_CONFIG_DIR": tmp},
                clear=False,
            ):
                self.assertEqual(
                    serverrf_cli._device_add_usrp_profile(
                        "9:lab_x310:x310:192.168.10.2"
                    ),
                    0,
                )
                records = serverrf_cli._read_device_records()
                self.assertEqual(records[9]["IDENT_KIND"], "address")
                self.assertEqual(
                    records[9]["INIT"],
                    {
                        "profile": "x3xx",
                        "type": "x300",
                        "addr": "192.168.10.2",
                    },
                )

    def test_n210_cli_rejects_non_ip_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(
                os.environ,
                {"REMOTERF_CONFIG_DIR": tmp},
                clear=False,
            ):
                self.assertEqual(
                    serverrf_cli._device_add_usrp_n210("8:lab_n210:not-an-ip"),
                    2,
                )
                self.assertFalse(Path(tmp, "devices.yml").exists())

    def test_pluto_cli_uses_registered_adalm_pluto_device_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(
                os.environ,
                {"REMOTERF_CONFIG_DIR": tmp},
                clear=False,
            ):
                self.assertEqual(
                    serverrf_cli._device_add_pluto("1:Pluto A:104473f6"),
                    0,
                )
                inventory = Path(tmp, "devices.yml")
                text = inventory.read_text(encoding="utf-8")
                self.assertIn("device_type: adalm_pluto", text)
                self.assertIn("serial: 104473f6", text)
                records = serverrf_cli._read_device_records()
                self.assertEqual(records[1]["TYPE"], "adalm_pluto")
                self.assertEqual(records[1]["IDENT"], "104473f6")
                self.assertEqual(records[1]["IDENT_KIND"], "iio_serial")
                self.assertFalse(Path(tmp, "devices.env").exists())

    def test_device_cli_migrates_legacy_env_inventory_to_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(
                os.environ,
                {"REMOTERF_CONFIG_DIR": tmp},
                clear=False,
            ):
                Path(tmp, "devices.env").write_text(
                    "DEVICE_1_TYPE=adalm_pluto\n"
                    "DEVICE_1_NAME=Pluto A\n"
                    "DEVICE_1_IDENT_KIND=iio_serial\n"
                    "DEVICE_1_IDENT=104473f6\n",
                    encoding="utf-8",
                )

                self.assertEqual(
                    serverrf_cli._device_add_usrp("7:lab_usrp:31A2B3C"),
                    0,
                )

                inventory = yaml.safe_load(
                    Path(tmp, "devices.yml").read_text(encoding="utf-8")
                )
                self.assertEqual(
                    inventory,
                    {
                        "devices": [
                            {
                                "device_id": 1,
                                "device_type": "adalm_pluto",
                                "name": "Pluto A",
                                "init": {"serial": "104473f6"},
                            },
                            {
                                "device_id": 7,
                                "device_type": "usrp",
                                "name": "lab_usrp",
                                "init": {
                                    "profile": "usrp2901",
                                    "type": "b200",
                                    "serial": "31A2B3C",
                                },
                            },
                        ]
                    },
                )
                self.assertFalse(Path(tmp, "devices.env").exists())

    def test_server_cli_exposes_headless_runtime(self):
        with (
            patch.object(
                serverrf_cli,
                "_serve",
                return_value=0,
            ) as serve,
            patch.object(
                sys,
                "argv",
                ["serverrf", "--serve", "--headless"],
            ),
        ):
            self.assertEqual(serverrf_cli.main(), 0)
        serve.assert_called_once_with(headless=True)


if __name__ == "__main__":
    unittest.main()
