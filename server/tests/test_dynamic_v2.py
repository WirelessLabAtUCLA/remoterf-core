import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from remoteRF_server import serverrf_cli
from remoteRF_server.common.grpc import grpc_pb2
from remoteRF_server.common.grpc.v2_codec import decode_value, encode_value
from remoteRF_server.common.idl.v2 import validate_schema
from remoteRF_server.drivers.usrp.policy import USRPPolicy
from remoteRF_server.drivers.usrp.uhd_manifest import (
    TARGET_UHD_VERSION,
    assert_release_coverage,
    build_usrp_schema_v2,
)
from remoteRF_server.server.dynamic_v2 import (
    DynamicControlV2Servicer,
    SampleDataV1Servicer,
    SessionManager,
)
from remoteRF_server.server.v2_errors import (
    RemoteRFOverloadError,
    RemoteRFPolicyError,
    RemoteRFSessionExpiredError,
    RemoteRFStaleHandleError,
)


class FakeRXStreamer:
    def get_max_num_samps(self):
        return 256

    def recv(self, buffer, metadata, timeout, one_packet):
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


class FakeLiveSchema:
    def __init__(self):
        self.device = FakeNativeDevice()
        self.closed = False

    def get_capabilities_v2(self, policy_restrictions=None):
        return {
            "hardware_profile": "usrp2901",
            "uhd_version": TARGET_UHD_VERSION,
            "uhd_abi": "test",
            "policy_restrictions": dict(policy_restrictions or {}),
        }

    def invoke_native(self, method, args, positional_args=None):
        if method == "get_rx_stream":
            return FakeRXStreamer()
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
    def test_manifest_is_valid_and_unqualified_entries_block_release(self):
        schema = build_usrp_schema_v2()
        validate_schema(schema)
        self.assertEqual(schema["schema_version"], "2.0")
        self.assertGreaterEqual(len(schema["methods"]), 140)
        self.assertIn("usrp2901", schema["hardware_profiles"])
        self.assertIn("deferred", schema["coverage"].values())
        with self.assertRaisesRegex(RuntimeError, "deferred"):
            assert_release_coverage(schema)

    def test_dynamic_value_ndarray_is_binary_and_exact(self):
        original = np.array([[1 + 2j, 3 + 4j]], dtype=np.complex64)
        encoded = encode_value(original)
        self.assertEqual(encoded.WhichOneof("value"), "ndarray_value")
        self.assertEqual(encoded.ndarray_value.data, original.tobytes())
        decoded = decode_value(encoded)
        self.assertEqual(decoded.dtype, original.dtype)
        np.testing.assert_array_equal(decoded, original)

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

    def test_policy_denies_tx_by_default_and_enforces_configured_limits(self):
        denied = USRPPolicy({})
        with self.assertRaises(RemoteRFPolicyError):
            denied.check_control("set_tx_freq", {"tune_request": 915e6})
        with self.assertRaises(RemoteRFPolicyError):
            denied.check_control("set_gpio_attr", {})

        policy = USRPPolicy(
            {
                "tx_enabled": True,
                "tx_frequency_ranges_hz": [[900e6, 930e6]],
                "max_tx_gain_db": 20,
                "max_tx_sample_rate_sps": 2e6,
                "max_burst_seconds": 1.0,
                "max_duty_cycle": 0.1,
                "duty_cycle_window_seconds": 60,
            }
        )
        policy.check_control("set_tx_freq", {"tune_request": 915e6})
        policy.check_control("set_tx_gain", {"gain": 19})
        with self.assertRaises(RemoteRFPolicyError):
            policy.check_control("set_tx_freq", {"tune_request": 2.4e9})
        with self.assertRaises(RemoteRFPolicyError):
            policy.check_control("set_tx_gain", {"gain": 21})

        low_level = USRPPolicy(
            {
                "low_level_write_enabled": True,
                "low_level_write_methods": ["set_gpio_attr", "set"],
                "gpio_write_masks": {"FP0": 0x03},
                "property_write_paths": ["/mboards/0/user"],
            }
        )
        low_level.check_control(
            "set_gpio_attr",
            {"bank": "FP0", "mask": 0x03},
        )
        with self.assertRaises(RemoteRFPolicyError):
            low_level.check_control(
                "set_gpio_attr",
                {"bank": "FP0", "mask": 0x04},
            )
        low_level.check_handle_call(
            "uhd.property_tree",
            "set",
            {"__args__": ["/mboards/0/user/value", 1]},
        )
        with self.assertRaises(RemoteRFPolicyError):
            low_level.check_handle_call(
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
            result, _ = manager.invoke(
                session.session_id,
                session.root_handle,
                "get_rx_stream",
                {"stream_args": {}},
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

    def test_binary_rx_stream_returns_only_native_received_prefix(self):
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
                {"stream_args": {}},
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
            self.assertEqual(data.sample_count, 2)
            self.assertEqual(len(data.payload), 2 * np.dtype(np.complex64).itemsize)
            np.testing.assert_array_equal(
                np.frombuffer(data.payload, dtype=np.complex64),
                np.array([1 + 2j, 3 + 4j], dtype=np.complex64),
            )
            self.assertEqual(json.loads(data.metadata_json)["error_code"], "none")
            self.assertEqual(
                malformed[-1].error.code,
                "RemoteRFProtocolError",
            )
            manager.close(session.session_id)

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

    def test_usrp_cli_writes_runtime_yaml_inventory_and_legacy_mirror(self):
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
                self.assertTrue(Path(tmp, "devices.env").exists())


if __name__ == "__main__":
    unittest.main()
