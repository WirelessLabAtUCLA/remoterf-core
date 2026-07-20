"""Opt-in RemoteRF v2 RX data-path test using a real USRP-2901."""
from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

import numpy as np

from remoteRF_server.common.grpc import grpc_pb2
from remoteRF_server.drivers.usrp.policy import USRPPolicy
from remoteRF_server.server.dynamic_v2 import (
    SampleDataV1Servicer,
    SessionManager,
)


SERIAL = os.getenv("REMOTERF_TEST_USRP_SERIAL", "").strip()
if SERIAL:
    from remoteRF_server.drivers.usrp.usrp_schema import UsrpSchema
else:
    UsrpSchema = None


@unittest.skipUnless(SERIAL, "set REMOTERF_TEST_USRP_SERIAL for hardware tests")
class RemoteRFUSRP2901RXHardwareTests(unittest.TestCase):
    def test_session_control_handle_and_binary_rx_path(self):
        inventory = UsrpSchema()
        inventory.bind_inventory({"serial": SERIAL})
        context = {
            "schema": inventory,
            "dtype": "usrp",
            "ident": SERIAL,
            "name": "usrp2901_hardware_test",
        }
        manager = SessionManager()
        session = None
        baseline = None
        with (
            patch(
                "remoteRF_server.server.dynamic_v2.resolve_gid_for_token",
                return_value=1,
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
            try:
                session = manager.open("hardware-test-token")
                self.assertEqual(
                    session.capabilities["hardware_profile"],
                    "usrp2901",
                )
                device = session.schema.device
                baseline = {
                    "rate": [
                        device.get_rx_rate(chan) for chan in range(2)
                    ],
                    "freq": [
                        device.get_rx_freq(chan) for chan in range(2)
                    ],
                    "gain": [
                        device.get_rx_gain(chan) for chan in range(2)
                    ],
                    "bandwidth": [
                        device.get_rx_bandwidth(chan) for chan in range(2)
                    ],
                    "antenna": [
                        device.get_rx_antenna(chan) for chan in range(2)
                    ],
                }
                for chan in range(2):
                    manager.invoke(
                        session.session_id,
                        session.root_handle,
                        "set_rx_rate",
                        {"rate": 1e6, "chan": chan},
                        overload_id="default",
                    )
                    manager.invoke(
                        session.session_id,
                        session.root_handle,
                        "set_rx_freq",
                        {"tune_request": 100e6, "chan": chan},
                        overload_id="default",
                    )
                    manager.invoke(
                        session.session_id,
                        session.root_handle,
                        "set_rx_gain",
                        {"gain": 10.0, "chan": chan},
                        overload_id="gain_chan",
                    )
                stream, _ = manager.invoke(
                    session.session_id,
                    session.root_handle,
                    "get_rx_stream",
                    {},
                    positional_args=[
                        {
                            "__uhd_type__": "StreamArgs",
                            "cpu_format": "fc32",
                            "otw_format": "sc16",
                            "channels": [0, 1],
                            "args": {},
                        }
                    ],
                    overload_id="default",
                )
                handle = stream["__remoterf_handle__"]
                generation = stream["generation"]
                first_start_time = (
                    device.get_time_now().get_real_secs() + 0.5
                )
                manager.invoke(
                    session.session_id,
                    handle,
                    "issue_stream_cmd",
                    {},
                    positional_args=[
                        {
                            "__uhd_type__": "StreamCMD",
                            "mode": "num_done",
                            "num_samps": 4096,
                            "stream_now": False,
                            "time_spec": {
                                "__uhd_type__": "TimeSpec",
                                "secs": first_start_time,
                            },
                        }
                    ],
                    overload_id="default",
                )
                frames = [
                    grpc_pb2.SampleFrame(
                        session_id=session.session_id,
                        handle=handle,
                        generation=generation,
                        operation_id="hardware-rx",
                        sequence=0,
                        direction=grpc_pb2.SAMPLE_DIRECTION_RX,
                        kind=grpc_pb2.SAMPLE_FRAME_OPEN,
                        credits=1,
                    ),
                    grpc_pb2.SampleFrame(
                        session_id=session.session_id,
                        handle=handle,
                        generation=generation,
                        operation_id="hardware-rx",
                        sequence=1,
                        direction=grpc_pb2.SAMPLE_DIRECTION_RX,
                        kind=grpc_pb2.SAMPLE_FRAME_REQUEST,
                        dtype=np.dtype(np.complex64).str,
                        shape=[2, 4096],
                        channels=[0, 1],
                        sample_count=4096,
                        timeout_sec=2.0,
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
                ):
                    responses = list(
                        SampleDataV1Servicer().SampleStream(
                            iter(frames),
                            None,
                        )
                    )
                data = responses[-1]
                self.assertEqual(
                    data.kind,
                    grpc_pb2.SAMPLE_FRAME_DATA,
                    msg=f"{data.error.code}: {data.error.message}",
                )
                self.assertGreater(data.sample_count, 0)
                self.assertLessEqual(data.sample_count, 4096)
                self.assertEqual(
                    len(data.payload),
                    2
                    * data.sample_count
                    * np.dtype(np.complex64).itemsize,
                )
                metadata = json.loads(data.metadata_json)
                self.assertEqual(metadata["error_code"], "none")
                manager.close_handle(session.session_id, handle)
                for chan in range(2):
                    manager.invoke(
                        session.session_id,
                        session.root_handle,
                        "set_rx_rate",
                        {"rate": 1e6, "chan": chan},
                        overload_id="default",
                    )

                multi_stream, _ = manager.invoke(
                    session.session_id,
                    session.root_handle,
                    "get_rx_stream",
                    {},
                    positional_args=[
                        {
                            "__uhd_type__": "StreamArgs",
                            "cpu_format": "fc32",
                            "otw_format": "sc16",
                            "channels": [0],
                            "args": {},
                        }
                    ],
                    overload_id="default",
                )
                multi_handle = multi_stream["__remoterf_handle__"]
                manager.invoke(
                    session.session_id,
                    multi_handle,
                    "issue_stream_cmd",
                    {},
                    positional_args=[
                        {
                            "__uhd_type__": "StreamCMD",
                            "mode": "num_done",
                            "num_samps": 2048,
                            "stream_now": True,
                        }
                    ],
                    overload_id="default",
                )
                multi_frames = [
                    grpc_pb2.SampleFrame(
                        session_id=session.session_id,
                        handle=multi_handle,
                        generation=multi_stream["generation"],
                        operation_id="hardware-rx-two-channel",
                        sequence=0,
                        direction=grpc_pb2.SAMPLE_DIRECTION_RX,
                        kind=grpc_pb2.SAMPLE_FRAME_OPEN,
                        credits=1,
                    ),
                    grpc_pb2.SampleFrame(
                        session_id=session.session_id,
                        handle=multi_handle,
                        generation=multi_stream["generation"],
                        operation_id="hardware-rx-two-channel",
                        sequence=1,
                        direction=grpc_pb2.SAMPLE_DIRECTION_RX,
                        kind=grpc_pb2.SAMPLE_FRAME_REQUEST,
                        dtype=np.dtype(np.complex64).str,
                        shape=[2048],
                        channels=[0],
                        sample_count=2048,
                        timeout_sec=2.0,
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
                ):
                    multi_responses = list(
                        SampleDataV1Servicer().SampleStream(
                            iter(multi_frames),
                            None,
                        )
                    )
                multi_data = multi_responses[-1]
                self.assertEqual(
                    multi_data.kind,
                    grpc_pb2.SAMPLE_FRAME_DATA,
                    msg=(
                        f"{multi_data.error.code}: "
                        f"{multi_data.error.message}"
                    ),
                )
                self.assertGreater(
                    multi_data.sample_count,
                    0,
                    msg=multi_data.metadata_json,
                )
                self.assertEqual(
                    len(multi_data.payload),
                    multi_data.sample_count
                    * np.dtype(np.complex64).itemsize,
                )
            finally:
                if session is not None and baseline is not None:
                    device = session.schema.device
                    if device is not None:
                        for chan in range(2):
                            device.set_rx_rate(
                                baseline["rate"][chan],
                                chan,
                            )
                            device.set_rx_freq(
                                baseline["freq"][chan],
                                chan,
                            )
                            device.set_rx_gain(
                                baseline["gain"][chan],
                                chan,
                            )
                            device.set_rx_bandwidth(
                                baseline["bandwidth"][chan],
                                chan,
                            )
                            device.set_rx_antenna(
                                baseline["antenna"][chan],
                                chan,
                            )
                if session is not None:
                    manager.close(session.session_id)


if __name__ == "__main__":
    unittest.main()
