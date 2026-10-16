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

import unittest
from unittest.mock import patch

from remoteRF_server.common.grpc import grpc_pb2
from remoteRF_server.common.grpc.v2_codec import decode_value, encode_value
from remoteRF_server.common.utils import map_arg, unmap_arg
from remoteRF_server.server.device_manager import VirtualDevice
from remoteRF_server.server.host_dynamic_v2 import HostDynamicV2Proxy


class HostDynamicV2ProxyTests(unittest.TestCase):
    def setUp(self):
        self.proxy = HostDynamicV2Proxy()
        self.device = VirtualDevice(
            gid=7,
            host_id="lab-host",
            device_id="7",
            label="usrp2901_lab",
            serial="31A2B3C",
            kind="usrp",
        )
        self.forwarded = []

        def forward(
            registry,
            *,
            host_id,
            device_id,
            function_name,
            args,
            timeout_sec,
        ):
            operation = function_name.split(":", 1)[1]
            wire = unmap_arg(args["wire"])
            self.forwarded.append((host_id, device_id, operation, wire))

            if operation == "GetSchema":
                request = grpc_pb2.GetSchemaRequest.FromString(wire)
                self.assertEqual(request.token, "")  # never sent to the host
                self.assertEqual(list(request.schema_versions), ["2.0"])
                response = grpc_pb2.GetSchemaResponse(
                    schema_version="2.0",
                    schema_json='{"schema_version":"2.0"}',
                    schema_hash="sha256:test",
                )
            elif operation == "OpenSession":
                self.assertEqual(grpc_pb2.OpenSessionRequest.FromString(wire).token, "")
                response = grpc_pb2.OpenSessionResponse(
                    session_id="host-session",
                    device_handle="host-root",
                    schema_hash="sha256:test",
                )
            elif operation == "Invoke":
                request = grpc_pb2.InvokeRequest.FromString(wire)
                self.assertEqual(request.session_id, "host-session")
                response = grpc_pb2.InvokeResponse(result=encode_value(1.5))
            elif operation == "SampleFrame":
                request = grpc_pb2.SampleFrame.FromString(wire)
                response = grpc_pb2.SampleFrame()
                response.CopyFrom(request)
                response.kind = grpc_pb2.SAMPLE_FRAME_RESULT
            elif operation == "CloseSession":
                request = grpc_pb2.CloseSessionRequest.FromString(wire)
                self.assertEqual(request.session_id, "host-session")
                response = grpc_pb2.CloseResponse(closed=True)
            else:
                raise AssertionError(f"unexpected operation {operation}")
            return {"wire": map_arg(response.SerializeToString())}

        self.patches = [
            patch(
                "remoteRF_server.server.host_dynamic_v2.resolve_gid_for_token",
                return_value=7,
            ),
            patch(
                "remoteRF_server.server.host_dynamic_v2.get_device_by_id",
                return_value=(self.device, "salt", "hash"),
            ),
            patch(
                "remoteRF_server.server.host_dynamic_v2.hts.get_tunnel_registry",
                # A host that reported no schema hash: everything goes to the host.
                return_value=type("Registry", (), {"get_host_device_schema_hash": lambda self, host_id, device_id, version="v1": ""})(),
            ),
            patch(
                "remoteRF_server.server.host_dynamic_v2.hts.handle_host_device",
                side_effect=forward,
            ),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_control_and_binary_sample_messages_route_to_host_session(self):
        schema = self.proxy.get_schema(
            grpc_pb2.GetSchemaRequest(
                token="reservation-token",
                schema_versions=["2.0"],
            )
        )
        self.assertEqual(schema.schema_version, "2.0")

        opened = self.proxy.open(
            grpc_pb2.OpenSessionRequest(
                token="reservation-token",
                control_protocol_version="2.0",
                streaming_protocol_version="1.0",
            )
        )
        self.assertEqual(opened.session_id, "host-session")
        self.assertTrue(self.proxy.is_remote_session("host-session"))

        invoked = self.proxy.invoke(
            grpc_pb2.InvokeRequest(
                session_id="host-session",
                handle="host-root",
                method="get_time_now",
            )
        )
        self.assertEqual(decode_value(invoked.result), 1.5)

        sample = self.proxy.sample_frame(
            grpc_pb2.SampleFrame(
                session_id="host-session",
                handle="rx-handle",
                operation_id="rx-operation",
                kind=grpc_pb2.SAMPLE_FRAME_DATA,
                payload=b"\x00\x01\x02\xff",
            )
        )
        self.assertEqual(sample.payload, b"\x00\x01\x02\xff")
        self.assertEqual(sample.kind, grpc_pb2.SAMPLE_FRAME_RESULT)

        closed = self.proxy.close_session(
            grpc_pb2.CloseSessionRequest(session_id="host-session")
        )
        self.assertTrue(closed.closed)
        self.assertFalse(self.proxy.is_remote_session("host-session"))
        self.assertEqual(
            [item[2] for item in self.forwarded],
            ["GetSchema", "OpenSession", "Invoke", "SampleFrame", "CloseSession"],
        )

    def test_reservation_end_closes_sessions_then_resets_the_host_device(self):
        from remoteRF_server.server import host_dynamic_v2

        self.proxy.open(grpc_pb2.OpenSessionRequest(token="reservation-token"))
        sent = []

        class Registry:
            def send_control(self, host_id, *, kind, device_id, payload):
                sent.append((host_id, kind, device_id, payload, [item[2] for item in calls]))
                return True

        calls = self.forwarded
        with patch.object(host_dynamic_v2, "host_session_proxy", self.proxy), patch(
            "remoteRF_server.server.host_dynamic_v2.hts.get_tunnel_registry", return_value=Registry()
        ):
            host_dynamic_v2._end_host_reservation(7)
        self.assertFalse(self.proxy.is_remote_session("host-session"))
        # The frame goes before the lab closes its routes (its CloseSession forward).
        self.assertEqual(sent[0][:3], ("lab-host", "reservation_end", "7"))
        self.assertEqual(set(sent[0][3]), {"at"})
        self.assertIsInstance(sent[0][3]["at"], float)
        self.assertEqual(sent[0][4], ["OpenSession"])
        self.assertEqual([item[2] for item in calls], ["OpenSession", "CloseSession"])


class HostRegistryControlTests(unittest.TestCase):
    def test_send_control_and_close_all_sessions(self):
        import tempfile
        from remoteRF_server.common.grpc import grpc_host_pb2
        from remoteRF_server.host import host_tunnel_server as hts

        with tempfile.TemporaryDirectory() as tmp, patch.object(hts, "cfg_dir_from_file", return_value=__import__("pathlib").Path(tmp)):
            registry = hts.HostTunnelRegistry()
            session = hts.HostSession("lab-host")
            registry.register_host("lab-host", session)
            self.assertTrue(registry.send_control("lab-host", kind="reservation_end", device_id="7"))
            frame = session.out_q.get_nowait()
            self.assertEqual(frame.WhichOneof("msg"), "control")
            self.assertEqual((frame.control.kind, frame.control.device_id), ("reservation_end", "7"))
            self.assertFalse(registry.send_control("other", kind="reservation_end", device_id="7"))
            self.assertEqual(registry.close_all_sessions(), 1)
            self.assertFalse(session.alive)
            self.assertIsNone(session.out_q.get_nowait())  # the stream's end sentinel
            self.assertIsInstance(frame, grpc_host_pb2.HostFrame)

    def test_hosts_wipe_closes_live_tunnels(self):
        import tempfile
        from pathlib import Path
        from remoteRF_server.host import host_tunnel_server as hts
        from remoteRF_server.server import grpc_server

        with tempfile.TemporaryDirectory() as tmp, patch.object(hts, "cfg_dir_from_file", return_value=Path(tmp)):
            registry = hts.HostTunnelRegistry()
            session = hts.HostSession("lab-host")
            registry.register_host("lab-host", session)
            with patch.object(hts, "get_tunnel_registry", return_value=registry), patch.object(
                grpc_server, "_host_state_files", return_value=[]
            ):
                grpc_server._cmd_hosts_wipe(yes=True)
            self.assertFalse(session.alive)
            self.assertEqual(registry.list_hosts(), {})



class HostLabCopyTests(unittest.TestCase):
    """Phase 2: a host device on a built-in driver is described by the lab's own copy."""

    def setUp(self):
        from remoteRF_server.drivers.usrp.usrp_schema import UsrpSchema

        self.schema = UsrpSchema()
        self.device = VirtualDevice(gid=7, host_id="lab-host", device_id="7", kind="usrp")
        self.reported = {("7", "v1"): self.schema.get_idl_hash(), ("7", "v2"): self.schema.get_idl_v2()["schema_hash"]}

        class Registry:
            def get_host_device_schema_hash(_self, host_id, device_id, version="v1"):
                assert host_id == "lab-host"
                return self.reported.get((device_id, version), "")

        for item in (
            patch("remoteRF_server.server.host_dynamic_v2.hts.get_tunnel_registry", return_value=Registry()),
            patch("remoteRF_server.server.host_dynamic_v2.get_device_schema", side_effect=lambda gid: self.schema),
            patch("remoteRF_server.server.host_dynamic_v2.resolve_gid_for_token", return_value=7),
            patch("remoteRF_server.server.host_dynamic_v2.get_device_by_id", return_value=(self.device, "s", "h")),
        ):
            item.start()
            self.addCleanup(item.stop)

    def test_only_a_built_in_hash_the_lab_also_has(self):
        from remoteRF_server.server.host_dynamic_v2 import lab_copy

        self.assertIs(lab_copy(7, self.device), self.schema)
        self.reported[("7", "v1")] = "sha256:" + "0" * 64  # a custom host driver
        self.assertIsNone(lab_copy(7, self.device))
        self.reported[("7", "v1")] = ""  # a host that reported nothing yet
        self.assertIsNone(lab_copy(7, self.device))

        from remoteRF_server.drivers.rtl_sdr.rtl_sdr_schema import RtlSdrSchema

        self.reported[("7", "v1")] = RtlSdrSchema().get_idl_hash()  # built-in, but not the lab's class for this device
        self.assertIsNone(lab_copy(7, self.device))

    def test_v2_get_schema_from_the_lab_copy_or_the_host(self):
        forwarded = []
        proxy = HostDynamicV2Proxy()
        with patch.object(HostDynamicV2Proxy, "_forward", side_effect=lambda *a, **k: forwarded.append(a[1]) or grpc_pb2.GetSchemaResponse()):
            local = proxy.get_schema(grpc_pb2.GetSchemaRequest(token="t", schema_versions=["2.0"]))
            self.assertEqual(local.schema_hash, self.schema.get_idl_v2()["schema_hash"])
            self.assertEqual(forwarded, [])
            self.reported[("7", "v2")] = "sha256:" + "0" * 64  # same v1, other v2 manifest: the host answers
            proxy.get_schema(grpc_pb2.GetSchemaRequest(token="t", schema_versions=["2.0"]))
            self.assertEqual(forwarded, ["GetSchema"])

    def test_v1_get_drivers_from_the_lab_copy_or_the_host(self):
        from remoteRF_server.server.rpc_manager import rpc_manager

        with patch("remoteRF_server.server.rpc_manager.get_device_by_id", return_value=(self.device, "s", "h")), patch(
            "remoteRF_server.server.rpc_manager.get_device_schema", return_value=self.schema
        ), patch.object(type(rpc_manager), "_fetch_host_idl", return_value={"from": map_arg("host")}) as fetch:
            args = {"device_id": map_arg(7)}
            local = rpc_manager._handle_idl("get_drivers", args)
            self.assertEqual(unmap_arg(local["schema_hash"]), self.schema.get_idl_hash())
            fetch.assert_not_called()
            self.reported[("7", "v1")] = "sha256:" + "0" * 64
            self.assertEqual(rpc_manager._handle_idl("get_drivers", args), {"from": map_arg("host")})

    def test_registry_keeps_the_reported_hash_until_forget(self):
        import tempfile
        from pathlib import Path
        from remoteRF_server.host import host_tunnel_server as real_hts

        with tempfile.TemporaryDirectory() as tmp, patch.object(real_hts, "cfg_dir_from_file", return_value=Path(tmp)):
            registry = real_hts.HostTunnelRegistry()
            device = lambda gid: real_hts.host_tunnel_pb2.DeviceInfo(device_id=gid, local_id=int(gid))  # noqa: E731
            registry.register_host("lab-host", real_hts.HostSession("lab-host"))
            registry.announce_devices("lab-host", [device("7"), device("8")], full_snapshot=True)
            registry.register_host("other", real_hts.HostSession("other"))
            registry.store_host_device_schema_hash("lab-host", "7", "sha256:abc")
            registry.store_host_device_schema_hash("lab-host", "8", "sha256:def")
            registry.store_host_device_schema_hash("other", "7", "sha256:evil")  # not its device
            self.assertEqual(registry.get_host_device_schema_hash("lab-host", "7"), "sha256:abc")
            self.assertEqual(registry.get_host_device_schema_hash("other", "7"), "")
            registry.announce_devices("lab-host", [device("7")], full_snapshot=True)  # 8 went away
            self.assertEqual(registry.get_host_device_schema_hash("lab-host", "8"), "")
            registry.register_host("lab-host", real_hts.HostSession("lab-host"), replace_if_stale_ms=0)  # a new session
            self.assertEqual(registry.get_host_device_schema_hash("lab-host", "7"), "")


if __name__ == "__main__":
    unittest.main()
