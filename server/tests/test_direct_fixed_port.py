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

"""The fixed port: a client dials the Server's one admitted UDP port with
QUIC, claims its session with the offer's secret, and is then a path like a
punched one -- same calls, same refusals, same caps."""

from __future__ import annotations

import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection

from remoteRF_server.common.grpc import grpc_pb2
from remoteRF_server.common.utils.process_arg import map_arg, unmap_arg
from remoteRF_server.server import direct_path

from test_gate_i_direct_path import SERVER_NAME, write_certs


def _offer(session="session-key", offer_id="abcd", bound=None):
    ice = json.dumps({"id": offer_id, "ufrag": "abcd", "pwd": "0123456789012345678901", "candidates": []})
    if bound is not None:
        return direct_path.offer_bound(session, "proxy", ice, bound=bound)
    reply = direct_path.offer(session, "tester", ice)
    assert "ace" not in reply, reply
    return json.loads(unmap_arg(reply["ice"]))


class FixedPortTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.ca_pem = write_certs(Path(self._tmp.name))
        direct_path.CERT_DIR = Path(self._tmp.name)
        direct_path.BIND_HOST = "127.0.0.1"
        self.addCleanup(direct_path.shutdown)
        self.addCleanup(setattr, direct_path, "CERT_DIR", None)
        self.addCleanup(setattr, direct_path, "BIND_HOST", "0.0.0.0")
        patches = [
            mock.patch.dict("os.environ", {"REMOTERF_STUN_SERVER": "off"}),
            mock.patch("remoteRF_server.server.global_onboarding.lan_endpoint", return_value="127.0.0.1:61005"),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        self.port = direct_path.start_listener(0)
        self.assertGreater(self.port, 0)

    async def _connect(self, answer, session=None, pinned=False):
        server_name = answer["server_name"] if pinned else SERVER_NAME
        configuration = QuicConfiguration(is_client=True, alpn_protocols=[direct_path.ALPN], server_name=server_name, idle_timeout=60)
        configuration.load_verify_locations(cadata=answer["ca_pem"].encode() if pinned else self.ca_pem)
        protocol = QuicConnectionProtocol(QuicConnection(configuration=configuration))
        host, port = answer["udp"].rsplit(":", 1)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: protocol, local_addr=("127.0.0.1", 0))
        protocol.connect((host, int(port)))
        await asyncio.wait_for(protocol.wait_connected(), 5)
        if session is not False:
            reader, writer = await protocol.create_stream()
            writer.write(direct_path.frame(json.dumps({"session": answer["session"] if session is None else session}).encode()))
            writer.write_eof()
            hello = json.loads(await asyncio.wait_for(direct_path.read_frame(reader), 5))
        else:
            hello = None
        return protocol, transport, hello

    async def _call(self, protocol, name, args):
        reader, writer = await protocol.create_stream()
        writer.write(direct_path.frame(grpc_pb2.GenericRPCRequest(function_name=name, args=args).SerializeToString()))
        writer.write_eof()
        response = grpc_pb2.GenericRPCResponse()
        response.ParseFromString(await asyncio.wait_for(direct_path.read_frame(reader), 10))
        return {k: unmap_arg(v) for k, v in response.results.items()}

    async def _gone(self, seconds=5.0):
        deadline = time.monotonic() + seconds
        while direct_path._paths and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        return not direct_path._paths

    def test_the_offer_names_the_fixed_port_and_a_session_claims_it(self):
        calls = []

        def fake_run_rpc(*, function_name, args):
            calls.append(function_name)
            return {"echo": map_arg(unmap_arg(args["a"]))}

        async def run():
            answer = await asyncio.get_running_loop().run_in_executor(None, _offer)
            self.assertEqual(answer["udp"], f"127.0.0.1:{self.port}")
            protocol, transport, hello = await self._connect(answer)
            try:
                self.assertEqual(hello, {"ok": True})
                self.assertEqual(list(direct_path._paths), ["session-key/abcd"])
                self.assertIsInstance(direct_path._paths["session-key/abcd"], direct_path._Conn)
                self.assertEqual((await self._call(protocol, "adalm_pluto:rx_lo:GET", {"a": map_arg("tok")}))["echo"], "tok")
                self.assertIn("not available", (await self._call(protocol, "ACC:get_dev", {}))["a"])
                self.assertEqual(calls, ["adalm_pluto:rx_lo:GET"])
                # The session secret was one-time.
                protocol2, transport2, hello2 = await self._connect(answer)
                self.assertEqual(hello2, {"a": "unknown session"})
                protocol2.close(); transport2.close()
            finally:
                protocol.close(); transport.close()
            self.assertTrue(await self._gone())

        with mock.patch("remoteRF_server.server.rpc_manager.rpc_manager.run_rpc", fake_run_rpc):
            asyncio.run(run())

    def test_a_connection_that_never_says_hello_is_dropped(self):
        async def run():
            answer = await asyncio.get_running_loop().run_in_executor(None, _offer)
            protocol, transport, _ = await self._connect(answer, session=False)
            try:
                await asyncio.wait_for(protocol.wait_closed(), 5)
            finally:
                transport.close()
            self.assertNotIn("session-key/abcd", {k: v for k, v in direct_path._paths.items() if isinstance(v, direct_path._Conn)})

        with mock.patch.object(direct_path, "HELLO_SECONDS", 0.5):
            asyncio.run(run())

    def test_a_bound_session_is_authorized_per_call_and_a_refusal_closes(self):
        seen, verdict = [], [None]

        def run_bound(name, args):
            return {"value": map_arg(42)}

        async def run():
            bound = {"run": run_bound, "authorize": lambda name: (seen.append(name), verdict[0])[1]}
            answer = await asyncio.get_running_loop().run_in_executor(None, lambda: _offer("federated/r/1", "p1", bound))
            protocol, transport, hello = await self._connect(answer)
            try:
                self.assertEqual(hello, {"ok": True})
                self.assertEqual((await self._call(protocol, "test:rx:GET", {"a": map_arg("x")}))["value"], 42)
                verdict[0] = "the reservation has ended"
                self.assertIn("reservation has ended", (await self._call(protocol, "test:rx:GET", {}))["a"])
                self.assertEqual(seen, ["test:rx:GET", "test:rx:GET"])
                self.assertTrue(await self._gone())
            finally:
                protocol.close(); transport.close()

        asyncio.run(run())

    def test_a_bound_answer_pins_this_servers_certificate(self):
        bound = {"run": lambda name, args: {"value": map_arg(42)}, "authorize": lambda name: None}

        async def run():
            answer = await asyncio.get_running_loop().run_in_executor(None, lambda: _offer("federated/r/2", "p2", bound))
            self.assertEqual(answer["server_name"], SERVER_NAME)
            self.assertEqual(answer["ca_pem"], self.ca_pem.decode())
            protocol, transport, hello = await self._connect(answer, pinned=True)
            try:
                self.assertEqual(hello, {"ok": True})
            finally:
                protocol.close(); transport.close()
            self.assertTrue(await self._gone())

        with mock.patch.object(direct_path, "hostname", return_value=SERVER_NAME):
            asyncio.run(run())
            (Path(self._tmp.name) / "ca.crt").unlink()
            with self.assertRaises(OSError):
                _offer("federated/r/3", "p3", bound)
        self.assertEqual(direct_path._paths, {})  # no CA, no path prepared

    def test_the_session_cap_applies_to_fixed_port_paths(self):
        cap = direct_path.MAX_PATHS_PER_SESSION

        async def run():
            conns = []
            for i in range(cap + 1):
                answer = await asyncio.get_running_loop().run_in_executor(None, lambda i=i: _offer("session-key", f"proc-{i}"))
                conns.append(await self._connect(answer))
            try:
                await asyncio.sleep(0.2)
                fixed = [k for k, v in direct_path._paths.items() if isinstance(v, direct_path._Conn)]
                self.assertEqual(len(fixed), cap)
                self.assertNotIn("session-key/proc-0", fixed)  # the oldest made room
            finally:
                for protocol, transport, _ in conns:
                    protocol.close(); transport.close()

        asyncio.run(run())

    def test_without_a_lan_address_the_offer_carries_no_fixed_port(self):
        with mock.patch("remoteRF_server.server.global_onboarding.lan_endpoint", return_value=None):
            answer = _offer(offer_id="nolan")
        self.assertNotIn("udp", answer)
        self.assertNotIn("session", answer)
