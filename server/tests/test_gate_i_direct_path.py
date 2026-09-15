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

"""Gate I: ICE + QUIC on this machine with both ends in-process, framing,
device-plane routing and RELAYED classification of direct-path peers."""

from __future__ import annotations

import asyncio
import datetime
import json
import unittest
from pathlib import Path
from unittest import mock

import numpy as np
from aioice import Candidate, Connection
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from remoteRF_server.common.grpc import grpc_pb2
from remoteRF_server.common.utils.process_arg import map_arg, unmap_arg
from remoteRF_server.server import direct_path
from remoteRF_server.server.global_onboarding import RELAYED, is_offsite

SERVER_NAME = "direct.test"


def write_certs(cert_dir: Path) -> bytes:
    """A throwaway CA and a server certificate for SERVER_NAME; returns the CA PEM."""
    now = datetime.datetime.now(datetime.timezone.utc)

    def cert(subject, issuer, key, signer, *, ca):
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        )
        if not ca:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(SERVER_NAME)]), critical=False
            )
        return builder.sign(signer, hashes.SHA256())

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RemoteRF test CA")])
    ca_cert = cert(ca_name, ca_name, ca_key, ca_key, ca=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = cert(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVER_NAME)]),
        ca_name, key, ca_key, ca=False,
    )
    (cert_dir / "server.crt").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (cert_dir / "server.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    (cert_dir / "ca.crt").write_bytes(ca_pem)
    return ca_pem


class FramingTests(unittest.TestCase):
    def test_round_trip(self):
        async def run():
            reader = asyncio.StreamReader()
            reader.feed_data(direct_path.frame(b"abc") + direct_path.frame(b""))
            return await direct_path.read_frame(reader), await direct_path.read_frame(reader)

        self.assertEqual(asyncio.run(run()), (b"abc", b""))

    def test_oversized_frame_is_refused(self):
        async def run():
            reader = asyncio.StreamReader()
            reader.feed_data((direct_path.MAX_FRAME + 1).to_bytes(4, "big"))
            await direct_path.read_frame(reader)

        with self.assertRaises(ValueError):
            asyncio.run(run())


class PeerClassificationTests(unittest.TestCase):
    def test_local_addresses(self):
        with mock.patch(
            "remoteRF_server.server.global_onboarding.detected_lan_ip",
            return_value="164.67.195.210",
        ):
            for host in ("127.0.0.1", "::1", "fe80::1", "10.4.5.6", "192.168.1.20",
                         "::ffff:192.168.1.20", "164.67.195.7"):
                self.assertFalse(is_offsite(host), host)
            for host in ("8.8.4.4", "164.67.196.1", "100.64.0.1", "2607:f8b0::1",
                         "fd7a:115c:a1e0::8601:f120", "bogus"):
                self.assertTrue(is_offsite(host), host)


class DispatchTests(unittest.TestCase):
    def _run(self, name, peer, args=None):
        request = grpc_pb2.GenericRPCRequest(function_name=name, args=args or {})
        seen = {}

        def fake_run_rpc(*, function_name, args):
            seen["relayed"] = RELAYED.get()
            return {"echo": map_arg(function_name)}

        with mock.patch("remoteRF_server.server.rpc_manager.rpc_manager.run_rpc", fake_run_rpc), \
             mock.patch("remoteRF_server.server.global_onboarding.detected_lan_ip",
                        return_value="164.67.195.210"):
            return direct_path._dispatch(request, peer), seen

    def test_control_plane_is_refused(self):
        for name in ("ACC:login", "ACC:get_dev", "echo", "RemoteAdmin:x"):
            results, seen = self._run(name, "8.8.4.4")
            self.assertIn("not available on the direct path", unmap_arg(results["a"]), name)
            self.assertEqual(seen, {})

    def test_device_plane_sets_relayed_from_the_peer(self):
        results, seen = self._run("adalm_pluto:rx_lo:GET", "8.8.4.4")
        self.assertEqual(unmap_arg(results["echo"]), "adalm_pluto:rx_lo:GET")
        self.assertTrue(seen["relayed"])
        _, seen = self._run("IDL:get_drivers", "192.168.4.2")
        self.assertFalse(seen["relayed"])
        self.assertFalse(RELAYED.get())


class LoopbackPathTests(unittest.TestCase):
    """Both ends in this process: the real server module answers a real offer."""

    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.ca_pem = write_certs(Path(self._tmp.name))
        direct_path.CERT_DIR = Path(self._tmp.name)
        self.addCleanup(direct_path.shutdown)
        self.addCleanup(setattr, direct_path, "CERT_DIR", None)

    async def _client(self, offer_id="abcd"):
        loop = asyncio.get_running_loop()
        ice = Connection(ice_controlling=True, use_ipv6=False)
        await ice.gather_candidates()
        offer = json.dumps({
            "id": offer_id,
            "ufrag": ice.local_username,
            "pwd": ice.local_password,
            "candidates": [c.to_sdp() for c in ice.local_candidates],
        })
        # The offer RPC is synchronous on the Server: a gRPC worker thread calls it.
        reply = await loop.run_in_executor(None, direct_path.offer, "session-key", "tester", offer)
        self.assertNotIn("ace", reply, reply)
        answer = json.loads(unmap_arg(reply["ice"]))
        ice.remote_username = answer["ufrag"]
        ice.remote_password = answer["pwd"]
        for sdp in answer["candidates"]:
            await ice.add_remote_candidate(Candidate.from_sdp(sdp))
        await ice.add_remote_candidate(None)
        await asyncio.wait_for(ice.connect(), 10)
        peer = direct_path.peer_address(ice)

        configuration = QuicConfiguration(
            is_client=True, alpn_protocols=[direct_path.ALPN], server_name=SERVER_NAME
        )
        configuration.load_verify_locations(cadata=self.ca_pem)
        protocol = QuicConnectionProtocol(QuicConnection(configuration=configuration))
        protocol.connection_made(direct_path._IceTransport(ice))

        async def pump():
            while True:
                data, _ = await ice.recvfrom()
                protocol.datagram_received(data, peer)

        pump_task = asyncio.ensure_future(pump())
        protocol.connect(peer)
        await asyncio.wait_for(protocol.wait_connected(), 10)
        return ice, protocol, pump_task

    async def _call(self, protocol, name, args):
        reader, writer = await protocol.create_stream()
        request = grpc_pb2.GenericRPCRequest(function_name=name, args=args)
        writer.write(direct_path.frame(request.SerializeToString()))
        writer.write_eof()
        response = grpc_pb2.GenericRPCResponse()
        response.ParseFromString(await asyncio.wait_for(direct_path.read_frame(reader), 30))
        return response

    def test_device_rpc_over_the_punched_path(self):
        samples = (np.random.default_rng(1).standard_normal(1_000_000)
                   + 1j * np.random.default_rng(2).standard_normal(1_000_000))
        calls = []

        def fake_run_rpc(*, function_name, args):
            calls.append((function_name, RELAYED.get()))
            if function_name.endswith(":rx:GET"):
                return {"rx": map_arg(samples)}
            return {"echo": map_arg(unmap_arg(args["a"]))}

        async def run():
            ice, protocol, pump = await self._client()
            try:
                response = await self._call(protocol, "adalm_pluto:rx_lo:GET", {"a": map_arg("tok")})
                self.assertEqual(unmap_arg(response.results["echo"]), "tok")
                response = await self._call(protocol, "adalm_pluto:rx:GET", {"a": map_arg("tok")})
                got = unmap_arg(response.results["rx"])
                self.assertEqual(got.shape, samples.shape)
                self.assertTrue(np.array_equal(got, samples))
                response = await self._call(protocol, "ACC:get_dev", {"un": map_arg("x")})
                self.assertIn("not available", unmap_arg(response.results["a"]))
                self.assertEqual([name for name, _ in calls],
                                 ["adalm_pluto:rx_lo:GET", "adalm_pluto:rx:GET"])
                # A peer on this machine's own network is not relayed.
                self.assertEqual({relayed for _, relayed in calls}, {False})
                self.assertEqual(len(direct_path._paths), 1)
            finally:
                pump.cancel()
                protocol.close()
                await ice.close()

        with mock.patch("remoteRF_server.server.rpc_manager.rpc_manager.run_rpc", fake_run_rpc), \
             mock.patch.dict("os.environ", {"REMOTERF_STUN_SERVER": "off"}):
            asyncio.run(run())

    def test_a_new_offer_replaces_that_client_path(self):
        async def run():
            ice, protocol, pump = await self._client()
            first = direct_path._paths["session-key/abcd"]
            ice2, protocol2, pump2 = await self._client()
            try:
                self.assertIsNot(direct_path._paths["session-key/abcd"], first)
                self.assertEqual(len(direct_path._paths), 1)
            finally:
                for p, pr, i in ((pump, protocol, ice), (pump2, protocol2, ice2)):
                    p.cancel()
                    pr.close()
                    await i.close()

        with mock.patch.dict("os.environ", {"REMOTERF_STUN_SERVER": "off"}):
            asyncio.run(run())

    def test_bad_offer_is_an_answer_not_an_exception(self):
        reply = direct_path.offer("session-key", "tester", "not json")
        self.assertIn("direct path unavailable", unmap_arg(reply["ace"]))
        reply = direct_path.offer("session-key", "tester", json.dumps({"ufrag": "x"}))
        self.assertIn("ace", reply)
        self.assertEqual(direct_path._paths, {})


if __name__ == "__main__":
    unittest.main()
