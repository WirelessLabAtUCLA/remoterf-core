from __future__ import annotations

import asyncio
import json
import os
import queue
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from remoteRF_host.common.grpc import grpc_pb2
from remoteRF_host.common.utils.process_arg import map_arg, unmap_arg
from remoteRF_host.server import direct_host


def _certificate(ca_key, ca_cert, public_key, name: str) -> str:
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class DirectHostGrantTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.grant_key = ed25519.Ed25519PrivateKey.generate()
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
        now = datetime.now(timezone.utc)
        self.ca_cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(self.ca_key, hashes.SHA256())
        )
        self.host = direct_host.DirectHost(
            host_id="lab-host", key_path=Path(self.tmp.name) / "direct.key", run_call=lambda *_: {},
        )
        public_key = serialization.load_pem_public_key(self.host.public_key_pem().encode())
        self.host.configure({
            "deployment_id": "deployment-1",
            "grant_key": self.grant_key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode(),
            "server_name": "lab-host--lab.global.remoterf.net",
            "cert_pem": _certificate(self.ca_key, self.ca_cert, public_key, "lab-host--lab.global.remoterf.net"),
            "ca_pem": self.ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
        })

    def _token(self, **changes):
        claims = {
            "iss": "deployment-1", "aud": "lab-host", "gid": 7, "jti": "grant-1",
            "iat": time.time(), "exp": int(time.time() + 60),
        }
        claims.update(changes)
        return jwt.encode(
            claims, self.grant_key, algorithm="EdDSA", headers={"typ": "remoterf-host-grant"},
        )

    def test_grant_validation(self):
        token = self._token()
        self.assertEqual(self.host.verify(token, 7)["gid"], 7)
        for changes, gid in (({"aud": "other-host"}, 7), ({"gid": 8}, 7), ({"iss": "other"}, 7), ({"exp": 1}, 7)):
            with self.assertRaises(PermissionError):
                self.host.verify(self._token(**changes), gid)

        self.host.refresh(7, token)
        self.host.end(7)
        with self.assertRaises(PermissionError):
            self.host.verify(token, 7)

        self.host._ended[7] = time.time()
        with self.assertRaises(PermissionError):
            self.host.verify(self._token(iat=time.time() - 1, jti="old-grant"), 7)

        other = ed25519.Ed25519PrivateKey.generate()
        bad = jwt.encode(
            {"iss": "deployment-1", "aud": "lab-host", "gid": 7, "jti": "bad", "iat": time.time(), "exp": int(time.time() + 60)},
            other, algorithm="EdDSA", headers={"typ": "remoterf-host-grant"},
        )
        with self.assertRaises(PermissionError):
            self.host.verify(bad, 7)


@unittest.skipUnless(direct_host.available(), "direct path dependencies are unavailable")
class DirectHostLoopbackTests(DirectHostGrantTests):
    def setUp(self):
        super().setUp()
        self.calls = []

        def run_call(gid, request):
            self.calls.append((gid, request.function_name))
            return {"value": map_arg("ok")}

        self.host.run_call = run_call
        os.environ["REMOTERF_STUN_SERVER"] = "off"
        self.addCleanup(os.environ.pop, "REMOTERF_STUN_SERVER", None)

    async def _run_loopback(self):
        from aioice import Candidate, Connection
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.connection import QuicConnection
        from remoterf_device_core import direct

        ice = Connection(ice_controlling=True, use_ipv6=False)
        protocol = pump = None
        try:
            await ice.gather_candidates()
            offer = json.dumps({
                "ufrag": ice.local_username,
                "pwd": ice.local_password,
                "candidates": [candidate.to_sdp() for candidate in ice.local_candidates],
            })
            answer = await asyncio.get_running_loop().run_in_executor(
                None, self.host.offer, 7, offer, self._token(jti="loopback"),
            )
            ice.remote_username, ice.remote_password = answer["ufrag"], answer["pwd"]
            for candidate in answer["candidates"]:
                await ice.add_remote_candidate(Candidate.from_sdp(candidate))
            await ice.add_remote_candidate(None)
            await asyncio.wait_for(ice.connect(), 8)
            peer = direct.peer_address(ice)
            configuration = QuicConfiguration(
                is_client=True, alpn_protocols=[direct.ALPN], server_name=answer["server_name"],
            )
            configuration.load_verify_locations(cadata=answer["ca_pem"].encode())
            protocol = QuicConnectionProtocol(QuicConnection(configuration=configuration))
            protocol.connection_made(direct.IceTransport(ice))

            async def receive():
                while True:
                    data, _ = await ice.recvfrom()
                    protocol.datagram_received(data, peer)

            pump = asyncio.create_task(receive())
            protocol.connect(peer)
            await asyncio.wait_for(protocol.wait_connected(), 8)

            async def call(name):
                reader, writer = await protocol.create_stream()
                writer.write(direct.frame(grpc_pb2.GenericRPCRequest(function_name=name).SerializeToString()))
                writer.write_eof()
                response = grpc_pb2.GenericRPCResponse.FromString(await asyncio.wait_for(direct.read_frame(reader), 5))
                return {key: unmap_arg(value) for key, value in response.results.items()}

            self.assertEqual((await call("radio:gain:GET"))["value"], "ok")
            self.assertIn("not available", (await call("IDL:get_drivers"))["a"])
            self.host.end(7)
            await asyncio.wait_for(protocol.wait_closed(), 5)
            self.assertTrue(protocol._closed.is_set())
        finally:
            if pump is not None:
                pump.cancel()
                await asyncio.gather(pump, return_exceptions=True)
            if protocol is not None:
                protocol.close()
                await asyncio.sleep(0)
            await ice.close()
            self.host.close_all()

    def test_punched_quic_path(self):
        try:
            asyncio.run(self._run_loopback())
        except (OSError, asyncio.TimeoutError) as exc:
            self.skipTest(f"loopback ICE is unavailable: {exc}")


class TunnelDirectControlTests(unittest.TestCase):
    def _agent(self, direct):
        from remoteRF_host.server.tunnel_agent import HostTunnelAgent

        agent = HostTunnelAgent.__new__(HostTunnelAgent)
        agent._direct_host = direct
        agent._devices = {7: {}}
        agent._out_q = queue.Queue()
        agent._host_id = "lab-host"
        agent._host_token = "token"
        agent.cfg = mock.Mock(version="test")
        return agent

    def test_hello_advertises_direct_only_when_present(self):
        class Direct:
            def public_key_pem(self):
                return "public key"

        hello = self._agent(Direct())._hello_frame().hello
        self.assertEqual(list(hello.capabilities), ["direct"])
        self.assertEqual(hello.tls_public_key, "public key")
        hello = self._agent(None)._hello_frame().hello
        self.assertEqual(list(hello.capabilities), [])
        self.assertEqual(hello.tls_public_key, "")

    def test_direct_offer_answers_and_reservation_end_closes(self):
        from remoteRF_host.common.grpc import grpc_host_pb2 as pb

        class Direct:
            def offer(self, gid, ice, grant):
                if grant == "bad":
                    raise PermissionError("invalid grant")
                return {"ufrag": "u"}

            def end(self, gid):
                self.ended = gid

        direct = Direct()
        agent = self._agent(direct)
        agent._handle_control(pb.Control(kind="direct_offer", device_id="7", req_id="one", payload=json.dumps({"ice": "{}", "grant": "ok"})))
        answer = agent._out_q.get(timeout=2).control
        self.assertEqual(json.loads(answer.payload), {"answer": {"ufrag": "u"}})
        agent._handle_control(pb.Control(kind="direct_offer", device_id="7", req_id="two", payload=json.dumps({"ice": "{}", "grant": "bad"})))
        answer = agent._out_q.get(timeout=2).control
        self.assertEqual(json.loads(answer.payload), {"error": "invalid grant"})
        with mock.patch("remoteRF_host.server.tunnel_agent.end_reservation"):
            agent._handle_control(pb.Control(kind="reservation_end", device_id="7"))
        self.assertEqual(direct.ended, 7)
