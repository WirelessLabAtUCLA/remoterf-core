from __future__ import annotations

import asyncio
import json
import os
import queue
import ssl
import stat
import tempfile
import threading
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
            "rid": "reservation-1", "iat": time.time(), "exp": int(time.time() + 60),
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

    def test_path_rid_must_match_current_grant(self):
        self.host.refresh(7, self._token(rid="reservation-one", jti="one"))
        self.host.refresh(7, self._token(rid="reservation-two", jti="two"))
        self.assertEqual(
            self.host._refusal(7, "reservation-one", "radio:gain:GET"),
            direct_host.GRANT_ENDED,
        )
        self.assertIsNone(self.host._refusal(7, "reservation-two", "radio:gain:GET"))

    def test_revoke_closes_only_matching_reservation_paths(self):
        self.host.refresh(7, self._token(rid="reservation-one", jti="one"))
        first = mock.Mock(gid=7, rid="reservation-one")
        second = mock.Mock(gid=7, rid="reservation-two")
        with mock.patch.object(self.host, "_close") as close:
            self.host.revoke(7, "reservation-one", 123.0)
        self.assertNotIn(7, self.host._grants)
        self.assertEqual(self.host._ended[7], 123.0)
        self.assertTrue(close.call_args.args[0](first))
        self.assertFalse(close.call_args.args[0](second))

    def test_end_uses_lab_timestamp(self):
        self.host.refresh(7, self._token(iat=100.0, jti="old"))
        with mock.patch.object(self.host, "_close"):
            self.host.end(7, 200.0)
        self.assertEqual(self.host._ended[7], 200.0)
        with self.assertRaises(PermissionError):
            self.host.verify(self._token(iat=200.0, jti="replacement"), 7)

    def test_private_key_is_created_0600(self):
        key_path = Path(self.tmp.name) / "new" / "direct.key"
        host = direct_host.DirectHost(host_id="lab-host", key_path=key_path, run_call=lambda *_: {})
        host.public_key_pem()
        self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)

    def test_relay_session_is_one_use_expiring_and_grant_bound(self):
        self.host.refresh(7, self._token(jti="relay-one"))
        session = self.host.issue_relay_session(7)
        gid, rid, expires = self.host._relay_sessions[session]
        self.assertEqual((gid, rid), (7, "reservation-1"))
        self.assertAlmostEqual(expires - time.time(), direct_host.RELAY_SESSION_SECONDS, delta=1)
        self.host.refresh(7, self._token(rid="reservation-2", jti="relay-two"))
        self.assertFalse(self.host._grant_is_current(gid, rid))

        class Reader:
            def __init__(self, value):
                self.parts = [len(value).to_bytes(4, "big"), value]

            async def readexactly(self, size):
                if not self.parts:
                    raise asyncio.IncompleteReadError(b"", size)
                return self.parts.pop(0)

        class Writer:
            def __init__(self):
                self.writes = []

            def write(self, value):
                self.writes.append(value)

            def close(self):
                pass

            async def wait_closed(self):
                pass

        writer = Writer()
        asyncio.run(self.host._relay_connection(Reader(json.dumps({"session": session}).encode()), writer))
        self.assertIn("invalid relay session", json.loads(writer.writes[0][4:].decode())["a"])
        self.assertNotIn(session, self.host._relay_sessions)

        expired = self.host.issue_relay_session(7)
        old_gid, old_rid, _ = self.host._relay_sessions[expired]
        self.host._relay_sessions[expired] = (old_gid, old_rid, time.time() - 1)
        writer = Writer()
        asyncio.run(self.host._relay_connection(Reader(json.dumps({"session": expired}).encode()), writer))
        self.assertIn("invalid relay session", json.loads(writer.writes[0][4:].decode())["a"])
        self.assertNotIn(expired, self.host._relay_sessions)

    def test_issuing_a_relay_session_prunes_expired_entries(self):
        now = [100.0]
        self.host._clock = lambda: now[0]
        self.host.refresh(7, self._token(jti="relay-prune"))
        self.host._relay_sessions["expired"] = (7, "reservation-1", 99.0)
        self.host._relay_sessions["live"] = (7, "reservation-1", 101.0)
        self.host.issue_relay_session(7)
        self.assertNotIn("expired", self.host._relay_sessions)
        self.assertIn("live", self.host._relay_sessions)

    def test_relay_hello_deadline_and_connection_limit(self):
        class Reader:
            async def readexactly(self, size):
                await asyncio.Event().wait()

        class Writer:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

            async def wait_closed(self):
                pass

        self.host._relay_hello_seconds = 0.001
        writer = Writer()
        asyncio.run(self.host._relay_connection(Reader(), writer))
        self.assertTrue(writer.closed)
        self.assertEqual(self.host._relay_unauthenticated, 0)

        self.host._relay_unauthenticated = direct_host.MAX_UNAUTHENTICATED_RELAY_CONNECTIONS
        writer = Writer()
        asyncio.run(self.host._relay_connection(Reader(), writer))
        self.assertTrue(writer.closed)

    def test_authenticated_relay_connection_has_an_idle_deadline(self):
        class Reader:
            def __init__(self, value):
                self.parts = [len(value).to_bytes(4, "big"), value]

            async def readexactly(self, size):
                if self.parts:
                    return self.parts.pop(0)
                await asyncio.Event().wait()

        class Writer:
            def __init__(self):
                self.writes = []
                self.closed = False

            def write(self, value):
                self.writes.append(value)

            async def drain(self):
                pass

            def close(self):
                self.closed = True

            async def wait_closed(self):
                pass

        self.host.refresh(7, self._token(jti="relay-idle"))
        self.host._relay_idle_seconds = 0.001
        session = self.host.issue_relay_session(7)
        writer = Writer()
        asyncio.run(self.host._relay_connection(Reader(json.dumps({"session": session}).encode()), writer))
        self.assertEqual(json.loads(writer.writes[0][4:].decode()), {"ok": True})
        self.assertTrue(writer.closed)

    def test_relay_context_is_rebuilt_after_a_certificate_change(self):
        class Server:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

            async def wait_closed(self):
                pass

        server = Server()
        self.host._relay_server = server
        self.host._relay_port = 50123

        async def run():
            with mock.patch.object(self.host, "_relay_cert_changed", return_value=True), mock.patch.object(
                self.host, "_listen_relay", new_callable=mock.AsyncMock,
            ) as listen:
                await self.host._refresh_relay_context()
                listen.assert_awaited_once_with(50123)

        asyncio.run(run())
        self.assertTrue(server.closed)

    def test_close_is_scheduled_without_waiting(self):
        class Future:
            def add_done_callback(self, callback):
                self.callback = callback

        future = Future()

        def schedule(coroutine, loop):
            coroutine.close()
            return future

        self.host._loop = object()
        with mock.patch("remoteRF_host.server.direct_host.asyncio.run_coroutine_threadsafe", side_effect=schedule):
            self.host._close(lambda path: True)
        self.assertTrue(hasattr(future, "callback"))

    def test_large_request_closes_path(self):
        class Reader:
            async def readexactly(self, size):
                return (direct_host.MAX_REQUEST_BYTES + 1).to_bytes(4, "big")

        class Writer:
            def close(self):
                self.closed = True

        class Ice:
            _check_list = []
            _protocols = []

            async def close(self):
                self.closed = True

        self.host.refresh(7, self._token())
        path = direct_host._HostPath(self.host, 7, "reservation-1", Ice())
        self.host._paths[7] = [path]
        writer = Writer()
        asyncio.run(path._serve(Reader(), writer))
        self.assertTrue(path.closed)
        self.assertTrue(writer.closed)

    def test_calls_for_a_device_are_serialized(self):
        active = 0
        maximum = 0
        lock = threading.Lock()

        def run_call(gid, request):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return {"value": map_arg("ok")}

        class Reader:
            def __init__(self, request):
                self.parts = [len(request).to_bytes(4, "big"), request]

            async def readexactly(self, size):
                return self.parts.pop(0)

        class Writer:
            def write(self, data):
                self.data = data

            def write_eof(self):
                pass

            def close(self):
                pass

        self.host.run_call = run_call
        self.host.refresh(7, self._token())
        first = direct_host._HostPath(self.host, 7, "reservation-1", mock.Mock())
        second = direct_host._HostPath(self.host, 7, "reservation-1", mock.Mock())
        request = grpc_pb2.GenericRPCRequest(function_name="radio:gain:GET").SerializeToString()
        async def serve_both():
            await asyncio.gather(
                first._serve(Reader(request), Writer()), second._serve(Reader(request), Writer()),
            )

        asyncio.run(serve_both())
        self.assertEqual(maximum, 1)

    def test_path_refuses_extra_streams(self):
        path = direct_host._HostPath(self.host, 7, "reservation-1", mock.Mock())
        started = asyncio.Event()
        busy = []

        async def serve(reader, writer):
            await started.wait()

        async def refuse(reader, writer):
            busy.append(True)

        path._serve = serve
        path._busy = refuse

        async def open_streams():
            for _ in range(direct_host.MAX_STREAMS_PER_PATH + 1):
                path._stream(None, None)
            await asyncio.sleep(0)
            self.assertEqual(busy, [True])
            started.set()
            await asyncio.gather(*path.streams)

        asyncio.run(open_streams())


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

    async def _relay_client(self, session: str):
        context = ssl.create_default_context()
        context.load_verify_locations(cadata=self.ca_cert.public_bytes(serialization.Encoding.PEM).decode())
        context.check_hostname = True
        port = self.host.start_relay()
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", port, ssl=context, server_hostname="lab-host--lab.global.remoterf.net",
        )
        writer.write(direct_host.DirectHost._frame(json.dumps({"session": session}).encode()))
        await writer.drain()
        return reader, writer

    def test_tls_relay_serves_calls_and_closes_on_revoke(self):
        async def run():
            self.host.refresh(7, self._token(jti="relay-tls"))
            reader, writer = await self._relay_client(self.host.issue_relay_session(7))
            self.assertEqual(json.loads((await direct_host.DirectHost._read_frame(reader, 1024)).decode()), {"ok": True})

            async def call(name):
                writer.write(direct_host.DirectHost._frame(
                    grpc_pb2.GenericRPCRequest(function_name=name).SerializeToString()))
                await writer.drain()
                response = grpc_pb2.GenericRPCResponse.FromString(
                    await direct_host.DirectHost._read_frame(reader, direct_host.MAX_REQUEST_BYTES))
                return {key: unmap_arg(value) for key, value in response.results.items()}

            self.assertEqual((await call("radio:gain:GET"))["value"], "ok")
            self.assertIn("not available", (await call("IDL:get_drivers"))["a"])
            self.host.revoke(7, "reservation-1")
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
            writer.close()
            await writer.wait_closed()

            bad_reader, bad_writer = await self._relay_client("not-a-session")
            self.assertIn("invalid relay session", json.loads(
                (await direct_host.DirectHost._read_frame(bad_reader, 1024)).decode())["a"])
            bad_writer.close()
            await bad_writer.wait_closed()

        try:
            asyncio.run(run())
        except OSError as exc:
            self.skipTest(f"loopback TLS is unavailable: {exc}")
        finally:
            self.host.stop_relay()


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

            def end(self, gid, at=None):
                self.ended = (gid, at)

            def revoke(self, gid, rid, at=None):
                self.revoked = (gid, rid, at)

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
        self.assertEqual(direct.ended, (7, None))

    def test_direct_offer_serializes_relay_inside_answer(self):
        from remoteRF_host.common.grpc import grpc_host_pb2 as pb

        class Direct:
            def offer(self, gid, ice, grant):
                return {"ufrag": "u"}

            def issue_relay_session(self, gid):
                return "relay-session"

        agent = self._agent(Direct())
        agent._relay_supervisor = mock.Mock(is_up=lambda: True)
        agent._handle_control(pb.Control(
            kind="direct_offer", device_id="7", req_id="one", payload=json.dumps({"ice": "{}", "grant": "ok"}),
        ))
        answer = agent._out_q.get(timeout=2).control
        self.assertEqual(answer.payload, '{"answer": {"ufrag": "u", "relay": {"session": "relay-session"}}}')

    def test_reservation_end_forwards_lab_timestamp(self):
        from remoteRF_host.common.grpc import grpc_host_pb2 as pb

        class Direct:
            def end(self, gid, at=None):
                self.ended = (gid, at)

        direct = Direct()
        agent = self._agent(direct)
        with mock.patch("remoteRF_host.server.tunnel_agent.end_reservation"):
            agent._handle_control(pb.Control(
                kind="reservation_end", device_id="7", payload=json.dumps({"at": 12.5}),
            ))
        self.assertEqual(direct.ended, (7, 12.5))

    def test_revoke_does_not_reset_device(self):
        from remoteRF_host.common.grpc import grpc_host_pb2 as pb

        class Direct:
            def revoke(self, gid, rid, at=None):
                self.revoked = (gid, rid, at)

        direct = Direct()
        agent = self._agent(direct)
        with mock.patch("remoteRF_host.server.tunnel_agent.end_reservation") as end:
            agent._handle_control(pb.Control(
                kind="revoke", device_id="7", payload=json.dumps({"rid": "reservation-1", "at": 12.5}),
            ))
        self.assertEqual(direct.revoked, (7, "reservation-1", 12.5))
        end.assert_not_called()

    def test_direct_call_uses_path_gid(self):
        agent = self._agent(None)
        request = grpc_pb2.GenericRPCRequest(function_name="radio:gain:GET")
        request.args["g"].CopyFrom(map_arg("99"))
        request.args["gid"].CopyFrom(map_arg("98"))
        request.args["device_id"].CopyFrom(map_arg(97))
        request.args["token"].CopyFrom(map_arg("untrusted"))
        request.args["gain"].CopyFrom(map_arg(1))
        with mock.patch("remoteRF_host.server.tunnel_agent.rpc_manager.run_rpc", return_value={}) as run:
            agent._run_direct_call(7, request)
        args = run.call_args.kwargs["args"]
        self.assertEqual(unmap_arg(args["g"]), "7")
        self.assertEqual(unmap_arg(args["gid"]), "7")
        self.assertEqual(unmap_arg(args["device_id"]), 7)
        self.assertEqual(unmap_arg(args["gain"]), 1)
        self.assertNotIn("token", args)

    def test_direct_answer_queue_failure_is_logged(self):
        from remoteRF_host.common.grpc import grpc_host_pb2 as pb

        class Direct:
            def offer(self, gid, ice, grant):
                return {"ufrag": "u"}

        agent = self._agent(Direct())
        with mock.patch.object(agent, "_enqueue", return_value=False), mock.patch(
            "remoteRF_host.server.tunnel_agent.warn"
        ) as warn:
            agent._handle_direct_offer(pb.Control(
                kind="direct_offer", device_id="7", req_id="answer", payload=json.dumps({"ice": "{}", "grant": "ok"}),
            ))
        self.assertIn("Could not queue direct answer", warn.call_args.args[0])

    def test_relay_info_writes_known_hosts_and_uses_expected_ssh_argv(self):
        from remoteRF_host.server.tunnel_agent import RelaySupervisor

        class Direct:
            def start_relay(self):
                return 50123

            def stop_relay(self):
                self.stopped = True

        class Process:
            def __init__(self):
                self.done = threading.Event()
                self.terminated = False

            def poll(self):
                return 0 if self.terminated else None

            def wait(self):
                self.done.wait(2)

            def terminate(self):
                self.terminated = True
                self.done.set()

        calls, started = [], threading.Event()

        def runner(argv):
            calls.append(argv)
            started.set()
            return Process()

        with tempfile.TemporaryDirectory() as directory:
            supervisor = RelaySupervisor(Direct(), Path(directory), runner)
            supervisor.start({
                "tunnel_host": "tunnel.example", "tunnel_port": 2200, "tunnel_user": "relay",
                "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest", "port": 62010,
                "server_name": "lab-host--lab.global.remoterf.net", "endpoint": "lab-host--lab.global.remoterf.net:12321",
            })
            self.assertTrue(started.wait(2))
            self.assertEqual(
                calls[0],
                [
                    "ssh", "-NT", "-o", "StrictHostKeyChecking=yes", "-o",
                    f"UserKnownHostsFile={Path(directory) / 'relay_known_hosts'}", "-o", "IdentitiesOnly=yes",
                    "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30", "-o",
                    "ServerAliveCountMax=3", "-i", str(Path(directory) / "relay_ed25519"), "-p", "2200", "-R",
                    "127.0.0.1:62010:127.0.0.1:50123", "relay@tunnel.example",
                ],
            )
            self.assertEqual(
                (Path(directory) / "relay_known_hosts").read_text(),
                "[tunnel.example]:2200 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest\n",
            )
            supervisor.stop()

    def test_relay_key_and_hello_are_available_only_with_ssh_tools(self):
        from remoteRF_host.server import tunnel_agent

        class Hello:
            DESCRIPTOR = type("Descriptor", (), {"fields_by_name": {"relay_ssh_public_key": object()}})()

            def __init__(self, **fields):
                self.host_id = fields["host_id"]
                self.version = fields["version"]
                self.host_token = ""
                self.capabilities = []
                self.tls_public_key = ""
                self.relay_ssh_public_key = ""

        class Frame:
            def __init__(self, *, hello):
                self.hello = hello

        class Direct:
            def public_key_pem(self):
                return "direct public key"

        def make_agent():
            agent = tunnel_agent.HostTunnelAgent.__new__(tunnel_agent.HostTunnelAgent)
            agent._direct_host = Direct()
            agent._relay_command_runner = None
            agent._relay_public_key = ""
            agent._relay_supervisor = None
            agent._host_id = "lab-host"
            agent._host_token = "token"
            agent.cfg = mock.Mock(version="test")
            return agent

        def generate(argv, **kwargs):
            key_path = Path(argv[-1])
            key_path.write_text("private")
            key_path.with_name(key_path.name + ".pub").write_text(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest relay\n")

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            tunnel_agent.host_pb2, "HostHello", Hello,
        ), mock.patch.object(tunnel_agent.host_pb2, "HostFrame", Frame), mock.patch(
            "remoteRF_host.server.tunnel_agent._cfg_dir", return_value=Path(directory),
        ), mock.patch("remoteRF_host.server.tunnel_agent.shutil.which", return_value="/usr/bin/ssh"), mock.patch(
            "remoteRF_host.server.tunnel_agent.subprocess.run", side_effect=generate,
        ):
            agent = make_agent()
            agent._setup_relay()
            self.assertEqual(stat.S_IMODE((Path(directory) / "relay_ed25519").stat().st_mode), 0o600)
            hello = agent._hello_frame().hello
            self.assertEqual(hello.capabilities, ["direct", "relay"])
            self.assertEqual(hello.relay_ssh_public_key, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest")

            unavailable = make_agent()
            with mock.patch("remoteRF_host.server.tunnel_agent.shutil.which", return_value=None):
                unavailable._setup_relay()
            self.assertEqual(unavailable._hello_frame().hello.capabilities, ["direct"])

            disabled = make_agent()
            with mock.patch.dict(os.environ, {"HOSTRF_RELAY": "0"}), mock.patch(
                "remoteRF_host.server.tunnel_agent.shutil.which",
            ) as which:
                disabled._setup_relay()
            which.assert_not_called()
            self.assertEqual(disabled._hello_frame().hello.capabilities, ["direct"])

    def test_connected_is_reported_only_after_the_first_lab_frame(self):
        import grpc
        from remoteRF_host.common.grpc import grpc_host_pb2 as pb
        from remoteRF_host.server import tunnel_agent

        class HandshakeFailed(grpc.RpcError):
            def code(self):
                return grpc.StatusCode.UNAVAILABLE

            def details(self):
                return "Handshake read failed"

        streams = [HandshakeFailed(), [pb.HostFrame(heartbeat=pb.Heartbeat())]]

        def connect(_frames):  # like gRPC: the call returns at once, failures surface on read
            stream = streams.pop(0)
            if isinstance(stream, Exception):
                def failing():
                    raise stream
                    yield
                return failing()
            return iter(stream)

        agent = self._agent(None)
        agent.cfg = mock.Mock(
            version="test", server_host="lab", server_port=1, ca_pem_path="ca",
            reconnect_min_delay_sec=0.01, reconnect_max_delay_sec=0.01, heartbeat_interval_sec=60,
        )
        agent._stop = threading.Event()
        agent._relay_supervisor = None
        lines = []

        def sleep(_seconds):  # the retry wait; the heartbeat thread sleeps too
            if not streams and threading.current_thread() is threading.main_thread():
                agent._stop.set()

        with mock.patch.object(agent, "_reload_from_env"), mock.patch.object(
            agent, "_drain_outbound_queue"
        ), mock.patch.object(agent, "_make_channel"), mock.patch.object(
            agent, "_device_announce_frame", return_value=pb.HostFrame()
        ), mock.patch.object(agent, "_outbound_generator"), mock.patch.object(
            tunnel_agent.host_pb2_grpc, "HostTunnelStub", return_value=mock.Mock(Connect=connect)
        ), mock.patch.object(
            tunnel_agent, "status", side_effect=lambda msg, **_k: lines.append(msg)
        ), mock.patch.object(tunnel_agent.time, "sleep", side_effect=sleep), mock.patch.object(
            tunnel_agent, "end_reservation", None
        ):
            agent.run_forever()

        self.assertTrue(lines[1].startswith("Unable to connect to lab:1 (UNAVAILABLE: Handshake read failed)"), lines)
        self.assertTrue(lines[2].startswith("Connected to lab:1 as 'lab-host'"), lines)
        self.assertTrue(lines[3].startswith("Connection to lab:1 lost (server closed the stream)"), lines)
