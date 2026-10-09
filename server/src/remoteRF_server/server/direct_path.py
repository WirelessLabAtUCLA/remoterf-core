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

"""Gate I: the direct UDP device path (docs/gate-i-direct-path.md).

ICE (aioice) punches one UDP pair between a logged-in client and this Server;
QUIC (aioquic) carries device RPCs over it, one bidirectional stream per call:
4-byte big-endian length + GenericRPCRequest, reply likewise. Control RPCs
(ACC:*) stay on gRPC and are refused here. Signaling is ACC:direct_offer.

A *bound* path is the owner side of a federated reservation (docs/
deployment-groups.md §7.6): it carries no bearer token, every call is
re-authorized by the binding and pinned to its device, and a refusal closes
the path.

The *fixed port*: a Server with a reachable address also listens for QUIC on
one UDP port -- the gRPC port's number, which a lab's firewall already admits
-- so a client dials it like any QUIC server, no punch, whatever its NAT. The
offer reply carries that address and a one-time session secret; the client's
first stream says the secret and the connection becomes that session's path.
ICE stays for Servers the client cannot reach that way.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import ipaddress
import json
import logging
import os
import secrets
import socket
import threading
from pathlib import Path
from typing import Optional

from aioice import Candidate, Connection
from aioquic.asyncio import serve as quic_serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import Buffer
from aioquic.quic import events
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.packet import QuicPacketType, pull_quic_header

from ..common.grpc import grpc_pb2
from ..common.utils.process_arg import map_arg
from .global_onboarding import RELAYED, hostname, is_offsite

logger = logging.getLogger("remoteRF_server.direct")


async def close_ice(ice) -> None:
    """Close an aioice Connection without the library's after-close noise.

    A cancelled ``connect()`` (a punch that timed out) never reaches aioice's
    own "cancel remaining checks" loop, so its check tasks keep running and
    its STUN timers stay armed against sockets close() is about to take. Stop
    both before closing."""
    # Cancel the connectivity checks first. Failing their STUN transactions
    # instead only makes aioice start replacement checks, which then hang on
    # a closed socket and die "pending" when they are collected.
    checks = [pair.task for pair in list(getattr(ice, "_check_list", [])) if pair.task is not None]
    for task in checks:
        task.cancel()
    if checks:
        await asyncio.gather(*checks, return_exceptions=True)
    for protocol in list(getattr(ice, "_protocols", [])):
        for transaction in list(getattr(protocol, "transactions", {}).values()):
            handle = getattr(transaction, "_Transaction__timeout_handle", None)
            if handle is not None:
                handle.cancel()  # a retry would fire on the socket close() is about to take
    await ice.close()


async def cancel_tasks(tasks) -> None:
    """Cancel these tasks and wait for them to finish.

    A task that is cancelled but never awaited can be collected while still
    pending, and Python prints a traceback for it that nobody can act on.
    The caller's own task is never cancelled, so this is safe to call from
    inside one of the tasks being torn down."""
    current = asyncio.current_task()
    tasks = [task for task in tasks if task is not None and task is not current and not task.done()]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


def quiet_aioice_errors(loop) -> None:
    """A STUN retry on an already-closed socket is not an error worth a
    traceback in someone's shell; everything else keeps the default handler.

    The retry fires from a TimerHandle named for aioice's Transaction and
    dies inside asyncio's own transport code once the socket is gone (an
    AttributeError on the closed transport or its dropped loop)."""
    default = loop.default_exception_handler

    def handler(loop, context):
        exc = context.get("exception")
        where = repr(context.get("handle", "")) + str(context.get("message", ""))
        if isinstance(exc, (AttributeError, OSError)) and "Transaction.__retry" in where:
            return
        default(context)

    loop.set_exception_handler(handler)

ALPN = "remoterf-direct/1"
MAX_FRAME = 100 * 1024 * 1024  # the gRPC message ceiling
IDLE_SECONDS = 600
CONNECT_SECONDS = 30  # ICE checks, then the QUIC handshake; a silent client is dropped
# How long the punch waits for the client's first check when the answer also
# offered the fixed port. A 2.1.0 client dials that port for 2 s before its
# first check; a check of ours reaching its NAT before then leaves a stale
# entry there that shadows the port its own checks are then mapped to (Linux
# NAT picks another), and the punch can never complete. A check that arrives
# sooner ends the wait; a client that never reaches us gets ours after it.
# 3.0 = the 2 s dial plus ~1 s for the relay round trip that carries the
# answer; a shorter hold reproduces the shadow on a slow relay.
HOLD_SECONDS = 3.0
# A client that punches at once ("race" in its offer) sends its first check
# as soon as the answer reaches it, but that check is dropped at a border
# that has not seen ours yet, so it cannot end the hold: ours must simply
# leave after its first check has, and before its retransmit at 0.5 s.
RACE_HOLD_SECONDS = 0.4
MAX_PATHS_PER_SESSION = 8  # processes of one login; the oldest path makes room
DEFAULT_STUN = "stun.l.google.com:19302"
STUN_SECONDS = 1.5  # a STUN server answers in milliseconds or not at all

HELLO_SECONDS = 5  # a fixed-port connection that never says which session it is
SESSION_SECONDS = 60  # how long an offer's session secret stays redeemable

CERT_DIR: Optional[Path] = None  # set by start_server_runtime
UDP_PORT: int = 0  # the fixed port; 0 = none (start_server_runtime sets the gRPC port's number)
BIND_HOST: str = "0.0.0.0"

_loop: Optional[asyncio.AbstractEventLoop] = None
_thread: Optional[threading.Thread] = None
_lock = threading.Lock()
_paths: dict[str, "_Path"] = {}
_sessions: dict[str, dict] = {}  # secret -> the path a fixed-port hello may claim
_listener = None
_listener_port = 0


def frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + payload


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    size = int.from_bytes(await reader.readexactly(4), "big")
    if size > MAX_FRAME:
        raise ValueError(f"frame of {size} bytes exceeds {MAX_FRAME}")
    return await reader.readexactly(size)


def default_route_address() -> Optional[str]:
    """The IPv4 address the default route leaves from, or None without one."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            return probe.getsockname()[0]
    except OSError:
        return None


def stun_server(address: Optional[str] = None) -> Optional[tuple[str, int]]:
    """The STUN server to learn this Server's public address from, or None.

    A Server whose own address is already public learns nothing from STUN.
    """
    value = os.getenv("REMOTERF_STUN_SERVER", DEFAULT_STUN).strip()
    if value.lower() in {"", "off", "none", "0"}:
        return None
    if address is not None and ipaddress.ip_address(address).is_global:
        return None
    host, _, port = value.rpartition(":")
    return host, int(port)


class Ice(Connection):
    """aioice's Connection, gathering on the default-route interface only.

    Every other interface (a VPN, an overlay, a bridge) cannot reach the STUN
    server, and aioice would hold gathering for its whole 5 s timeout on each
    one, on every offer. One interface and a short STUN wait instead; a
    machine without a default route gathers the way aioice does.

    ``heard`` is set by the peer's first check, which may arrive before
    connect() (aioice holds it as an early check until then).
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.heard = asyncio.Event()

    async def gather_candidates(self) -> None:
        address = default_route_address()
        if address is None or self._local_candidates_start:
            return await super().gather_candidates()
        self._local_candidates_start = True
        self._local_candidates += await self.get_component_candidates(
            component=1, addresses=[address], timeout=STUN_SECONDS
        )
        self._local_candidates_end = True

    def request_received(self, *args) -> None:
        super().request_received(*args)
        self.heard.set()


def peer_address(ice: Connection) -> tuple[str, int]:
    """The remote end of the nominated pair (aioice keeps it private)."""
    return ice._nominated[1].remote_addr


class PathRefused(Exception):
    """A bound path's authorizer said no: the reply carries why, then the path closes."""


def _dispatch(request: grpc_pb2.GenericRPCRequest, peer_host: str, bound: Optional[dict] = None) -> dict:
    """Run one call exactly as GenericRPCServicer.Call does, device plane only."""
    from .rpc_manager import rpc_manager

    name = request.function_name
    device = rpc_manager._looks_like_device_rpc(name)
    if bound is not None:
        if not (device or name == "IDL:get_drivers"):
            return {"a": map_arg(f"{name} is not available on the direct path")}
        try:
            reason = bound["authorize"](name)
        except Exception as exc:  # noqa: BLE001 - undecidable is not a refusal: the call does not run
            return {"a": map_arg(f"authorization unavailable: {exc}")}
        if reason is not None:
            raise PathRefused(reason)
    elif not (device or name.startswith("IDL:")):
        return {"a": map_arg(f"{name} is not available on the direct path")}
    token = RELAYED.set(is_offsite(peer_host))
    try:
        if bound is not None:
            return bound["run"](name, dict(request.args))
        return rpc_manager.run_rpc(function_name=name, args=request.args)
    except Exception as exc:  # noqa: BLE001 - the reply carries it, as a device error would
        return {"a": map_arg(str(exc))}
    finally:
        RELAYED.reset(token)


class _IceTransport:
    """The sendto() surface aioquic's protocol needs, on a nominated ICE pair."""

    def __init__(self, ice: Connection):
        self._ice = ice
        self._loop = asyncio.get_running_loop()
        self._queue: collections.deque[bytes] = collections.deque()
        self._pump: Optional[asyncio.Task] = None
        self._closed = False

    def sendto(self, data: bytes, addr=None) -> None:
        if self._closed:
            return
        self._queue.append(data)
        if self._pump is None:
            self._pump = self._loop.create_task(self._drain())

    def close(self) -> None:
        """Drop the transport: QUIC's later timers must not touch a dead pair."""
        self._closed = True
        self._queue.clear()

    async def _drain(self) -> None:
        try:
            while self._queue:
                await self._ice.sendto(self._queue.popleft(), 1)
        except ConnectionError:
            self._queue.clear()
        finally:
            self._pump = None


def _cert_dir() -> Path:
    return CERT_DIR or Path(
        os.getenv(
            "REMOTERF_CERT_DIR",
            Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config")) / "remoterf" / "certs",
        )
    )


def _server_configuration() -> QuicConfiguration:
    cert_dir = _cert_dir()
    configuration = QuicConfiguration(
        is_client=False, alpn_protocols=[ALPN], idle_timeout=IDLE_SECONDS
    )
    configuration.load_cert_chain(cert_dir / "server.crt", cert_dir / "server.key")
    return configuration


class _Protocol(QuicConnectionProtocol):
    """aioquic's protocol, remembering why the connection ended."""

    terminated = ""

    def quic_event_received(self, event) -> None:
        if isinstance(event, events.ConnectionTerminated):
            self.terminated = event.reason_phrase or (
                f"QUIC error {event.error_code:#x}" if event.error_code else ""
            )
        super().quic_event_received(event)


class _Path:
    """One client session's punched pair and the QUIC connection over it."""

    def __init__(self, key: str, user: str, ice: Connection, bound: Optional[dict] = None, hold: float = 0.0):
        self.key = key
        self.user = user
        self.ice = ice
        self.bound = bound
        self.hold = hold  # seconds to wait for the client's first check (a fixed port was offered too)
        self.peer: Optional[tuple[str, int]] = None
        self.calls = 0
        self.task: Optional[asyncio.Task] = None
        self.transport: Optional[_IceTransport] = None
        self.streams: set[asyncio.Task] = set()

    async def run(self) -> None:
        protocol = None
        try:
            if self.hold:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self.ice.heard.wait(), self.hold)
            await asyncio.wait_for(self.ice.connect(), CONNECT_SECONDS)
            self.peer = peer_address(self.ice)
            protocol = await asyncio.wait_for(self._accept(), CONNECT_SECONDS)
            pump = asyncio.ensure_future(self._pump(protocol))
            closed = asyncio.ensure_future(protocol.wait_closed())
            try:
                try:
                    await asyncio.wait_for(protocol.wait_connected(), CONNECT_SECONDS)
                except ConnectionError:
                    raise ConnectionError(f"QUIC handshake failed: {protocol.terminated}") from None
                await asyncio.wait({pump, closed}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                await cancel_tasks((pump, closed))
        except Exception:  # noqa: BLE001 - a failed punch is expected on some networks; the client retries
            pass
        finally:
            if protocol is not None:
                protocol.close()
                await asyncio.sleep(0)  # the CONNECTION_CLOSE leaves before the pair goes
            if self.transport is not None:
                self.transport.close()
            await self.close()

    async def _accept(self) -> QuicConnectionProtocol:
        """The client's Initial packet decides the connection, as aioquic's server does."""
        transport = self.transport = _IceTransport(self.ice)
        while True:
            data, _ = await self.ice.recvfrom()
            try:
                header = pull_quic_header(Buffer(data=data), host_cid_length=8)
            except ValueError:
                continue
            if header.packet_type != QuicPacketType.INITIAL:
                continue
            quic = QuicConnection(
                configuration=_server_configuration(),
                original_destination_connection_id=header.destination_cid,
            )
            protocol = _Protocol(quic, stream_handler=self._stream)
            protocol.connection_made(transport)
            protocol.datagram_received(data, self.peer)
            return protocol

    async def _pump(self, protocol: QuicConnectionProtocol) -> None:
        with contextlib.suppress(ConnectionError):
            while True:
                data, _ = await self.ice.recvfrom()
                protocol.datagram_received(data, self.peer)

    def _stream(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Tracked, not fire-and-forget: a stream holds a device call, and the
        # path may close under it.
        task = asyncio.ensure_future(self._serve(reader, writer))
        self.streams.add(task)
        task.add_done_callback(self.streams.discard)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _serve_call(self, reader, writer)

    drop = None  # set below: closing a path, from either kind

    async def close(self) -> None:
        if _paths.get(self.key) is self:
            del _paths[self.key]
        task = self.task
        if task is not None and task is not asyncio.current_task():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await cancel_tasks(list(self.streams))
        await close_ice(self.ice)


async def _serve_call(path, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """One stream = one device call, on an ICE path or a fixed-port connection."""
    bad_frame = refused = None
    try:
        try:
            request = grpc_pb2.GenericRPCRequest()
            request.ParseFromString(await read_frame(reader))
        except asyncio.IncompleteReadError:
            return  # the client went away mid-frame
        except Exception as exc:  # noqa: BLE001 - not our framing: say so, then drop the path
            bad_frame = f"bad frame: {type(exc).__name__}: {exc}"
            results = {"a": map_arg(bad_frame)}
        else:
            try:
                results = await asyncio.get_running_loop().run_in_executor(
                    None, _dispatch, request, path.peer[0], path.bound
                )
            except PathRefused as exc:
                refused = str(exc)
                results = {"a": map_arg(refused)}
        writer.write(frame(grpc_pb2.GenericRPCResponse(results=results).SerializeToString()))
        writer.write_eof()
        path.calls += 1
    except Exception as exc:  # noqa: BLE001 - one lost stream must not take the path down
        logger.debug("direct path stream: %s", exc)
    finally:
        # Ends our side of the stream on every path; Python < 3.12 does not
        # close an abandoned StreamWriter, and the half-open stream lingers.
        writer.close()
    if bad_frame is not None:
        # A client that cannot frame a request is not ours; its bytes are
        # still arriving and would only pile up in this stream's buffer.
        await path.drop()
    if refused is not None:
        await path.drop()


_Path.drop = _Path.close


async def _make_room(key: str) -> None:
    """A new path for this key replaces the old one; a session (everything but
    the offer id: one login's processes, or one federated reservation's) keeps
    at most MAX_PATHS_PER_SESSION, the oldest making room."""
    old = _paths.get(key)
    if old is not None:
        await old.drop()
    session = key.rsplit("/", 1)[0]
    siblings = [path for k, path in _paths.items() if k.rsplit("/", 1)[0] == session]
    for path in siblings[: max(0, len(siblings) - MAX_PATHS_PER_SESSION + 1)]:
        await path.drop()


class _Conn(_Protocol):
    """One client's connection on the fixed port.

    Nobody's until its first stream says a session secret from an offer;
    then it is that session's path, exactly like a punched one.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key: Optional[str] = None
        self.user = "?"
        self.bound: Optional[dict] = None
        self.peer: Optional[tuple[str, int]] = None
        self.calls = 0
        self.streams: set[asyncio.Task] = set()
        self._stream_handler = self._stream
        self._hello_timer = asyncio.get_running_loop().call_later(HELLO_SECONDS, self._no_hello)

    def _no_hello(self) -> None:
        if self.key is None:
            self.close()

    def quic_event_received(self, event) -> None:
        super().quic_event_received(event)
        if isinstance(event, events.ConnectionTerminated):
            self._hello_timer.cancel()
            if self.key is not None and _paths.get(self.key) is self:
                del _paths[self.key]

    def _stream(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.ensure_future(self._hello(reader, writer) if self.key is None else _serve_call(self, reader, writer))
        self.streams.add(task)
        task.add_done_callback(self.streams.discard)

    async def _hello(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._claim(reader, writer)
        except Exception:  # noqa: BLE001 - a hello that cannot be honoured closes the connection
            self.close()

    async def _claim(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            hello = json.loads(await read_frame(reader))
            claim = _sessions.pop(str(hello.get("session", "")), None)
        except Exception:  # noqa: BLE001 - not a hello: not ours
            claim = None
        if claim is None or claim["expires"] < asyncio.get_running_loop().time():
            writer.write(frame(json.dumps({"a": "unknown session"}).encode()))
            writer.write_eof()
            await asyncio.sleep(0)  # the reply leaves on the next turn; the close must follow it
            self.close()
            return
        self.key, self.user, self.bound = claim["key"], claim["user"], claim["bound"]
        self.peer = self._quic._network_paths[0].addr[:2]
        await _make_room(self.key)
        _paths[self.key] = self
        writer.write(frame(json.dumps({"ok": True}).encode()))
        writer.write_eof()

    async def drop(self) -> None:
        if self.key is not None and _paths.get(self.key) is self:
            del _paths[self.key]
        await cancel_tasks([t for t in self.streams if t is not asyncio.current_task()])
        await asyncio.sleep(0)  # a reply written just before leaves on this turn; the close follows it
        self.close()
        await asyncio.sleep(0)


def _fixed_port_offer(key: str, user: str, bound: Optional[dict]) -> dict:
    """What the answer adds when the fixed port is up: where to dial, and the
    secret that makes the connection this session's path."""
    from .global_onboarding import lan_endpoint

    endpoint = lan_endpoint() if _listener is not None else None
    if not endpoint:
        return {}
    secret = secrets.token_urlsafe(24)
    _sessions[secret] = {"key": key, "user": user, "bound": bound, "expires": _loop.time() + SESSION_SECONDS}
    for stale in [s for s, claim in _sessions.items() if claim["expires"] < _loop.time()]:
        _sessions.pop(stale, None)
    return {"udp": f"{endpoint.rsplit(':', 1)[0]}:{_listener_port}", "session": secret}


async def _start_listener(port: int) -> int:
    global _listener, _listener_port
    _listener = await quic_serve(BIND_HOST, port, configuration=_server_configuration(), create_protocol=_Conn)
    _listener_port = _listener._transport.get_extra_info("sockname")[1]
    return _listener_port


def start_listener(port: Optional[int] = None) -> int:
    """Listen for QUIC on the fixed port (UDP_PORT unless given); returns the
    bound port, or 0 when there is none to bind."""
    if port is None:
        if not UDP_PORT:
            return 0
        port = UDP_PORT
    try:
        return asyncio.run_coroutine_threadsafe(_start_listener(port), _get_loop()).result(10)
    except Exception:  # noqa: BLE001 - the punch still works without it
        return 0


async def _offer(key: str, user: str, remote: dict, bound: Optional[dict] = None) -> dict:
    await _make_room(key)
    ice = Ice(ice_controlling=False, stun_server=stun_server(default_route_address()))
    try:
        await ice.gather_candidates()
        ice.remote_username = str(remote["ufrag"])
        ice.remote_password = str(remote["pwd"])
        for sdp in remote["candidates"]:
            await ice.add_remote_candidate(Candidate.from_sdp(str(sdp)))
        await ice.add_remote_candidate(None)
    except Exception:
        await close_ice(ice)
        raise
    fixed = _fixed_port_offer(key, user, bound)
    # A client that races the fixed port against the punch says so ("race")
    # and needs only a short hold; a 2.1.0 offer has no such key.
    hold = 0.0 if not fixed else RACE_HOLD_SECONDS if remote.get("race") else HOLD_SECONDS
    path = _paths[key] = _Path(key, user, ice, bound, hold=hold)
    path.task = asyncio.ensure_future(path.run())
    return {
        "ufrag": ice.local_username,
        "pwd": ice.local_password,
        "candidates": [candidate.to_sdp() for candidate in ice.local_candidates],
        **fixed,
    }


def _get_loop() -> asyncio.AbstractEventLoop:
    global _loop, _thread
    with _lock:
        if _loop is None:
            _loop = asyncio.new_event_loop()
            quiet_aioice_errors(_loop)
            _thread = threading.Thread(
                target=_loop.run_forever, name="remoterf-direct", daemon=True
            )
            _thread.start()
        return _loop


def _key(session_key: str, remote: dict) -> str:
    """session/offer-id; the id may not carry the separator, or a client could
    give each offer a session of its own and dodge the cap."""
    return f"{session_key}/{str(remote.get('id', ''))[:32].replace('/', '')}"


def offer(session_key: str, user: str, ice: str) -> dict:
    """ACC:direct_offer, already authenticated: answer the client's ICE offer.

    ``session_key`` names the client session and ``ice`` is the offer JSON,
    whose ``id`` tells that session's client processes apart: each keeps one
    path, and its next offer replaces it. Returns the answer, or
    ``{"ace": reason}`` -- the client then simply stays on the relay.
    """
    try:
        remote = json.loads(ice)
        key = _key(session_key, remote)
        answer = asyncio.run_coroutine_threadsafe(
            _offer(key, user, remote), _get_loop()
        ).result(20)
    except Exception:  # noqa: BLE001 - the client then stays on the relay
        return {"ace": map_arg("direct path unavailable")}
    return {"ice": map_arg(json.dumps(answer)), "server_name": map_arg(hostname() or "")}


def offer_bound(session_key: str, user: str, ice: str, *, bound: dict) -> dict:
    """The owner side of a federated reservation's path.

    ``bound["authorize"](function_name)`` decides every call (None allows,
    else the reason) and ``bound["run"](function_name, args)`` executes it
    against the reservation's device. Returns the ICE answer with this
    Server's TLS pin; raises when no path could be prepared.
    """
    # The owner pins itself: a Global client has no FederationPeers row for it.
    # Read before _offer, so a missing CA prepares no path.
    pin = {"server_name": hostname() or "", "ca_pem": (_cert_dir() / "ca.crt").read_text()}
    remote = json.loads(ice)
    answer = asyncio.run_coroutine_threadsafe(_offer(_key(session_key, remote), user, remote, bound), _get_loop()).result(20)
    return {**answer, **pin}


def shutdown() -> None:
    """Close every path, the fixed port, stop the loop and release it."""
    global _loop, _thread, _listener, _listener_port
    with _lock:
        loop, _loop = _loop, None
        thread, _thread = _thread, None
    if loop is None:
        return

    async def _close_all() -> None:
        global _listener, _listener_port
        for path in list(_paths.values()):
            await path.drop()
        if _listener is not None:
            _listener.close()
            _listener, _listener_port = None, 0
        _sessions.clear()

    with contextlib.suppress(Exception):
        asyncio.run_coroutine_threadsafe(_close_all(), loop).result(10)
    loop.call_soon_threadsafe(loop.stop)
    if thread is not None:
        thread.join(10)
    if not loop.is_running():
        with contextlib.suppress(Exception):
            loop.close()  # the selector and its wake-up pipe go with it
