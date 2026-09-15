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
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Optional

from aioice import Candidate, Connection
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.packet import QuicPacketType, pull_quic_header

from ..common.grpc import grpc_pb2
from ..common.utils.ansi_codes import Sty, printf
from ..common.utils.process_arg import map_arg
from .global_onboarding import RELAYED, hostname, is_offsite

logger = logging.getLogger("remoteRF_server.direct")

ALPN = "remoterf-direct/1"
MAX_FRAME = 100 * 1024 * 1024  # the gRPC message ceiling
IDLE_SECONDS = 600
CONNECT_SECONDS = 30  # ICE checks, then the QUIC handshake; a silent client is dropped
DEFAULT_STUN = "stun.l.google.com:19302"

CERT_DIR: Optional[Path] = None  # set by start_server_runtime

_loop: Optional[asyncio.AbstractEventLoop] = None
_lock = threading.Lock()
_paths: dict[str, "_Path"] = {}


def frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + payload


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    size = int.from_bytes(await reader.readexactly(4), "big")
    if size > MAX_FRAME:
        raise ValueError(f"frame of {size} bytes exceeds {MAX_FRAME}")
    return await reader.readexactly(size)


def stun_server() -> Optional[tuple[str, int]]:
    value = os.getenv("REMOTERF_STUN_SERVER", DEFAULT_STUN).strip()
    if value.lower() in {"", "off", "none", "0"}:
        return None
    host, _, port = value.rpartition(":")
    return host, int(port)


def peer_address(ice: Connection) -> tuple[str, int]:
    """The remote end of the nominated pair (aioice keeps it private)."""
    return ice._nominated[1].remote_addr


def _dispatch(request: grpc_pb2.GenericRPCRequest, peer_host: str) -> dict:
    """Run one call exactly as GenericRPCServicer.Call does, device plane only."""
    from .rpc_manager import rpc_manager

    name = request.function_name
    if not (name.startswith("IDL:") or rpc_manager._looks_like_device_rpc(name)):
        return {"a": map_arg(f"{name} is not available on the direct path")}
    token = RELAYED.set(is_offsite(peer_host))
    try:
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


def _server_configuration() -> QuicConfiguration:
    cert_dir = CERT_DIR or Path(
        os.getenv(
            "REMOTERF_CERT_DIR",
            Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config")) / "remoterf" / "certs",
        )
    )
    configuration = QuicConfiguration(
        is_client=False, alpn_protocols=[ALPN], idle_timeout=IDLE_SECONDS
    )
    configuration.load_cert_chain(cert_dir / "server.crt", cert_dir / "server.key")
    return configuration


class _Path:
    """One client session's punched pair and the QUIC connection over it."""

    def __init__(self, key: str, user: str, ice: Connection):
        self.key = key
        self.user = user
        self.ice = ice
        self.peer: Optional[tuple[str, int]] = None
        self.calls = 0
        self.task: Optional[asyncio.Task] = None
        self.transport: Optional[_IceTransport] = None

    async def run(self) -> None:
        protocol = None
        try:
            await asyncio.wait_for(self.ice.connect(), CONNECT_SECONDS)
            self.peer = peer_address(self.ice)
            protocol = await asyncio.wait_for(self._accept(), CONNECT_SECONDS)
            pump = asyncio.ensure_future(self._pump(protocol))
            closed = asyncio.ensure_future(protocol.wait_closed())
            try:
                await asyncio.wait_for(protocol.wait_connected(), CONNECT_SECONDS)
                where = "offsite" if is_offsite(self.peer[0]) else "local"
                printf(f"Direct path open: {self.user} from {self.peer[0]}:{self.peer[1]} ({where})", Sty.GRAY)
                await asyncio.wait({pump, closed}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                pump.cancel()
                closed.cancel()
        except Exception as exc:  # noqa: BLE001 - a failed punch is expected on some networks
            printf(f"Direct path failed: {self.user}: {type(exc).__name__}: {exc}", Sty.GRAY)
        finally:
            if protocol is not None:
                protocol.close()
                await asyncio.sleep(0)  # the CONNECTION_CLOSE leaves before the pair goes
            if self.transport is not None:
                self.transport.close()
            await self.close()
            if self.peer is not None:
                printf(f"Direct path closed: {self.user} from {self.peer[0]}:{self.peer[1]} after {self.calls} calls", Sty.GRAY)

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
            protocol = QuicConnectionProtocol(quic, stream_handler=self._stream)
            protocol.connection_made(transport)
            protocol.datagram_received(data, self.peer)
            return protocol

    async def _pump(self, protocol: QuicConnectionProtocol) -> None:
        with contextlib.suppress(ConnectionError):
            while True:
                data, _ = await self.ice.recvfrom()
                protocol.datagram_received(data, self.peer)

    def _stream(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        asyncio.ensure_future(self._serve(reader, writer))

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = grpc_pb2.GenericRPCRequest()
            request.ParseFromString(await read_frame(reader))
            results = await asyncio.get_running_loop().run_in_executor(
                None, _dispatch, request, self.peer[0]
            )
            writer.write(frame(grpc_pb2.GenericRPCResponse(results=results).SerializeToString()))
            writer.write_eof()
            self.calls += 1
        except Exception as exc:  # noqa: BLE001 - one bad stream must not take the path down
            logger.debug("direct path stream: %s", exc)

    async def close(self) -> None:
        if _paths.get(self.key) is self:
            del _paths[self.key]
        task = self.task
        if task is not None and task is not asyncio.current_task():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await self.ice.close()


async def _offer(key: str, user: str, remote: dict) -> dict:
    old = _paths.get(key)
    if old is not None:
        await old.close()
    ice = Connection(ice_controlling=False, stun_server=stun_server())
    try:
        await ice.gather_candidates()
        ice.remote_username = str(remote["ufrag"])
        ice.remote_password = str(remote["pwd"])
        for sdp in remote["candidates"]:
            await ice.add_remote_candidate(Candidate.from_sdp(str(sdp)))
        await ice.add_remote_candidate(None)
    except Exception:
        await ice.close()
        raise
    path = _paths[key] = _Path(key, user, ice)
    path.task = asyncio.ensure_future(path.run())
    return {
        "ufrag": ice.local_username,
        "pwd": ice.local_password,
        "candidates": [candidate.to_sdp() for candidate in ice.local_candidates],
    }


def _get_loop() -> asyncio.AbstractEventLoop:
    global _loop
    with _lock:
        if _loop is None:
            _loop = asyncio.new_event_loop()
            threading.Thread(
                target=_loop.run_forever, name="remoterf-direct", daemon=True
            ).start()
        return _loop


def offer(session_key: str, user: str, ice: str) -> dict:
    """ACC:direct_offer, already authenticated: answer the client's ICE offer.

    ``session_key`` names the client session and ``ice`` is the offer JSON,
    whose ``id`` tells that session's client processes apart: each keeps one
    path, and its next offer replaces it. Returns the answer, or
    ``{"ace": reason}`` -- the client then simply stays on the relay.
    """
    try:
        remote = json.loads(ice)
        key = f"{session_key}/{str(remote.get('id', ''))[:32]}"
        answer = asyncio.run_coroutine_threadsafe(
            _offer(key, user, remote), _get_loop()
        ).result(20)
    except Exception as exc:  # noqa: BLE001
        return {"ace": map_arg(f"direct path unavailable: {exc}")}
    return {"ice": map_arg(json.dumps(answer)), "server_name": map_arg(hostname() or "")}


def shutdown() -> None:
    """Close every path and stop the loop (server stop, tests)."""
    global _loop
    with _lock:
        loop, _loop = _loop, None
    if loop is None:
        return

    async def _close_all() -> None:
        for path in list(_paths.values()):
            await path.close()

    with contextlib.suppress(Exception):
        asyncio.run_coroutine_threadsafe(_close_all(), loop).result(10)
    loop.call_soon_threadsafe(loop.stop)
