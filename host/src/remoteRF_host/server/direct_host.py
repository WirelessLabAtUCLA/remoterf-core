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

"""A client's punched path straight to this host, for one device.

The lab signals it down the tunnel: a direct_offer carrying the client's ICE
offer and a grant (an EdDSA JWT the lab signed for this host and device). The
host checks the grant offline, answers the offer, and serves that device's
calls over QUIC (the lab's Gate I framing) until the grant expires, the lab
revokes it, or the tunnel drops. Schema (IDL) calls stay on the lab's path.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import math
import os
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from ..common.grpc import grpc_pb2
from ..common.utils.process_arg import map_arg

CONNECT_SECONDS = 30
OFFER_SECONDS = 18
IDLE_SECONDS = 600
MAX_PATHS_PER_DEVICE = 4  # one holder's processes; the oldest makes room
MAX_STREAMS_PER_PATH = 8
MAX_REQUEST_BYTES = 16 * 1024 * 1024
GRANT_ENDED = "the reservation's grant has ended"


def available() -> bool:
    try:
        import aioice  # noqa: F401
        import aioquic  # noqa: F401
        from remoterf_device_core import direct  # noqa: F401
        from remoterf_federation_core.federation import verify_eddsa_jwt  # noqa: F401
    except Exception:
        return False
    return True


class DirectHost:
    def __init__(self, *, host_id: str, key_path: Path, run_call: Callable):
        self.host_id = host_id
        self.key_path = Path(key_path)
        self.cert_path = self.key_path.with_suffix(".crt")
        self.run_call = run_call  # (gid, GenericRPCRequest) -> {name: Argument}
        self._lock = threading.Lock()
        self._lab: dict = {}  # deployment_id, server_name, ca_pem, key (Ed25519PublicKey)
        self._grants: dict[int, dict] = {}  # gid -> claims of its newest grant
        self._revoked: set[str] = set()
        self._ended: dict[int, float] = {}
        self._accepted_iat: dict[int, float] = {}
        self._paths: dict[int, list] = {}
        self._call_locks: dict[int, asyncio.Lock] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # -- identity --------------------------------------------------------

    def public_key_pem(self) -> str:
        """This host's TLS key (made once, kept 0600); the lab's CA certifies it."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        if not self.key_path.exists():
            key = ec.generate_private_key(ec.SECP256R1())
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            pem = key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            try:
                fd = os.open(self.key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "wb") as key_file:
                    key_file.write(pem)
        os.chmod(self.key_path, 0o600)
        key = serialization.load_pem_private_key(self.key_path.read_bytes(), None)
        return key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def configure(self, info: dict) -> None:
        """lab_info: who signs grants, and the certificate clients will see."""
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_public_key(str(info["grant_key"]).encode())
        self.cert_path.parent.mkdir(parents=True, exist_ok=True)
        self.cert_path.write_text(str(info["cert_pem"]))
        with self._lock:
            self._lab = {
                "deployment_id": str(info["deployment_id"]),
                "server_name": str(info["server_name"]),
                "ca_pem": str(info["ca_pem"]),
                "key": key,
            }

    # -- grants ----------------------------------------------------------

    def verify(self, token: str, gid: int) -> dict:
        from remoterf_federation_core.federation import FederationError, verify_eddsa_jwt

        with self._lock:
            lab = dict(self._lab)
        if not lab:
            raise PermissionError("this host has no lab grant key yet")
        try:
            claims = verify_eddsa_jwt(token, lab["key"], code="invalid_grant")
        except FederationError:
            raise PermissionError("invalid grant") from None
        try:
            header = json.loads(base64.urlsafe_b64decode(token.split(".", 1)[0] + "=="))
        except (AttributeError, ValueError, UnicodeDecodeError):
            raise PermissionError("invalid grant") from None
        iat = claims.get("iat")
        now = time.time()
        with self._lock:
            ended = self._ended.get(int(gid), float("-inf"))
            revoked = set(self._revoked)
        if (
            header.get("typ") != "remoterf-host-grant"
            or type(claims.get("iss")) is not str
            or claims["iss"] != lab["deployment_id"]
            or type(claims.get("aud")) is not str
            or claims["aud"] != self.host_id
            or type(claims.get("gid")) is not int
            or claims["gid"] != int(gid)
            or type(claims.get("rid")) is not str
            or type(claims.get("jti")) is not str
            or not claims["jti"]
            or type(claims.get("exp")) is not int
            or claims["exp"] <= now
            or type(iat) not in (int, float)
            or isinstance(iat, bool)
            or iat <= ended
            or claims["jti"] in revoked
        ):
            raise PermissionError("grant is not for this device now")
        return claims

    def refresh(self, gid: int, token: str) -> None:
        claims = self.verify(token, gid)
        with self._lock:
            if claims["iat"] <= self._ended.get(int(gid), float("-inf")) or claims["jti"] in self._revoked:
                raise PermissionError("grant is not for this device now")
            self._grants[int(gid)] = claims
            self._accepted_iat[int(gid)] = max(
                float(claims["iat"]), self._accepted_iat.get(int(gid), float("-inf")),
            )

    def _refusal(self, gid: int, rid: str, function_name: str) -> Optional[str]:
        parts = function_name.split(":", 2)
        if len(parts) != 3 or not all(parts) or parts[0] in ("IDL", "ACC"):
            return f"{function_name} is not available on the direct path"
        with self._lock:
            claims = self._grants.get(int(gid))
            if (
                claims is None
                or claims["rid"] != rid
                or claims["exp"] <= time.time()
                or claims["jti"] in self._revoked
            ):
                return GRANT_ENDED
        return None

    # -- paths -----------------------------------------------------------

    def offer(self, gid: int, ice: str, grant: str) -> dict:
        """direct_offer: answer the client's ICE offer for this device."""
        self.refresh(gid, grant)
        with self._lock:
            pin = {"server_name": self._lab["server_name"], "ca_pem": self._lab["ca_pem"]}
            rid = self._grants[int(gid)]["rid"]
        remote = json.loads(ice)
        future = asyncio.run_coroutine_threadsafe(self._offer(int(gid), rid, remote), self._get_loop())
        try:
            answer = future.result(OFFER_SECONDS)
        except TimeoutError:
            future.cancel()
            raise TimeoutError("direct offer timed out") from None
        return {**answer, **pin}

    def _record_end(self, gid: int, at: Optional[float]) -> None:
        fallback = self._accepted_iat.get(gid, float("-inf"))
        ended = fallback if at is None or not math.isfinite(float(at)) else float(at)
        self._ended[gid] = max(ended, self._ended.get(gid, float("-inf")))

    def end(self, gid: int, at: Optional[float] = None) -> None:
        """The reservation ended (or the lab revoked it): drop its grant and paths."""
        with self._lock:
            claims = self._grants.pop(int(gid), None)
            self._record_end(int(gid), at)
            if claims is not None:
                self._revoked.add(claims["jti"])
        self._close(lambda path: path.gid == int(gid))

    def revoke(self, gid: int, rid: str, at: Optional[float] = None) -> None:
        """Drop paths for one reservation without resetting the device."""
        with self._lock:
            self._record_end(int(gid), at)
            claims = self._grants.get(int(gid))
            if claims is not None and claims["rid"] == rid:
                self._grants.pop(int(gid), None)
                self._revoked.add(claims["jti"])
        self._close(lambda path: path.gid == int(gid) and path.rid == rid)

    def close_all(self) -> None:
        """The tunnel dropped: no lab, no grants."""
        with self._lock:
            for claims in self._grants.values():
                self._revoked.add(claims["jti"])
            self._grants.clear()
            self._lab.clear()
        self._close(lambda path: True)

    def _close(self, which) -> None:
        if self._loop is None:
            return

        async def close() -> None:
            for paths in list(self._paths.values()):
                for path in [p for p in paths if which(p)]:
                    await path.close()

        coroutine = close()
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, self._loop)
        except Exception:
            coroutine.close()
            return
        future.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        from remoterf_device_core import direct as core

        with self._lock:
            if self._loop is None:
                self._loop = asyncio.new_event_loop()
                core.quiet_aioice_errors(self._loop)
                threading.Thread(target=self._loop.run_forever, name="hostrf-direct", daemon=True).start()
            return self._loop

    def _grant_is_current(self, gid: int, rid: str) -> bool:
        with self._lock:
            claims = self._grants.get(gid)
            return bool(
                claims is not None
                and claims["rid"] == rid
                and claims["exp"] > time.time()
                and claims["jti"] not in self._revoked
            )

    def _require_current_grant(self, gid: int, rid: str) -> None:
        if not self._grant_is_current(gid, rid):
            raise PermissionError(GRANT_ENDED)

    async def _offer(self, gid: int, rid: str, remote: dict) -> dict:
        from aioice import Candidate

        from remoterf_device_core import direct as core

        self._require_current_grant(gid, rid)
        paths = self._paths.setdefault(gid, [])
        ice = None
        try:
            for old in paths[: max(0, len(paths) - MAX_PATHS_PER_DEVICE + 1)]:
                await old.close()
                self._require_current_grant(gid, rid)
            ice = core.Ice(ice_controlling=False, stun_server=core.stun_server(core.default_route_address()))
            await ice.gather_candidates()
            self._require_current_grant(gid, rid)
            ice.remote_username = str(remote["ufrag"])
            ice.remote_password = str(remote["pwd"])
            for sdp in remote["candidates"]:
                await ice.add_remote_candidate(Candidate.from_sdp(str(sdp)))
                self._require_current_grant(gid, rid)
            await ice.add_remote_candidate(None)
            self._require_current_grant(gid, rid)
        except Exception:
            if ice is not None:
                await core.close_ice(ice)
            raise
        path = _HostPath(self, gid, rid, ice)
        paths.append(path)
        path.task = asyncio.ensure_future(path.run())
        return {
            "ufrag": ice.local_username,
            "pwd": ice.local_password,
            "candidates": [candidate.to_sdp() for candidate in ice.local_candidates],
        }

    def _configuration(self):
        from aioquic.quic.configuration import QuicConfiguration

        from remoterf_device_core import direct as core

        configuration = QuicConfiguration(is_client=False, alpn_protocols=[core.ALPN], idle_timeout=IDLE_SECONDS)
        configuration.load_cert_chain(self.cert_path, self.key_path)
        return configuration


class _HostPath:
    """One punched pair and its QUIC connection, for one device."""

    def __init__(self, owner: DirectHost, gid: int, rid: str, ice):
        self.owner, self.gid, self.rid, self.ice = owner, gid, rid, ice
        self.peer = None
        self.task: Optional[asyncio.Task] = None
        self.transport = None
        self.streams: set = set()
        self.closed = False

    async def run(self) -> None:
        from remoterf_device_core import direct as core

        protocol = None
        try:
            await asyncio.wait_for(self.ice.connect(), CONNECT_SECONDS)
            self.peer = core.peer_address(self.ice)
            protocol = await asyncio.wait_for(self._accept(), CONNECT_SECONDS)
            pump = asyncio.ensure_future(self._pump(protocol))
            closed = asyncio.ensure_future(protocol.wait_closed())
            try:
                await asyncio.wait_for(protocol.wait_connected(), CONNECT_SECONDS)
                await asyncio.wait({pump, closed}, return_when=asyncio.FIRST_COMPLETED)
            finally:
                await core.cancel_tasks((pump, closed))
        except Exception:  # noqa: BLE001 - a failed punch is expected on some networks; the client keeps the relay
            pass
        finally:
            if protocol is not None:
                protocol.close()
                await asyncio.sleep(0)
            if self.transport is not None:
                self.transport.close()
            await self.close()

    async def _accept(self):
        from aioquic.buffer import Buffer
        from aioquic.quic.connection import QuicConnection
        from aioquic.quic.packet import QuicPacketType, pull_quic_header

        from remoterf_device_core import direct as core

        transport = self.transport = core.IceTransport(self.ice)
        while True:
            data, _ = await self.ice.recvfrom()
            try:
                header = pull_quic_header(Buffer(data=data), host_cid_length=8)
            except ValueError:
                continue
            if header.packet_type != QuicPacketType.INITIAL:
                continue
            quic = QuicConnection(
                configuration=self.owner._configuration(),
                original_destination_connection_id=header.destination_cid,
            )
            protocol = core.Protocol(quic, stream_handler=self._stream)
            protocol.connection_made(transport)
            protocol.datagram_received(data, self.peer)
            return protocol

    async def _pump(self, protocol) -> None:
        with contextlib.suppress(ConnectionError):
            while True:
                data, _ = await self.ice.recvfrom()
                protocol.datagram_received(data, self.peer)

    def _stream(self, reader, writer) -> None:
        serve = self._serve if len(self.streams) < MAX_STREAMS_PER_PATH else self._busy
        task = asyncio.ensure_future(serve(reader, writer))
        self.streams.add(task)
        task.add_done_callback(self.streams.discard)

    async def _busy(self, reader, writer) -> None:
        from remoterf_device_core import direct as core

        writer.write(core.frame(grpc_pb2.GenericRPCResponse(results={"a": map_arg("busy")}).SerializeToString()))
        writer.write_eof()
        writer.close()

    async def _serve(self, reader, writer) -> None:
        from remoterf_device_core import direct as core

        drop = False
        try:
            try:
                size = int.from_bytes(await reader.readexactly(4), "big")
                if size > MAX_REQUEST_BYTES:
                    raise ValueError("direct request frame is too large")
                request = grpc_pb2.GenericRPCRequest.FromString(await reader.readexactly(size))
            except asyncio.IncompleteReadError:
                return
            refused = self.owner._refusal(self.gid, self.rid, request.function_name)
            drop = refused == GRANT_ENDED
            if refused is not None:
                results = {"a": map_arg(refused)}
            else:
                lock = self.owner._call_locks.setdefault(self.gid, asyncio.Lock())
                async with lock:
                    refused = self.owner._refusal(self.gid, self.rid, request.function_name)
                    if refused is None:
                        try:
                            results = await asyncio.get_running_loop().run_in_executor(
                                None, self.owner.run_call, self.gid, request)
                        except Exception as exc:  # device exceptions are normal RPC results
                            results = {"a": map_arg(str(exc))}
                        refused = self.owner._refusal(self.gid, self.rid, request.function_name)
                    if refused is not None:
                        results = {"a": map_arg(refused)}
                        drop = refused == GRANT_ENDED
            writer.write(core.frame(grpc_pb2.GenericRPCResponse(results=results).SerializeToString()))
            writer.write_eof()
        except Exception:  # noqa: BLE001 - not our framing: answer nothing more on this path
            drop = True
        finally:
            writer.close()
        if drop:
            await self.close()

    async def close(self) -> None:
        from remoterf_device_core import direct as core

        if self.closed:
            return
        self.closed = True
        paths = self.owner._paths.get(self.gid, [])
        if self in paths:
            paths.remove(self)
        task, current = self.task, asyncio.current_task()
        if task is not None and task is not current:
            task.cancel()
            await asyncio.wait({task})
        await core.cancel_tasks(list(self.streams))
        await core.close_ice(self.ice)
