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

"""Shared ICE and QUIC primitives for RemoteRF direct paths."""

from __future__ import annotations

import asyncio
import collections
import ipaddress
import os
import socket
from typing import Optional

from aioice import Connection
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic import events

ALPN = "remoterf-direct/1"
MAX_FRAME = 100 * 1024 * 1024
DEFAULT_STUN = "stun.l.google.com:19302"
STUN_SECONDS = 1.5


async def close_ice(ice) -> None:
    """Close an aioice Connection without its after-close retry noise."""
    checks = [pair.task for pair in list(getattr(ice, "_check_list", [])) if pair.task is not None]
    for task in checks:
        task.cancel()
    if checks:
        await asyncio.gather(*checks, return_exceptions=True)
    for protocol in list(getattr(ice, "_protocols", [])):
        for transaction in list(getattr(protocol, "transactions", {}).values()):
            handle = getattr(transaction, "_Transaction__timeout_handle", None)
            if handle is not None:
                handle.cancel()
    await ice.close()


async def cancel_tasks(tasks) -> None:
    """Cancel these tasks and wait for them to finish."""
    current = asyncio.current_task()
    tasks = [task for task in tasks if task is not None and task is not current and not task.done()]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


def quiet_aioice_errors(loop) -> None:
    """Suppress expected aioice retry errors after a socket is closed."""
    default = loop.default_exception_handler

    def handler(loop, context):
        exc = context.get("exception")
        where = repr(context.get("handle", "")) + str(context.get("message", ""))
        if isinstance(exc, (AttributeError, OSError)) and "Transaction.__retry" in where:
            return
        default(context)

    loop.set_exception_handler(handler)


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
    """The configured STUN endpoint, unless the server is publicly addressed."""
    value = os.getenv("REMOTERF_STUN_SERVER", DEFAULT_STUN).strip()
    if value.lower() in {"", "off", "none", "0"}:
        return None
    if address is not None and ipaddress.ip_address(address).is_global:
        return None
    host, _, port = value.rpartition(":")
    return host, int(port)


class Ice(Connection):
    """aioice Connection restricted to the default-route interface."""

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
    """The remote end of aioice's nominated pair."""
    return ice._nominated[1].remote_addr


class _IceTransport:
    """The sendto() surface aioquic's protocol needs on a nominated pair."""

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


class _Protocol(QuicConnectionProtocol):
    """aioquic protocol which remembers why the connection ended."""

    terminated = ""

    def quic_event_received(self, event) -> None:
        if isinstance(event, events.ConnectionTerminated):
            self.terminated = event.reason_phrase or (
                f"QUIC error {event.error_code:#x}" if event.error_code else ""
            )
        super().quic_event_received(event)


IceTransport = _IceTransport
Protocol = _Protocol
