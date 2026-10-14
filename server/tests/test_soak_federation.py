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

"""Slice 5: soak. Several federated clients on one owner at once, idle
close, revocation under a running stream, and nothing left behind.

The broker-offline run is test_peer_transport (the broker there is a closed
port for the whole run); both-NAT rendezvous through the relay is a live
check only.
"""

from __future__ import annotations

import asyncio
import gc
import os
import sqlite3
import threading
import time

from remoteRF_server.server import direct_path

from test_federated_direct_path import Client, _gone, federated  # noqa: F401 - fixture
from test_gate_h_devices import world  # noqa: F401 - fixture
from test_home_device_plane import home  # noqa: F401 - fixture

CLIENTS = 5
CALLS = 10


def _open_fds() -> int:
    return len(os.listdir("/dev/fd"))


def _direct_threads() -> list:
    return [t for t in threading.enumerate() if t.name == "remoterf-direct"]


def test_five_concurrent_clients_on_one_owner_and_nothing_leaks(federated):
    """Two identical rounds: warm-up opens per-thread handler connections and
    pool threads, which a plateau tells apart from a per-round leak."""
    fed = federated

    async def round_trip(tag):
        clients = [Client(fed, offer_id=f"{tag}-{i}") for i in range(CLIENTS)]
        try:
            await asyncio.gather(*(c.punch() for c in clients))
            assert len(direct_path._paths) == CLIENTS
            results = await asyncio.gather(*(c.call("Test:rx:CALL0") for c in clients for _ in range(CALLS)))
            assert [r["value"] for r in results] == [42] * (CLIENTS * CALLS)
            assert all(p.calls == CALLS for p in direct_path._paths.values())
        finally:
            await asyncio.gather(*(c.close() for c in clients))
        assert await _gone()

    asyncio.run(round_trip("first"))
    # Pool threads start lazily and open their handler connections on first
    # use, so warm-up can spill into a later round. It is bounded; a leak grows
    # every round: some round must add (almost) nothing.
    deltas = []
    for tag in ("second", "third", "fourth", "fifth"):
        gc.collect()  # the executor's error paths leave connections to the collector
        before = _open_fds()
        asyncio.run(round_trip(tag))
        gc.collect()
        deltas.append(_open_fds() - before)
        if deltas[-1] <= 2:
            break
    assert len(fed["rpc"].device_calls) == (len(deltas) + 1) * CLIENTS * CALLS
    assert deltas[-1] <= 2, deltas  # nothing per round is left behind
    direct_path.shutdown()
    deadline = time.monotonic() + 5
    while _direct_threads() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _direct_threads()


def test_an_idle_path_closes_by_itself(federated, monkeypatch):
    fed = federated
    monkeypatch.setattr(direct_path, "IDLE_SECONDS", 1)

    async def run():
        client = Client(fed)
        try:
            await client.punch()
            assert len(direct_path._paths) == 1
            assert await _gone(8)  # the owner let the unused path go
        finally:
            await client.close()

    asyncio.run(run())


def test_revocation_under_a_running_stream_closes_every_path(federated):
    fed = federated

    async def run():
        clients = [Client(fed, offer_id=f"stream-{i}") for i in range(3)]
        try:
            await asyncio.gather(*(c.punch() for c in clients))
            stop = asyncio.Event()
            outcomes = {"ok": 0, "refused": 0}

            async def stream(client):
                while not stop.is_set():
                    result = await client.call("Test:rx:CALL0")
                    if result.get("value") == 42:
                        outcomes["ok"] += 1
                    else:
                        outcomes["refused"] += 1
                        return
                    await asyncio.sleep(0.01)

            streams = [asyncio.ensure_future(stream(c)) for c in clients]
            await asyncio.sleep(0.3)
            with sqlite3.connect(fed["dest_db"]) as conn:
                conn.execute("UPDATE FederatedPrincipals SET status='disabled', disabled_at=100")  # `members remove`
            await asyncio.wait_for(asyncio.gather(*streams), 10)
            stop.set()
            assert outcomes["ok"] > 0 and outcomes["refused"] == 3
            assert await _gone()
        finally:
            await asyncio.gather(*(c.close() for c in clients))

    asyncio.run(run())
