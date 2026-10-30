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

"""Slice 4: the federated direct path, both ends in this process.

HOME and owner are the `home` fixture (real executor, real grants); the
client punches a real ICE + QUIC pair to the owner's direct-path loop and
drives the owner's (fake) hardware over it, authorized per call by the
owner's own reservation and contract tables, never by a bearer token.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import pytest
from aioice import Candidate, Connection
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from remoterf_federation_core import build_device_payload
from remoterf_federation_core.devices import MAX_ICE_BYTES

from remoteRF_server.common.grpc import grpc_pb2
from remoteRF_server.common.utils import map_arg, unmap_arg
from remoteRF_server.server import direct_path
from remoteRF_server.server.federation.home_devices import ALIAS_BASE
from remoteRF_server.server.federation.peers import PeerStore

from test_gate_e_federation import CONTRACT, DEST
from test_gate_h_devices import world  # noqa: F401 - fixture
from test_gate_i_direct_path import SERVER_NAME, write_certs
from test_home_device_plane import _acc, _window, home  # noqa: F401 - fixture


@pytest.fixture
def federated(home, tmp_path, monkeypatch):
    """alice, enrolled at the owner, holding a live reservation on its device."""
    cert_dir = tmp_path / "owner-certs"
    cert_dir.mkdir()
    ca_pem = write_certs(cert_dir)
    monkeypatch.setattr(direct_path, "CERT_DIR", cert_dir)
    monkeypatch.setenv("REMOTERF_STUN_SERVER", "off")
    # Fixed pools on both ends: the handlers keep a connection per thread, so
    # a pool that grows between rounds would read as a leak in the soak.
    loop = direct_path._get_loop()
    loop.call_soon_threadsafe(loop.set_default_executor, ThreadPoolExecutor(4, "remoterf-direct-call"))
    PeerStore(home["dest_db"]).upsert(
        deployment_id=DEST, display_name="Destination", source="admin",
        route={"grpc_endpoint": "127.0.0.1:1", "tls_server_name": SERVER_NAME, "ca_pem": ca_pem.decode()},
    )
    home["plane"].record_enrollment(local_account_id=home["account_id"], destination_deployment_id=DEST)
    alias = next(int(k) for k in _acc(home, "get_dev") if int(k) >= ALIAS_BASE)
    start, end = _window()
    reserved = _acc(home, "reserve_device", dd=alias, st=int(start.timestamp()), et=int(end.timestamp()))
    with sqlite3.connect(home["root"] / "reservations.db") as conn:
        res_id, remote = conn.execute(
            "SELECT res_id, remote_reservation_id FROM HomeFederatedReservations"
        ).fetchone()
    try:
        yield {**home, "token": reserved["Token"], "res_id": res_id, "remote_res_id": remote, "ca_pem": ca_pem}
    finally:
        direct_path.shutdown()


_OFFERS = ThreadPoolExecutor(2, "test-offer")  # the blocking ACC calls, off the loop


class Client:
    """One client process's end of a path to the owner."""

    def __init__(self, fed, *, offer_id="abcd", ca_pem=None, idle_timeout=60.0, login=True):
        self.fed, self.offer_id, self.ca_pem, self.idle_timeout = fed, offer_id, ca_pem, idle_timeout
        self.login = login
        self.ice = self.protocol = self.pump = None

    def offer(self, ice):
        ice = json.dumps({
            "id": self.offer_id, "ufrag": ice.local_username, "pwd": ice.local_password,
            "candidates": [c.to_sdp() for c in ice.local_candidates],
        })
        if self.login:
            return _acc(self.fed, "direct_offer", a=self.fed["token"], ice=ice)
        return _token_offer(self.fed, self.fed["token"], ice)

    async def punch(self):
        loop = asyncio.get_running_loop()
        self.ice = ice = Connection(ice_controlling=True, use_ipv6=False)
        await ice.gather_candidates()
        reply = await loop.run_in_executor(_OFFERS, self.offer, ice)
        if "ace" in reply:
            await ice.close()
            raise direct_path.PathRefused(reply["ace"])
        answer = json.loads(reply["ice"])
        ice.remote_username, ice.remote_password = answer["ufrag"], answer["pwd"]
        for sdp in answer["candidates"]:
            await ice.add_remote_candidate(Candidate.from_sdp(sdp))
        await ice.add_remote_candidate(None)
        await asyncio.wait_for(ice.connect(), 10)
        peer = direct_path.peer_address(ice)
        configuration = QuicConfiguration(
            is_client=True, alpn_protocols=[direct_path.ALPN], server_name=reply["server_name"],
            idle_timeout=self.idle_timeout,
        )
        configuration.load_verify_locations(cadata=self.ca_pem or reply["ca_pem"].encode())
        self.protocol = protocol = QuicConnectionProtocol(QuicConnection(configuration=configuration))
        protocol.connection_made(direct_path._IceTransport(ice))

        async def pump():
            while True:
                data, _ = await ice.recvfrom()
                protocol.datagram_received(data, peer)

        self.pump = asyncio.ensure_future(pump())
        protocol.connect(peer)
        await asyncio.wait_for(protocol.wait_connected(), 10)
        return reply

    async def call(self, name, args=None):
        reader, writer = await self.protocol.create_stream()
        request = grpc_pb2.GenericRPCRequest(function_name=name, args=args or {"a": map_arg(self.fed["token"])})
        writer.write(direct_path.frame(request.SerializeToString()))
        writer.write_eof()
        response = grpc_pb2.GenericRPCResponse()
        response.ParseFromString(await asyncio.wait_for(direct_path.read_frame(reader), 30))
        return {k: unmap_arg(v) for k, v in response.results.items()}

    async def close(self):
        if self.pump is not None:
            self.pump.cancel()
        if self.protocol is not None:
            self.protocol.close()
            await asyncio.sleep(0)
        if self.ice is not None:
            await self.ice.close()


def _token_offer(fed, token, ice="{}"):
    """ACC:direct_offer from a script with no login: the token is all it sends."""
    reply = fed["reservations"].handle_call(
        function_name="direct_offer", args={"a": map_arg(token), "ice": map_arg(ice)},
    )
    return {k: unmap_arg(v) for k, v in reply.items()}


async def _gone(seconds=5.0):
    deadline = time.monotonic() + seconds
    while direct_path._paths and time.monotonic() < deadline:
        await asyncio.sleep(0.1)
    return not direct_path._paths


def test_a_partner_reservation_drives_the_device_over_a_punched_path(federated):
    fed = federated

    async def run():
        client = Client(fed)
        try:
            reply = await client.punch()
            assert reply["owner"] == DEST and reply["server_name"] == SERVER_NAME
            assert (await client.call("Test:rx:CALL0", {"a": map_arg(fed["token"]), "n": map_arg(3)}))["value"] == 42
            gid, name, args = fed["rpc"].device_calls[-1]
            assert (gid, name) == (fed["allowed"], "Test:rx:CALL0")
            assert "a" not in args and unmap_arg(args["n"]) == 3  # pinned to the reservation's device
            schema = await client.call("IDL:get_drivers", {"token": map_arg("whatever")})
            assert schema["device_type"] == "test"
            assert unmap_arg(fed["rpc"].control_calls[-1][1]["device_id"]) == fed["allowed"]
            refused = await client.call("ACC:get_dev", {"un": map_arg("x")})
            assert "not available" in refused["a"]
            assert len(direct_path._paths) == 1  # ACC:* is refused, not a reason to close
        finally:
            await client.close()
        assert await _gone()

    asyncio.run(run())
    # The offer was one grant to the owner; nothing rode the broker afterwards.
    assert fed["calls"][-1] == "direct_open"
    assert fed["calls"].count("device_rpc") == 0


def test_the_owner_signed_answer_carries_its_pin_within_the_ice_limit(federated, monkeypatch):
    monkeypatch.setattr(direct_path, "hostname", lambda: "owner.global.test")

    async def run():
        client = Client(federated, offer_id="pin1")
        try:
            return await client.punch()
        finally:
            await client.close()
            assert await _gone()

    reply = asyncio.run(run())
    answer = json.loads(reply["ice"])
    assert answer["server_name"] == "owner.global.test"
    assert answer["ca_pem"] == federated["ca_pem"].decode()
    assert len(reply["ice"].encode()) <= MAX_ICE_BYTES
    # A partner client still pins the HOME's FederationPeers values for the owner.
    assert reply["server_name"] == SERVER_NAME


def test_an_offer_for_a_reservation_that_is_not_live_is_refused_before_ice(federated):
    fed = federated
    assert "UC" in _acc(fed, "cancel_res", res_id=fed["res_id"])

    async def run():
        with pytest.raises(direct_path.PathRefused) as refused:
            await Client(fed).punch()
        assert "does not name a partner device" in str(refused.value)  # the HOME no longer routes it
        assert not direct_path._paths

    asyncio.run(run())


def test_a_replayed_direct_open_grant_is_refused(federated):
    fed = federated
    issuer, executor = fed["plane"].outbound.issuer, fed["executor"]
    issued = issuer.issue(
        local_account_id=fed["account_id"], destination_deployment_id=DEST, contract_id=CONTRACT,
        contract_version=1, action="direct_open",
        device_payload=build_device_payload(action="direct_open", reservation_id="424242", ice="{}"),
    )
    first = issuer.verify_result(executor.execute("2", issued.grant, issued.request.json)["signed_result"], issued)
    assert first["error_code"] == "no_active_reservation"  # refused before any ICE work
    second = issuer.verify_result(executor.execute("2", issued.grant, issued.request.json)["signed_result"], issued)
    assert second["error_code"] == "replayed"
    assert not direct_path._paths


def test_a_cancelled_reservation_closes_the_path_on_the_next_call(federated):
    fed = federated

    async def run():
        client = Client(fed)
        try:
            await client.punch()
            assert (await client.call("Test:rx:CALL0"))["value"] == 42
            assert "UC" in await asyncio.get_running_loop().run_in_executor(
                _OFFERS, lambda: _acc(fed, "cancel_res", res_id=fed["res_id"])
            )
            assert "reservation has ended" in (await client.call("Test:rx:CALL0"))["a"]
            assert await _gone()
        finally:
            await client.close()

    asyncio.run(run())


def test_a_revoked_agreement_or_disabled_proxy_closes_the_path(federated):
    fed = federated

    async def run():
        client = Client(fed)
        try:
            await client.punch()
            assert (await client.call("Test:rx:CALL0"))["value"] == 42
            with sqlite3.connect(fed["dest_db"]) as conn:
                conn.execute("UPDATE FederatedPrincipals SET status='disabled', disabled_at=100")
            assert "disabled" in (await client.call("Test:rx:CALL0"))["a"]
            assert await _gone()
            with sqlite3.connect(fed["dest_db"]) as conn:
                conn.execute("UPDATE FederatedPrincipals SET status='active', disabled_at=NULL")
                conn.execute("UPDATE FederationContracts SET state='suspended'")
        finally:
            await client.close()
        client = Client(fed, offer_id="second")
        try:
            with pytest.raises(direct_path.PathRefused):
                await client.punch()  # the owner's executor refuses the grant outright
        finally:
            await client.close()

    asyncio.run(run())


def test_a_client_with_the_wrong_ca_cannot_complete_the_handshake(federated, tmp_path):
    fed = federated
    other = tmp_path / "other"
    other.mkdir()

    async def run():
        client = Client(fed, ca_pem=write_certs(other))
        try:
            with pytest.raises((ConnectionError, asyncio.TimeoutError)):
                await client.punch()
        finally:
            await client.close()
        assert await _gone(10)

    asyncio.run(run())


def test_without_a_route_the_client_stays_on_the_relay(federated):
    fed = federated
    PeerStore(fed["dest_db"]).remove(DEST)

    async def run():
        with pytest.raises(direct_path.PathRefused) as refused:
            await Client(fed).punch()
        assert "No direct route" in str(refused.value)

    asyncio.run(run())


def test_a_token_alone_punches_to_the_owner_for_its_live_reservation(federated):
    fed = federated

    async def run():
        client = Client(fed, login=False)
        try:
            reply = await client.punch()
            assert reply["owner"] == DEST and reply["server_name"] == SERVER_NAME
            assert (await client.call("Test:rx:CALL0", {"a": map_arg(fed["token"])}))["value"] == 42
            assert fed["rpc"].device_calls[-1][:2] == (fed["allowed"], "Test:rx:CALL0")
        finally:
            await client.close()
        assert await _gone()

    asyncio.run(run())
    assert fed["calls"][-1] == "direct_open"


def test_a_token_alone_is_refused_without_a_live_reservation(federated):
    fed = federated
    calls = len(fed["calls"])
    assert "does not name a partner device" in _token_offer(fed, "not-a-token")["ace"]
    assert "does not name a partner device" in _token_offer(fed, "")["ace"]
    with sqlite3.connect(fed["root"] / "reservations.db") as conn:  # ended a minute ago
        conn.execute("UPDATE Reservations SET end_time=? WHERE res_id=?",
                     (datetime.now() - timedelta(minutes=1), fed["res_id"]))
    assert "not active" in _token_offer(fed, fed["token"])["ace"]
    with sqlite3.connect(fed["root"] / "reservations.db") as conn:  # not started yet
        conn.execute("UPDATE Reservations SET start_time=?, end_time=? WHERE res_id=?",
                     (datetime.now() + timedelta(minutes=5), datetime.now() + timedelta(minutes=30), fed["res_id"]))
    assert "not active" in _token_offer(fed, fed["token"])["ace"]
    assert "not active" in _acc(fed, "direct_offer", a=fed["token"], ice="{}")["ace"]  # a login gets no more
    assert len(fed["calls"]) == calls and not direct_path._paths  # nothing reached the owner
