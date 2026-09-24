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

"""Edges of the peer transport and the federated direct path: what a HOME
does with a partner that answers badly or not at all, and what an owner's
bound path does with every way a call can stop being legitimate."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
import uuid
from concurrent import futures
from datetime import datetime, timedelta

import grpc
import pytest
from remoterf_federation_core import TransportFailure, build_device_payload

from remoteRF_server.common.grpc import federation_pb2 as pb
from remoteRF_server.common.grpc import federation_pb2_grpc as rpc
from remoteRF_server.common.utils import hash_token, map_arg, unmap_arg
from remoteRF_server.server import direct_path
from remoteRF_server.server.federation.destination import register_grpc_federation
from remoteRF_server.server.federation.home_devices import ALIAS_BASE
from remoteRF_server.server.federation.peers import PeerStore, own_route

from test_federated_direct_path import Client, _gone, federated  # noqa: F401 - fixture
from test_gate_e_federation import CONTRACT, DEST
from test_gate_h_devices import world  # noqa: F401 - fixture
from test_gate_i_direct_path import SERVER_NAME, write_certs
from test_home_device_plane import _acc, _window, home  # noqa: F401 - fixture
from test_peer_transport import _list, _outbound, _pin, _route, listener  # noqa: F401 - fixture


# -- the HOME and a partner that answers badly ---------------------------

def _serve(tmp_path, servicer):
    cert_dir = tmp_path / "bad-listener"
    cert_dir.mkdir()
    ca_pem = write_certs(cert_dir).decode()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    rpc.add_FederationV2Servicer_to_server(servicer, server)
    credentials = grpc.ssl_server_credentials(
        [((cert_dir / "server.key").read_bytes(), (cert_dir / "server.crt").read_bytes())]
    )
    port = server.add_secure_port("127.0.0.1:0", credentials)
    server.start()
    return server, {"endpoint": f"127.0.0.1:{port}", "ca_pem": ca_pem}


def test_a_partner_with_federation_off_is_a_typed_refusal_not_a_transport_failure(world, tmp_path):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    register_grpc_federation(server, None)  # a Server whose federation runtime never came up
    cert_dir = tmp_path / "off"
    cert_dir.mkdir()
    ca_pem = write_certs(cert_dir).decode()
    port = server.add_secure_port("127.0.0.1:0", grpc.ssl_server_credentials(
        [((cert_dir / "server.key").read_bytes(), (cert_dir / "server.crt").read_bytes())]))
    server.start()
    try:
        _pin(world, {"grpc_endpoint": f"127.0.0.1:{port}", "tls_server_name": SERVER_NAME, "ca_pem": ca_pem})
        with pytest.raises(TransportFailure) as failure:
            _list(world)
        assert failure.value.code == "federation_disabled"
    finally:
        server.stop(0)


def test_a_partner_speaking_another_protocol_version_is_rejected(world, tmp_path):
    class Servicer(rpc.FederationV2Servicer):
        def Execute(self, request, context):
            return pb.FederationResponse(protocol_version="1", signed_result="not-a-result")

    server, route = _serve(tmp_path, Servicer())
    try:
        _pin(world, {"grpc_endpoint": route["endpoint"], "tls_server_name": SERVER_NAME, "ca_pem": route["ca_pem"]})
        with pytest.raises(TransportFailure) as failure:
            _list(world)
        assert failure.value.code == "invalid_transport_response"
    finally:
        server.stop(0)


def test_a_closed_port_fails_fast_even_with_the_read_retry(world, listener):
    _pin(world, _route(listener, grpc_endpoint="127.0.0.1:1"))
    started = time.monotonic()
    with pytest.raises(TransportFailure) as failure:
        _list(world)  # device_list is read-only: two attempts, both refused at once
    assert failure.value.code == "route_unavailable"
    assert time.monotonic() - started < 5


# -- a lab's own route ----------------------------------------------------

def test_own_route_needs_a_relay_port_and_a_readable_ca(tmp_path, monkeypatch):
    from remoteRF_server.server import global_onboarding as g

    root = tmp_path / "cfg"
    monkeypatch.setenv("REMOTERF_CONFIG_DIR", str(root))
    monkeypatch.delenv("REMOTERF_CERT_DIR", raising=False)
    (root / "certs").mkdir(parents=True)
    monkeypatch.setattr(g, "cfg_dir", lambda: root)
    monkeypatch.setattr(g, "load", lambda: {"GLOBAL_FINAL_NAME": "lab", "GLOBAL_RELAY_GRPC_PORT": "62005"})
    assert own_route() is None  # no ca.crt yet
    (root / "certs" / "ca.crt").write_text("not a certificate")
    assert own_route() is None
    ca_pem = write_certs(root / "certs")
    route = own_route()
    assert route["grpc_endpoint"] == f"lab.{g.domain()}:62005" and route["tls_server_name"] == f"lab.{g.domain()}"
    assert route["ca_pem"] == ca_pem.decode()
    monkeypatch.setattr(g, "load", lambda: {"GLOBAL_FINAL_NAME": "lab"})
    assert own_route() is None  # no relay port assigned yet


def test_a_cluster_note_pins_a_route_only_when_the_lab_signed_it(world, monkeypatch):
    from remoteRF_server.server.federation import cluster

    db = world["issuer"].usergroups_path
    monkeypatch.setattr(cluster, "_db_path", lambda: db)
    route = {"grpc_endpoint": "dest.global.remoterf.net:62011", "tls_server_name": "dest.global.remoterf.net",
             "ca_pem": write_certs(db.parent).decode()}
    party = {"display_name": "Destination"}
    parties = {DEST: party}
    monkeypatch.setattr(cluster, "_parties", lambda c: list(parties.items()))
    monkeypatch.setattr(cluster.g, "_signing_material", lambda: (None, None, "owner"))
    status = {"owner": "owner", "cluster_name": "lab", "deployment_id": DEST, "groups": 1, "devices": 2, "route": route}

    monkeypatch.setattr(cluster, "_roster_signed_by", lambda *a: False)
    cluster._take_statuses("lab", {"role": "owner"}, [{"status": status, "signature": "x"}])
    assert PeerStore(db).get(DEST) is None and "sharing" not in party

    monkeypatch.setattr(cluster, "_roster_signed_by", lambda *a: True)
    cluster._take_statuses("lab", {"role": "owner"}, [{"status": status, "signature": "x"}])
    row = PeerStore(db).get(DEST)
    assert row["endpoint"] == route["grpc_endpoint"] and row["via"] == "relay" and row["source"] == "cluster"
    assert party["sharing"]["devices"] == 2

    broken = {**status, "route": {**route, "ca_pem": "nope"}}
    cluster._take_statuses("lab", {"role": "owner"}, [{"status": broken, "signature": "x"}])
    assert PeerStore(db).get(DEST)["ca_pem"] == route["ca_pem"]  # a malformed route changes nothing


# -- the owner's direct_open and its bound path --------------------------

def _open(fed, **payload):
    issuer, executor = fed["plane"].outbound.issuer, fed["executor"]
    issued = issuer.issue(
        local_account_id=fed["account_id"], destination_deployment_id=DEST, contract_id=CONTRACT,
        contract_version=1, action="direct_open",
        device_payload=build_device_payload(action="direct_open", **payload),
    )
    return issuer.verify_result(executor.execute("2", issued.grant, issued.request.json)["signed_result"], issued)


def test_an_offer_that_is_not_json_is_a_signed_refusal_and_opens_nothing(federated):
    result = _open(federated, reservation_id=federated["remote_res_id"], ice="not json")
    assert result["error_code"] == "direct_path_unavailable" and not direct_path._paths


def test_another_principals_reservation_cannot_be_opened(federated):
    fed = federated
    with sqlite3.connect(fed["root"] / "reservations.db") as conn:
        start, end = _window()
        other = conn.execute(
            "INSERT INTO Reservations (username, device_id, start_time, end_time, salt, hash) VALUES (?,?,?,?,'','')",
            ("someone-else", fed["allowed"], start, end),
        ).lastrowid
        conn.execute(
            "INSERT INTO FederatedReservations (res_id,issuer_deployment_id,remote_subject_id,local_account_id,"
            "contract_id,contract_version,request_id,created_at) VALUES (?,?,?,?,?,1,?,1)",
            (other, "33333333-3333-4333-8333-333333333333", str(uuid.uuid4()), 999, CONTRACT, str(uuid.uuid4())),
        )
    result = _open(federated, reservation_id=str(other), ice="{}")
    assert result["error_code"] == "no_active_reservation" and not direct_path._paths


def test_a_reservation_that_has_not_started_is_refused(federated):
    fed = federated
    start, end = _window(offset_minutes=30, length_minutes=20)  # after the live one ends
    alias = next(int(k) for k in _acc(fed, "get_dev") if int(k) >= ALIAS_BASE)
    later = _acc(fed, "reserve_device", dd=alias, st=int(start.timestamp()), et=int(end.timestamp()))
    assert "Token" in later, later
    with sqlite3.connect(fed["root"] / "reservations.db") as conn:
        remote = conn.execute(
            "SELECT remote_reservation_id FROM HomeFederatedReservations WHERE remote_reservation_id != ?",
            (str(fed["remote_res_id"]),),
        ).fetchone()[0]
    assert _open(fed, reservation_id=str(remote), ice="{}")["error_code"] == "no_active_reservation"


def test_a_new_offer_with_the_same_id_replaces_that_clients_path(federated):
    fed = federated

    async def run():
        first, second = Client(fed, offer_id="same"), Client(fed, offer_id="same")
        try:
            await first.punch()
            assert (await first.call("Test:rx:CALL0"))["value"] == 42
            await second.punch()
            assert len(direct_path._paths) == 1
            assert (await second.call("Test:rx:CALL0"))["value"] == 42
            with pytest.raises((ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError)):
                await asyncio.wait_for(first.call("Test:rx:CALL0"), 5)
        finally:
            await first.close()
            await second.close()

    asyncio.run(run())


def test_the_path_cap_is_per_reservation_not_per_owner(federated):
    fed = federated
    cap = direct_path.MAX_PATHS_PER_SESSION

    async def run():
        clients = [Client(fed, offer_id=f"proc-{i}") for i in range(cap + 1)]
        try:
            for client in clients:
                await client.punch()
            assert len(direct_path._paths) == cap  # the oldest process made room
            assert (await clients[-1].call("Test:rx:CALL0"))["value"] == 42
        finally:
            for client in clients:
                await client.close()

    asyncio.run(run())


def test_an_offer_id_cannot_smuggle_a_session_separator(federated):
    fed = federated
    assert direct_path._key("s", {"id": "a/b/c"}) == "s/abc" and direct_path._key("s", {}) == "s/"

    async def run():
        client = Client(fed, offer_id="p/q")
        try:
            await client.punch()
            (key,) = direct_path._paths
            assert key.endswith("/pq") and key.rsplit("/", 1)[0].endswith(str(fed["remote_res_id"]))
        finally:
            await client.close()

    asyncio.run(run())


def test_only_get_drivers_of_the_idl_family_is_allowed_on_a_bound_path(federated):
    fed = federated

    async def run():
        client = Client(fed)
        try:
            await client.punch()
            assert "not available" in (await client.call("IDL:list_devices", {}))["a"]
            assert len(direct_path._paths) == 1  # not a refusal: the path stays
            assert (await client.call("Test:rx:CALL0"))["value"] == 42
        finally:
            await client.close()

    asyncio.run(run())


def test_a_hardware_error_is_a_reply_a_refusal_closes(federated):
    fed = federated

    async def run():
        client = Client(fed)
        try:
            await client.punch()
            assert "not connected" in (await client.call("Test:rx:explode"))["a"]
            assert len(direct_path._paths) == 1
            assert (await client.call("Test:rx:CALL0"))["value"] == 42
        finally:
            await client.close()

    asyncio.run(run())


def test_a_smuggled_owner_token_never_reaches_another_device(federated):
    fed = federated
    salt, hashed = hash_token("owner-token")
    with sqlite3.connect(fed["root"] / "reservations.db") as conn:
        start, end = _window()
        conn.execute(
            "INSERT INTO Reservations (username, device_id, start_time, end_time, salt, hash) VALUES (?,?,?,?,?,?)",
            ("native-owner-user", fed["hidden"], start, end, salt, hashed),
        )

    async def run():
        client = Client(fed)
        try:
            await client.punch()
            result = await client.call("Test:rx:CALL0", {"a": map_arg("owner-token"), "token": map_arg("owner-token")})
            assert result["value"] == 42
            gid, _name, args = fed["rpc"].device_calls[-1]
            assert gid == fed["allowed"] and "a" not in args and "token" not in args
        finally:
            await client.close()

    asyncio.run(run())


def test_a_device_made_invisible_refuses_get_drivers_and_closes(federated):
    fed = federated

    async def run():
        client = Client(fed)
        try:
            await client.punch()
            assert (await client.call("IDL:get_drivers", {"token": map_arg("x")}))["device_type"] == "test"
            with sqlite3.connect(fed["dest_db"]) as conn:
                conn.execute("DELETE FROM UsersLookup")  # the proxy left every group
            assert "not visible" in (await client.call("IDL:get_drivers", {"token": map_arg("x")}))["a"]
            assert await _gone()
        finally:
            await client.close()

    asyncio.run(run())


def test_a_superseded_contract_closes_the_path(federated):
    fed = federated

    async def run():
        client = Client(fed)
        try:
            await client.punch()
            assert (await client.call("Test:rx:CALL0"))["value"] == 42
            with sqlite3.connect(fed["dest_db"]) as conn:
                conn.execute("UPDATE FederationContracts SET superseded_by_version=2")
            assert "no longer active" in (await client.call("Test:rx:CALL0"))["a"]
            assert await _gone()
        finally:
            await client.close()

    asyncio.run(run())


def test_a_reservation_that_ends_mid_session_closes_the_path(federated):
    fed = federated

    async def run():
        client = Client(fed)
        try:
            await client.punch()
            assert (await client.call("Test:rx:CALL0"))["value"] == 42
            with sqlite3.connect(fed["root"] / "reservations.db") as conn:
                conn.execute(
                    "UPDATE Reservations SET end_time=? WHERE res_id=?",
                    (datetime.now().replace(microsecond=0) + timedelta(seconds=1), int(fed["remote_res_id"])),
                )
            await asyncio.sleep(1.5)
            assert "reservation has ended" in (await client.call("Test:rx:CALL0"))["a"]
            assert await _gone()
        finally:
            await client.close()

    asyncio.run(run())


def test_an_authorizer_that_cannot_decide_answers_without_running_or_closing(federated, monkeypatch):
    fed = federated
    from remoteRF_server.server.federation import devices as devices_module

    real = devices_module.path_authorizer

    def flaky(**kwargs):
        decide = real(**kwargs)
        calls = {"n": 0}

        def authorize(function_name):
            calls["n"] += 1
            if calls["n"] == 2:
                raise sqlite3.OperationalError("database is locked")
            return decide(function_name)

        return authorize

    monkeypatch.setattr(devices_module, "path_authorizer", flaky)

    async def run():
        client = Client(fed)
        try:
            await client.punch()
            assert (await client.call("Test:rx:CALL0"))["value"] == 42
            before = len(fed["rpc"].device_calls)
            assert "authorization unavailable" in (await client.call("Test:rx:CALL0"))["a"]
            assert len(fed["rpc"].device_calls) == before and len(direct_path._paths) == 1
            assert (await client.call("Test:rx:CALL0"))["value"] == 42
        finally:
            await client.close()

    asyncio.run(run())


# -- the HOME side of an offer --------------------------------------------

def test_another_user_cannot_offer_with_someone_elses_token(federated):
    fed = federated
    from remoteRF_server.server import reservation as reservation_module

    salt, hashed = hash_token("bob-password")
    with sqlite3.connect(fed["root"] / "reservations.db") as conn:
        bob = conn.execute(
            "INSERT INTO Accounts (username,email,pass_salt,pass_hash,auth_type) VALUES ('bob','bob@example.test',?,?,'local_password')",
            (salt, hashed),
        ).lastrowid
        conn.execute(
            "INSERT INTO LocalAccountSubjects (local_account_id,subject_id,status,created_at) VALUES (?,?,'active',1)",
            (bob, str(uuid.uuid4())),
        )
    reservation_module.perms.set_user("bob")
    args = {"un": map_arg("bob"), "pw": map_arg("bob-password"), "a": map_arg(fed["token"]), "ice": map_arg("{}")}
    reply = {k: unmap_arg(v) for k, v in fed["reservations"].handle_call(function_name="direct_offer", args=args).items()}
    assert "does not name a partner device of yours" in reply["ace"]
    assert not direct_path._paths and fed["calls"][-1] != "direct_open"


def test_a_native_token_is_not_offered_to_any_partner(federated):
    fed = federated
    from test_home_device_plane import NATIVE

    salt, hashed = hash_token("native-token")
    with sqlite3.connect(fed["root"] / "reservations.db") as conn:
        start, end = _window()
        conn.execute(
            "INSERT INTO Reservations (username, device_id, start_time, end_time, salt, hash) VALUES (?,?,?,?,?,?)",
            (NATIVE, 5, start, end, salt, hashed),  # alice's own, local device: no partner behind it
        )
    reply = _acc(fed, "direct_offer", a="native-token", ice="{}")
    assert "does not name a partner device" in reply["ace"] and fed["calls"][-1] != "direct_open"
