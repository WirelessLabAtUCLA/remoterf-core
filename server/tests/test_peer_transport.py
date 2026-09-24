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

"""Slice 1: the HOME dials a partner's own FederationV2 listener, pinned to
its CA, and only falls back to the broker for a partner without a route.

The destination is the real Gate H executor on a real TLS gRPC port; the
broker is a closed port, so anything that reaches it fails at once.
"""

from __future__ import annotations

import logging
import sqlite3
import uuid
from concurrent import futures

import grpc
import pytest
from remoterf_federation_core import TransportFailure

from remoteRF_server.server.federation.destination import register_grpc_federation
from remoteRF_server.server.federation.home import HomeFederationOutbound
from remoteRF_server.server.federation.peers import PeerStore, validate_route, via

from test_gate_e_federation import CONTRACT, DEST
from test_gate_h_devices import world  # noqa: F401 - fixture
from test_gate_i_direct_path import SERVER_NAME, write_certs


@pytest.fixture
def listener(world, tmp_path):
    cert_dir = tmp_path / "listener"
    cert_dir.mkdir()
    ca_pem = write_certs(cert_dir).decode()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    register_grpc_federation(server, world["executor"])
    credentials = grpc.ssl_server_credentials(
        [((cert_dir / "server.key").read_bytes(), (cert_dir / "server.crt").read_bytes())]
    )
    port = server.add_secure_port("127.0.0.1:0", credentials)
    server.start()
    world["enroll"](devices=[world["allowed"]])
    try:
        yield {"endpoint": f"127.0.0.1:{port}", "ca_pem": ca_pem}
    finally:
        server.stop(0)


def _outbound(world):
    issuer = world["issuer"]
    return HomeFederationOutbound(
        issuer, broker_base_url="https://127.0.0.1:9", broker_deployment_id=str(uuid.uuid4()),
        broker_private_key=issuer.private_key, broker_kid=issuer.signing_kid, timeout=2.0,
    )


def _route(listener, **override):
    return {"grpc_endpoint": listener["endpoint"], "tls_server_name": SERVER_NAME,
            "ca_pem": listener["ca_pem"], **override}


def _store(world):
    return PeerStore(world["issuer"].usergroups_path)


def _pin(world, route):
    _store(world).upsert(deployment_id=DEST, display_name="Destination", route=route, source="admin")


def _jtis(world):
    with sqlite3.connect(world["dest_db"]) as conn:
        return conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0]


def _list(world):
    return _outbound(world).execute(
        local_account_id=1, destination_deployment_id=DEST, contract_id=CONTRACT,
        contract_version=1, action="device_list",
    )


def test_a_route_carries_the_grant_directly_and_the_result_verifies(world, listener, caplog):
    _pin(world, _route(listener))
    with caplog.at_level(logging.INFO, logger="remoteRF_server.federation.home"):
        result = _list(world)
    assert result["status"] == "ok"
    assert [d["display_name"] for d in result["payload"]["devices"]] == ["gate-h-allowed"]
    assert "via=direct" in caplog.text  # the (dead) broker was never needed


def test_the_wrong_ca_never_reaches_the_destination(world, listener, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    _pin(world, _route(listener, ca_pem=write_certs(other).decode()))
    before = _jtis(world)
    with pytest.raises(TransportFailure) as failure:
        _list(world)
    assert failure.value.code == "route_unavailable" and _jtis(world) == before


def test_the_wrong_server_name_never_reaches_the_destination(world, listener):
    _pin(world, _route(listener, tls_server_name="other.test"))
    before = _jtis(world)
    with pytest.raises(TransportFailure) as failure:
        _list(world)
    assert failure.value.code == "route_unavailable" and _jtis(world) == before


def test_without_a_route_the_broker_path_is_taken_and_labeled(world, listener, caplog):
    with caplog.at_level(logging.INFO, logger="remoteRF_server.federation.home"):
        with pytest.raises(TransportFailure) as failure:
            _list(world)
    assert failure.value.code == "route_unavailable" and "via=broker" in caplog.text


def test_a_removed_route_goes_back_to_the_broker(world, listener):
    _pin(world, _route(listener))
    assert _list(world)["status"] == "ok"
    assert _store(world).remove(DEST) and _store(world).get(DEST) is None
    with pytest.raises(TransportFailure):
        _list(world)


def test_routes_are_validated_and_an_admin_row_outranks_the_cluster_agent(world, listener):
    good = _route(listener)
    for bad in (
        {**good, "grpc_endpoint": "nope"}, {**good, "tls_server_name": "a b"},
        {**good, "ca_pem": "not pem"}, {**good, "extra": 1},
    ):
        with pytest.raises(ValueError):
            validate_route(bad)
    assert via("ucla-dev0.global.remoterf.net:12321") == "relay"
    assert via("10.0.0.5:12321") == "direct"
    store = _store(world)
    assert store.upsert(deployment_id=DEST, display_name="Admin", route=good, source="admin")
    assert not store.upsert(
        deployment_id=DEST, display_name="Agent", route={**good, "tls_server_name": "other.test"}, source="cluster"
    )
    row = store.get(DEST)
    assert row["tls_server_name"] == SERVER_NAME and row["source"] == "admin" and row["via"] == "direct"
    assert [r["deployment_id"] for r in store.list()] == [DEST]
