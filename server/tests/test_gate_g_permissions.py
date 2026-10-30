import sqlite3
import threading
import time
import json
from types import SimpleNamespace
from uuid import UUID, uuid4

from remoterf_federation_core import TransportFailure
from remoteRF_server.server.federation.destination import ActionRegistry
from remoteRF_server.server.federation.permissions import (
    ServerHomePermissions,
    ServerPermissionsReadHandler,
    build_server_gate_g_executor,
)

from test_gate_e_federation import active_pair, executor, issue


def _verified(pair, destination):
    issued = issue(pair)
    response = destination.execute("2", issued.grant, issued.request.json)
    assert response["error"] is None
    return pair["issuer"].verify_result(response["signed_result"], issued)


def _permissions_destination(pair):
    return executor(
        pair,
        ActionRegistry(
            {
                "permissions_read": ServerPermissionsReadHandler(
                    local_deployment_id=pair["destination_id"],
                    display_name="Destination",
                    clock=lambda: pair["now"][0],
                )
            }
        ),
    )


def test_server_destination_reads_current_owner_state_without_allocation(tmp_path):
    pair = active_pair(tmp_path)
    destination = _permissions_destination(pair)

    unknown = _verified(pair, destination)
    assert unknown["status"] == "ok"
    assert unknown["groups"] == []
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM FederatedPrincipals").fetchone() == (0,)
        assert conn.execute("SELECT COUNT(*) FROM EnrollmentRedemptions").fetchone() == (0,)

        principal_id = str(uuid4())
        conn.execute(
            "INSERT INTO FederatedPrincipals"
            "(id,issuer_deployment_id,remote_subject_id,local_account_id,status,"
            "created_at,last_seen_at,disabled_at,display_metadata_json) "
            "VALUES (?,?,?,?, 'active',100,100,NULL,'{}')",
            (principal_id, pair["home_id"], pair["subject"], 900),
        )
        conn.execute(
            "INSERT INTO UserGroups(group_id,group_name,devices_whitelist,"
            "max_reservation_time_sec,max_reservations,lifetime_sec,created_at) "
            "VALUES (7,'current-readers','[]',3600,2,0,'1970-01-01 00:00:00')"
        )
        conn.execute("INSERT INTO UsersLookup(user_id,group_id) VALUES (900,7)")

    current = _verified(pair, destination)
    assert current["groups"] == [
        {"group_id": "7", "group_name": "current-readers"}
    ]

    with sqlite3.connect(pair["dest_db"]) as conn:
        conn.execute("DELETE FROM UsersLookup WHERE user_id=900 AND group_id=7")
    removed = _verified(pair, destination)
    assert removed["status"] == "ok"
    assert removed["groups"] == []

    with sqlite3.connect(pair["dest_db"]) as conn:
        conn.execute(
            "INSERT INTO UserGroups(group_id,group_name,devices_whitelist,"
            "max_reservation_time_sec,max_reservations,lifetime_sec,created_at) "
            "VALUES (8,'expired-readers','[]',3600,2,50,0)"
        )
        conn.execute("INSERT INTO UsersLookup(user_id,group_id) VALUES (900,8)")
    expired = _verified(pair, destination)
    assert expired["status"] == "ok"
    assert expired["groups"] == []

    with sqlite3.connect(pair["dest_db"]) as conn:
        conn.execute("DELETE FROM UsersLookup WHERE user_id=900 AND group_id=8")
        conn.execute("INSERT INTO UsersLookup(user_id,group_id) VALUES (900,7)")
        conn.execute("DELETE FROM UserGroups WHERE group_id=7")
    deleted = _verified(pair, destination)
    assert deleted["status"] == "ok"
    assert deleted["groups"] == []

    with sqlite3.connect(pair["dest_db"]) as conn:
        conn.execute(
            "INSERT INTO UserGroups(group_id,group_name,devices_whitelist,"
            "max_reservation_time_sec,max_reservations,lifetime_sec,created_at) "
            "VALUES (9,'invalid-readers','[]',3600,2,50,'not-a-time')"
        )
        conn.execute("INSERT INTO UsersLookup(user_id,group_id) VALUES (900,9)")
    invalid = _verified(pair, destination)
    assert invalid["status"] == "error"
    assert invalid["error_code"] == "group_lifetime_invalid"

    with sqlite3.connect(pair["dest_db"]) as conn:
        conn.execute(
            "UPDATE FederatedPrincipals SET status='disabled',disabled_at=100 "
            "WHERE local_account_id=900"
        )
    disabled = _verified(pair, destination)
    assert disabled["status"] == "error"
    assert disabled["error_code"] == "principal_disabled"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM FederationAuditEvents "
            "WHERE event_type='permissions_read' AND result_code='ok'"
        ).fetchone() == (5,)
        assert conn.execute(
            "SELECT COUNT(*) FROM FederationAuditEvents "
            "WHERE result_code IN ('group_lifetime_invalid','principal_disabled')"
        ).fetchone() == (2,)


class _OutcomeOutbound:
    def __init__(self, pair, outcome):
        self.pair = pair
        self.outcome = outcome
        self.calls = []

    def execute(self, **kwargs):
        self.calls.append(kwargs)
        if self.outcome == "transport":
            raise TransportFailure("unsigned-private-details-must-not-render")
        return {
            "deployment_id": self.pair["destination_id"],
            "display_name": "Destination",
            "contract_id": self.pair["contract_id"],
            "contract_version": 1,
            "state": "active",
            "groups": [{"group_id": "7", "group_name": "remote-readers"}],
            "retrieved_at": self.pair["now"][0],
        }


def test_server_home_summary_is_exact_additive_and_active_contract_scoped(tmp_path):
    pair = active_pair(tmp_path)
    outbound = _OutcomeOutbound(pair, "ok")
    home = ServerHomePermissions(
        usergroups_path=pair["home_db"],
        local_deployment_id=pair["home_id"],
        display_name="Home",
        outbound=outbound,
        clock=lambda: pair["now"][0],
    )
    with sqlite3.connect(pair["home_db"]) as conn:
        conn.execute(
            "INSERT INTO UserGroups(group_id,group_name,devices_whitelist,"
            "max_reservation_time_sec,max_reservations,lifetime_sec,created_at) "
            "VALUES (3,'local-readers','[]',3600,2,0,'1970-01-01 00:00:00')"
        )
        conn.execute("INSERT INTO UsersLookup(user_id,group_id) VALUES (1,3)")
    summary = home.summary(local_account_id=1)
    assert set(summary) == {"local", "federation", "incomplete", "omitted_count"}
    assert summary["incomplete"] is False
    assert summary["omitted_count"] == 0
    assert summary["local"]["groups"] == [
        {"group_id": "3", "group_name": "local-readers"}
    ]
    assert summary["federation"][0]["status"] == "ok"
    assert summary["federation"][0]["provenance"] == "destination_signed"
    assert len(outbound.calls) == 1

    with sqlite3.connect(pair["home_db"]) as conn:
        conn.execute(
            "UPDATE FederationContracts SET state='suspended' "
            "WHERE contract_id=? AND version=1",
            (pair["contract_id"],),
        )
    assert home.summary(local_account_id=1)["federation"] == []
    assert len(outbound.calls) == 1


def test_server_home_transport_failure_has_no_fake_owner_snapshot(tmp_path):
    pair = active_pair(tmp_path)
    home = ServerHomePermissions(
        usergroups_path=pair["home_db"],
        local_deployment_id=pair["home_id"],
        display_name="Home",
        outbound=_OutcomeOutbound(pair, "transport"),
        clock=lambda: pair["now"][0],
    )
    remote = home.summary(local_account_id=1)["federation"][0]
    assert remote["status"] == "unavailable"
    assert remote["provenance"] == "transport"
    assert remote["groups"] == []
    assert remote["retrieved_at"] is None
    assert remote["error_code"] is None


def test_server_permissions_rechecks_contract_key_and_time_before_handler(tmp_path):
    pair = active_pair(tmp_path)
    destination = _permissions_destination(pair)
    issued = issue(pair)
    with sqlite3.connect(pair["dest_db"]) as conn:
        conn.execute(
            "UPDATE FederationContracts SET state='suspended' "
            "WHERE contract_id=? AND version=1",
            (pair["contract_id"],),
        )
    response = destination.execute("2", issued.grant, issued.request.json)
    suspended = pair["issuer"].verify_result(response["signed_result"], issued)
    assert suspended["status"] == "error"
    assert suspended["error_code"] == "contract_inactive"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM FederationAuditEvents "
            "WHERE event_type='permissions_read'"
        ).fetchone() == (0,)

    (tmp_path / "key-revocation").mkdir()
    other = active_pair(tmp_path / "key-revocation")
    destination = _permissions_destination(other)
    issued = issue(other)
    with sqlite3.connect(other["dest_db"]) as conn:
        conn.execute(
            "UPDATE TrustedDeploymentKeys SET state='revoked' WHERE deployment_id=?",
            (other["home_id"],),
        )
    response = destination.execute("2", issued.grant, issued.request.json)
    revoked = other["issuer"].verify_result(response["signed_result"], issued)
    assert revoked["status"] == "error"
    assert revoked["error_code"] == "contract_inactive"

    (tmp_path / "expiry").mkdir()
    expired = active_pair(tmp_path / "expiry")
    outbound = _OutcomeOutbound(expired, "ok")
    home = ServerHomePermissions(
        usergroups_path=expired["home_db"],
        local_deployment_id=expired["home_id"],
        display_name="Home",
        outbound=outbound,
        clock=lambda: expired["now"][0],
    )
    expired["now"][0] = 1001
    assert home.summary(local_account_id=1)["federation"] == []
    assert outbound.calls == []


def test_server_home_fanout_has_hard_concurrency_and_latency_bounds(tmp_path, monkeypatch):
    pair = active_pair(tmp_path)
    home = ServerHomePermissions(
        usergroups_path=pair["home_db"],
        local_deployment_id=pair["home_id"],
        display_name="Home",
        outbound=object(),
        clock=lambda: pair["now"][0],
        max_concurrency=3,
        per_destination_timeout=0.02,
        overall_timeout=0.06,
    )
    candidates = [
        {
            "deployment_id": str(UUID(int=index + 100)),
            "contract_id": str(UUID(int=index + 1000)),
            "contract_version": 1,
            "state": "active",
        }
        for index in range(12)
    ]
    monkeypatch.setattr(home, "_candidates", lambda _now: candidates)
    release = threading.Event()
    lock = threading.Lock()
    active = 0
    peak = 0

    def blocked(_account, candidate):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        release.wait(2)
        with lock:
            active -= 1
        return home._unavailable(candidate)

    monkeypatch.setattr(home, "_query", blocked)
    started = time.monotonic()
    summary = home.summary(local_account_id=1)
    elapsed = time.monotonic() - started
    release.set()
    assert elapsed < 0.25
    assert peak <= 3
    assert len(summary["federation"]) == 12
    assert all(item["status"] == "unavailable" for item in summary["federation"])


def test_server_gate_g_registry_contains_only_phase_one_actions(tmp_path):
    pair = active_pair(tmp_path)
    built = build_server_gate_g_executor(
        usergroups_path=pair["dest_db"],
        reservations_path=tmp_path / "destination-reservations.db",
        local_deployment_id=pair["destination_id"],
        private_key=pair["dest_key"],
        signing_kid=pair["dest_material"]["kid"],
        display_name="Destination",
        clock=lambda: pair["now"][0],
    )
    assert set(built.registry._handlers) == {"federated_enroll", "permissions_read"}


def test_server_acc_get_perms_adds_summary_without_changing_local_contract(monkeypatch):
    from remoteRF_server.common.utils import map_arg, unmap_arg
    import remoteRF_server.server.reservation as reservation

    monkeypatch.setattr(reservation.perms, "get_perms", lambda _username: [["Normal User"]])
    monkeypatch.setattr(
        reservation.user_group_handler, "get_users_devices", lambda uid: []
    )
    monkeypatch.setattr(
        reservation.user_group_handler, "get_groups_user_in", lambda uid: ["local-readers"]
    )
    summary = {
        "local": {
            "deployment_id": "11111111-1111-4111-8111-111111111111",
            "display_name": "Server HOME",
            "groups": [{"group_id": "3", "group_name": "local-readers"}],
        },
        "federation": [],
    }
    handler = object.__new__(reservation.ReservationHandler)
    handler.login_user = lambda username, password: {"UC": map_arg(username)}
    handler.get_uid = lambda username: 1
    handler.federation_permissions = SimpleNamespace(
        summary=lambda **_kwargs: summary
    )
    args = {"un": map_arg("native"), "pw": map_arg("native-password")}
    response = handler.handle_call(function_name="get_perms", args=args)
    details = json.loads(unmap_arg(response["details"]))
    assert response["UC"] == map_arg(str([["Normal User"]]))
    assert details["devices"] == []
    assert details["groups"] == ["local-readers"]
    assert details["home_permissions"] == summary

    handler.federation_permissions = SimpleNamespace(
        summary=lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("offline"))
    )
    fallback = handler.handle_call(function_name="get_perms", args=args)
    fallback_details = json.loads(unmap_arg(fallback["details"]))
    assert fallback["UC"] == response["UC"]
    assert "home_permissions" not in fallback_details
