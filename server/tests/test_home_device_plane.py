"""HOME side of Server-to-Server device federation.

One process plays both ends: the Gate H `world` destination executor is the
owner, and the same ReservationHandler / perms / groups act as the HOME for a
native account.  Grants are real (Ed25519, contract, JTI); only the broker
hop is replaced by an in-process call into the destination executor, and the
hardware dispatcher is the Gate H fake.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from remoteRF_server.common.utils import hash_token, map_arg, unmap_arg
from remoteRF_server.server.federation.home import HomeFederationOutbound, ServerHomeGrantIssuer
from remoteRF_server.server.federation.home_devices import ALIAS_BASE, HomeDeviceError, ServerHomeDevices
from remoteRF_server.server.federation.permissions import ServerHomePermissions
from remoteRF_server.server.federation.principals import prepare_federated_account

from test_gate_e_federation import DEST, HOME
from test_gate_h_devices import world  # noqa: F401 - fixture

NATIVE, PASSWORD = "alice", "alice-password"


@pytest.fixture
def home(world):
    root, dest_db, now = world["root"], world["dest_db"], world["now"]
    reservations = world["reservations"]
    from remoteRF_server.server import reservation as reservation_module

    perms, groups = reservation_module.perms, reservation_module.user_group_handler

    salt, hashed = hash_token(PASSWORD)
    subject = str(uuid.uuid4())
    with sqlite3.connect(root / "reservations.db") as conn:
        account_id = conn.execute(
            "INSERT INTO Accounts (username,email,pass_salt,pass_hash,auth_type) "
            "VALUES (?,?,?,?,'local_password')",
            (NATIVE, "alice@example.test", salt, hashed),
        ).lastrowid
        conn.execute(
            "INSERT INTO LocalAccountSubjects (local_account_id,subject_id,status,created_at) "
            "VALUES (?,?,'active',?)",
            (account_id, subject, now[0]),
        )
    perms.set_user(NATIVE)

    # The owner side of enrollment: a proxy for alice's subject in a group
    # that may see exactly one device.
    prepared = prepare_federated_account(
        root / "reservations.db", issuer_deployment_id=HOME, remote_subject_id=subject,
        perms_path=root / "perms.db", now=now[0],
    )
    group_id = groups.create_user_group(
        group_name=f"visitors-{uuid.uuid4().hex[:6]}", devices_whitelist=[world["allowed"]],
        max_reservation_time_sec=3600, max_reservations=5, lifetime_sec=0,
    )
    with sqlite3.connect(dest_db) as conn:
        conn.execute(
            "INSERT INTO FederatedPrincipals(id,issuer_deployment_id,remote_subject_id,"
            "local_account_id,status,created_at,last_seen_at,disabled_at,display_metadata_json) "
            "VALUES (?,?,?,?,'active',100,100,NULL,'{}')",
            (str(uuid.uuid4()), HOME, subject, prepared.local_account_id),
        )
        conn.execute(
            "INSERT INTO UsersLookup(user_id,group_id) VALUES (?,?)",
            (prepared.local_account_id, group_id),
        )

    gate_h = world["issuer"]
    issuer = ServerHomeGrantIssuer(
        reservations_path=root / "reservations.db", usergroups_path=dest_db,
        local_deployment_id=HOME, private_key=gate_h.private_key,
        signing_kid=gate_h.signing_kid, clock=lambda: now[0],
    )
    calls = []
    executor = world["executor"]

    def sender(body, token, deadline):
        envelope = json.loads(body)
        calls.append(json.loads(envelope["request_json"])["action"])
        return executor.execute("2", envelope["grant"], envelope["request_json"])

    outbound = HomeFederationOutbound(
        issuer, broker_base_url="https://broker.invalid", broker_deployment_id=str(uuid.uuid4()),
        broker_private_key=gate_h.private_key, broker_kid=gate_h.signing_kid, sender=sender,
    )
    permissions = ServerHomePermissions(
        usergroups_path=dest_db, local_deployment_id=HOME, display_name="Home", outbound=outbound,
        clock=lambda: now[0],
    )
    plane = ServerHomeDevices(
        reservations_path=root / "reservations.db", permissions=permissions, outbound=outbound,
        clock=lambda: now[0], overall_timeout=5.0, per_destination_timeout=5.0,
    )
    reservations.federation_devices = plane
    try:
        yield {**world, "plane": plane, "account_id": account_id, "calls": calls}
    finally:
        reservations.federation_devices = None
        plane.close()
        permissions.close()


def _acc(home, name, **extra):
    args = {"un": map_arg(NATIVE), "pw": map_arg(PASSWORD), **{k: map_arg(v) for k, v in extra.items()}}
    return {k: unmap_arg(v) for k, v in home["reservations"].handle_call(function_name=name, args=args).items()}


def _window(offset_minutes=-5, length_minutes=30):
    start = datetime.now().replace(microsecond=0) + timedelta(minutes=offset_minutes)
    return start, start + timedelta(minutes=length_minutes)


def _jti_count(home):
    with sqlite3.connect(home["dest_db"]) as conn:
        return conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0]


def test_unenrolled_user_sees_only_local_devices_and_no_grant_is_issued(home):
    before = _jti_count(home)
    devices = _acc(home, "get_dev")
    assert all(int(k) < ALIAS_BASE for k in devices)
    assert home["calls"] == [] and _jti_count(home) == before


def test_get_dev_merges_partner_devices_under_alias_ids(home):
    home["plane"].record_enrollment(local_account_id=home["account_id"], destination_deployment_id=DEST)
    devices = _acc(home, "get_dev")
    aliases = {int(k): v for k, v in devices.items() if int(k) >= ALIAS_BASE}
    assert len(aliases) == 1
    (alias, label), = aliases.items()
    assert label == "gate-h-allowed @Destination (online)"
    assert home["calls"] == ["device_list"]
    # Stable across listings: the Client can keep using the id it saw.
    assert set(int(k) for k in _acc(home, "get_dev") if int(k) >= ALIAS_BASE) == {alias}
    assert home["plane"].alias(alias)["remote_device_id"] == str(home["allowed"])


def test_reserve_drive_and_cancel_through_a_home_minted_token(home):
    plane, account_id = home["plane"], home["account_id"]
    plane.record_enrollment(local_account_id=account_id, destination_deployment_id=DEST)
    alias = next(int(k) for k in _acc(home, "get_dev") if int(k) >= ALIAS_BASE)
    start, end = _window()

    reserved = _acc(home, "reserve_device", dd=alias, st=int(start.timestamp()), et=int(end.timestamp()))
    token = reserved["Token"]
    with sqlite3.connect(home["root"] / "reservations.db") as conn:
        rows = conn.execute(
            "SELECT r.res_id, r.username, r.device_id FROM Reservations r "
            "JOIN HomeFederatedReservations h ON h.res_id=r.res_id"
        ).fetchall()
        owner_rows = conn.execute("SELECT COUNT(*) FROM FederatedReservations").fetchone()[0]
    assert len(rows) == 1 and rows[0][1] == NATIVE and rows[0][2] == alias
    assert owner_rows == 1
    res_id = rows[0][0]

    listed = _acc(home, "get_res")
    assert listed[str(res_id)].startswith(f"{NATIVE},{alias},")

    # Device RPC over the native surface: the token routes to the owner.
    from remoteRF_server.server import rpc_manager as rpc_module

    with patch.object(rpc_module, "reservation_handler", home["reservations"]):
        manager = rpc_module.RpcManager()
        result = manager.run_rpc(function_name="Test:rx:CALL0", args={"a": map_arg(token), "n": map_arg(3)})
        assert unmap_arg(result["value"]) == 42
        gid, function_name, args = home["rpc"].device_calls[-1]
        assert (gid, function_name) == (home["allowed"], "Test:rx:CALL0")
        assert "a" not in args and unmap_arg(args["n"]) == 3

        schema = manager.run_rpc(function_name="IDL:get_drivers", args={"token": map_arg(token)})
        assert unmap_arg(schema["device_type"]) == "test"

        bad = manager.run_rpc(function_name="Test:rx:CALL0", args={"a": map_arg("not-a-token")})
        assert "a" in bad and home["rpc"].device_calls[-1][1] == "Test:rx:CALL0"  # nothing new dispatched

    cancelled = _acc(home, "cancel_res", res_id=res_id)
    assert "UC" in cancelled
    with sqlite3.connect(home["root"] / "reservations.db") as conn:
        assert conn.execute("SELECT COUNT(*) FROM HomeFederatedReservations").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM Reservations WHERE res_id=?", (res_id,)).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM FederatedReservations").fetchone()[0] == 0
    # Every hop was one grant to the owner; the bad token issued none.
    assert home["calls"] == [
        "device_list", "device_reserve", "device_reservations", "device_rpc", "device_rpc", "device_cancel",
    ]


def test_owner_refusals_surface_as_ace_and_leave_no_home_rows(home):
    plane, account_id = home["plane"], home["account_id"]
    plane.record_enrollment(local_account_id=account_id, destination_deployment_id=DEST)
    start, end = _window()
    # A hidden device is never aliased by a listing, so reserve it by hand.
    with sqlite3.connect(home["root"] / "reservations.db") as conn:
        conn.execute(
            "INSERT INTO FederatedDeviceAliases (alias_id,owner_deployment_id,remote_device_id,display_name) "
            "VALUES (?,?,?,?)",
            (ALIAS_BASE + 77, DEST, str(home["hidden"]), "hidden"),
        )
    refused = _acc(
        home, "reserve_device", dd=ALIAS_BASE + 77, st=int(start.timestamp()), et=int(end.timestamp())
    )
    assert refused["ace"].startswith("Partner refused:")
    with sqlite3.connect(home["root"] / "reservations.db") as conn:
        assert conn.execute("SELECT COUNT(*) FROM HomeFederatedReservations").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM FederatedReservations").fetchone()[0] == 0

    with pytest.raises(HomeDeviceError):
        plane.cancel(local_account_id=account_id, res_id=424242)


def test_cluster_code_enrols_a_student_into_the_partners_attached_groups(home, tmp_path):
    """One `cluster.` code at HOME; the partner puts the proxy into every group
    it attached to the cluster, without the HOME ever naming a group."""
    from types import SimpleNamespace

    from remoteRF_server.server.federation import cluster
    from test_gate_e_federation import CONTRACT

    plane, account_id, groups = home["plane"], home["account_id"], home["reservations"]
    from remoteRF_server.server import reservation as reservation_module

    handler = reservation_module.user_group_handler
    group_id = handler.create_user_group(
        group_name=f"cluster-{uuid.uuid4().hex[:6]}", devices_whitelist=[home["allowed"]],
        max_reservation_time_sec=3600, max_reservations=5, lifetime_sec=0,
    )
    # One process plays both labs, so one state file and one usergroups.db
    # serve as HOME's and the partner's; the contract id is what links them.
    state = tmp_path / "clusters.json"
    with patch.object(cluster, "_state_path", return_value=state), \
         patch.object(cluster, "_db_path", return_value=home["dest_db"]):
        cluster.save({"lab": {"role": "member", "state": "active", "peer": DEST, "contract_id": CONTRACT,
                              "created_at": 1, "groups": [group_id]}})
        (code,) = cluster.mint_codes("lab")
        result = _acc(home, "set_enroll", ec=code)
        assert result["UC"] == f"Enrolled {NATIVE} in cluster lab."
        # Not yet at the partner: the HOME fan-out needs the runtime, which the
        # handler under test lacks; the tick supplies it.
        assert home["calls"] == []
        fake_home = SimpleNamespace(
            federation_enroller=SimpleNamespace(outbound=plane.outbound), federation_devices=plane,
        )
        notes = []
        cluster.enroll_students(fake_home, notes.append)
        assert home["calls"] == ["federated_enroll"] and notes == [], notes
        assert plane.enrolled(account_id) == {DEST}
        cluster.enroll_students(fake_home)  # idempotent: already enrolled there
        assert home["calls"] == ["federated_enroll"]

        with sqlite3.connect(home["dest_db"]) as conn:
            proxy = conn.execute(
                "SELECT local_account_id FROM FederatedPrincipals WHERE issuer_deployment_id=? "
                "AND remote_subject_id=?", (HOME, home["subject"] if "subject" in home else None)
            ).fetchone()
            kinds = dict(conn.execute("SELECT kind,COUNT(*) FROM ClusterAccounts GROUP BY kind").fetchall())
            assert kinds == {"local": 1, "proxy": 1}
            proxies = conn.execute("SELECT local_account_id FROM ClusterAccounts WHERE kind='proxy'").fetchall()
            member = conn.execute("SELECT 1 FROM UsersLookup WHERE user_id=? AND group_id=?",
                                  (proxies[0][0], group_id)).fetchone()
            assert member is not None
        # The device shows up at HOME through the ordinary alias path.
        devices = _acc(home, "get_dev")
        assert any(int(k) >= ALIAS_BASE for k in devices)


def test_the_v2_schema_service_sends_a_partner_token_to_the_v1_plane(home):
    """The Client tries Dynamic v2 first; for a partner device the HOME must
    answer with a protocol error (fall back), never a reservation error."""
    from remoteRF_server.server import dynamic_v2

    plane, account_id = home["plane"], home["account_id"]
    plane.record_enrollment(local_account_id=account_id, destination_deployment_id=DEST)
    alias = next(int(k) for k in _acc(home, "get_dev") if int(k) >= ALIAS_BASE)
    start, end = _window()
    token = _acc(home, "reserve_device", dd=alias, st=int(start.timestamp()), et=int(end.timestamp()))["Token"]
    with patch("remoteRF_server.server.reservation.reservation_handler", home["reservations"]):
        with pytest.raises(dynamic_v2.RemoteRFProtocolError, match="v1 device plane"):
            dynamic_v2.session_manager.schema_for_token(token)
        with pytest.raises(dynamic_v2.RemoteRFProtocolError):
            dynamic_v2.session_manager.open(token)
        with pytest.raises(dynamic_v2.RemoteRFReservationError):
            dynamic_v2.session_manager.schema_for_token("not-a-token")  # a native miss is still a miss
