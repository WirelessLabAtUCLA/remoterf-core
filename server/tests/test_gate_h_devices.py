"""Gate H: federated device plane on a Server destination.

Every test drives the real destination executor with real Ed25519 grants,
real contracts, and the real ReservationHandler / permission tables pointed
at a temporary directory.  Only the device registry and the hardware RPC
dispatcher are faked, so the authorization decisions, idempotency, replay
consumption, and post-commit finalization under test are the production ones.
"""

import base64
import sqlite3
import time
import uuid
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from remoterf_federation_core import (
    MAX_DEVICE_RESULT_BYTES,
    build_contract_terms,
    build_device_payload,
)
from remoteRF_server.common.grpc import grpc_pb2
from remoteRF_server.common.utils import map_arg, unmap_arg
from remoteRF_server.server import device_manager
from remoteRF_server.server.acc_perms import perms_db
from remoteRF_server.server.device_manager import _DeviceState
from remoteRF_server.server.federation.contracts import ContractStore
from remoteRF_server.server.federation.devices import build_server_gate_h_executor
from remoteRF_server.server.federation.home import ServerHomeGrantIssuer
from remoteRF_server.server.federation.migrations import (
    GATE_H_MIGRATION_NAME,
    initialize_native_subjects,
    migrate_gate_f_usergroups_schema,
    migrate_gate_h_usergroups_schema,
    migrate_reservations_schema,
)
from remoteRF_server.server.federation.principals import prepare_federated_account
from remoteRF_server.server.reservation import ReservationHandler
from remoteRF_server.server.user_group_handler import UserGroupHandler

from test_gate_e_federation import CONTRACT, DEST, HOME, material, pin

ALL_DEVICE_CAPABILITIES = [
    "FEDERATED_ENROLL",
    "PERMISSIONS_READ",
    "DEVICE_READ",
    "DEVICE_RESERVE",
    "DEVICE_CONTROL",
]


class FakeRpcManager:
    """Records dispatches; never touches hardware."""

    def __init__(self):
        self.device_calls = []
        self.control_calls = []
        self.response = {"value": map_arg(42)}

    def run_device_rpc_for_gid(self, *, gid, function_name, args):
        self.device_calls.append((gid, function_name, dict(args)))
        if function_name.endswith(":explode"):
            raise RuntimeError("device disappeared / not connected")
        if function_name.endswith(":SET"):
            return {}  # a setter answers with no results: an empty frame
        return dict(self.response)

    def run_rpc(self, *, function_name, args):
        self.control_calls.append((function_name, dict(args)))
        return {"schema": map_arg("{}"), "device_type": map_arg("test")}


def _device(*, connected, name):
    return _DeviceState(
        dev=object() if connected else None,
        origin="local",
        online=connected,
        salt="",
        hsh="",
        name=name,
        ident="",
        dtype="test",
    )


@pytest.fixture
def world(tmp_path):
    """One HOME issuer and one fully populated Server destination."""

    root = tmp_path / "dest"
    root.mkdir()
    patches = [
        patch(target, return_value=root)
        for target in (
            "remoteRF_server.server.reservation.get_db_dir",
            "remoteRF_server.server.acc_perms.get_db_dir",
            "remoteRF_server.server.user_group_handler.get_db_dir",
        )
    ]
    for item in patches:
        item.start()
    perms = perms_db()
    groups = UserGroupHandler()
    reservations = ReservationHandler()
    patches += [
        patch("remoteRF_server.server.reservation.perms", perms),
        patch("remoteRF_server.server.reservation.user_group_handler", groups),
        patch("remoteRF_server.server.acc_perms.user_group_handler", groups),
    ]
    for item in patches[3:]:
        item.start()

    base = 700_000 + (uuid.uuid4().int % 90_000)
    allowed_id, hidden_id, offline_id = base, base + 1, base + 2
    with device_manager._state_lock:
        saved = dict(device_manager._devices)
        device_manager._devices[allowed_id] = _device(connected=True, name="gate-h-allowed")
        device_manager._devices[hidden_id] = _device(connected=True, name="gate-h-hidden")
        device_manager._devices[offline_id] = _device(connected=False, name="gate-h-offline")

    now = [100]
    home_key, dest_key = (
        __import__("cryptography.hazmat.primitives.asymmetric.ed25519", fromlist=["x"])
        .Ed25519PrivateKey.generate(),
        __import__("cryptography.hazmat.primitives.asymmetric.ed25519", fromlist=["x"])
        .Ed25519PrivateKey.generate(),
    )
    home_material, dest_material = material(HOME, home_key), material(DEST, dest_key)
    home_db, dest_db = tmp_path / "home-usergroups.db", root / "usergroups.db"
    for path in (home_db, dest_db):
        pin(path, home_material, now)
        pin(path, dest_material, now)
    home_store = ContractStore(
        home_db, local_deployment_id=HOME, private_key=home_key,
        signing_kid=home_material["kid"], clock=lambda: now[0],
    )
    dest_store = ContractStore(
        dest_db, local_deployment_id=DEST, private_key=dest_key,
        signing_kid=dest_material["kid"], clock=lambda: now[0],
    )
    terms = build_contract_terms(
        contract_id=CONTRACT, version=1,
        participant_1=HOME, participant_1_kid=home_material["kid"],
        participant_1_sha256=home_material["public_key_sha256"],
        participant_2=DEST, participant_2_kid=dest_material["kid"],
        participant_2_sha256=dest_material["public_key_sha256"],
        valid_from=50, valid_until=1000,
        allowed_capabilities=ALL_DEVICE_CAPABILITIES,
    )
    home_store.propose(terms, actor_admin_ref="home")
    dest_store.import_bundle(home_store.export_bundle(CONTRACT, 1))
    dest_store.accept(CONTRACT, 1, actor_admin_ref="dest")
    home_store.import_bundle(dest_store.export_bundle(CONTRACT, 1))
    home_store.activate(CONTRACT, 1, actor_admin_ref="home")
    dest_store.import_bundle(home_store.export_bundle(CONTRACT, 1))
    dest_store.activate(CONTRACT, 1, actor_admin_ref="dest")
    home_store.import_bundle(dest_store.export_bundle(CONTRACT, 1))

    home_reservations = tmp_path / "home-reservations.db"
    from remoteRF_server.common.utils import hash_token

    salt, hashed = hash_token("native-password")
    with sqlite3.connect(home_reservations) as conn:
        migrate_reservations_schema(conn)
        conn.execute(
            "INSERT INTO Accounts (username,email,pass_salt,pass_hash,auth_type) "
            "VALUES ('native','native@example.test',?,?,'local_password')",
            (salt, hashed),
        )
    subject = initialize_native_subjects(home_reservations, HOME)[1]
    issuer = ServerHomeGrantIssuer(
        reservations_path=home_reservations, usergroups_path=home_db,
        local_deployment_id=HOME, private_key=home_key,
        signing_kid=home_material["kid"], clock=lambda: now[0],
    )

    rpc = FakeRpcManager()
    executor = build_server_gate_h_executor(
        usergroups_path=dest_db,
        reservations_path=root / "reservations.db",
        perms_path=root / "perms.db",
        local_deployment_id=DEST,
        private_key=dest_key,
        signing_kid=dest_material["kid"],
        display_name="Destination",
        clock=lambda: now[0],
        reservation_handler=reservations,
        rpc_manager=rpc,
    )

    def enroll(*, devices, admin=False):
        prepared = prepare_federated_account(
            root / "reservations.db",
            issuer_deployment_id=HOME,
            remote_subject_id=subject,
            perms_path=root / "perms.db",
            now=now[0],
        )
        with sqlite3.connect(dest_db) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO FederatedPrincipals"
                "(id,issuer_deployment_id,remote_subject_id,local_account_id,status,"
                "created_at,last_seen_at,disabled_at,display_metadata_json) "
                "VALUES (?,?,?,?,'active',100,100,NULL,'{}')",
                (str(uuid.uuid4()), HOME, subject, prepared.local_account_id),
            )
        if admin:
            with sqlite3.connect(root / "perms.db") as conn:
                conn.execute("DELETE FROM Users WHERE Username=?", (prepared.username,))
                conn.execute("INSERT INTO Admins(Username) VALUES (?)", (prepared.username,))
        elif devices:
            group_id = groups.create_user_group(
                group_name=f"gate-h-{uuid.uuid4().hex[:6]}",
                devices_whitelist=list(devices),
                max_reservation_time_sec=3600,
                max_reservations=5,
                lifetime_sec=0,
            )
            with sqlite3.connect(dest_db) as conn:
                conn.execute(
                    "INSERT INTO UsersLookup(user_id,group_id) VALUES (?,?)",
                    (prepared.local_account_id, group_id),
                )
        return prepared

    def call(action, *, request_id=None, **device_kwargs):
        issued = issuer.issue(
            local_account_id=1,
            destination_deployment_id=DEST,
            contract_id=CONTRACT,
            contract_version=1,
            action=action,
            request_id=request_id,
            device_payload=build_device_payload(action=action, **device_kwargs),
        )
        response = executor.execute("2", issued.grant, issued.request.json)
        assert response["error"] is None, response
        return issuer.verify_result(response["signed_result"], issued), issued

    try:
        yield {
            "now": now,
            "root": root,
            "dest_db": dest_db,
            "issuer": issuer,
            "executor": executor,
            "reservations": reservations,
            "rpc": rpc,
            "enroll": enroll,
            "call": call,
            "allowed": allowed_id,
            "hidden": hidden_id,
            "offline": offline_id,
            "subject": subject,
        }
    finally:
        with device_manager._state_lock:
            device_manager._devices.clear()
            device_manager._devices.update(saved)
        for item in patches:
            item.stop()


def _frame(function_name, **args):
    request = grpc_pb2.GenericRPCRequest(function_name=function_name)
    for key, value in args.items():
        request.args[key].CopyFrom(map_arg(value))
    return base64.b64encode(request.SerializeToString()).decode("ascii")


def _decode(response_b64):
    response = grpc_pb2.GenericRPCResponse()
    response.ParseFromString(base64.b64decode(response_b64))
    return {key: unmap_arg(value) for key, value in response.results.items()}


def _window(start_offset_minutes, length_minutes=30):
    start = datetime.now().replace(microsecond=0) + timedelta(minutes=start_offset_minutes)
    end = start + timedelta(minutes=length_minutes)
    return int(start.timestamp()), int(end.timestamp())


# ── migration ───────────────────────────────────────────────────────────


def test_gate_h_migration_widens_jti_actions_without_dropping_evidence(tmp_path):
    path = tmp_path / "usergroups.db"
    with sqlite3.connect(path) as conn:
        migrate_gate_f_usergroups_schema(conn)
        conn.execute(
            "INSERT INTO FederationGrantJTIs VALUES (?,?,?,?,?,1,?,?,?,?,200,205,100)",
            (HOME, str(uuid.uuid4()), "3" * 36, DEST, CONTRACT, "a" * 64,
             "permissions_read", str(uuid.uuid4()), "b" * 64),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO FederationGrantJTIs VALUES (?,?,?,?,?,1,?,?,?,?,200,205,100)",
                (HOME, str(uuid.uuid4()), "3" * 36, DEST, CONTRACT, "a" * 64,
                 "device_rpc", str(uuid.uuid4()), "b" * 64),
            )
    with sqlite3.connect(path) as conn:
        migrate_gate_h_usergroups_schema(conn)
        migrate_gate_h_usergroups_schema(conn)  # idempotent
        assert conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone() == (1,)
        conn.execute(
            "INSERT INTO FederationGrantJTIs VALUES (?,?,?,?,?,1,?,?,?,?,200,205,100)",
            (HOME, str(uuid.uuid4()), "3" * 36, DEST, CONTRACT, "a" * 64,
             "device_rpc", str(uuid.uuid4()), "b" * 64),
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE FederationGrantJTIs SET consumed_at=101")
        assert conn.execute(
            "SELECT COUNT(*) FROM SchemaMigrations WHERE name=?", (GATE_H_MIGRATION_NAME,)
        ).fetchone() == (1,)
        assert conn.execute(
            "SELECT name FROM sqlite_master WHERE name='FederatedDeviceReceipts'"
        ).fetchone() is not None


# ── discovery ───────────────────────────────────────────────────────────


def test_device_list_requires_an_enrolled_principal_and_follows_local_permissions(world):
    unknown, _ = world["call"]("device_list")
    assert unknown["status"] == "error"
    assert unknown["error_code"] == "principal_unknown"
    assert unknown["payload"] == {"devices": []}

    world["enroll"](devices=[world["allowed"], world["offline"]])
    listed, _ = world["call"]("device_list")
    assert listed["status"] == "ok"
    by_id = {entry["local_device_id"]: entry for entry in listed["payload"]["devices"]}
    assert set(by_id) == {str(world["allowed"]), str(world["offline"])}
    assert by_id[str(world["allowed"])]["online"] is True
    assert by_id[str(world["offline"])]["online"] is False
    assert by_id[str(world["allowed"])]["display_name"] == "gate-h-allowed"
    assert by_id[str(world["allowed"])]["max_reservation_time_sec"] == 3600

    with sqlite3.connect(world["dest_db"]) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM FederationAuditEvents WHERE event_type='device_list' "
            "AND result_code='ok'"
        ).fetchone() == (1,)


def test_admin_principal_sees_every_registered_device(world):
    world["enroll"](devices=[], admin=True)
    listed, _ = world["call"]("device_list")
    ids = {entry["local_device_id"] for entry in listed["payload"]["devices"]}
    assert {str(world["allowed"]), str(world["hidden"]), str(world["offline"])} <= ids


# ── reservation lifecycle ───────────────────────────────────────────────


def test_reserve_is_idempotent_per_request_and_authorizes_device_rpc(world):
    world["enroll"](devices=[world["allowed"]])
    start, end = _window(-5)
    request_id = str(uuid.uuid4())
    first, _ = world["call"](
        "device_reserve", request_id=request_id,
        local_device_id=str(world["allowed"]), start_time=start, end_time=end,
    )
    assert first["status"] == "ok", first
    reservation = first["payload"]["reservation"]
    assert reservation["local_device_id"] == str(world["allowed"])
    assert (reservation["start_time"], reservation["end_time"]) == (start, end)

    # A retried write with the same logical request returns the same row.
    again, _ = world["call"](
        "device_reserve", request_id=request_id,
        local_device_id=str(world["allowed"]), start_time=start, end_time=end,
    )
    assert again["payload"]["reservation"] == reservation
    with sqlite3.connect(world["root"] / "reservations.db") as conn:
        assert conn.execute("SELECT COUNT(*) FROM Reservations").fetchone() == (1,)
        assert conn.execute("SELECT COUNT(*) FROM FederatedReservations").fetchone() == (1,)

    # A different request that overlaps is an ordinary local conflict.
    overlap, _ = world["call"](
        "device_reserve",
        local_device_id=str(world["allowed"]),
        start_time=start + 600, end_time=end + 600,
    )
    assert overlap["status"] == "error"
    assert overlap["error_code"] == "reservation_conflict"

    # A device outside the principal's local permissions is refused locally.
    refused, _ = world["call"](
        "device_reserve",
        local_device_id=str(world["hidden"]),
        start_time=start + 7200, end_time=end + 7200,
    )
    assert refused["status"] == "error"
    assert refused["error_code"] == "reservation_refused"

    # The plaintext bearer token never appears in any signed result.
    for result in (first, again):
        assert "token" not in str(result).lower()

    # Reservations are visible, own rows flagged, no usernames leaked.
    mine, _ = world["call"]("device_reservations")
    rows = mine["payload"]["reservations"]
    assert len(rows) == 1 and rows[0]["mine"] is True
    assert rows[0]["reservation_id"] == reservation["reservation_id"]
    assert rows[0]["display_name"] == "you"

    # Live reservation authorizes a hardware RPC after commit.
    executed, issued = world["call"](
        "device_rpc",
        local_device_id=str(world["allowed"]),
        request_b64=_frame("test:ip:CALL0", a="smuggled-bearer-token"),
    )
    assert executed["status"] == "ok", executed
    assert _decode(executed["payload"]["response_b64"]) == {"value": 42}
    gid, function_name, args = world["rpc"].device_calls[-1]
    assert (gid, function_name) == (world["allowed"], "test:ip:CALL0")
    assert "a" not in args

    # A setter's empty response frame is a valid ok result, not an error.
    setter, _ = world["call"](
        "device_rpc",
        local_device_id=str(world["allowed"]),
        request_b64=_frame("test:rx_lo:SET", rx_lo=915000000),
    )
    assert setter["status"] == "ok", setter
    assert setter["payload"]["response_b64"] == ""
    assert _decode(setter["payload"]["response_b64"]) == {}

    # Replaying the very same grant is rejected before any hardware call.
    calls_before = len(world["rpc"].device_calls)
    replay = world["executor"].execute("2", issued.grant, issued.request.json)
    replayed = world["issuer"].verify_result(replay["signed_result"], issued)
    assert replayed["status"] == "error"
    assert replayed["error_code"] == "replayed"
    assert replayed["payload"] == {"response_b64": None}
    assert len(world["rpc"].device_calls) == calls_before

    with sqlite3.connect(world["dest_db"]) as conn:
        assert conn.execute(
            "SELECT result_code FROM FederatedDeviceReceipts WHERE action='device_rpc'"
        ).fetchall() == [("authorized",), ("authorized",)]


def test_device_rpc_without_live_reservation_or_capability_is_refused(world):
    world["enroll"](devices=[world["allowed"]])
    no_reservation, _ = world["call"](
        "device_rpc",
        local_device_id=str(world["allowed"]),
        request_b64=_frame("test:ip:CALL0"),
    )
    assert no_reservation["status"] == "error"
    assert no_reservation["error_code"] == "no_active_reservation"
    assert world["rpc"].device_calls == []

    # A future reservation does not authorize hardware now.
    start, end = _window(60)
    reserved, _ = world["call"](
        "device_reserve", local_device_id=str(world["allowed"]),
        start_time=start, end_time=end,
    )
    assert reserved["status"] == "ok"
    future, _ = world["call"](
        "device_rpc",
        local_device_id=str(world["allowed"]),
        request_b64=_frame("test:ip:CALL0"),
    )
    assert future["error_code"] == "no_active_reservation"

    # An out-of-band Reservations row on the proxy carries no authorization.
    with sqlite3.connect(world["root"] / "reservations.db") as conn:
        username = conn.execute(
            "SELECT username FROM Accounts WHERE auth_type='federated'"
        ).fetchone()[0]
        live_start, live_end = _window(-5)
        conn.execute(
            "INSERT INTO Reservations (username, device_id, start_time, end_time, salt, hash) "
            "VALUES (?,?,?,?,'s','h')",
            (username, world["allowed"],
             datetime.fromtimestamp(live_start), datetime.fromtimestamp(live_end)),
        )
    smuggled, _ = world["call"](
        "device_rpc",
        local_device_id=str(world["allowed"]),
        request_b64=_frame("test:ip:CALL0"),
    )
    assert smuggled["error_code"] == "no_active_reservation"
    assert world["rpc"].device_calls == []


def test_cancel_only_removes_own_federation_reservations(world):
    world["enroll"](devices=[world["allowed"]])
    start, end = _window(30)
    reserved, _ = world["call"](
        "device_reserve", local_device_id=str(world["allowed"]),
        start_time=start, end_time=end,
    )
    reservation_id = reserved["payload"]["reservation"]["reservation_id"]

    with sqlite3.connect(world["root"] / "reservations.db") as conn:
        conn.execute(
            "INSERT INTO Reservations (username, device_id, start_time, end_time, salt, hash) "
            "VALUES ('someone-native',?,?,?,'s','h')",
            (world["allowed"], datetime.fromtimestamp(end + 600),
             datetime.fromtimestamp(end + 2400)),
        )
        native_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    listed, _ = world["call"]("device_reservations")
    labels = {row["reservation_id"]: row for row in listed["payload"]["reservations"]}
    assert labels[str(native_id)]["mine"] is False
    assert labels[str(native_id)]["display_name"] == "reserved"
    assert "someone-native" not in str(listed)

    foreign, _ = world["call"]("device_cancel", reservation_id=str(native_id))
    assert foreign["error_code"] == "reservation_not_found"

    cancelled, _ = world["call"]("device_cancel", reservation_id=reservation_id)
    assert cancelled["status"] == "ok"
    assert cancelled["payload"] == {"cancelled": True}
    twice, _ = world["call"]("device_cancel", reservation_id=reservation_id)
    assert twice["error_code"] == "reservation_not_found"
    with sqlite3.connect(world["root"] / "reservations.db") as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM Reservations WHERE res_id=?", (int(reservation_id),)
        ).fetchone() == (0,)
        assert conn.execute(
            "SELECT COUNT(*) FROM Reservations WHERE res_id=?", (native_id,)
        ).fetchone() == (1,)


# ── driver schema and finalize edge cases ───────────────────────────────


def test_idl_schema_fetch_requires_visibility_not_a_reservation(world):
    world["enroll"](devices=[world["allowed"]])
    schema, _ = world["call"](
        "device_rpc",
        local_device_id=str(world["allowed"]),
        request_b64=_frame(
            "IDL:get_drivers", device_id=999999, device_name="other", token="x"
        ),
    )
    assert schema["status"] == "ok", schema
    assert _decode(schema["payload"]["response_b64"])["device_type"] == "test"
    function_name, args = world["rpc"].control_calls[-1]
    assert function_name == "IDL:get_drivers"
    assert unmap_arg(args["device_id"]) == world["allowed"]
    assert "device_name" not in args and "token" not in args

    hidden, _ = world["call"](
        "device_rpc",
        local_device_id=str(world["hidden"]),
        request_b64=_frame("IDL:get_drivers"),
    )
    assert hidden["error_code"] == "device_not_visible"


def test_finalize_failures_become_destination_signed_errors(world):
    world["enroll"](devices=[world["allowed"]])
    start, end = _window(-5)
    world["call"](
        "device_reserve", local_device_id=str(world["allowed"]),
        start_time=start, end_time=end,
    )

    unsupported, _ = world["call"](
        "device_rpc", local_device_id=str(world["allowed"]),
        request_b64=_frame("echo"),
    )
    assert unsupported["error_code"] == "unsupported_device_rpc"

    unavailable, _ = world["call"](
        "device_rpc", local_device_id=str(world["allowed"]),
        request_b64=_frame("test:x:explode"),
    )
    assert unavailable["status"] == "error"
    assert unavailable["error_code"] == "device_unavailable"
    assert unavailable["payload"] == {"response_b64": None}

    world["rpc"].response = {"blob": map_arg("x" * (MAX_DEVICE_RESULT_BYTES + 10))}
    oversized, _ = world["call"](
        "device_rpc", local_device_id=str(world["allowed"]),
        request_b64=_frame("test:x:CALL0"),
    )
    assert oversized["status"] == "error"
    assert oversized["error_code"] == "response_too_large"

    with sqlite3.connect(world["dest_db"]) as conn:
        # Each of those consumed its grant: the JTI table has one row per call
        # (reserve + three rpc attempts), none of them replayable.
        assert conn.execute(
            "SELECT COUNT(*) FROM FederationGrantJTIs WHERE action='device_rpc'"
        ).fetchone() == (3,)


def test_contract_without_device_capability_cannot_reach_hardware(tmp_path, world):
    """Gate G contracts grant no hardware reach even at a Gate H destination."""

    from test_gate_e_federation import active_pair, issue

    (tmp_path / "gate-g").mkdir()
    pair = active_pair(tmp_path / "gate-g")
    executor = build_server_gate_h_executor(
        usergroups_path=pair["dest_db"],
        reservations_path=tmp_path / "gate-g" / "dest-reservations.db",
        local_deployment_id=pair["destination_id"],
        private_key=pair["dest_key"],
        signing_kid=pair["dest_material"]["kid"],
        display_name="Destination",
        clock=lambda: pair["now"][0],
        reservation_handler=world["reservations"],
        rpc_manager=world["rpc"],
    )
    # The HOME refuses to even issue for a capability its contract lacks.
    from remoterf_federation_core import FederationError

    with pytest.raises(FederationError) as refused:
        pair["issuer"].issue(
            local_account_id=1, destination_deployment_id=pair["destination_id"],
            contract_id=pair["contract_id"], contract_version=1,
            action="device_list",
        )
    assert refused.value.code == "contract_inactive"
    # And the destination still answers Gate G actions normally.
    issued = issue(pair)
    response = executor.execute("2", issued.grant, issued.request.json)
    assert response["error"] is None
