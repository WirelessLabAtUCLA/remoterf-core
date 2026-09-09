import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from remoterf_federation_core import parse_federation_invitation
from remoteRF_server.server.federation.destination import ActionRegistry
from remoteRF_server.server.federation.enrollment import (
    ServerEnrollmentCodeStore,
    ServerFederatedEnrollHandler,
)
from remoteRF_server.server.federation.migrations import migrate_reservations_schema
from remoteRF_server.server.federation.migrations import check_gate_f_ready

from test_gate_e_federation import CONTRACT, DEST, HOME, active_pair, executor


def _gate_f(tmp_path, uses=1):
    pair = active_pair(tmp_path)
    store = ServerEnrollmentCodeStore(
        pair["dest_db"], local_deployment_id=DEST, clock=lambda: pair["now"][0]
    )
    with sqlite3.connect(pair["dest_db"]) as conn:
        conn.execute(
            "INSERT INTO UserGroups(group_id,group_name,devices_whitelist,"
            "max_reservation_time_sec,max_reservations,lifetime_sec,created_at) "
            "VALUES (7,'federated-lab','[]',3600,2,0,CURRENT_TIMESTAMP)"
        )
    invitation = store.create_federated(
        group_id=7,
        uses=uses,
        duration_sec=300,
        contract_id=CONTRACT,
        contract_version=1,
        allowed_issuer_deployment_id=HOME,
    )
    dest_reservations = tmp_path / "dest-reservations.db"
    with sqlite3.connect(dest_reservations) as conn:
        migrate_reservations_schema(conn)
    handler = ServerFederatedEnrollHandler(
        usergroups_path=pair["dest_db"],
        reservations_path=dest_reservations,
        local_deployment_id=DEST,
        display_name="Destination",
        clock=lambda: pair["now"][0],
    )
    return pair, invitation, executor(
        pair, ActionRegistry({"federated_enroll": handler})
    )


def _issue(pair, invitation, request_id=None, code_name=None):
    value = parse_federation_invitation(invitation).value
    return pair["issuer"].issue(
        local_account_id=1,
        destination_deployment_id=DEST,
        contract_id=CONTRACT,
        contract_version=1,
        action="federated_enroll",
        request_id=request_id,
        code_name=code_name or value["code_name"],
    )


def _result(pair, destination, issued):
    response = destination.execute("2", issued.grant, issued.request.json)
    assert response["error"] is None
    return pair["issuer"].verify_result(response["signed_result"], issued)


def test_server_federated_enrollment_receipt_retry_tracks_current_membership(tmp_path):
    pair, invitation, destination = _gate_f(tmp_path)
    first = _issue(pair, invitation)
    completed = _result(pair, destination, first)
    assert completed["status"] == "ok"
    assert completed["membership_present"] is True
    receipt_id = completed["redemption_id"]
    with sqlite3.connect(pair["dest_db"]) as conn:
        receipt = conn.execute(
            "SELECT local_account_id,code_sha256 FROM EnrollmentRedemptions"
        ).fetchone()
        assert len(receipt[1]) == 64
        assert conn.execute("SELECT COUNT(*) FROM EnrollmentCodes").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM UsersLookup").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM FederatedPrincipals").fetchone()[0] == 1
    check_gate_f_ready(pair["dest_db"], local_deployment_id=DEST)
    # Even an owner edit that whitelists a real-looking device does not turn
    # Gate F membership into a password, session, or resource capability.
    with sqlite3.connect(pair["dest_db"]) as conn:
        conn.execute("UPDATE UserGroups SET devices_whitelist='[7]' WHERE group_id=7")
    with sqlite3.connect(tmp_path / "dest-reservations.db") as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS Reservations"
            "(device_id INTEGER NOT NULL,end_time TIMESTAMP NOT NULL)"
        )
        proxy_name = conn.execute(
            "SELECT username FROM Accounts WHERE acc_id=?", (receipt[0],)
        ).fetchone()[0]
    from remoteRF_server.common.utils import map_arg
    from remoteRF_server.server.reservation import ReservationHandler

    resources = object.__new__(ReservationHandler)
    resources.filepath = tmp_path / "dest-reservations.db"
    resources.lock = threading.RLock()
    resources.federation_enroller = None
    assert "UE" in resources.login_user(proxy_name, "any-password")
    assert "ace" in resources.handle_call(
        function_name="get_dev",
        args={"un": map_arg(proxy_name), "pw": map_arg("any-password")},
    )
    assert "ace" in resources.reserve_device(
        proxy_name,
        7,
        datetime.now() + timedelta(minutes=1),
        datetime.now() + timedelta(minutes=5),
        is_server=True,
    )

    retry = _issue(pair, invitation, request_id=first.claims["request_id"])
    retried = _result(pair, destination, retry)
    assert retried["redemption_id"] == receipt_id
    assert retried["membership_present"] is True

    with sqlite3.connect(pair["dest_db"]) as conn:
        conn.execute("DELETE FROM UsersLookup WHERE user_id=? AND group_id=7", (receipt[0],))
    third = _issue(pair, invitation, request_id=first.claims["request_id"])
    current = _result(pair, destination, third)
    assert current["redemption_id"] == receipt_id
    assert current["membership_present"] is False
    assert current["groups"] == []
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM EnrollmentRedemptions").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM UsersLookup").fetchone()[0] == 0


def test_server_same_request_changed_payload_conflicts_without_mutation(tmp_path):
    pair, invitation, destination = _gate_f(tmp_path)
    first = _issue(pair, invitation)
    assert _result(pair, destination, first)["status"] == "ok"
    changed = _issue(
        pair,
        invitation,
        request_id=first.claims["request_id"],
        code_name="different-high-entropy-code",
    )
    result = _result(pair, destination, changed)
    assert result["status"] == "error"
    assert result["error_code"] == "request_conflict"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM EnrollmentRedemptions").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM UsersLookup").fetchone()[0] == 1


def test_server_post_commit_sign_failure_recovers_from_receipt_after_restart(
    tmp_path, monkeypatch
):
    pair, invitation, destination = _gate_f(tmp_path)
    first = _issue(pair, invitation)
    monkeypatch.setattr(
        destination,
        "_sign_after_commit",
        lambda *args: (_ for _ in ()).throw(RuntimeError("signing unavailable")),
    )
    failed = destination.execute("2", first.grant, first.request.json)
    assert failed["error"]["code"] == "internal_error"
    with sqlite3.connect(pair["dest_db"]) as conn:
        receipt_id = conn.execute("SELECT id FROM EnrollmentRedemptions").fetchone()[0]
        assert conn.execute("SELECT COUNT(*) FROM EnrollmentCodes").fetchone()[0] == 0
    # Reconstruct both handler and executor: recovery is DB-backed, not memory-backed.
    restarted_handler = ServerFederatedEnrollHandler(
        usergroups_path=pair["dest_db"],
        reservations_path=tmp_path / "dest-reservations.db",
        local_deployment_id=DEST,
        display_name="Destination",
        clock=lambda: pair["now"][0],
    )
    restarted = executor(
        pair, ActionRegistry({"federated_enroll": restarted_handler})
    )
    retry = _issue(pair, invitation, request_id=first.claims["request_id"])
    recovered = _result(pair, restarted, retry)
    assert recovered["redemption_id"] == receipt_id
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM EnrollmentRedemptions").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM UsersLookup").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0] == 2


def test_server_same_logical_request_concurrency_mutates_once(tmp_path):
    pair, invitation, destination = _gate_f(tmp_path)
    request_id = __import__("uuid").uuid4()
    grants = [
        _issue(pair, invitation, request_id=str(request_id)),
        _issue(pair, invitation, request_id=str(request_id)),
    ]
    barrier = threading.Barrier(2)

    def run(issued):
        barrier.wait(timeout=5)
        return _result(pair, destination, issued)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, grants))
    assert all(item["status"] == "ok" for item in results)
    assert len({item["redemption_id"] for item in results}) == 1
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM EnrollmentRedemptions").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM UsersLookup").fetchone()[0] == 1


def test_server_one_use_code_concurrency_allows_exactly_one_subject(tmp_path):
    from remoteRF_server.common.utils import hash_token
    from remoteRF_server.server.federation.migrations import initialize_native_subjects

    pair, invitation, destination = _gate_f(tmp_path)
    salt, digest = hash_token("second-password")
    with sqlite3.connect(pair["reservations"]) as conn:
        conn.execute(
            "INSERT INTO Accounts(username,email,pass_salt,pass_hash,auth_type) "
            "VALUES ('second','second@example.test',?,?,'local_password')",
            (salt, digest),
        )
    subjects = initialize_native_subjects(pair["reservations"], HOME)
    grants = []
    code = parse_federation_invitation(invitation).value["code_name"]
    for account_id in (1, 2):
        grants.append(
            pair["issuer"].issue(
                local_account_id=account_id,
                destination_deployment_id=DEST,
                contract_id=CONTRACT,
                contract_version=1,
                action="federated_enroll",
                code_name=code,
            )
        )
    assert len(subjects) == 2
    barrier = threading.Barrier(2)

    def run(issued):
        barrier.wait(timeout=5)
        return _result(pair, destination, issued)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, grants))
    assert sum(item["status"] == "ok" for item in results) == 1
    assert sum(item["error_code"] in {"code_invalid", "code_exhausted"} for item in results) == 1
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM EnrollmentRedemptions").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM UsersLookup").fetchone()[0] == 1
        assert conn.execute("SELECT MIN(uses) FROM EnrollmentCodes").fetchone()[0] is None


def test_server_old_retry_does_not_restore_but_new_request_can_reenroll(tmp_path):
    pair, invitation, destination = _gate_f(tmp_path, uses=2)
    first = _issue(pair, invitation)
    completed = _result(pair, destination, first)
    with sqlite3.connect(pair["dest_db"]) as conn:
        account_id = conn.execute(
            "SELECT local_account_id FROM EnrollmentRedemptions"
        ).fetchone()[0]
        conn.execute("DELETE FROM UsersLookup WHERE user_id=? AND group_id=7", (account_id,))
    old_retry = _issue(pair, invitation, request_id=first.claims["request_id"])
    assert _result(pair, destination, old_retry)["membership_present"] is False
    deliberate = _issue(pair, invitation)
    reenrolled = _result(pair, destination, deliberate)
    assert reenrolled["membership_present"] is True
    assert reenrolled["redemption_id"] != completed["redemption_id"]
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM EnrollmentRedemptions").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM UsersLookup").fetchone()[0] == 1


def test_server_current_principal_and_contract_state_override_receipt(tmp_path):
    pair, invitation, destination = _gate_f(tmp_path, uses=2)
    first = _issue(pair, invitation)
    assert _result(pair, destination, first)["status"] == "ok"
    with sqlite3.connect(pair["dest_db"]) as conn:
        conn.execute(
            "UPDATE FederatedPrincipals SET status='disabled',disabled_at=101"
        )
    retry = _issue(pair, invitation, request_id=first.claims["request_id"])
    disabled = _result(pair, destination, retry)
    assert disabled["status"] == "error"
    assert disabled["error_code"] == "principal_disabled"
    new_request = _issue(pair, invitation)
    assert _result(pair, destination, new_request)["error_code"] == "principal_disabled"
    with sqlite3.connect(pair["dest_db"]) as conn:
        conn.execute(
            "UPDATE FederatedPrincipals SET status='active',disabled_at=NULL"
        )
        conn.execute(
            "UPDATE FederationContracts SET state='suspended' "
            "WHERE contract_id=? AND version=1",
            (CONTRACT,),
        )
    suspended_retry = _issue(pair, invitation, request_id=first.claims["request_id"])
    suspended = _result(pair, destination, suspended_retry)
    assert suspended["status"] == "error"
    assert suspended["error_code"] == "contract_inactive"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM EnrollmentRedemptions").fetchone()[0] == 1


def test_server_local_and_federated_code_paths_are_strictly_separate(tmp_path):
    from remoteRF_server.server.user_group_handler import UserGroupHandler

    pair, invitation, destination = _gate_f(tmp_path, uses=2)
    federation_code = parse_federation_invitation(invitation).value["code_name"]
    handler = object.__new__(UserGroupHandler)
    handler.filepath = pair["dest_db"]
    handler.lock = threading.RLock()
    assert handler.validate_enrollment_code(code_name=federation_code) is False
    with sqlite3.connect(pair["dest_db"]) as conn:
        conn.execute(
            "INSERT INTO EnrollmentCodes(code_name,group_id,uses,duration_sec,created_at) "
            "VALUES ('plain-local-code',7,1,300,CURRENT_TIMESTAMP)"
        )
    issued = _issue(pair, invitation, code_name="plain-local-code")
    rejected = _result(pair, destination, issued)
    assert rejected["status"] == "error"
    assert rejected["error_code"] == "code_restriction_mismatch"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute(
            "SELECT uses FROM EnrollmentCodes WHERE code_name='plain-local-code'"
        ).fetchone()[0] == 1


def test_server_code_and_group_expiry_are_synchronous(tmp_path):
    pair, invitation, destination = _gate_f(tmp_path, uses=2)
    pair["now"][0] = 400
    expired = _result(pair, destination, _issue(pair, invitation))
    assert expired["error_code"] == "code_expired"
    with sqlite3.connect(pair["dest_db"]) as conn:
        conn.execute("UPDATE EnrollmentCodes SET federation_expires_at=500")
        conn.execute(
            "UPDATE UserGroups SET lifetime_sec=1,created_at='1969-12-31 00:00:00' "
            "WHERE group_id=7"
        )
    group_expired = _result(pair, destination, _issue(pair, invitation))
    assert group_expired["error_code"] == "group_expired"


def test_server_code_restrictions_are_exact_and_raw_code_is_not_receipted(tmp_path):
    from uuid import uuid4

    pair, invitation, destination = _gate_f(tmp_path, uses=2)
    code = parse_federation_invitation(invitation).value["code_name"]
    for column, value in (
        ("allowed_issuer_deployment_id", str(uuid4())),
        ("federation_contract_id", str(uuid4())),
        ("federation_contract_version", 2),
    ):
        with sqlite3.connect(pair["dest_db"]) as conn:
            conn.execute(
                f"UPDATE EnrollmentCodes SET {column}=? WHERE code_name=?",
                (value, code),
            )
        rejected = _result(pair, destination, _issue(pair, invitation))
        assert rejected["error_code"] == "code_restriction_mismatch"
        with sqlite3.connect(pair["dest_db"]) as conn:
            conn.execute(
                "UPDATE EnrollmentCodes SET federation_contract_id=?,"
                "federation_contract_version=1,allowed_issuer_deployment_id=? "
                "WHERE code_name=?",
                (CONTRACT, HOME, code),
            )
            assert conn.execute(
                "SELECT uses FROM EnrollmentCodes WHERE code_name=?", (code,)
            ).fetchone()[0] == 2
    successful = _result(pair, destination, _issue(pair, invitation))
    assert successful["status"] == "ok"
    with sqlite3.connect(pair["dest_db"]) as conn:
        for table in ("EnrollmentRedemptions", "FederationAuditEvents", "FederatedPrincipals"):
            rows = conn.execute(f"SELECT * FROM {table}").fetchall()
            assert code not in repr(rows)
