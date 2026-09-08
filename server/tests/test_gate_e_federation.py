import base64
import hashlib
import json
import sqlite3
import threading
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from remoterf_federation_core import (
    FEDERATION_RESULT_TYP,
    FederationError,
    build_contract_terms,
)
from remoteRF_server.server.federation.contracts import ContractStore
from remoteRF_server.server.federation.destination import (
    ActionRegistry,
    ServerFederationExecutor,
)
from remoteRF_server.server.federation.home import HomeFederationOutbound, ServerHomeGrantIssuer
import remoteRF_server.server.federation.destination as server_destination
from remoteRF_server.server.federation.migrations import (
    initialize_native_subjects,
    migrate_reservations_schema,
)
from remoteRF_server.server.federation.trust import TrustedKeyStore

HOME = "11111111-1111-4111-8111-111111111111"
DEST = "22222222-2222-4222-8222-222222222222"
CONTRACT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def material(deployment_id, key, valid_until=10_000):
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    digest = hashlib.sha256(raw).hexdigest()
    return {
        "deployment_id": deployment_id,
        "kid": digest[:32],
        "public_key_b64": base64.b64encode(raw).decode(),
        "public_key_sha256": digest,
        "valid_from": 0,
        "valid_until": valid_until,
    }


def pin(path, item, now):
    store = TrustedKeyStore(path, clock=lambda: now[0])
    store.import_key(
        item,
        approved_by="test-admin",
        approval_source="manual_offline",
        confirm_deployment_id=item["deployment_id"],
        confirm_kid=item["kid"],
        confirm_fingerprint=item["public_key_sha256"],
    )


def active_pair(tmp_path, *, key_valid_until=10_000, contract_valid_until=1000):
    now = [100]
    home_key, dest_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    home_material = material(HOME, home_key, key_valid_until)
    dest_material = material(DEST, dest_key, key_valid_until)
    home_db, dest_db = tmp_path / "home-usergroups.db", tmp_path / "dest-usergroups.db"
    for path in (home_db, dest_db):
        pin(path, home_material, now)
        pin(path, dest_material, now)
    home_store = ContractStore(
        home_db,
        local_deployment_id=HOME,
        private_key=home_key,
        signing_kid=home_material["kid"],
        clock=lambda: now[0],
    )
    dest_store = ContractStore(
        dest_db,
        local_deployment_id=DEST,
        private_key=dest_key,
        signing_kid=dest_material["kid"],
        clock=lambda: now[0],
    )
    terms = build_contract_terms(
        contract_id=CONTRACT,
        version=1,
        participant_1=HOME,
        participant_1_kid=home_material["kid"],
        participant_1_sha256=home_material["public_key_sha256"],
        participant_2=DEST,
        participant_2_kid=dest_material["kid"],
        participant_2_sha256=dest_material["public_key_sha256"],
        valid_from=50,
        valid_until=contract_valid_until,
        allowed_capabilities=["FEDERATED_ENROLL", "PERMISSIONS_READ"],
    )
    home_store.propose(terms, actor_admin_ref="home")
    dest_store.import_bundle(home_store.export_bundle(CONTRACT, 1))
    dest_store.accept(CONTRACT, 1, actor_admin_ref="dest")
    home_store.import_bundle(dest_store.export_bundle(CONTRACT, 1))
    home_store.activate(CONTRACT, 1, actor_admin_ref="home")
    dest_store.import_bundle(home_store.export_bundle(CONTRACT, 1))
    dest_store.activate(CONTRACT, 1, actor_admin_ref="dest")
    home_store.import_bundle(dest_store.export_bundle(CONTRACT, 1))

    reservations = tmp_path / "reservations.db"
    with sqlite3.connect(reservations) as conn:
        migrate_reservations_schema(conn)
        conn.execute(
            "INSERT INTO Accounts "
            "(username,email,pass_salt,pass_hash,auth_type) VALUES (?,?,?,?,?)",
            ("native", "native@example.test", "salt", "hash", "local_password"),
        )
    subjects = initialize_native_subjects(reservations, HOME)
    issuer = ServerHomeGrantIssuer(
        reservations_path=reservations,
        usergroups_path=home_db,
        local_deployment_id=HOME,
        private_key=home_key,
        signing_kid=home_material["kid"],
        clock=lambda: now[0],
    )
    return {
        "now": now,
        "issuer": issuer,
        "home_db": home_db,
        "dest_db": dest_db,
        "dest_key": dest_key,
        "dest_material": dest_material,
        "subject": subjects[1],
    }


def ok_handler(destination):
    def handler(conn, action):
        conn.execute(
            "CREATE TABLE IF NOT EXISTS test_invocations (request_id TEXT PRIMARY KEY)"
        )
        conn.execute(
            "INSERT INTO test_invocations VALUES (?)", (action.claims["request_id"],)
        )
        return {
            "status": "ok",
            "error_code": None,
            "deployment_id": DEST,
            "display_name": destination,
            "contract_id": CONTRACT,
            "contract_version": 1,
            "state": "active",
            "groups": [{"group_id": "9", "group_name": "synthetic-readers"}],
            "retrieved_at": 100,
            "redemption_id": None,
            "membership_present": None,
        }

    return handler


def issue(pair, action="permissions_read"):
    return pair["issuer"].issue(
        local_account_id=1,
        destination_deployment_id=DEST,
        contract_id=CONTRACT,
        contract_version=1,
        action=action,
        **({"code_name": "future-only"} if action == "federated_enroll" else {}),
    )


def executor(pair, registry=None):
    return ServerFederationExecutor(
        pair["dest_db"],
        local_deployment_id=DEST,
        private_key=pair["dest_key"],
        signing_kid=pair["dest_material"]["kid"],
        display_name="Destination",
        clock=lambda: pair["now"][0],
        registry=registry,
    )


def test_server_execute_commits_then_signs_and_rejects_replay_after_restart(tmp_path):
    pair = active_pair(tmp_path)
    registry = ActionRegistry({"permissions_read": ok_handler("Destination")})
    issued = issue(pair)
    first = executor(pair, registry).execute("2", issued.grant, issued.request.json)
    assert first["error"] is None
    result = pair["issuer"].verify_result(first["signed_result"], issued)
    assert result["groups"] == [
        {"group_id": "9", "group_name": "synthetic-readers"}
    ]
    replay = executor(pair, registry).execute("2", issued.grant, issued.request.json)
    replay_result = pair["issuer"].verify_result(replay["signed_result"], issued)
    assert replay_result["status"] == "error"
    assert replay_result["error_code"] == "replayed"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM test_invocations").fetchone()[0] == 1
        row = conn.execute(
            "SELECT request_id,retain_until-expires_at FROM FederationGrantJTIs"
        ).fetchone()
    assert row == (issued.claims["request_id"], 5)


def test_server_missing_runtime_handler_fails_closed_and_consumes(tmp_path):
    pair = active_pair(tmp_path)
    issued = issue(pair, "federated_enroll")
    response = executor(pair).execute("2", issued.grant, issued.request.json)
    result = pair["issuer"].verify_result(response["signed_result"], issued)
    assert result["status"] == "error"
    assert result["error_code"] == "action_unavailable"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0] == 1
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "EnrollmentRedemptions" not in tables


def test_server_request_substitution_and_cross_token_fail_without_jti(tmp_path):
    pair = active_pair(tmp_path)
    issued = issue(pair)
    changed = json.loads(issued.request.json)
    changed["payload"]["terms_sha256"] = "0" * 64
    substituted = json.dumps(changed, sort_keys=True, separators=(",", ":"))
    response = executor(pair).execute("2", issued.grant, substituted)
    assert response["signed_result"] is None
    assert response["error"]["code"] == "invalid_grant"
    claims = dict(issued.claims)
    claims["token_type"] = "federation_result"
    wrong = jwt.encode(
        claims,
        pair["issuer"].private_key,
        algorithm="EdDSA",
        headers={
            "typ": "remoterf-federation-result+jwt",
            "kid": pair["issuer"].signing_kid,
        },
    )
    response = executor(pair).execute("2", wrong, issued.request.json)
    assert response["error"]["code"] == "invalid_grant"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0] == 0


@pytest.mark.parametrize(
    "field",
    ["code_name", "request_id", "action", "destination", "contract_version", "terms_sha256"],
)
def test_server_rejects_complete_request_substitution_matrix_before_jti(tmp_path, field):
    pair = active_pair(tmp_path)
    issued = issue(pair, "federated_enroll")
    changed = json.loads(issued.request.json)
    if field == "code_name":
        changed["payload"]["code_name"] = "substituted"
    elif field == "request_id":
        changed["payload"]["request_id"] = str(uuid4())
    elif field == "action":
        changed["action"] = "permissions_read"
        changed["payload"].pop("code_name")
    elif field == "destination":
        changed["payload"]["destination_deployment_id"] = str(uuid4())
    elif field == "contract_version":
        changed["payload"]["contract_version"] = 2
    else:
        changed["payload"]["terms_sha256"] = "0" * 64
    request_json = json.dumps(changed, sort_keys=True, separators=(",", ":"))
    response = executor(pair).execute("2", issued.grant, request_json)
    assert response["signed_result"] is None
    assert response["error"]["code"] == "invalid_grant"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0] == 0


def test_home_rejects_cryptographically_valid_result_substitution_matrix(tmp_path):
    pair = active_pair(tmp_path)
    issued = issue(pair)
    response = executor(
        pair, ActionRegistry({"permissions_read": ok_handler("Destination")})
    ).execute("2", issued.grant, issued.request.json)
    claims = jwt.decode(response["signed_result"], options={"verify_signature": False})
    substitutions = {
        "sub": str(uuid4()),
        "request_id": str(uuid4()),
        "grant_jti": str(uuid4()),
        "action": "federated_enroll",
        "contract_id": str(uuid4()),
        "contract_version": 2,
        "terms_sha256": "0" * 64,
        "aud": str(uuid4()),
        "exp": pair["now"][0],
    }
    for field, value in substitutions.items():
        changed = json.loads(json.dumps(claims))
        changed[field] = value
        token = jwt.encode(
            changed,
            pair["dest_key"],
            algorithm="EdDSA",
            headers={"typ": FEDERATION_RESULT_TYP, "kid": pair["dest_material"]["kid"]},
        )
        with pytest.raises(FederationError):
            pair["issuer"].verify_result(token, issued)


def test_server_handler_internal_error_rolls_back_jti_and_application_write(tmp_path):
    pair = active_pair(tmp_path)

    def broken(conn, action):
        conn.execute("CREATE TABLE transient_write (value TEXT)")
        conn.execute("INSERT INTO transient_write VALUES ('partial')")
        raise RuntimeError("test-only failure")

    issued = issue(pair)
    response = executor(pair, ActionRegistry({"permissions_read": broken})).execute(
        "2", issued.grant, issued.request.json
    )
    assert response["signed_result"] is None
    assert response["error"]["code"] == "internal_error"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0] == 0
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name='transient_write'"
        ).fetchone() is None


def test_server_post_commit_signing_failure_does_not_undo_action_or_jti(tmp_path, monkeypatch):
    pair = active_pair(tmp_path)
    issued = issue(pair)
    target = executor(pair, ActionRegistry({"permissions_read": ok_handler("Destination")}))
    monkeypatch.setattr(
        target,
        "_sign_after_commit",
        lambda *args: (_ for _ in ()).throw(RuntimeError("sign failure")),
    )
    response = target.execute("2", issued.grant, issued.request.json)
    assert response["error"]["code"] == "internal_error"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM test_invocations").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0] == 1


def test_server_state_changing_retry_requires_application_idempotency(tmp_path):
    pair = active_pair(tmp_path)
    attempts = []

    def sender(body, token):
        attempts.append((body, token))
        raise TimeoutError()

    outbound = HomeFederationOutbound(
        pair["issuer"],
        broker_base_url="https://broker.example",
        broker_deployment_id=str(uuid4()),
        broker_private_key=pair["issuer"].private_key,
        broker_kid=pair["issuer"].signing_kid,
        sender=sender,
    )
    with pytest.raises(FederationError, match="route_unavailable"):
        outbound.execute(
            local_account_id=1,
            destination_deployment_id=DEST,
            contract_id=CONTRACT,
            contract_version=1,
            action="federated_enroll",
            code_name="future-only",
        )
    assert len(attempts) == 1


@pytest.mark.parametrize("change", ["suspend", "revoke_key", "expire_key", "expire_contract", "supersede"])
def test_server_executor_rechecks_authority_after_action_lock_wait(
    tmp_path, monkeypatch, change
):
    pair = active_pair(
        tmp_path,
        key_valid_until=130 if change == "expire_key" else 10_000,
        contract_valid_until=130 if change == "expire_contract" else 1000,
    )
    calls = []

    def handler(conn, action):
        calls.append(action.claims["jti"])
        return ok_handler("Destination")(conn, action)

    target = executor(pair, ActionRegistry({"permissions_read": handler}))
    issued = issue(pair)
    entered, release = threading.Event(), threading.Event()
    real_connect = sqlite3.connect

    class GatedConnection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if threading.current_thread().name == "gate-e-action" and sql == "BEGIN IMMEDIATE":
                entered.set()
                assert release.wait(timeout=5)
            return super().execute(sql, *args, **kwargs)

    def gated_connect(*args, **kwargs):
        kwargs["factory"] = GatedConnection
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(server_destination.sqlite3, "connect", gated_connect)
    outcome = []
    thread = threading.Thread(
        target=lambda: outcome.append(
            target.execute("2", issued.grant, issued.request.json)
        ),
        name="gate-e-action",
    )
    thread.start()
    assert entered.wait(timeout=5)
    with real_connect(pair["dest_db"]) as conn:
        if change == "suspend":
            conn.execute(
                "UPDATE FederationContracts SET state='suspended' "
                "WHERE contract_id=? AND version=1",
                (CONTRACT,),
            )
        elif change == "revoke_key":
            conn.execute(
                "UPDATE TrustedDeploymentKeys SET state='revoked' "
                "WHERE deployment_id=?",
                (HOME,),
            )
        elif change == "supersede":
            conn.execute(
                "UPDATE FederationContracts SET superseded_by_version=2 "
                "WHERE contract_id=? AND version=1",
                (CONTRACT,),
            )
    if change == "expire_key":
        pair["now"][0] = 130
    elif change == "expire_contract":
        pair["now"][0] = 130
    release.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert len(outcome) == 1
    assert calls == []
    assert outcome[0]["signed_result"] is None or pair["issuer"].verify_result(
        outcome[0]["signed_result"], issued
    )["status"] == "error"
