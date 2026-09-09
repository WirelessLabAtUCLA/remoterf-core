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
    ActionRetryPolicy,
    FEDERATION_RESULT_TYP,
    FederationError,
    OwnerSignedFailure,
    TransportFailure,
    build_contract_terms,
    canonical_json,
)
from remoteRF_server.server.federation.contracts import ContractStore
from remoteRF_server.server.federation.destination import (
    ActionRegistry,
    FederationBusinessError,
    ServerFederationExecutor,
)
from remoteRF_server.server.federation.home import (
    MAX_FORWARD_RESPONSE_BYTES,
    HomeFederationOutbound,
    ServerHomeGrantIssuer,
)
import remoteRF_server.server.federation.home as server_home
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
    from remoteRF_server.common.utils import hash_token

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
    password_salt, password_hash = hash_token("native-password")
    with sqlite3.connect(reservations) as conn:
        migrate_reservations_schema(conn)
        conn.execute(
            "INSERT INTO Accounts "
            "(username,email,pass_salt,pass_hash,auth_type) VALUES (?,?,?,?,?)",
            (
                "native",
                "native@example.test",
                password_salt,
                password_hash,
                "local_password",
            ),
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
        "reservations": reservations,
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
    # Gate F installs the receipt table as part of destination readiness even
    # when no runtime action handler is registered.
    assert "EnrollmentRedemptions" in tables


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


def test_federation_grant_is_not_any_legacy_or_dynamic_credential(
    tmp_path, monkeypatch
):
    import threading

    from remoteRF_server.common.utils import hash_token, map_arg, validate_token
    from remoteRF_server.server import device_manager, dynamic_v2
    from remoteRF_server.server.reservation import ReservationHandler

    pair = active_pair(tmp_path)
    grant = issue(pair).grant

    # GenericRPC native password/login path.
    reservations = ReservationHandler.__new__(ReservationHandler)
    reservations.filepath = pair["reservations"]
    reservations.lock = threading.RLock()
    reservations.db = reservations.cursor = None
    login = reservations.handle_call(
        function_name="login",
        args={"un": map_arg("native"), "pw": map_arg(grant)},
    )
    assert "UE" in login and "UC" not in login

    # Reservation/device opaque token hash and master-token grammars.
    salt, digest = hash_token("real-reservation-token")
    assert not validate_token(salt, digest, grant)
    assert device_manager.parse_mastertoken(
        grant, configured_token="real-master-token"
    ) is None
    monkeypatch.setattr(device_manager, "_sync_host_devices", lambda *a, **k: None)
    monkeypatch.setattr(device_manager, "_get_master_token", lambda: "real-master-token")
    monkeypatch.setattr(device_manager, "_devices", {})
    assert device_manager.resolve_gid_for_token(grant) is None

    # Dynamic device token and live session-ID paths.
    monkeypatch.setattr(
        dynamic_v2, "resolve_gid_for_token", device_manager.resolve_gid_for_token
    )
    manager = dynamic_v2.SessionManager()
    with pytest.raises(dynamic_v2.RemoteRFReservationError):
        manager.schema_for_token(grant)
    with pytest.raises(dynamic_v2.RemoteRFSessionExpiredError):
        manager.get(grant)


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
    # Gate F makes federated enrollment receipt-idempotent, so ambiguous
    # transport failures receive the single policy retry.
    assert len(attempts) == 2


def test_server_retry_policy_is_typed_and_integration_controlled(tmp_path):
    pair = active_pair(tmp_path)
    base = {
        "issuer": pair["issuer"],
        "broker_base_url": "https://broker.example",
        "broker_deployment_id": str(uuid4()),
        "broker_private_key": pair["issuer"].private_key,
        "broker_kid": pair["issuer"].signing_kid,
    }
    for invalid in ("false", False, 1, None, object()):
        with pytest.raises(FederationError, match="invalid_retry_policy"):
            HomeFederationOutbound(
                **base,
                retry_policies={"federated_enroll": invalid},
            )

    attempts = []

    def unavailable(body, token):
        attempts.append((body, token))
        raise TimeoutError()

    outbound = HomeFederationOutbound(
        **base,
        sender=unavailable,
        retry_policies={
            "federated_enroll": ActionRetryPolicy.RECEIPT_IDEMPOTENT
        },
    )
    with pytest.raises(TransportFailure, match="route_unavailable"):
        outbound.execute(
            local_account_id=1,
            destination_deployment_id=DEST,
            contract_id=CONTRACT,
            contract_version=1,
            action="federated_enroll",
            code_name="future-only",
        )
    assert len(attempts) == 2
    for invalid in ("false", 1, None, object()):
        with pytest.raises(FederationError, match="invalid_retry_policy"):
            outbound.execute(
                local_account_id=1,
                destination_deployment_id=DEST,
                contract_id=CONTRACT,
                contract_version=1,
                action="federated_enroll",
                code_name="future-only",
                retry_ambiguous=invalid,
            )


def test_server_outbound_preserves_transport_vs_owner_signed_provenance(tmp_path):
    pair = active_pair(tmp_path)
    arguments = {
        "local_account_id": 1,
        "destination_deployment_id": DEST,
        "contract_id": CONTRACT,
        "contract_version": 1,
        "action": "permissions_read",
        "retry_ambiguous": False,
    }
    base = {
        "issuer": pair["issuer"],
        "broker_base_url": "https://broker.example",
        "broker_deployment_id": str(uuid4()),
        "broker_private_key": pair["issuer"].private_key,
        "broker_kid": pair["issuer"].signing_kid,
    }
    transport = HomeFederationOutbound(
        **base,
        sender=lambda body, token: {
            "protocol_version": "2",
            "signed_result": None,
            "error": {
                "code": "route_unavailable",
                "message": "not owner-authenticated",
                "retryable": False,
            },
        },
    )
    with pytest.raises(TransportFailure) as unsigned:
        transport.execute(**arguments)
    assert unsigned.value.code == "route_unavailable"

    destination = executor(pair)

    def signed_rejection(body, token):
        envelope = json.loads(body)
        return destination.execute("2", envelope["grant"], envelope["request_json"])

    owner = HomeFederationOutbound(**base, sender=signed_rejection)
    with pytest.raises(OwnerSignedFailure) as signed:
        owner.execute(**arguments)
    assert signed.value.result["error_code"] == "action_unavailable"


def test_server_home_streams_and_bounds_decoded_responses(monkeypatch, tmp_path):
    pair = active_pair(tmp_path)
    outbound = HomeFederationOutbound(
        pair["issuer"],
        broker_base_url="https://broker.example",
        broker_deployment_id=str(uuid4()),
        broker_private_key=pair["issuer"].private_key,
        broker_kid=pair["issuer"].signing_kid,
    )
    valid = canonical_json(
        {
            "protocol_version": "2",
            "signed_result": None,
            "error": {
                "code": "route_unavailable",
                "message": "bounded",
                "retryable": False,
            },
        }
    ).encode()

    class Response:
        def __init__(self, chunks, headers=None):
            self.chunks = chunks
            self.headers = headers or {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def raise_for_status(self):
            return None

        def iter_content(self, chunk_size):
            yield from self.chunks

    responses = iter(
        [
            Response([b"unused"], {"Content-Length": str(MAX_FORWARD_RESPONSE_BYTES + 1)}),
            Response([valid, b" " * (MAX_FORWARD_RESPONSE_BYTES - len(valid))]),
            Response([b"x" * MAX_FORWARD_RESPONSE_BYTES, b"x"]),
            Response(
                [b"x" * MAX_FORWARD_RESPONSE_BYTES, b"x"],
                {"Content-Encoding": "gzip"},
            ),
        ]
    )
    monkeypatch.setattr(server_home.requests, "post", lambda *a, **k: next(responses))
    for expected in ("response_too_large", None, "response_too_large", "response_too_large"):
        if expected is None:
            assert outbound._send(b"{}", "token", server_home.time.monotonic() + 5)[
                "protocol_version"
            ] == "2"
        else:
            with pytest.raises(TransportFailure, match=expected):
                outbound._send(b"{}", "token", server_home.time.monotonic() + 5)

    monkeypatch.setattr(
        server_home.requests,
        "post",
        lambda *a, **k: Response([valid[:1], valid[1:]]),
    )
    ticks = iter((0.0, 2.0))
    monkeypatch.setattr(server_home.time, "monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError):
        outbound._send(b"{}", "token", 1.0)


def test_handler_transaction_cannot_control_lifecycle(tmp_path):
    pair = active_pair(tmp_path)

    def handler(transaction, action):
        assert not any(
            hasattr(transaction, name)
            for name in ("commit", "rollback", "close", "executescript", "__enter__")
        )
        transaction.execute("CREATE TABLE handler_lifecycle (value TEXT)")
        transaction.execute("INSERT INTO handler_lifecycle VALUES ('partial')")
        transaction.execute("/* attempt */ COMMIT")

    issued = issue(pair)
    response = executor(pair, ActionRegistry({"permissions_read": handler})).execute(
        "2", issued.grant, issued.request.json
    )
    assert response["error"]["code"] == "internal_error"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0] == 0
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name='handler_lifecycle'"
        ).fetchone() is None


def test_business_exception_rolls_back_handler_writes_but_consumes_jti(tmp_path):
    pair = active_pair(tmp_path)

    def handler(transaction, action):
        transaction.execute("CREATE TABLE rejected_write (value TEXT)")
        transaction.execute("INSERT INTO rejected_write VALUES ('partial')")
        raise FederationBusinessError("test_rejected")

    issued = issue(pair)
    response = executor(pair, ActionRegistry({"permissions_read": handler})).execute(
        "2", issued.grant, issued.request.json
    )
    result = pair["issuer"].verify_result(response["signed_result"], issued)
    assert result["error_code"] == "test_rejected"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0] == 1
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name='rejected_write'"
        ).fetchone() is None


def test_returned_business_error_is_not_a_mutation_contract(tmp_path):
    pair = active_pair(tmp_path)

    def handler(transaction, action):
        transaction.execute("CREATE TABLE returned_error_write (value TEXT)")
        transaction.execute("INSERT INTO returned_error_write VALUES ('partial')")
        result = ok_handler("Destination")(transaction, action)
        result.update(status="error", error_code="test_rejected", groups=[])
        return result

    issued = issue(pair)
    response = executor(pair, ActionRegistry({"permissions_read": handler})).execute(
        "2", issued.grant, issued.request.json
    )
    assert response["error"]["code"] == "internal_error"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0] == 0
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name='returned_error_write'"
        ).fetchone() is None


def test_oversized_signed_result_rolls_back_handler_before_commit(tmp_path):
    pair = active_pair(tmp_path)

    def handler(transaction, action):
        transaction.execute("CREATE TABLE oversized_write (value TEXT)")
        transaction.execute("INSERT INTO oversized_write VALUES ('partial')")
        result = ok_handler("Destination")(transaction, action)
        result["groups"] = [
            {"group_id": str(index), "group_name": "g" * 20}
            for index in range(220)
        ]
        return result

    issued = issue(pair)
    response = executor(pair, ActionRegistry({"permissions_read": handler})).execute(
        "2", issued.grant, issued.request.json
    )
    result = pair["issuer"].verify_result(response["signed_result"], issued)
    assert result["error_code"] == "result_too_large"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0] == 1
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name='oversized_write'"
        ).fetchone() is None


def test_malformed_and_huge_inputs_are_bounded_without_state(tmp_path):
    pair = active_pair(tmp_path)
    issued = issue(pair)
    malformed = [
        ("2", issued.grant, '{"x":1,"x":2}'),
        ("2", "not-a-jwt", issued.request.json),
    ]
    claims = dict(issued.claims)
    claims["contract_version"] = 1 << 100
    huge = jwt.encode(
        claims,
        pair["issuer"].private_key,
        algorithm="EdDSA",
        headers={"typ": "remoterf-federation-grant+jwt", "kid": pair["issuer"].signing_kid},
    )
    malformed.append(("2", huge, issued.request.json))
    target = executor(pair)
    for args in malformed:
        response = target.execute(*args)
        assert response["signed_result"] is None
        assert response["error"]["code"] in {"invalid_grant", "internal_error"}
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0] == 0


def test_server_native_issuance_rejects_external_binding_incoherence(tmp_path):
    pair = active_pair(tmp_path)
    with sqlite3.connect(pair["reservations"]) as conn:
        conn.execute("DROP TRIGGER FederatedAccountBindings_proxy_insert")
        conn.execute(
            "INSERT INTO FederatedAccountBindings "
            "(issuer_deployment_id,remote_subject_id,local_account_id,created_at) "
            "VALUES (?,?,1,100)",
            (str(uuid4()), str(uuid4())),
        )
    with pytest.raises(FederationError, match="native_account_required"):
        issue(pair)


@pytest.mark.parametrize(
    "change",
    [
        "suspend",
        "revoke_key",
        "expire_key",
        "expire_contract",
        "supersede",
        "backward_clock",
        "disable_principal",
    ],
)
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
        elif change == "disable_principal":
            conn.execute(
                "INSERT INTO FederatedPrincipals "
                "(id,issuer_deployment_id,remote_subject_id,local_account_id,status,"
                "created_at,disabled_at,display_metadata_json) "
                "VALUES (?,?,?,?, 'disabled',100,100,'{}')",
                (str(uuid4()), HOME, pair["subject"], 999),
            )
    if change == "expire_key":
        pair["now"][0] = 130
    elif change == "expire_contract":
        pair["now"][0] = 130
    elif change == "backward_clock":
        pair["now"][0] = 90
    release.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert len(outcome) == 1
    assert calls == []
    assert outcome[0]["signed_result"] is None or pair["issuer"].verify_result(
        outcome[0]["signed_result"], issued
    )["status"] == "error"


def test_signing_authorization_serializes_with_local_key_revocation(tmp_path):
    pair = active_pair(tmp_path)
    registry = ActionRegistry({"permissions_read": ok_handler("Destination")})
    reached, release = threading.Event(), threading.Event()

    class PausedBeforeSigning(ServerFederationExecutor):
        def _sign_after_commit(self, claims, result):
            reached.set()
            assert release.wait(timeout=5)
            return super()._sign_after_commit(claims, result)

    target = PausedBeforeSigning(
        pair["dest_db"],
        local_deployment_id=DEST,
        private_key=pair["dest_key"],
        signing_kid=pair["dest_material"]["kid"],
        display_name="Destination",
        clock=lambda: pair["now"][0],
        registry=registry,
    )
    issued = issue(pair)
    outcome = []
    action_thread = threading.Thread(
        target=lambda: outcome.append(target.execute("2", issued.grant, issued.request.json))
    )
    action_thread.start()
    assert reached.wait(timeout=5)
    TrustedKeyStore(pair["dest_db"], clock=lambda: pair["now"][0]).revoke(
        DEST, pair["dest_material"]["kid"], approved_by="test-admin"
    )
    release.set()
    action_thread.join(timeout=5)
    assert outcome[0]["error"]["code"] == "internal_error"
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM test_invocations").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0] == 1

    # Reverse ordering: signing holds the write lock until the real Ed25519
    # token exists; revocation then commits after that ordered history.
    reverse_root = tmp_path / "reverse"
    reverse_root.mkdir()
    pair = active_pair(reverse_root)
    target = executor(pair, ActionRegistry({"permissions_read": ok_handler("Destination")}))
    locked, allow_sign = threading.Event(), threading.Event()
    target._signing_lock_hook = lambda: (locked.set(), allow_sign.wait(timeout=5))
    issued = issue(pair)
    outcome = []
    action_thread = threading.Thread(
        target=lambda: outcome.append(target.execute("2", issued.grant, issued.request.json))
    )
    action_thread.start()
    assert locked.wait(timeout=5)
    revoked = threading.Event()

    def revoke():
        TrustedKeyStore(pair["dest_db"], clock=lambda: pair["now"][0]).revoke(
            DEST, pair["dest_material"]["kid"], approved_by="test-admin"
        )
        revoked.set()

    revoke_thread = threading.Thread(target=revoke)
    revoke_thread.start()
    assert not revoked.wait(timeout=0.1)
    allow_sign.set()
    action_thread.join(timeout=5)
    revoke_thread.join(timeout=5)
    assert outcome[0]["signed_result"] is not None
    assert pair["issuer"].verify_result(outcome[0]["signed_result"], issued)["status"] == "ok"
    assert revoked.is_set()


def test_replay_pruning_uses_persisted_clock_floor_across_restart(tmp_path):
    pair = active_pair(tmp_path)
    calls = []

    def handler(transaction, action):
        calls.append(action.claims["jti"])
        result = ok_handler("Destination")(transaction, action)
        result["retrieved_at"] = pair["now"][0]
        return result

    target = executor(pair, ActionRegistry({"permissions_read": handler}))
    original = issue(pair)
    assert target.execute("2", original.grant, original.request.json)["signed_result"]
    pair["now"][0] = original.claims["exp"] + 5
    at_boundary = issue(pair)
    assert target.execute("2", at_boundary.grant, at_boundary.request.json)["signed_result"]
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM FederationGrantJTIs WHERE jti=?", (original.claims["jti"],)
        ).fetchone()[0] == 1
    pair["now"][0] += 1
    after_boundary = issue(pair)
    assert target.execute("2", after_boundary.grant, after_boundary.request.json)["signed_result"]
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM FederationGrantJTIs WHERE jti=?", (original.claims["jti"],)
        ).fetchone()[0] == 0
    pair["now"][0] = 100
    replay = executor(pair, ActionRegistry({"permissions_read": handler})).execute(
        "2", original.grant, original.request.json
    )
    result = pair["issuer"].verify_result(replay["signed_result"], original)
    assert result["error_code"] == "clock_rollback"
    assert len(calls) == 3


@pytest.mark.parametrize("corruption", ["terms", "key"])
def test_loaded_terms_and_key_material_are_rehashed_at_use(tmp_path, corruption):
    pair = active_pair(tmp_path)
    issued = issue(pair)
    with sqlite3.connect(pair["dest_db"]) as conn:
        if corruption == "terms":
            conn.execute("DROP TRIGGER FederationContracts_terms_immutable")
            conn.execute(
                "UPDATE FederationContracts SET allowed_capabilities_json='[\"PERMISSIONS_READ\"]' "
                "WHERE contract_id=?",
                (CONTRACT,),
            )
        else:
            conn.execute("DROP TRIGGER TrustedDeploymentKeys_material_immutable")
            conn.execute(
                "UPDATE TrustedDeploymentKeys SET public_key_b64=? "
                "WHERE deployment_id=? AND kid=?",
                (base64.b64encode(b"x" * 32).decode(), HOME, pair["issuer"].signing_kid),
            )
    response = executor(pair).execute("2", issued.grant, issued.request.json)
    assert response["signed_result"] is None
    assert response["error"]["code"] in {"invalid_grant", "internal_error"}
    with sqlite3.connect(pair["dest_db"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM FederationGrantJTIs").fetchone()[0] == 0


def test_destination_key_selection_and_contract_rotation_are_exact(tmp_path):
    pair = active_pair(tmp_path)
    alternate_key = Ed25519PrivateKey.generate()
    alternate = material(HOME, alternate_key)
    pin(pair["home_db"], alternate, pair["now"])
    pin(pair["dest_db"], alternate, pair["now"])
    issued_v1 = issue(pair)

    def resign(issued, key, kid):
        claims = dict(issued.claims)
        claims["jti"] = str(uuid4())
        return jwt.encode(
            claims,
            key,
            algorithm="EdDSA",
            headers={"typ": "remoterf-federation-grant+jwt", "kid": kid},
        )

    target = executor(pair)
    for token in (
        resign(issued_v1, alternate_key, alternate["kid"]),
        resign(issued_v1, pair["dest_key"], pair["dest_material"]["kid"]),
    ):
        response = target.execute("2", token, issued_v1.request.json)
        assert response["signed_result"] is None
        assert response["error"]["code"] == "invalid_grant"

    home_store = ContractStore(
        pair["home_db"],
        local_deployment_id=HOME,
        private_key=alternate_key,
        signing_kid=alternate["kid"],
        clock=lambda: pair["now"][0],
    )
    dest_store = ContractStore(
        pair["dest_db"],
        local_deployment_id=DEST,
        private_key=pair["dest_key"],
        signing_kid=pair["dest_material"]["kid"],
        clock=lambda: pair["now"][0],
    )
    terms_v2 = build_contract_terms(
        contract_id=CONTRACT,
        version=2,
        participant_1=HOME,
        participant_1_kid=alternate["kid"],
        participant_1_sha256=alternate["public_key_sha256"],
        participant_2=DEST,
        participant_2_kid=pair["dest_material"]["kid"],
        participant_2_sha256=pair["dest_material"]["public_key_sha256"],
        valid_from=50,
        valid_until=1000,
        allowed_capabilities=["PERMISSIONS_READ"],
        supersedes_version=1,
    )
    home_store.propose(terms_v2, actor_admin_ref="home-rotation")
    dest_store.import_bundle(home_store.export_bundle(CONTRACT, 2))
    dest_store.accept(CONTRACT, 2, actor_admin_ref="dest-rotation")
    home_store.import_bundle(dest_store.export_bundle(CONTRACT, 2))
    home_store.activate(CONTRACT, 2, actor_admin_ref="home-rotation")
    dest_store.import_bundle(home_store.export_bundle(CONTRACT, 2))
    dest_store.activate(CONTRACT, 2, actor_admin_ref="dest-rotation")
    home_store.import_bundle(dest_store.export_bundle(CONTRACT, 2))

    stale = target.execute("2", issued_v1.grant, issued_v1.request.json)
    assert pair["issuer"].verify_result(stale["signed_result"], issued_v1)[
        "error_code"
    ] == "contract_inactive"
    rotated_issuer = ServerHomeGrantIssuer(
        reservations_path=pair["reservations"],
        usergroups_path=pair["home_db"],
        local_deployment_id=HOME,
        private_key=alternate_key,
        signing_kid=alternate["kid"],
        clock=lambda: pair["now"][0],
    )
    issued_v2 = rotated_issuer.issue(
        local_account_id=1,
        destination_deployment_id=DEST,
        contract_id=CONTRACT,
        contract_version=2,
        action="permissions_read",
    )

    def versioned_handler(transaction, action):
        return {
            "status": "ok",
            "error_code": None,
            "deployment_id": DEST,
            "display_name": "Destination",
            "contract_id": CONTRACT,
            "contract_version": action.claims["contract_version"],
            "state": action.state,
            "groups": [],
            "retrieved_at": pair["now"][0],
            "redemption_id": None,
            "membership_present": None,
        }

    rotated = executor(
        pair, ActionRegistry({"permissions_read": versioned_handler})
    ).execute("2", issued_v2.grant, issued_v2.request.json)
    assert rotated_issuer.verify_result(rotated["signed_result"], issued_v2)[
        "status"
    ] == "ok"


def test_replay_classification_for_changed_request_and_payload(tmp_path):
    pair = active_pair(tmp_path)
    target = executor(
        pair, ActionRegistry({"permissions_read": ok_handler("Destination")})
    )
    first = issue(pair)
    assert target.execute("2", first.grant, first.request.json)["signed_result"]
    changed = pair["issuer"].issue(
        local_account_id=1,
        destination_deployment_id=DEST,
        contract_id=CONTRACT,
        contract_version=1,
        action="permissions_read",
    )
    changed_claims = dict(changed.claims)
    changed_claims["jti"] = first.claims["jti"]
    changed_token = jwt.encode(
        changed_claims,
        pair["issuer"].private_key,
        algorithm="EdDSA",
        headers={
            "typ": "remoterf-federation-grant+jwt",
            "kid": pair["issuer"].signing_kid,
        },
    )
    changed = type(changed)(changed_token, changed_claims, changed.request)
    replay = target.execute("2", changed.grant, changed.request.json)
    assert pair["issuer"].verify_result(replay["signed_result"], changed)[
        "error_code"
    ] == "replayed"

    logical_request_id = str(uuid4())
    outcomes = []
    for code_name in ("first-code", "changed-code"):
        enrollment = pair["issuer"].issue(
            local_account_id=1,
            destination_deployment_id=DEST,
            contract_id=CONTRACT,
            contract_version=1,
            action="federated_enroll",
            request_id=logical_request_id,
            code_name=code_name,
        )
        response = target.execute("2", enrollment.grant, enrollment.request.json)
        outcomes.append(
            pair["issuer"].verify_result(response["signed_result"], enrollment)[
                "error_code"
            ]
        )
    assert outcomes == ["action_unavailable", "action_unavailable"]
