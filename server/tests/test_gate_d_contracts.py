import base64
import hashlib
import json
import sqlite3
import threading
import time
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from remoterf_federation_core import (
    BROKER_REQUEST_TYP,
    CONTRACT_EVENT_TYP,
    ContractError,
    build_contract_event_claims,
    build_contract_terms,
    canonical_contract_bytes,
    contract_terms_sha256,
)

from remoteRF_server.server.federation import contracts as server_contracts
from remoteRF_server.server.federation.contracts import ContractStore
from remoteRF_server.server.federation.migrations import (
    GATE_D_MIGRATION_NAME,
    check_gate_d_ready,
    migrate_gate_d_usergroups_schema,
)
from remoteRF_server.server.federation.trust import TrustedKeyStore

A = "11111111-1111-4111-8111-111111111111"
B = "22222222-2222-4222-8222-222222222222"
UT = "33333333-3333-4333-8333-333333333333"
CONTRACT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def material(deployment_id, kid, key, *, valid_from=0, valid_until=1000):
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "deployment_id": deployment_id,
        "kid": kid,
        "public_key_b64": base64.b64encode(raw).decode("ascii"),
        "public_key_sha256": hashlib.sha256(raw).hexdigest(),
        "valid_from": valid_from,
        "valid_until": valid_until,
    }


def import_pin(store, value, *, source="manual_offline"):
    return store.import_key(
        value,
        approved_by="admin:test",
        approval_source=source,
        confirm_deployment_id=value["deployment_id"],
        confirm_kid=value["kid"],
        confirm_fingerprint=value["public_key_sha256"],
    )


def pair(
    tmp_path,
    left=A,
    right=B,
    *,
    contract_id=CONTRACT,
    now=None,
    key_valid_until=1000,
):
    now = now or [100]
    left_key = Ed25519PrivateKey.generate()
    right_key = Ed25519PrivateKey.generate()
    left_material = material(left, "left-key", left_key, valid_until=key_valid_until)
    right_material = material(
        right, "right-key", right_key, valid_until=key_valid_until
    )
    left_db, right_db = tmp_path / "left.db", tmp_path / "right.db"
    for path in (left_db, right_db):
        trust = TrustedKeyStore(path, clock=lambda: now[0])
        import_pin(trust, left_material)
        import_pin(trust, right_material)
    left_store = ContractStore(
        left_db,
        local_deployment_id=left,
        private_key=left_key,
        signing_kid="left-key",
        clock=lambda: now[0],
    )
    right_store = ContractStore(
        right_db,
        local_deployment_id=right,
        private_key=right_key,
        signing_kid="right-key",
        clock=lambda: now[0],
    )
    terms = build_contract_terms(
        contract_id=contract_id,
        version=1,
        participant_1=left,
        participant_1_kid="left-key",
        participant_1_sha256=left_material["public_key_sha256"],
        participant_2=right,
        participant_2_kid="right-key",
        participant_2_sha256=right_material["public_key_sha256"],
        valid_from=50,
        valid_until=900,
        allowed_capabilities=["FEDERATED_ENROLL", "PERMISSIONS_READ"],
    )
    return {
        "now": now,
        "left": left_store,
        "right": right_store,
        "left_key": left_key,
        "right_key": right_key,
        "left_material": left_material,
        "right_material": right_material,
        "terms": terms,
        "left_db": left_db,
        "right_db": right_db,
    }


def fully_activate(p):
    left, right, terms = p["left"], p["right"], p["terms"]
    cid = terms.contract_id
    left.propose(terms, actor_admin_ref="admin:left")
    right.import_bundle(left.export_bundle(cid, 1))
    assert not right.is_active(cid, 1, "FEDERATED_ENROLL")
    right.accept(cid, 1, actor_admin_ref="admin:right")
    left.import_bundle(right.export_bundle(cid, 1))
    left.activate(cid, 1, actor_admin_ref="admin:left")
    right.import_bundle(left.export_bundle(cid, 1))
    assert not right.is_active(cid, 1, "FEDERATED_ENROLL")
    right.activate(cid, 1, actor_admin_ref="admin:right")
    left.import_bundle(right.export_bundle(cid, 1))
    assert left.is_active(cid, 1, "FEDERATED_ENROLL")
    assert right.is_active(cid, 1, "PERMISSIONS_READ")


def prepare_final_activation(p):
    left, right, terms = p["left"], p["right"], p["terms"]
    cid = terms.contract_id
    left.propose(terms, actor_admin_ref="admin:left")
    right.import_bundle(left.export_bundle(cid, 1))
    right.accept(cid, 1, actor_admin_ref="admin:right")
    left.import_bundle(right.export_bundle(cid, 1))
    left.activate(cid, 1, actor_admin_ref="admin:left")
    right.import_bundle(left.export_bundle(cid, 1))
    right.activate(cid, 1, actor_admin_ref="admin:right")
    return right.export_bundle(cid, 1)


def install_begin_gates(monkeypatch, gates):
    """Pause named threads immediately before their BEGIN IMMEDIATE call."""

    real_connect = sqlite3.connect

    class GatedConnection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            gate = gates.get(threading.current_thread().name)
            if sql == "BEGIN IMMEDIATE" and gate is not None:
                entered, release = gate
                entered.set()
                assert release.wait(timeout=5), "timed out waiting to release DB gate"
            return super().execute(sql, *args, **kwargs)

    def gated_connect(*args, **kwargs):
        kwargs["factory"] = GatedConnection
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(server_contracts.sqlite3, "connect", gated_connect)


def local_projection_snapshot(path):
    with sqlite3.connect(path) as conn:
        state = conn.execute(
            "SELECT state,superseded_by_version FROM FederationContracts "
            "WHERE contract_id=? AND version=1",
            (CONTRACT,),
        ).fetchone()
        events = conn.execute(
            "SELECT event_id,actor_deployment_id,actor_sequence,event_type "
            "FROM FederationContractEvents ORDER BY rowid"
        ).fetchall()
        audits = conn.execute(
            "SELECT event_type,result_code FROM FederationAuditEvents ORDER BY rowid"
        ).fetchall()
    return state, events, audits


def assert_local_sequence_integrity(path):
    with sqlite3.connect(path) as conn:
        rows = conn.execute(
            "SELECT actor_deployment_id,actor_sequence,event_id "
            "FROM FederationContractEvents WHERE contract_id=? "
            "ORDER BY actor_deployment_id,actor_sequence",
            (CONTRACT,),
        ).fetchall()
    by_actor = {}
    for actor, sequence, event_id in rows:
        by_actor.setdefault(actor, []).append((sequence, event_id))
    for values in by_actor.values():
        assert [item[0] for item in values] == list(range(1, len(values) + 1))
        assert len({item[1] for item in values}) == len(values)


def test_trust_import_confirmation_conflicts_revocation_and_sources(tmp_path):
    key = Ed25519PrivateKey.generate()
    value = material(A, "key-1", key)
    store = TrustedKeyStore(tmp_path / "trust.db", clock=lambda: 100)
    with pytest.raises(ContractError, match="trust_confirmation_mismatch"):
        store.import_key(
            value,
            approved_by="admin",
            approval_source="manual_offline",
            confirm_deployment_id=A,
            confirm_kid="wrong",
            confirm_fingerprint=value["public_key_sha256"],
        )
    with pytest.raises(ContractError, match="invalid_approval_source"):
        store.import_key(
            value,
            approved_by="admin",
            approval_source="user_grant",
            confirm_deployment_id=A,
            confirm_kid="key-1",
            confirm_fingerprint=value["public_key_sha256"],
        )
    assert import_pin(store, value)["state"] == "active"
    with pytest.raises(ContractError, match="duplicate_trusted_key"):
        import_pin(store, value)
    replacement = material(A, "key-1", Ed25519PrivateKey.generate())
    with pytest.raises(ContractError, match="trusted_key_conflict"):
        import_pin(store, replacement, source="broker_candidate")
    assert store.get(A, "key-1")["public_key_sha256"] == value["public_key_sha256"]
    assert store.revoke(A, "key-1", approved_by="admin")["state"] == "revoked"
    with pytest.raises(ContractError, match="key_revoked"):
        store.require_current(A, "key-1", now=100)
    with pytest.raises(ContractError, match="trusted_key_conflict"):
        import_pin(store, value)


def test_trust_future_expired_unknown_and_malformed_material(tmp_path):
    key = Ed25519PrivateKey.generate()
    store = TrustedKeyStore(tmp_path / "trust.db", clock=lambda: 100)
    future = material(A, "future", key, valid_from=101, valid_until=200)
    import_pin(store, future)
    with pytest.raises(ContractError, match="key_not_current"):
        store.require_current(A, "future", now=100)
    expired = material(B, "expired", Ed25519PrivateKey.generate(), valid_until=100)
    import_pin(store, expired)
    with pytest.raises(ContractError, match="key_not_current"):
        store.require_current(B, "expired", now=100)
    with pytest.raises(ContractError, match="unknown_kid"):
        store.require_current(UT, "missing", now=100)
    for change in (
        {"public_key_b64": "%%%"},
        {"public_key_b64": base64.b64encode(b"short").decode("ascii")},
        {"public_key_sha256": "00" * 32},
        {"jku": "https://broker.invalid/key"},
    ):
        with pytest.raises(ContractError):
            import_pin(store, {**material(UT, "bad", key), **change})


def test_bilateral_lifecycle_offline_exchange_suspend_and_idempotency(tmp_path):
    p = pair(tmp_path)
    fully_activate(p)
    left, right = p["left"], p["right"]
    bundle = left.export_bundle(CONTRACT, 1)
    assert right.import_bundle(bundle)["events_applied"] == 0
    left.suspend(CONTRACT, 1, actor_admin_ref="admin:left")
    assert not left.is_active(CONTRACT, 1, "FEDERATED_ENROLL")
    assert right.is_active(CONTRACT, 1, "FEDERATED_ENROLL")
    right.import_bundle(left.export_bundle(CONTRACT, 1))
    assert not right.is_active(CONTRACT, 1, "FEDERATED_ENROLL")
    with pytest.raises(ContractError, match="illegal_contract_transition"):
        right.activate(CONTRACT, 1, actor_admin_ref="admin:right")
    left.revoke(CONTRACT, 1, actor_admin_ref="admin:left")
    right.import_bundle(left.export_bundle(CONTRACT, 1))
    assert right.show(CONTRACT, 1)["state"] == "revoked"
    version2 = build_contract_terms(
        **{
            "contract_id": CONTRACT,
            "version": 2,
            "participant_1": A,
            "participant_1_kid": "left-key",
            "participant_1_sha256": p["left_material"]["public_key_sha256"],
            "participant_2": B,
            "participant_2_kid": "right-key",
            "participant_2_sha256": p["right_material"]["public_key_sha256"],
            "valid_from": 50,
            "valid_until": 900,
            "allowed_capabilities": ["PERMISSIONS_READ"],
            "supersedes_version": 1,
        }
    )
    with pytest.raises(ContractError, match="contract_revoked"):
        left.propose(version2, actor_admin_ref="admin:left")


def test_activation_needs_both_and_expiry_and_revoked_key_deny(tmp_path):
    p = pair(tmp_path)
    left, right, terms = p["left"], p["right"], p["terms"]
    left.propose(terms, actor_admin_ref="admin:left")
    assert left.show(CONTRACT, 1)["state"] == "proposed"
    right.import_bundle(left.export_bundle(CONTRACT, 1))
    right.accept(CONTRACT, 1, actor_admin_ref="admin:right")
    assert right.show(CONTRACT, 1)["state"] == "accepted"
    left.import_bundle(right.export_bundle(CONTRACT, 1))
    left.activate(CONTRACT, 1, actor_admin_ref="admin:left")
    assert left.show(CONTRACT, 1)["state"] == "accepted"
    p["now"][0] = 900
    assert not left.is_active(CONTRACT, 1, "PERMISSIONS_READ")
    p["now"][0] = 100
    right.import_bundle(left.export_bundle(CONTRACT, 1))
    right.activate(CONTRACT, 1, actor_admin_ref="admin:right")
    assert right.is_active(CONTRACT, 1, "PERMISSIONS_READ")
    TrustedKeyStore(p["right_db"], clock=lambda: 100).revoke(
        A, "left-key", approved_by="admin:right"
    )
    assert not right.is_active(CONTRACT, 1, "PERMISSIONS_READ")


def test_signed_event_sequence_gap_replay_conflict_wrong_key_and_domain(tmp_path):
    p = pair(tmp_path)
    left, right, terms = p["left"], p["right"], p["terms"]
    left.propose(terms, actor_admin_ref="admin:left")
    bundle = json.loads(left.export_bundle(CONTRACT, 1))
    right.import_bundle(json.dumps(bundle))
    proposal = bundle["events"][0]
    with pytest.raises(ContractError, match="event_id_conflict"):
        parts = proposal.split(".")
        conflicting = (
            parts[0]
            + "."
            + parts[1]
            + "."
            + ("A" if parts[2][0] != "A" else "B")
            + parts[2][1:]
        )
        right.import_event(terms, conflicting)

    claims = build_contract_event_claims(
        actor_deployment_id=B,
        event_id=str(uuid4()),
        contract_id=CONTRACT,
        contract_version=1,
        event_type="accept",
        terms_sha256=contract_terms_sha256(terms),
        actor_sequence=2,
        occurred_at=100,
        actor_admin_ref="admin:right",
        reason_code="operator_accept",
    )
    gap = jwt.encode(
        claims,
        p["right_key"],
        algorithm="EdDSA",
        headers={"typ": CONTRACT_EVENT_TYP, "kid": "right-key"},
    )
    with pytest.raises(ContractError, match="event_sequence_gap"):
        right.import_event(terms, gap)
    wrong = jwt.encode(
        {**claims, "actor_sequence": 1},
        p["left_key"],
        algorithm="EdDSA",
        headers={"typ": CONTRACT_EVENT_TYP, "kid": "right-key"},
    )
    with pytest.raises(ContractError, match="invalid_event_signature"):
        right.import_event(terms, wrong)
    broker_domain = jwt.encode(
        {**claims, "actor_sequence": 1},
        p["right_key"],
        algorithm="EdDSA",
        headers={"typ": BROKER_REQUEST_TYP, "kid": "right-key"},
    )
    with pytest.raises(ContractError, match="invalid_event_domain"):
        right.import_event(terms, broker_domain)


def test_same_sequence_different_event_and_lower_sequence_reject(tmp_path):
    p = pair(tmp_path)
    left, right, terms = p["left"], p["right"], p["terms"]
    left.propose(terms, actor_admin_ref="admin:left")
    right.import_bundle(left.export_bundle(CONTRACT, 1))
    right.accept(CONTRACT, 1, actor_admin_ref="admin:right")
    claims = build_contract_event_claims(
        actor_deployment_id=B,
        event_id=str(uuid4()),
        contract_id=CONTRACT,
        contract_version=1,
        event_type="activate",
        terms_sha256=contract_terms_sha256(terms),
        actor_sequence=1,
        occurred_at=100,
        actor_admin_ref="admin:right",
        reason_code="operator_activate",
    )
    token = jwt.encode(
        claims,
        p["right_key"],
        algorithm="EdDSA",
        headers={"typ": CONTRACT_EVENT_TYP, "kid": "right-key"},
    )
    with pytest.raises(ContractError, match="event_sequence_replay"):
        right.import_event(terms, token)


def test_supersession_retires_old_active_version(tmp_path):
    p = pair(tmp_path)
    fully_activate(p)
    left, right = p["left"], p["right"]
    terms2 = build_contract_terms(
        contract_id=CONTRACT,
        version=2,
        participant_1=A,
        participant_1_kid="left-key",
        participant_1_sha256=p["left_material"]["public_key_sha256"],
        participant_2=B,
        participant_2_kid="right-key",
        participant_2_sha256=p["right_material"]["public_key_sha256"],
        valid_from=50,
        valid_until=950,
        allowed_capabilities=["PERMISSIONS_READ"],
        supersedes_version=1,
    )
    left.propose(terms2, actor_admin_ref="admin:left")
    right.import_bundle(left.export_bundle(CONTRACT, 2))
    right.accept(CONTRACT, 2, actor_admin_ref="admin:right")
    left.import_bundle(right.export_bundle(CONTRACT, 2))
    left.activate(CONTRACT, 2, actor_admin_ref="admin:left")
    right.import_bundle(left.export_bundle(CONTRACT, 2))
    right.activate(CONTRACT, 2, actor_admin_ref="admin:right")
    left.import_bundle(right.export_bundle(CONTRACT, 2))
    for store in (left, right):
        assert store.is_active(CONTRACT, 2, "PERMISSIONS_READ")
        assert not store.is_active(CONTRACT, 1, "PERMISSIONS_READ")
        assert store.show(CONTRACT, 1)["superseded_by_version"] == 2


def test_server_key_expiry_is_rechecked_after_waiting_for_lock(tmp_path, monkeypatch):
    p = pair(tmp_path, key_valid_until=101)
    p["left"].propose(p["terms"], actor_admin_ref="admin:left")
    p["right"].import_bundle(p["left"].export_bundle(CONTRACT, 1))
    before = local_projection_snapshot(p["right_db"])
    blocker = sqlite3.connect(p["right_db"], timeout=5.0)
    blocker.execute("PRAGMA journal_mode=WAL")
    blocker.execute("BEGIN IMMEDIATE")
    entered, release = threading.Event(), threading.Event()
    install_begin_gates(monkeypatch, {"expiry-transition": (entered, release)})
    outcome = []

    def transition():
        try:
            p["right"].accept(CONTRACT, 1, actor_admin_ref="admin:right")
        except Exception as exc:  # captured for deterministic main-thread checks
            outcome.append(exc)

    thread = threading.Thread(target=transition, name="expiry-transition")
    thread.start()
    assert entered.wait(timeout=5), "transition did not reach BEGIN IMMEDIATE"
    p["now"][0] = 101
    blocker.commit()
    blocker.close()
    release.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert len(outcome) == 1
    assert isinstance(outcome[0], ContractError)
    assert outcome[0].code == "key_not_current"
    assert local_projection_snapshot(p["right_db"]) == before


def test_server_activate_suspend_race_has_only_serialized_outcomes(
    tmp_path, monkeypatch
):
    gates = {}
    install_begin_gates(monkeypatch, gates)

    first_dir = tmp_path / "activate-first"
    first_dir.mkdir()
    p = pair(first_dir)
    bundle = json.loads(prepare_final_activation(p))
    activation = next(
        token
        for token in bundle["events"]
        if jwt.decode(token, options={"verify_signature": False})["event_type"]
        == "activate"
        and jwt.decode(token, options={"verify_signature": False})["iss"] == B
    )
    suspend_entered, allow_suspend = threading.Event(), threading.Event()
    gates["suspend-after-activation"] = (suspend_entered, allow_suspend)
    outcomes = {}

    def suspend_after_activation():
        try:
            outcomes["suspend"] = p["left"].suspend(
                CONTRACT, 1, actor_admin_ref="admin:left"
            )
        except Exception as exc:
            outcomes["suspend"] = exc

    suspend_thread = threading.Thread(
        target=suspend_after_activation, name="suspend-after-activation"
    )
    suspend_thread.start()
    assert suspend_entered.wait(timeout=5)
    outcomes["activate"] = p["left"].import_event(p["terms"], activation)
    allow_suspend.set()
    suspend_thread.join(timeout=5)
    assert outcomes["activate"] is True
    assert not isinstance(outcomes["suspend"], Exception)
    assert p["left"].show(CONTRACT, 1)["state"] == "suspended"
    assert_local_sequence_integrity(p["left_db"])

    second_dir = tmp_path / "suspend-first"
    second_dir.mkdir()
    p = pair(second_dir)
    fully_activate(p)
    bundle = json.loads(p["right"].export_bundle(CONTRACT, 1))
    activation = next(
        token
        for token in bundle["events"]
        if jwt.decode(token, options={"verify_signature": False})["event_type"]
        == "activate"
        and jwt.decode(token, options={"verify_signature": False})["iss"] == B
    )
    activation_entered, allow_activation = threading.Event(), threading.Event()
    gates["activation-after-suspend"] = (activation_entered, allow_activation)
    outcomes = {}

    def delayed_activation():
        try:
            outcomes["activate"] = p["left"].import_event(p["terms"], activation)
        except Exception as exc:
            outcomes["activate"] = exc

    activation_thread = threading.Thread(
        target=delayed_activation, name="activation-after-suspend"
    )
    activation_thread.start()
    assert activation_entered.wait(timeout=5)
    p["left"].suspend(CONTRACT, 1, actor_admin_ref="admin:left")
    allow_activation.set()
    activation_thread.join(timeout=5)
    assert outcomes["activate"] is False
    assert p["left"].show(CONTRACT, 1)["state"] == "suspended"
    assert_local_sequence_integrity(p["left_db"])


def test_server_activate_revoke_race_keeps_revocation_terminal(tmp_path, monkeypatch):
    gates = {}
    install_begin_gates(monkeypatch, gates)

    first_dir = tmp_path / "activate-before-revoke"
    first_dir.mkdir()
    p = pair(first_dir)
    bundle = json.loads(prepare_final_activation(p))
    activation = next(
        token
        for token in bundle["events"]
        if jwt.decode(token, options={"verify_signature": False})["event_type"]
        == "activate"
        and jwt.decode(token, options={"verify_signature": False})["iss"] == B
    )
    revoke_entered, allow_revoke = threading.Event(), threading.Event()
    gates["revoke-after-activation"] = (revoke_entered, allow_revoke)
    outcomes = {}

    def delayed_revoke():
        try:
            outcomes["revoke"] = p["left"].revoke(
                CONTRACT, 1, actor_admin_ref="admin:left"
            )
        except Exception as exc:
            outcomes["revoke"] = exc

    revoke_thread = threading.Thread(
        target=delayed_revoke, name="revoke-after-activation"
    )
    revoke_thread.start()
    assert revoke_entered.wait(timeout=5)
    assert p["left"].import_event(p["terms"], activation) is True
    allow_revoke.set()
    revoke_thread.join(timeout=5)
    assert not isinstance(outcomes["revoke"], Exception)
    assert p["left"].show(CONTRACT, 1)["state"] == "revoked"
    assert_local_sequence_integrity(p["left_db"])

    second_dir = tmp_path / "revoke-before-activation"
    second_dir.mkdir()
    p = pair(second_dir)
    bundle = json.loads(prepare_final_activation(p))
    activation = next(
        token
        for token in bundle["events"]
        if jwt.decode(token, options={"verify_signature": False})["event_type"]
        == "activate"
        and jwt.decode(token, options={"verify_signature": False})["iss"] == B
    )
    activation_entered, allow_activation = threading.Event(), threading.Event()
    gates["activation-after-revoke"] = (activation_entered, allow_activation)
    outcomes = {}

    def delayed_activation():
        try:
            outcomes["activate"] = p["left"].import_event(p["terms"], activation)
        except Exception as exc:
            outcomes["activate"] = exc

    activation_thread = threading.Thread(
        target=delayed_activation, name="activation-after-revoke"
    )
    activation_thread.start()
    assert activation_entered.wait(timeout=5)
    p["left"].revoke(CONTRACT, 1, actor_admin_ref="admin:left")
    allow_activation.set()
    activation_thread.join(timeout=5)
    assert isinstance(outcomes["activate"], ContractError)
    assert outcomes["activate"].code == "contract_revoked"
    assert p["left"].show(CONTRACT, 1)["state"] == "revoked"
    assert_local_sequence_integrity(p["left_db"])


def test_server_concurrent_conflicting_sequence_accepts_only_one(tmp_path, monkeypatch):
    p = pair(tmp_path)
    p["left"].propose(p["terms"], actor_admin_ref="admin:left")

    def acceptance(reason_code):
        claims = build_contract_event_claims(
            actor_deployment_id=B,
            event_id=str(uuid4()),
            contract_id=CONTRACT,
            contract_version=1,
            event_type="accept",
            terms_sha256=contract_terms_sha256(p["terms"]),
            actor_sequence=1,
            occurred_at=100,
            actor_admin_ref="admin:right",
            reason_code=reason_code,
        )
        return jwt.encode(
            claims,
            p["right_key"],
            algorithm="EdDSA",
            headers={"typ": CONTRACT_EVENT_TYP, "kid": "right-key"},
        )

    first = acceptance("first_accept")
    conflicting = acceptance("conflicting_accept")
    entered, release = threading.Event(), threading.Event()
    install_begin_gates(monkeypatch, {"conflicting-import": (entered, release)})
    outcome = []

    def delayed_conflict():
        try:
            outcome.append(p["left"].import_event(p["terms"], conflicting))
        except Exception as exc:
            outcome.append(exc)

    thread = threading.Thread(target=delayed_conflict, name="conflicting-import")
    thread.start()
    assert entered.wait(timeout=5)
    assert p["left"].import_event(p["terms"], first) is True
    release.set()
    thread.join(timeout=5)
    assert len(outcome) == 1
    assert isinstance(outcome[0], ContractError)
    assert outcome[0].code == "event_sequence_replay"
    assert p["left"].show(CONTRACT, 1)["state"] == "accepted"
    assert_local_sequence_integrity(p["left_db"])


def test_broker_directory_cannot_authorize_local_store(tmp_path):
    p = pair(tmp_path)
    p["left"].propose(p["terms"], actor_admin_ref="admin:left")
    broker = sqlite3.connect(tmp_path / "broker.db")
    broker.execute(
        "CREATE TABLE broker_contract_directory "
        "(contract_id TEXT,version INTEGER,terms_sha256 TEXT,reported_state_a TEXT)"
    )
    for version, digest, state in (
        (1, contract_terms_sha256(p["terms"]), "active"),
        (2, "00" * 32, "active"),
    ):
        broker.execute(
            "INSERT INTO broker_contract_directory VALUES (?,?,?,?)",
            (CONTRACT, version, digest, state),
        )
    broker.commit()
    assert not p["left"].is_active(CONTRACT, 1, "PERMISSIONS_READ")
    assert not p["left"].is_active(CONTRACT, 2, "PERMISSIONS_READ")


def test_key_revoked_while_transition_waits_for_lock_rejects(tmp_path):
    p = pair(tmp_path)
    p["left"].propose(p["terms"], actor_admin_ref="admin:left")
    p["right"].import_bundle(p["left"].export_bundle(CONTRACT, 1))
    blocker = sqlite3.connect(p["right_db"], timeout=5.0, check_same_thread=False)
    blocker.execute("PRAGMA journal_mode=WAL")
    blocker.execute("BEGIN IMMEDIATE")
    outcome = []

    def transition():
        try:
            p["right"].accept(CONTRACT, 1, actor_admin_ref="admin:right")
            outcome.append("accepted")
        except Exception as exc:  # captured for the main test thread
            outcome.append(exc)

    thread = threading.Thread(target=transition)
    thread.start()
    time.sleep(0.1)
    blocker.execute(
        "UPDATE TrustedDeploymentKeys SET state='revoked' "
        "WHERE deployment_id=? AND kid=?",
        (B, "right-key"),
    )
    blocker.commit()
    thread.join(timeout=5)
    blocker.close()
    assert len(outcome) == 1
    assert isinstance(outcome[0], ContractError)
    assert outcome[0].code == "key_revoked"


def test_schema_is_idempotent_checksumed_and_append_only(tmp_path):
    path = tmp_path / "schema.db"
    with sqlite3.connect(path) as conn:
        migrate_gate_d_usergroups_schema(conn)
        migrate_gate_d_usergroups_schema(conn)
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM SchemaMigrations WHERE name=?",
                (GATE_D_MIGRATION_NAME,),
            ).fetchone()[0]
            == 1
        )
    check_gate_d_ready(path)
    key = Ed25519PrivateKey.generate()
    value = material(A, "key", key)
    store = TrustedKeyStore(path, clock=lambda: 100)
    import_pin(store, value)
    with sqlite3.connect(path) as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "UPDATE TrustedDeploymentKeys SET public_key_sha256=?",
            ("00" * 32,),
        )


@pytest.mark.parametrize("left,right", [(A, B), (UT, B), (A, UT)])
def test_same_contract_adapter_is_symmetric_for_all_deployment_pairs(
    tmp_path, left, right
):
    contract_id = str(uuid4())
    p = pair(tmp_path, left, right, contract_id=contract_id)
    fully_activate(p)
    assert p["left"].is_active(contract_id, 1, "FEDERATED_ENROLL")
    assert p["right"].is_active(contract_id, 1, "PERMISSIONS_READ")


def test_canonical_vector_matches_shared_core(tmp_path):
    p = pair(tmp_path)
    encoded = canonical_contract_bytes(p["terms"])
    assert (
        encoded
        == json.dumps(
            p["terms"].to_dict(), sort_keys=True, separators=(",", ":")
        ).encode()
    )
    assert contract_terms_sha256(p["terms"]) == hashlib.sha256(encoded).hexdigest()
