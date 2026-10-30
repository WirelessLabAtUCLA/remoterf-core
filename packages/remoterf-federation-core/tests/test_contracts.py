import base64
import hashlib
import json
import unittest

from remoterf_federation_core import (
    BROKER_REQUEST_TYP,
    CONTRACT_EVENT_TYP,
    ContractError,
    build_broker_request_claims,
    build_contract_event_claims,
    build_contract_terms,
    canonical_contract_bytes,
    contract_allows,
    contract_terms_sha256,
    key_is_current,
    project_contract_state,
    validate_broker_request_claims,
    validate_broker_request_header,
    validate_contract_event_claims,
    validate_contract_event_header,
    validate_contract_terms,
    validate_contract_transition,
    validate_trusted_key_material,
)

A = "11111111-1111-4111-8111-111111111111"
B = "22222222-2222-4222-8222-222222222222"
C = "33333333-3333-4333-8333-333333333333"
CONTRACT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
EVENTS = [
    "aaaaaaaa-0000-4000-8000-000000000001",
    "aaaaaaaa-0000-4000-8000-000000000002",
    "aaaaaaaa-0000-4000-8000-000000000003",
    "aaaaaaaa-0000-4000-8000-000000000004",
    "aaaaaaaa-0000-4000-8000-000000000005",
]
FP_A = "11" * 32
FP_B = "22" * 32


def terms(**changes):
    values = dict(
        contract_id=CONTRACT,
        version=1,
        participant_1=B,
        participant_1_kid="b-key",
        participant_1_sha256=FP_B,
        participant_2=A,
        participant_2_kid="a-key",
        participant_2_sha256=FP_A,
        valid_from=100,
        valid_until=1000,
        allowed_capabilities=["PERMISSIONS_READ", "FEDERATED_ENROLL"],
    )
    values.update(changes)
    return build_contract_terms(**values)


def event(actor, sequence, kind, event_id):
    value = terms()
    return build_contract_event_claims(
        actor_deployment_id=actor,
        event_id=event_id,
        contract_id=CONTRACT,
        contract_version=1,
        event_type=kind,
        terms_sha256=contract_terms_sha256(value),
        actor_sequence=sequence,
        occurred_at=200 + sequence,
        actor_admin_ref="admin:test",
        reason_code="operator_request",
    )


class ContractCoreTests(unittest.TestCase):
    def test_trusted_key_material_is_strict_and_fingerprint_bound(self):
        raw = bytes(range(32))
        encoded = base64.b64encode(raw).decode()
        material = {
            "deployment_id": A,
            "kid": "key-1",
            "public_key_b64": encoded,
            "public_key_sha256": hashlib.sha256(raw).hexdigest(),
            "valid_from": 10,
            "valid_until": 100,
        }
        self.assertEqual(validate_trusted_key_material(material), material)
        for name, value, code in (
            ("public_key_b64", "%%%", "invalid_public_key"),
            ("public_key_b64", base64.b64encode(b"short").decode(), "invalid_public_key"),
            ("public_key_sha256", "00" * 32, "key_fingerprint_mismatch"),
        ):
            with self.subTest(name=name), self.assertRaisesRegex(ContractError, code):
                validate_trusted_key_material({**material, name: value})
        with self.assertRaisesRegex(ContractError, "invalid_trust_fields"):
            validate_trusted_key_material({**material, "jku": "https://peer/jwks"})

    def test_key_current_interval_and_revocation(self):
        row = {"state": "active", "valid_from": 100, "valid_until": 200}
        self.assertFalse(key_is_current(row, 99))
        self.assertTrue(key_is_current(row, 100))
        self.assertFalse(key_is_current(row, 200))
        self.assertFalse(key_is_current({**row, "state": "revoked"}, 150))

    def test_canonical_terms_order_and_frozen_hash_vector(self):
        value = terms()
        self.assertEqual(value.deployment_a, A)
        self.assertEqual(value.key_a_kid, "a-key")
        self.assertEqual(
            canonical_contract_bytes(value),
            json.dumps(
                value.to_dict(), sort_keys=True, separators=(",", ":")
            ).encode(),
        )
        self.assertEqual(
            contract_terms_sha256(value),
            "32b4e35b42447ac73525d769ad7e84cebba87cf3c846c854e57d234c06692ff0",
        )
        reordered = terms(
            participant_1=A,
            participant_1_kid="a-key",
            participant_1_sha256=FP_A,
            participant_2=B,
            participant_2_kid="b-key",
            participant_2_sha256=FP_B,
            allowed_capabilities=["FEDERATED_ENROLL", "PERMISSIONS_READ"],
        )
        self.assertEqual(canonical_contract_bytes(value), canonical_contract_bytes(reordered))

    def test_terms_reject_noncanonical_or_invalid_values(self):
        value = terms().to_dict()
        mutations = [
            {"version": 0},
            {"deployment_b": A},
            {"valid_until": 100},
            {"allowed_capabilities": ["RESOURCE_EXECUTE"]},
            {"allowed_capabilities": ["PERMISSIONS_READ", "PERMISSIONS_READ"]},
            {"allowed_capabilities": ["PERMISSIONS_READ", "FEDERATED_ENROLL"]},
            {"unexpected": 1},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ContractError):
                validate_contract_terms({**value, **mutation})
        with self.assertRaisesRegex(ContractError, "capabilities_not_canonical"):
            terms(allowed_capabilities=["PERMISSIONS_READ", "PERMISSIONS_READ"])

    def test_terms_hash_changes_for_key_or_field_mutation(self):
        baseline = contract_terms_sha256(terms())
        self.assertNotEqual(baseline, contract_terms_sha256(terms(valid_until=1001)))
        self.assertNotEqual(
            baseline,
            contract_terms_sha256(terms(participant_1_sha256="33" * 32)),
        )

    def test_contract_event_domain_and_exact_binding(self):
        value = terms()
        claims = event(A, 1, "propose", EVENTS[0])
        self.assertEqual(validate_contract_event_claims(claims, value), claims)
        self.assertEqual(
            validate_contract_event_header(
                {"alg": "EdDSA", "typ": CONTRACT_EVENT_TYP, "kid": "a-key"}
            )["kid"],
            "a-key",
        )
        for header in (
            {"alg": "EdDSA", "typ": "remoterf-home-access+jwt", "kid": "a-key"},
            {"alg": "EdDSA", "typ": BROKER_REQUEST_TYP, "kid": "a-key"},
            {"alg": "EdDSA", "typ": CONTRACT_EVENT_TYP, "kid": "a-key", "jku": "https://peer"},
            {"alg": "RS256", "typ": CONTRACT_EVENT_TYP, "kid": "a-key"},
        ):
            with self.subTest(header=header), self.assertRaises(ContractError):
                validate_contract_event_header(header)
        with self.assertRaisesRegex(ContractError, "event_terms_mismatch"):
            validate_contract_event_claims({**claims, "terms_sha256": "00" * 32}, value)
        with self.assertRaisesRegex(ContractError, "invalid_event_fields"):
            validate_contract_event_claims({**claims, "public_key_b64": "not-trust"}, value)

    def test_lifecycle_requires_peer_acceptance_and_two_activations(self):
        value = terms()
        proposal = event(A, 1, "propose", EVENTS[0])
        acceptance = event(B, 1, "accept", EVENTS[1])
        activate_a = event(A, 2, "activate", EVENTS[2])
        activate_b = event(B, 2, "activate", EVENTS[3])
        sequence = []
        for expected, item in (
            ("proposed", proposal),
            ("accepted", acceptance),
            ("accepted", activate_a),
            ("active", activate_b),
        ):
            self.assertEqual(
                validate_contract_transition(value, sequence, item, now=300), expected
            )
            sequence.append(item)
        self.assertTrue(contract_allows(value, "active", "FEDERATED_ENROLL", now=300))
        self.assertFalse(contract_allows(value, "accepted", "FEDERATED_ENROLL", now=300))

    def test_suspend_no_resume_revoke_and_expiry(self):
        value = terms()
        active = [
            event(A, 1, "propose", EVENTS[0]),
            event(B, 1, "accept", EVENTS[1]),
            event(A, 2, "activate", EVENTS[2]),
            event(B, 2, "activate", EVENTS[3]),
        ]
        suspension = event(B, 3, "suspend", EVENTS[4])
        self.assertEqual(
            validate_contract_transition(value, active, suspension, now=300), "suspended"
        )
        with self.assertRaisesRegex(ContractError, "illegal_contract_transition"):
            validate_contract_transition(
                value,
                [*active, suspension],
                event(A, 3, "activate", "aaaaaaaa-0000-4000-8000-000000000006"),
                now=300,
            )
        revoked = event(A, 3, "revoke", "aaaaaaaa-0000-4000-8000-000000000007")
        self.assertEqual(
            validate_contract_transition(value, [*active, suspension], revoked, now=300),
            "revoked",
        )
        self.assertEqual(project_contract_state(value, active, now=1000), "expired")
        self.assertFalse(contract_allows(value, "active", "PERMISSIONS_READ", now=1000))

    def test_illegal_accept_activate_and_actor(self):
        value = terms()
        with self.assertRaisesRegex(ContractError, "illegal_contract_transition"):
            validate_contract_transition(
                value, [], event(B, 1, "accept", EVENTS[1]), now=300
            )
        proposal = event(A, 1, "propose", EVENTS[0])
        with self.assertRaisesRegex(ContractError, "illegal_contract_transition"):
            validate_contract_transition(
                value, [proposal], event(A, 2, "accept", EVENTS[1]), now=300
            )
        bad = {**proposal, "iss": C}
        with self.assertRaisesRegex(ContractError, "event_terms_mismatch"):
            validate_contract_event_claims(bad, value)

    def test_broker_request_is_exact_short_lived_and_separate_domain(self):
        claims = build_broker_request_claims(
            deployment_id=A,
            broker_deployment_id=C,
            method="GET",
            path="/v2/broker/contracts",
            body_sha256=hashlib.sha256(b"").hexdigest(),
            issued_at=100,
            expires_at=160,
            jti="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        )
        self.assertEqual(
            validate_broker_request_claims(
                claims,
                now=120,
                broker_deployment_id=C,
                method="GET",
                path="/v2/broker/contracts",
                body_sha256=hashlib.sha256(b"").hexdigest(),
            ),
            claims,
        )
        self.assertEqual(
            validate_broker_request_header(
                {"alg": "EdDSA", "typ": BROKER_REQUEST_TYP, "kid": "a-key"}
            )["kid"],
            "a-key",
        )
        with self.assertRaises(ContractError):
            validate_broker_request_header(
                {"alg": "EdDSA", "typ": CONTRACT_EVENT_TYP, "kid": "a-key"}
            )
        with self.assertRaisesRegex(ContractError, "broker_request_mismatch"):
            validate_broker_request_claims(
                claims,
                now=120,
                broker_deployment_id=C,
                method="POST",
                path="/v2/broker/contracts/events",
                body_sha256=hashlib.sha256(b"{}").hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
