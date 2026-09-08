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

"""
End-to-end test of GlobalAuthV1's core orchestration
(server/global_access/principal_mapping.py): assertion verification, replay
protection, JIT mapping/shadow-account creation, public_group assignment,
and local session issuance — using real ReservationHandler/perms_db/
UserGroupHandler/GlobalDB instances backed by one isolated temp directory.

The module-level singletons in reservation.py/acc_perms.py/
user_group_handler.py are process-wide and bound at first import (a
pre-existing property of this codebase, not something this test changes),
so this test explicitly monkey-patches those singleton *references* to
point at fresh, temp-dir-backed instances for its duration, rather than
relying on environment-variable isolation alone.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import tempfile
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from remoteRF_server.server.acc_perms import perms_db
from remoteRF_server.server.global_access import principal_mapping
from remoteRF_server.server.global_access.config import parse_global_config
from remoteRF_server.server.global_access.db import GlobalDB
from remoteRF_server.server.global_access.jwks_cache import JWKSCache
from remoteRF_server.server.reservation import ReservationHandler
from remoteRF_server.server.user_group_handler import UserGroupHandler

from tests.test_global_config import _BASE as _BASE_CONFIG

ISSUER = "https://global.remoterf.net"
DEPLOYMENT_ID = "22222222-2222-2222-2222-222222222222"
KID = "mapping-test-key"
PUBLIC_GROUP = "global-public-test"


def _jwk_from_public_key(pub, kid: str) -> dict:
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    x = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": x}


def _mint_assertion(priv, *, subject, **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": subject,
        "aud": DEPLOYMENT_ID,
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
        "email_verified": True,
        "scope": ["remoterf:connect"],
        "token_type": "deployment_access",
    }
    claims.update(overrides)
    return jwt.encode(claims, priv, algorithm="EdDSA", headers={"kid": KID})


def _cfg(**overrides):
    data = copy.deepcopy(_BASE_CONFIG)
    data["global"]["issuer"] = ISSUER
    data["global"]["public_group"] = PUBLIC_GROUP
    data["global"]["exports"] = []
    for path, value in overrides.items():
        keys = path.split(".")
        node = data["global"]
        for k in keys[:-1]:
            node = node[k]
        node[keys[-1]] = value
    return parse_global_config(data)


class ExchangeAssertionIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db_dir = Path(self._tmp.name)

        self._stack = contextlib.ExitStack()
        self.addCleanup(self._stack.close)

        # Point every subsystem's db_dir at the same isolated directory,
        # then rebind the process-wide singletons to fresh instances that
        # actually use it.
        self._stack.enter_context(
            patch("remoteRF_server.server.reservation.get_db_dir", return_value=self.db_dir)
        )
        self.reservation_handler = ReservationHandler()
        self._stack.enter_context(
            patch("remoteRF_server.server.reservation.reservation_handler", self.reservation_handler)
        )

        self._stack.enter_context(
            patch("remoteRF_server.server.acc_perms.get_db_dir", return_value=self.db_dir)
        )
        self.perms = perms_db()
        self._stack.enter_context(patch("remoteRF_server.server.acc_perms.perms", self.perms))

        self._stack.enter_context(
            patch("remoteRF_server.server.user_group_handler.get_db_dir", return_value=self.db_dir)
        )
        self.user_group_handler = UserGroupHandler()
        self._stack.enter_context(
            patch(
                "remoteRF_server.server.user_group_handler.user_group_handler",
                self.user_group_handler,
            )
        )

        self.gdb = GlobalDB(db_dir=self.db_dir)
        self._stack.enter_context(
            patch("remoteRF_server.server.global_access.db.get_global_db", return_value=self.gdb)
        )

        self.user_group_handler.create_user_group(
            group_name=PUBLIC_GROUP,
            devices_whitelist=[],
            max_reservation_time_sec=1800,
            max_reservations=1,
            lifetime_sec=0,
        )

        self.priv = Ed25519PrivateKey.generate()
        jwk = _jwk_from_public_key(self.priv.public_key(), KID)
        self._stack.enter_context(
            patch("requests.get", return_value=self._mock_jwks_response(jwk))
        )
        self.jwks = JWKSCache(f"{ISSUER}/.well-known/jwks.json")

    @staticmethod
    def _mock_jwks_response(jwk):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        resp.json.return_value = {"keys": [jwk]}
        return resp

    def _exchange(self, token, *, cfg=None, session_minutes=60):
        return principal_mapping.exchange_assertion(
            token,
            cfg=cfg or _cfg(enabled=True),
            deployment_id=DEPLOYMENT_ID,
            jwks=self.jwks,
            session_minutes=session_minutes,
        )

    def test_first_assertion_creates_mapping_and_shadow_account(self):
        token = _mint_assertion(self.priv, subject="user-0001")
        result = self._exchange(token)

        self.assertTrue(result.local_username.startswith("global-"))
        self.assertEqual(self.reservation_handler.get_auth_type(result.local_username), "remoterf_global")

        mapping = self.gdb.get_mapping(issuer=ISSUER, global_subject="user-0001")
        self.assertIsNotNone(mapping)
        self.assertEqual(mapping.status, "active")

    def test_shadow_account_is_assigned_only_to_the_configured_public_group(self):
        token = _mint_assertion(self.priv, subject="user-0001")
        result = self._exchange(token)

        groups = self.user_group_handler.get_groups_user_in(uid=result.local_account_id)
        self.assertEqual(groups, [PUBLIC_GROUP])

    def test_second_assertion_for_same_subject_reuses_mapping_and_account(self):
        token1 = _mint_assertion(self.priv, subject="user-0001")
        result1 = self._exchange(token1)

        token2 = _mint_assertion(self.priv, subject="user-0001")
        result2 = self._exchange(token2)

        self.assertEqual(result1.local_account_id, result2.local_account_id)
        self.assertEqual(result1.local_username, result2.local_username)
        self.assertEqual(len(self.gdb.list_mappings()), 1)

    def test_replayed_jti_is_rejected(self):
        token = _mint_assertion(self.priv, subject="user-0001")
        self._exchange(token)
        with self.assertRaises(principal_mapping.GlobalAuthError) as ctx:
            self._exchange(token)
        self.assertEqual(ctx.exception.code, "replayed")

    def test_lost_response_retry_creates_only_short_lived_revocable_sessions(self):
        """Model a committed exchange whose response was lost, then one retry.

        The Client's retry policy already proves it makes at most two
        attempts.  This Server-side companion proves the only possible
        extra owner-local session is scoped to the same mapping, has the
        requested short lifetime, and can be revoked alongside the retry's
        returned session.
        """
        before = datetime.now(timezone.utc).replace(tzinfo=None)
        first = self._exchange(
            _mint_assertion(self.priv, subject="lost-response-user"),
            session_minutes=1,
        )
        retried = self._exchange(
            _mint_assertion(self.priv, subject="lost-response-user"),
            session_minutes=1,
        )

        self.assertNotEqual(first.local_session_token, retried.local_session_token)
        self.assertEqual(first.mapping_id, retried.mapping_id)
        for result in (first, retried):
            self.assertGreater(result.expires_at, before)
            self.assertLessEqual(result.expires_at, before + timedelta(minutes=1, seconds=2))
            self.assertIsNotNone(self.gdb.validate_session(token=result.local_session_token))

        self.assertEqual(self.gdb.revoke_sessions_for_mapping(mapping_id=first.mapping_id), 2)
        self.assertIsNone(self.gdb.validate_session(token=first.local_session_token))
        self.assertIsNone(self.gdb.validate_session(token=retried.local_session_token))

    def test_disabled_mapping_rejects_new_exchanges(self):
        token = _mint_assertion(self.priv, subject="user-0001")
        self._exchange(token)
        self.gdb.set_mapping_status(global_subject="user-0001", status="disabled")

        token2 = _mint_assertion(self.priv, subject="user-0001")
        with self.assertRaises(principal_mapping.GlobalAuthError) as ctx:
            self._exchange(token2)
        self.assertEqual(ctx.exception.code, "mapping_disabled")

    def test_reenabled_mapping_accepts_exchanges_again(self):
        token = _mint_assertion(self.priv, subject="user-0001")
        self._exchange(token)
        self.gdb.set_mapping_status(global_subject="user-0001", status="disabled")
        self.gdb.set_mapping_status(global_subject="user-0001", status="active")

        token2 = _mint_assertion(self.priv, subject="user-0001")
        result = self._exchange(token2)
        self.assertIsNotNone(result.local_session_token)

    def test_disabled_global_integration_rejects_before_verifying_anything(self):
        token = _mint_assertion(self.priv, subject="user-0001")
        with self.assertRaises(principal_mapping.GlobalAuthError) as ctx:
            self._exchange(token, cfg=_cfg(enabled=False))
        self.assertEqual(ctx.exception.code, "global_disabled")
        self.assertIsNone(self.gdb.get_mapping(issuer=ISSUER, global_subject="user-0001"))

    def test_missing_public_group_is_reported_clearly(self):
        token = _mint_assertion(self.priv, subject="user-0002")
        cfg = _cfg(enabled=True, **{"public_group": "does-not-exist"})
        with self.assertRaises(principal_mapping.GlobalAuthError) as ctx:
            self._exchange(token, cfg=cfg)
        self.assertEqual(ctx.exception.code, "public_group_missing")

    def test_local_session_token_is_usable_against_ordinary_login_rpc(self):
        token = _mint_assertion(self.priv, subject="user-0003")
        result = self._exchange(token)

        login_result = self.reservation_handler.login_user(
            result.local_username, result.local_session_token
        )
        self.assertEqual(login_result.get("UC").string_value, result.local_username)

    def test_two_different_subjects_get_two_distinct_accounts(self):
        r1 = self._exchange(_mint_assertion(self.priv, subject="user-A"))
        r2 = self._exchange(_mint_assertion(self.priv, subject="user-B"))
        self.assertNotEqual(r1.local_account_id, r2.local_account_id)
        self.assertNotEqual(r1.local_username, r2.local_username)


if __name__ == "__main__":
    unittest.main()
