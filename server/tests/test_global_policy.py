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

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from remoteRF_server.server.global_access.config import parse_global_config
from remoteRF_server.server.global_access.ingress_policy import (
    is_trusted_relay_peer,
    parse_grpc_peer,
)
from remoteRF_server.server.global_access import operation_policy
from remoteRF_server.server.v2_errors import RemoteRFPolicyError

from tests.test_global_config import _BASE as _BASE_CONFIG


def _cfg(**export_overrides):
    import copy

    data = copy.deepcopy(_BASE_CONFIG)
    data["global"]["exports"][0]["operation_policy"].update(export_overrides)
    return parse_global_config(data)


class GrpcPeerParsingTests(unittest.TestCase):
    def test_parses_ipv4_peer(self):
        addr = parse_grpc_peer("ipv4:10.77.0.1:54321")
        self.assertEqual(str(addr), "10.77.0.1")

    def test_parses_ipv6_peer(self):
        addr = parse_grpc_peer("ipv6:[::1]:54321")
        self.assertEqual(str(addr), "::1")

    def test_unparseable_peer_returns_none(self):
        self.assertIsNone(parse_grpc_peer("unix:/tmp/socket"))
        self.assertIsNone(parse_grpc_peer(""))


class TrustedRelayPeerTests(unittest.TestCase):
    def test_configured_relay_peer_is_trusted(self):
        self.assertTrue(is_trusted_relay_peer("ipv4:10.77.0.1:5555", ["10.77.0.1/32"]))

    def test_arbitrary_public_address_is_not_trusted(self):
        self.assertFalse(is_trusted_relay_peer("ipv4:203.0.113.9:5555", ["10.77.0.1/32"]))

    def test_lan_address_is_not_misclassified_as_relay(self):
        self.assertFalse(is_trusted_relay_peer("ipv4:192.168.1.50:5555", ["10.77.0.1/32"]))

    def test_no_configured_cidrs_trusts_nobody(self):
        self.assertFalse(is_trusted_relay_peer("ipv4:10.77.0.1:5555", []))


class OperationPolicyPureLogicTests(unittest.TestCase):
    def test_allowlisted_operation_permitted(self):
        cfg = _cfg(allow_operations=["freq:GET", "freq:SET"])
        operation_policy.check_legacy_rpc_operation(cfg, device_id="1", prop="freq", verb="GET")

    def test_non_allowlisted_operation_denied(self):
        cfg = _cfg(allow_operations=["freq:GET"])
        with self.assertRaises(RemoteRFPolicyError):
            operation_policy.check_legacy_rpc_operation(cfg, device_id="1", prop="tx", verb="SET")

    def test_unexported_device_denied_by_default(self):
        cfg = _cfg(allow_operations=["freq:GET"])
        with self.assertRaises(RemoteRFPolicyError):
            operation_policy.check_legacy_rpc_operation(cfg, device_id="999", prop="freq", verb="GET")

    def test_dynamic_v2_method_allowlist_enforced(self):
        cfg = _cfg(allow_operations=["get_frequency"])
        operation_policy.check_dynamic_v2_operation(cfg, device_id="1", method="get_frequency")
        with self.assertRaises(RemoteRFPolicyError):
            operation_policy.check_dynamic_v2_operation(cfg, device_id="1", method="set_frequency")

    def test_sample_upload_denied_by_default(self):
        cfg = _cfg(allow_client_sample_upload=False)
        self.assertFalse(operation_policy.sample_upload_allowed(cfg, device_id="1"))

    def test_sample_upload_allowed_when_explicitly_enabled(self):
        cfg = _cfg(allow_client_sample_upload=True)
        self.assertTrue(operation_policy.sample_upload_allowed(cfg, device_id="1"))


class OperationPolicyGatingTests(unittest.TestCase):
    """
    Confirms the composite enforce_for_* entry points are true no-ops for
    ordinary local/LAN accounts, and only ever engage for Global-principal
    accounts — the actual enforcement logic itself is covered above.
    """

    def test_disabled_global_is_a_complete_noop_for_legacy_rpc(self):
        with patch.dict(os.environ, {"REMOTERF_GLOBAL_ENABLED": "false"}):
            # Should not raise and should not even look at auth_type.
            operation_policy.enforce_for_legacy_rpc(
                api_token="whatever", device_id="1", function_name="Pluto:tx:SET"
            )

    def test_local_account_is_unaffected_even_when_global_enabled(self):
        with patch.dict(os.environ, {"REMOTERF_GLOBAL_ENABLED": "true"}):
            with patch(
                "remoteRF_server.server.reservation.reservation_handler.get_username_for_active_token",
                return_value="alice",
            ), patch(
                "remoteRF_server.server.reservation.reservation_handler.get_auth_type",
                return_value="local_password",
            ):
                operation_policy.enforce_for_legacy_rpc(
                    api_token="tok", device_id="1", function_name="Pluto:tx:SET"
                )

    def test_global_principal_is_denied_a_non_allowlisted_legacy_rpc_operation(self):
        with patch.dict(os.environ, {"REMOTERF_GLOBAL_ENABLED": "true"}):
            with patch(
                "remoteRF_server.server.reservation.reservation_handler.get_username_for_active_token",
                return_value="global-abc",
            ), patch(
                "remoteRF_server.server.reservation.reservation_handler.get_auth_type",
                return_value="remoterf_global",
            ), patch(
                "remoteRF_server.server.global_access.operation_policy._load_cfg_or_none",
                return_value=_cfg(allow_operations=["freq:GET"]),
            ):
                with self.assertRaises(RemoteRFPolicyError):
                    operation_policy.enforce_for_legacy_rpc(
                        api_token="tok", device_id="1", function_name="Pluto:tx:SET"
                    )

    def test_global_principal_is_allowed_an_allowlisted_legacy_rpc_operation(self):
        with patch.dict(os.environ, {"REMOTERF_GLOBAL_ENABLED": "true"}):
            with patch(
                "remoteRF_server.server.reservation.reservation_handler.get_username_for_active_token",
                return_value="global-abc",
            ), patch(
                "remoteRF_server.server.reservation.reservation_handler.get_auth_type",
                return_value="remoterf_global",
            ), patch(
                "remoteRF_server.server.global_access.operation_policy._load_cfg_or_none",
                return_value=_cfg(allow_operations=["freq:GET"]),
            ):
                operation_policy.enforce_for_legacy_rpc(
                    api_token="tok", device_id="1", function_name="Pluto:freq:GET"
                )

    def test_misconfigured_global_denies_rather_than_falls_back_open(self):
        with patch.dict(os.environ, {"REMOTERF_GLOBAL_ENABLED": "true"}):
            with patch(
                "remoteRF_server.server.reservation.reservation_handler.get_username_for_active_token",
                return_value="global-abc",
            ), patch(
                "remoteRF_server.server.reservation.reservation_handler.get_auth_type",
                return_value="remoterf_global",
            ), patch(
                "remoteRF_server.server.global_access.operation_policy._load_cfg_or_none",
                return_value=None,
            ):
                with self.assertRaises(RemoteRFPolicyError):
                    operation_policy.enforce_for_legacy_rpc(
                        api_token="tok", device_id="1", function_name="Pluto:freq:GET"
                    )

    def test_sample_upload_allowed_for_defaults_true_for_local_accounts(self):
        with patch.dict(os.environ, {"REMOTERF_GLOBAL_ENABLED": "true"}):
            self.assertTrue(
                operation_policy.sample_upload_allowed_for(username=None, device_id="1")
            )


if __name__ == "__main__":
    unittest.main()
