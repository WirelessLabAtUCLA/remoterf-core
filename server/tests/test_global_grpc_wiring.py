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
Covers the two actual integration points added to grpc_server.py:
GenericRPCServicer.Call's relay-ingress gate, and GlobalAuthV1Servicer's
disabled/misconfigured/not-enrolled response paths. Neither test starts a
real gRPC server — both call the servicer methods directly with a fake
context, matching how grpc itself would invoke them.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from remoteRF_server.common.grpc import grpc_pb2
from remoteRF_server.server import grpc_server
from remoteRF_server.server.global_access import identity as identity_mod

_VALID_CONFIG_YAML = """
global:
  enabled: true
  base_url: https://global.remoterf.net
  issuer: https://global.remoterf.net
  jwks_url: https://global.remoterf.net/.well-known/jwks.json
  deployment_state_path: {state_dir}/deployment.json
  deployment_private_key_path: {state_dir}/deployment-private.pem
  heartbeat_seconds: 30
  offline_seconds: 90
  relay_ingress:
    trusted_peer_cidrs:
      - 10.77.0.1/32
  public_group: global-public
  route:
    kind: tcp-relay
    grpc_endpoint: ucla.global.remoterf.net:61005
    certificate_endpoint: ucla.global.remoterf.net:61006
    tls_server_name: ucla.global.remoterf.net
  exports: []
"""


class _FakeContext:
    def __init__(self, peer: str):
        self._peer = peer

    def peer(self) -> str:
        return self._peer


class RelayIngressGateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_dir = Path(self._tmp.name)
        config_path = self.state_dir / "global.yaml"
        config_path.write_text(_VALID_CONFIG_YAML.format(state_dir=self.state_dir))
        self.config_path = config_path

    def _request(self, function_name: str):
        return grpc_pb2.GenericRPCRequest(function_name=function_name)

    def test_disabled_global_never_gates_anything(self):
        with patch.dict(os.environ, {"REMOTERF_GLOBAL_ENABLED": "false"}):
            servicer = grpc_server.GenericRPCServicer()
            with patch(
                "remoteRF_server.server.grpc_server.rpc_manager.run_rpc", return_value={}
            ) as mock_run:
                servicer.Call(self._request("ACC:login"), _FakeContext("ipv4:10.77.0.1:4444"))
                mock_run.assert_called_once()

    def test_relay_peer_is_blocked_from_password_login_when_enabled(self):
        with patch.dict(
            os.environ,
            {
                "REMOTERF_GLOBAL_ENABLED": "true",
                "REMOTERF_GLOBAL_CONFIG_PATH": str(self.config_path),
            },
        ):
            servicer = grpc_server.GenericRPCServicer()
            with patch(
                "remoteRF_server.server.grpc_server.rpc_manager.run_rpc", return_value={}
            ) as mock_run:
                response = servicer.Call(
                    self._request("ACC:login"), _FakeContext("ipv4:10.77.0.1:4444")
                )
                mock_run.assert_not_called()
                self.assertIn("ace", response.results)

    def test_relay_peer_is_blocked_from_account_creation_when_enabled(self):
        with patch.dict(
            os.environ,
            {
                "REMOTERF_GLOBAL_ENABLED": "true",
                "REMOTERF_GLOBAL_CONFIG_PATH": str(self.config_path),
            },
        ):
            servicer = grpc_server.GenericRPCServicer()
            with patch(
                "remoteRF_server.server.grpc_server.rpc_manager.run_rpc", return_value={}
            ) as mock_run:
                servicer.Call(self._request("ACC:create_user"), _FakeContext("ipv4:10.77.0.1:4444"))
                mock_run.assert_not_called()

    def test_non_relay_peer_is_never_gated(self):
        with patch.dict(
            os.environ,
            {
                "REMOTERF_GLOBAL_ENABLED": "true",
                "REMOTERF_GLOBAL_CONFIG_PATH": str(self.config_path),
            },
        ):
            servicer = grpc_server.GenericRPCServicer()
            with patch(
                "remoteRF_server.server.grpc_server.rpc_manager.run_rpc", return_value={}
            ) as mock_run:
                servicer.Call(self._request("ACC:login"), _FakeContext("ipv4:192.168.1.50:4444"))
                mock_run.assert_called_once()

    def test_relay_peer_does_not_block_unrelated_functions(self):
        with patch.dict(
            os.environ,
            {
                "REMOTERF_GLOBAL_ENABLED": "true",
                "REMOTERF_GLOBAL_CONFIG_PATH": str(self.config_path),
            },
        ):
            servicer = grpc_server.GenericRPCServicer()
            with patch(
                "remoteRF_server.server.grpc_server.rpc_manager.run_rpc", return_value={}
            ) as mock_run:
                servicer.Call(self._request("ACC:get_res"), _FakeContext("ipv4:10.77.0.1:4444"))
                mock_run.assert_called_once()

    def test_misconfigured_global_never_opens_a_hole(self):
        # No config file at the configured path at all: enforcement must
        # degrade to "cannot evaluate" (pass through to rpc_manager, same
        # as disabled), never to "trust everyone."
        missing_path = self.state_dir / "does-not-exist.yaml"
        with patch.dict(
            os.environ,
            {
                "REMOTERF_GLOBAL_ENABLED": "true",
                "REMOTERF_GLOBAL_CONFIG_PATH": str(missing_path),
            },
        ):
            servicer = grpc_server.GenericRPCServicer()
            with patch(
                "remoteRF_server.server.grpc_server.rpc_manager.run_rpc", return_value={}
            ) as mock_run:
                servicer.Call(self._request("ACC:login"), _FakeContext("ipv4:10.77.0.1:4444"))
                mock_run.assert_called_once()


class GlobalAuthV1ServicerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_dir = Path(self._tmp.name)
        config_path = self.state_dir / "global.yaml"
        config_path.write_text(_VALID_CONFIG_YAML.format(state_dir=self.state_dir))
        self.config_path = config_path

    def _request(self):
        from remoteRF_server.common.grpc import global_auth_pb2

        return global_auth_pb2.ExchangeAssertionRequest(assertion="whatever", protocol_version="1.0")

    def test_disabled_global_returns_structured_error(self):
        with patch.dict(os.environ, {"REMOTERF_GLOBAL_ENABLED": "false"}):
            servicer = grpc_server.GlobalAuthV1Servicer()
            response = servicer.ExchangeAssertion(self._request(), _FakeContext("ipv4:1.2.3.4:1"))
            self.assertEqual(response.error.code, "global_disabled")
            self.assertEqual(response.local_session_token, "")

    def test_misconfigured_global_returns_structured_error(self):
        missing_path = self.state_dir / "does-not-exist.yaml"
        with patch.dict(
            os.environ,
            {
                "REMOTERF_GLOBAL_ENABLED": "true",
                "REMOTERF_GLOBAL_CONFIG_PATH": str(missing_path),
            },
        ):
            servicer = grpc_server.GlobalAuthV1Servicer()
            response = servicer.ExchangeAssertion(self._request(), _FakeContext("ipv4:1.2.3.4:1"))
            self.assertEqual(response.error.code, "global_misconfigured")

    def test_unenrolled_deployment_returns_structured_error(self):
        identity_mod.init_identity(self.state_dir)  # identity exists, but never enrolled
        with patch.dict(
            os.environ,
            {
                "REMOTERF_GLOBAL_ENABLED": "true",
                "REMOTERF_GLOBAL_CONFIG_PATH": str(self.config_path),
            },
        ):
            servicer = grpc_server.GlobalAuthV1Servicer()
            response = servicer.ExchangeAssertion(self._request(), _FakeContext("ipv4:1.2.3.4:1"))
            self.assertEqual(response.error.code, "not_enrolled")


if __name__ == "__main__":
    unittest.main()
