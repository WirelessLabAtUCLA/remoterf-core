from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from remoteRF_server.common.grpc import grpc_pb2
from remoteRF_server.common.utils import map_arg
from remoteRF_server.server import grpc_server

_CONFIG = """
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
    trusted_peer_cidrs: [10.77.0.1/32]
  public_group: global-public
  route:
    kind: tcp-relay
    grpc_endpoint: ucla.global.remoterf.net:61005
    certificate_endpoint: ucla.global.remoterf.net:61006
    tls_server_name: ucla.global.remoterf.net
  exports: []
"""


class Context:
    def __init__(self, peer):
        self.value = peer

    def peer(self):
        return self.value


class RelayIngressGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.config = root / "global.yaml"
        self.config.write_text(_CONFIG.format(state_dir=root))

    @staticmethod
    def request(function_name, password=None):
        request = grpc_pb2.GenericRPCRequest(function_name=function_name)
        if password is not None:
            request.args["pw"].CopyFrom(map_arg(password))
        return request

    def call(self, function_name, peer, password=None):
        servicer = grpc_server.GenericRPCServicer()
        with patch(
            "remoteRF_server.server.grpc_server.rpc_manager.run_rpc", return_value={}
        ) as run:
            response = servicer.Call(self.request(function_name, password), Context(peer))
        return response, run

    def test_disabled_global_does_not_gate_native_calls(self):
        with patch.dict(os.environ, {"REMOTERF_GLOBAL_ENABLED": "false"}):
            _, run = self.call("ACC:login", "ipv4:10.77.0.1:4444")
        run.assert_called_once()

    def test_relay_never_accepts_password_or_removed_destination_session(self):
        env = {
            "REMOTERF_GLOBAL_ENABLED": "true",
            "REMOTERF_GLOBAL_CONFIG_PATH": str(self.config),
        }
        with patch.dict(os.environ, env):
            for credential in ("password", "former-global-local-session"):
                response, run = self.call(
                    "ACC:login", "ipv4:10.77.0.1:4444", credential
                )
                run.assert_not_called()
                self.assertIn("ace", response.results)

    def test_non_relay_and_unrelated_calls_keep_existing_path(self):
        env = {
            "REMOTERF_GLOBAL_ENABLED": "true",
            "REMOTERF_GLOBAL_CONFIG_PATH": str(self.config),
        }
        with patch.dict(os.environ, env):
            _, direct = self.call("ACC:login", "ipv4:192.168.1.50:4444")
            _, unrelated = self.call("ACC:get_res", "ipv4:10.77.0.1:4444")
        direct.assert_called_once()
        unrelated.assert_called_once()


class RemovedGlobalAuthTests(unittest.TestCase):
    def test_global_auth_service_is_not_in_the_runtime_descriptor(self):
        self.assertNotIn("GlobalAuthV1", grpc_pb2.DESCRIPTOR.services_by_name)
        self.assertFalse(hasattr(grpc_server, "GlobalAuthV1Servicer"))
