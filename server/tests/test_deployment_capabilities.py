import hashlib
import subprocess
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
import grpc
from remoterf_federation_core import validate_capabilities
from remoteRF_server.common.grpc import deployment_capabilities_pb2 as pb
from remoteRF_server.common.grpc import deployment_capabilities_pb2_grpc as rpc
from remoteRF_server.server.deployment.capabilities import register_capabilities


class CapabilityTests(unittest.TestCase):
    def test_real_rpc_without_identity_or_network_initialization(self):
        server = grpc.server(ThreadPoolExecutor(max_workers=2))
        register_capabilities(server)
        port = server.add_insecure_port('127.0.0.1:0')
        server.start()
        try:
            with grpc.insecure_channel(f'127.0.0.1:{port}') as channel:
                stub=rpc.DeploymentCapabilitiesV1Stub(channel)
                response=stub.GetCapabilities(pb.DeploymentCapabilitiesRequest(protocol_version='2'),timeout=2)
                caps=validate_capabilities(response.capabilities_json)
                self.assertIsNone(caps['deployment_id'])
                self.assertFalse(caps['federation_enabled'])
                self.assertFalse(caps['registration_policy']['email_verification_required'])
                self.assertTrue(caps['registration_policy']['enrollment_code_required'])
                error=stub.GetCapabilities(pb.DeploymentCapabilitiesRequest(protocol_version='1'),timeout=2)
                self.assertEqual(error.error.code,'unsupported_version')
                self.assertFalse(error.capabilities_json)
        finally:
            server.stop(0).wait()

    def test_protected_proto_bytes(self):
        root=Path(__file__).resolve().parents[1]
        path='src/remoteRF_server/common/grpc/grpc.proto'
        base=subprocess.check_output(['git','show','1452ad042782c659a2891e84e8d72f9d1ba3d9a1:'+path],cwd=root)
        core=root/'packages/remoterf-device-core/src/remoterf_device_core/grpc/grpc.proto'  # moved here, same bytes
        self.assertEqual(base,core.read_bytes())
        fields=pb.DeploymentCapabilitiesResponse.DESCRIPTOR.fields_by_name
        self.assertEqual(fields['capabilities_json'].number,1)
        self.assertEqual(fields['error'].number,2)
        self.assertEqual(fields['error'].message_type.full_name,'remote_rf.ErrorEnvelope')
