"""Read-only Gate B discovery. No federation keys, DBs or connector imports."""
from remoterf_federation_core import canonical_json, local_capabilities
from ...common.grpc import grpc_pb2, deployment_capabilities_pb2 as pb
from ...common.grpc import deployment_capabilities_pb2_grpc as rpc


class DeploymentCapabilitiesServicer(rpc.DeploymentCapabilitiesV1Servicer):
    def GetCapabilities(self, request, context):
        if request.protocol_version != "2":
            return pb.DeploymentCapabilitiesResponse(error=grpc_pb2.ErrorEnvelope(
                code="unsupported_version", message="Supported deployment protocol: 2"))
        return pb.DeploymentCapabilitiesResponse(capabilities_json=canonical_json(local_capabilities()))


def register_capabilities(server):
    rpc.add_DeploymentCapabilitiesV1Servicer_to_server(DeploymentCapabilitiesServicer(), server)
