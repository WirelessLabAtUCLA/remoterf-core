import hashlib
from pathlib import Path

from remoteRF_server.common.grpc import federation_pb2


def test_federation_proto_source_hash_and_descriptor_are_canonical():
    root = Path(__file__).resolve().parents[1]
    proto = root / "src/remoteRF_server/common/grpc/federation.proto"
    protected = root / "packages/remoterf-device-core/src/remoterf_device_core/grpc/grpc.proto"
    assert hashlib.sha256(proto.read_bytes()).hexdigest() == (
        "e890c399b61e8eb92e67762661c0ce99f3daacdb06b0139b34f26a749ff736c1"
    )
    assert hashlib.sha256(protected.read_bytes()).hexdigest() == (
        "5fce641a1dc3832a4fb1bfec0e3b4044291d6fdd575cd3abe86893af66b111c6"
    )
    descriptor = federation_pb2.DESCRIPTOR
    assert descriptor.package == "remote_rf"
    method = descriptor.services_by_name["FederationV2"].methods_by_name["Execute"]
    assert method.input_type.full_name == "remote_rf.FederationRequest"
    assert method.output_type.full_name == "remote_rf.FederationResponse"
    request = descriptor.message_types_by_name["FederationRequest"]
    assert [(field.name, field.number) for field in request.fields] == [
        ("protocol_version", 1),
        ("grant", 2),
        ("request_json", 3),
        ("frame", 4),
        ("accept_detached", 5),
    ]
    response = descriptor.message_types_by_name["FederationResponse"]
    assert [(field.name, field.number) for field in response.fields] == [
        ("protocol_version", 1),
        ("signed_result", 2),
        ("error", 3),
        ("frame", 4),
    ]
    assert response.fields_by_name["error"].message_type.full_name == "remote_rf.ErrorEnvelope"
