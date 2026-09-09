# Gate B deployment capabilities

`global-dev` adds only `DeploymentCapabilitiesV1.GetCapabilities` beside the
protected RPC services. It uses protocol version `2` and imports the existing
ErrorEnvelope. `grpc.proto`, GenericRPC, DynamicControlV2 and SampleDataV1 are
unchanged. Standalone discovery returns a null deployment ID, gRPC accounts,
registration codes required, and email verification/federation disabled.
No keys, new native DB schema or Global connection are initialized by this
handler. Gate C removed GlobalAuthV1, and Gate G removed the retired Global-v1
connector/catalog/relay-ingress runtime. Federation v2 is the only Global
integration surface in the Server process.

The canonical file is `src/remoteRF_server/common/grpc/deployment_capabilities.proto`.
`scripts/generate-capabilities.py` runs the established grpc_tools.protoc
process with grpcio-tools 1.74.0/protobuf 6.31.1, and makes generated imports
package-relative. Copy these three capability files byte-for-byte to the
Client; never regenerate or renumber protected grpc.proto for this addition.

The independent core lives in `packages/remoterf-federation-core`, version
0.2.0, source commit `a627550e1915c79d385734fb5b25f53deaa5d5e0`. Install its
verified wheel before the Server wheel; it has no runtime dependencies.
The VPS repository's `dependencies/core.lock.json` and
`scripts/build-core-wheel.py` pin source, build tools and SHA-256:
`512c4b57fa16ab656f9a48c9c50e1e8da5a83830f48d71802d97803ee563b4c0`.
Consumers use a wheel, never sibling source or an editable core install.
This is a development package (`remoteRF-server 1.1.0.dev2`), not a replacement
for the pinned production `v1.0.20` artifact.
