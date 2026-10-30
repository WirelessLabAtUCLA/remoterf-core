# RemoteRF Federation Research Brief

## Purpose

This document describes the current RemoteRF implementation and a concrete
path from its current LAN-oriented, single-deployment model to a federation of
independent RemoteRF deployments.  It is intended as background for technical
design/research, not as a claim that federation is already implemented.

The target product experience is:

> A lab can install its own RemoteRF deployment, join a trusted RemoteRF
> network, and receive approved access to devices exported by another lab (for
> example, UCLA ADALM-Plutos).  That lab can later export selected devices of
> its own.  Every device owner retains final policy and reservation authority.

## Executive summary

RemoteRF already supports a related pattern: one **RemoteRF Server** accepts a
long-lived bidirectional gRPC connection from one or more **HostRF** agents.
The host owns physical hardware; the server treats it as a `VirtualDevice` and
forwards RPC/Dynamic-v2 requests through the host tunnel.

That is *not* deployment federation.  The current design has one controlling
server, one reservation database, integer global device IDs, and a host-agent
trust model.  Two independent `serverrf` deployments cannot currently discover
each other, exchange exports, delegate reservations, or use each other's
devices.

The recommended federation model is **owner-authoritative federation**:

```text
Deployment A                         Deployment B
------------                         ------------
users, DB, radios                    users, DB, radios
exports a device                     requests an approved export
  ^                                           |
  | owns policy, schedule, and lease          |
  +-------- authenticated peer request -------+
```

The deployment that physically owns a radio is always authoritative for:

- whether the device is exported;
- whether an incoming peer/delegated user may use it;
- reservation conflict detection and lease issuance;
- session expiration, revocation, and hardware safety controls;
- audit records for the actual device operation.

The consuming deployment may show a remote device in its own UI and make a
peer request, but it must not write the owner's database or independently
schedule the owner's hardware.

## Terms

| Term | Meaning in the proposed design |
| --- | --- |
| **Deployment** | An independently administered RemoteRF installation: its own server, users, database, policy, and one or more radios/HostRF agents. |
| **Owner deployment** | The deployment responsible for a device and its schedule. |
| **Consumer deployment** | A trusted peer deployment whose users are permitted to request an exported device. |
| **Federation peer** | A RemoteRF deployment speaking the new server-to-server protocol. It is an equal peer, not a hardware agent. |
| **Federation relay** | A publicly reachable routing/registration service used when peer deployments cannot dial one another because of NAT/firewalls. It must not become owner of peer devices or reservations. |
| **HostRF agent** | The existing edge process that owns hardware and connects to one RemoteRF server. It is not a federation peer. |
| **Lease/grant** | A short-lived, owner-issued authorization for one resource and one reservation/session scope. |

## Current repositories and roles

The workspace contains at least two relevant codebases:

| Repository | Current role |
| --- | --- |
| `RemoteRF-Server` | Main server: user accounts, groups, reservations, TLS gRPC services, device management, and host-tunnel registry/routing. |
| `RemoteRF-Host` | Host-side agent: inventories locally attached SDR hardware, connects to one RemoteRF Server, announces devices, and executes forwarded requests locally. |

The server package is Python (`remoteRF-server` 1.0.21) and the host package
is also Python.  The server README describes Linux deployment and explicitly
supports HostRF-owned devices, but there is no existing federation protocol or
deployment invitation workflow.

## Current implementation: what already exists

### Client-facing RemoteRF Server

`src/remoteRF_server/server/grpc_server.py` starts one TLS-enabled gRPC server
with these services registered on the main gRPC port:

- legacy `GenericRPC`;
- `DynamicControlV2` for schema negotiation, sessions, and operations;
- `SampleDataV1` for bidirectional sample frames;
- `HostTunnel`, when host-tunnel support is enabled.

The common protocol is in `src/remoteRF_server/common/grpc/grpc.proto`.
`DynamicControlV2` uses version negotiation, schema hashes, opaque session and
handle IDs, and structured `ErrorEnvelope` messages. `SampleDataV1` carries
binary payloads inside `SampleFrame`; the server config currently allows gRPC
messages up to 100 MiB.

The runtime binds to `REMOTERF_BIND_HOST` when set. Otherwise it derives a
non-loopback LAN address by opening a UDP socket toward `8.8.8.8`; it falls
back to `127.0.0.1`. The gRPC and certificate ports come from configuration.
This is ordinary server binding, not NAT traversal or public deployment
discovery.

### Existing Host Tunnel

`src/remoteRF_server/common/grpc/grpc_host.proto` defines one bidirectional
streaming RPC:

```proto
service HostTunnel {
  rpc Connect(stream HostFrame) returns (stream HostFrame);
}
```

The envelope supports:

- `HostHello`: `host_id`, version, host token;
- full `DeviceAnnounce` snapshots;
- `RpcRequest` and `RpcResponse`, correlated with `req_id` and deadline;
- heartbeats;
- cancellation;
- server-pulled metadata/capability responses.

The server implementation,
`src/remoteRF_server/host/host_tunnel_server.py`, maintains an in-memory
`HostTunnelRegistry`. It tracks active host sessions, device-to-host routes,
in-flight requests, heartbeat state, cached metadata, and a small persisted
host/device directory. It rejects duplicate active host IDs, expires failed
requests, and marks devices offline on disconnect.

The current tunnel is structurally useful for federation research because it
already demonstrates a reconnecting gRPC stream, request correlation,
heartbeats, cancellation, and routed remote execution. It must not be treated
as the federation protocol unchanged, however: it encodes a main-server to
hardware-host hierarchy.

### Current HostRF agent

`RemoteRF-Host/src/remoteRF_host/server/tunnel_agent.py` is the active-side
agent. It reads `REMOTERF_ADDR`, the optional CA/client certificate paths, a
stable `HOST_ID`, a host token, and a device inventory. It then:

1. opens a bidirectional `HostTunnel.Connect` gRPC stream to the configured
   RemoteRF Server;
2. sends `HostHello` and a full device announcement;
3. sends a heartbeat every 10 seconds;
4. receives forwarded RPC/meta/cancel frames;
5. executes the request using its local drivers and returns a correlated
   response;
6. reconnects with exponential backoff (configured from 1 to 30 seconds).

This agent makes an **outbound** connection. Therefore it can technically
operate across different routed networks today *if the target RemoteRF Server
has a reachable address, correct TLS certificate/DNS/IP subject name, and the
network allows the connection*. It does not solve the case where two
independent servers are both private behind NAT/firewalls, and it does not
create peer federation.

### Current identity and routing assumptions

The present host model makes a strong assumption that cannot survive
multi-deployment federation:

- a host announces `DeviceInfo.device_id` as a canonical decimal integer;
- the server converts it to an integer `gid`;
- a host device ID is assumed to be that server's global device ID;
- conflicting IDs from distinct hosts are rejected.

Examples are in `RemoteRF-Host/.../tunnel_agent.py` and
`RemoteRF-Server/src/remoteRF_server/server/device_manager.py`.
`HostTunnelRegistry.announce_devices` also rejects nonnumeric IDs and IDs with
leading zeroes. A local device with an already-used GID takes precedence over
a host `VirtualDevice`.

This is acceptable within one deployment where an administrator allocates all
device IDs. It is a hard blocker for federation because two independent labs
will naturally both have a device numbered `1` or `7`.

### Current reservations and permissions

`src/remoteRF_server/server/reservation.py` owns the `Accounts` and
`Reservations` SQLite tables. The reservation table stores an integer
`device_id`, start/end timestamps, and a salted/hash API token. The normal
reservation flow is:

1. client authenticates to the local deployment;
2. local server validates local user/group permissions;
3. local server checks reservation overlap for its integer device ID;
4. local server inserts the reservation and returns a token;
5. periodic device-state updates make an active reservation usable.

The existing authorization policy and user/group data are local to each
deployment. There is no peer identity, exported-resource policy, delegated
principal claim, remote reservation request, or cross-server audit model.

### Current remote operation path inside one deployment

For a HostRF-owned device, the server creates a `VirtualDevice` containing
`gid`, `host_id`, and `device_id`. `rpc_manager.py` forwards legacy device RPCs
through `HostTunnelRegistry`. `host_dynamic_v2.py` proxies Dynamic-v2
`GetSchema`, `OpenSession`, `Invoke`, close, and sample-frame operations by
serializing the protobuf request into a host tunnel RPC envelope.

`DynamicControlV2Servicer` checks whether a reservation token/session belongs
to a host `VirtualDevice`; if so, it sends the operation through that proxy.
`SampleDataV1Servicer` similarly forwards each remote sample frame through
the host-session proxy. The owner/main server is therefore in the data path
for host-owned sessions.

This is a useful control-plane starting point, but a federation design should
not permanently proxy high-rate IQ through an unrelated consumer deployment
or a public relay.

## Current security posture relevant to federation

The server's normal gRPC endpoint uses a server certificate and key via
`grpc.ssl_server_credentials`. The default credential loader does **not**
configure a client CA or require client certificates. Host tunnel access is
instead authenticated at the application layer by a stable host ID plus a
token carried in `HostHello`. Server-side token records are salted/hashed and
have an approved/disabled status.

The HostRF agent can be configured with a CA certificate and optional client
certificate/key. With the default server credentials, however, optional
client-certificate material is not sufficient by itself to make mTLS enforced
server-side.

For federation, this must be strengthened:

- every deployment needs a durable cryptographic identity;
- server-to-server connections should use mutual TLS, with a CA/issuer and
  certificate revocation/rotation process;
- peer authorization should be separate from transport authentication;
- per-device export policy must restrict each peer's requested operations,
  quota, time window, and TX/RX authority;
- owners should receive an auditable delegated subject, not another
  deployment's raw user password or reusable local API token;
- grants must be short-lived, audience-bound, resource-bound, and revocable.

Do not expose the current main gRPC port broadly to the Internet and call that
federation. The current service combines client APIs and host-tunnel traffic
and does not yet have the required peer policy/mTLS boundary.

## What the two UCLA-LAN servers can test now

Two isolated RemoteRF Server deployments on the same UCLA LAN are valuable.
They can test nearly all **federation semantics** before Internet connectivity
is involved:

- distinct deployment identities and separate databases;
- export catalog exchange;
- owner-side reservation acceptance/rejection;
- duplicate-reservation prevention;
- delegated-session issuance and expiration;
- remote Dynamic-v2 control proxying;
- revocation, offline peer state, and audit behavior;
- API/version compatibility checks.

They do **not** validate the following:

- NAT traversal or two private networks that cannot accept inbound traffic;
- public DNS and certificate subject-name validation;
- campus firewall/proxy behavior;
- WAN latency, packet loss, bandwidth constraints, or relay throughput;
- public enrollment/invitation abuse resistance.

To make the two test deployments genuinely independent, give them different
configuration/database roots, separate TLS certificates and ports, different
deployment IDs, and non-overlapping inventories. Do not point two tests at
the same `~/.config/remoterf` state directory.

## Network paths for different-LAN deployments

### Option 1: private overlay network for the MVP

Place both deployments on an encrypted private overlay/VPN. Each gets a
stable private overlay address, and peer gRPC uses that address with TLS. This
is the lowest-risk way to validate federation code because it removes NAT and
firewall discovery from the first milestone.

It is a valid inter-network test, but it is not the final onboarding product.
It requires each participating organization to install/configure an overlay
agent or equivalent private network access.

### Option 2: direct peer-to-peer mTLS

Each deployment exposes a dedicated federation endpoint and peers dial it
directly. This is viable only if at least the receiving endpoint has routable
DNS/IP, valid certificates, and explicit firewall rules. It is simple for a
small number of administratively cooperative labs, but it is brittle for
machines behind NAT, consumer ISPs, or restrictive campus networks.

### Option 3: outbound federation relay (recommended product topology)

Each deployment opens an outbound, long-lived, mutually-authenticated stream
to a public federation relay. The relay maintains only active connection
routing and enrollment/peer-directory state. It forwards an encrypted or
authenticated peer request to the owner deployment that is currently
connected.

```text
Deployment A (private LAN) -- outbound mTLS --> Federation relay <-- outbound mTLS -- Deployment B (private LAN)
         |                                                                    |
         +--- keeps A's DB and device authority                               +--- keeps B's DB and device authority
```

This is mechanically similar to the existing Host Tunnel, except that a
deployment is an equal peer and the relay must not take over peer reservation
authority. It avoids making each lab open an inbound firewall port. A relay
may be hosted by UCLA or another trusted operator, but its compromise should
not let it obtain unrestricted device authority.

For initial testing, start with Option 1; use Option 3 when the federation
semantics are correct and the goal is frictionless cross-LAN onboarding.

## Recommended target architecture

### 1. Separate control plane and data plane

**Control plane** is low bandwidth and must be strongly authorized:

- peer enrollment/trust;
- export catalog and availability events;
- reservation requests and lease lifecycle;
- session grants, Dynamic-v2 control calls, cancellation, audit events.

It can safely use a federation relay/tunnel in early deployments.

**Data plane** consists of SDR sample traffic. It can be large and latency
sensitive. For an initial proof of concept, proxying a small stream is fine.
For a scalable system, the owner deployment should issue an expiring
data-session ticket so the client reaches the owner directly over an approved
private/direct path. A relay fallback may be necessary, but it must apply
strict bandwidth quotas/backpressure and must not be the normal high-rate IQ
path.

### 2. Global resource references

Replace integer-only cross-deployment identity with a canonical reference:

```text
deployment_id: 550e8400-e29b-41d4-a716-446655440000
local_device_id: pluto-8
resource_ref:   remoterf://550e8400-e29b-41d4-a716-446655440000/pluto-8
```

`deployment_id` should be an immutable UUID, not a mutable display name. A
human-readable lab name and device label can be stored separately. Local
integer GIDs may remain as an implementation detail inside each deployment;
they cannot be the federation identifier.

### 3. Owner-authoritative reservations

Example for a user connected to Deployment B requesting an export owned by A:

1. B validates its own user and decides whether it will request the resource.
2. B sends A a signed/mTLS-authenticated `RequestReservation` message with a
   peer identity, a delegated principal identifier, resource reference,
   requested time range, requested capabilities, and idempotency key.
3. A validates peer trust and its export policy, checks A's own reservation
   database, and atomically creates or rejects the owner-side reservation.
4. A returns an opaque owner lease ID and an expiring grant, never a password
   or A's reusable user API token.
5. A records that B made the request on behalf of the delegated principal.
6. When the lease expires, A closes owner sessions and hardware state even if
   B is disconnected.

For a database migration, an owner-side reservation record needs at least a
text resource reference, owner lease ID, requesting peer deployment ID,
delegated subject, UTC start/end, capability scope, grant state, and
idempotency key. The current `Reservations.device_id INTEGER` schema is not
sufficient.

### 4. Deployment invitation and enrollment

The product feature "invite another deployment" should be a safe wrapper
around peer enrollment, not a shared secret pasted into a permanent config:

1. An owner admin creates a single-use, short-expiry invite with intended
   peer name/limits.
2. The consuming deployment presents the invite while generating its own key
   pair/certificate signing request.
3. The federation authority/owner approves the new deployment identity and
   pins/records its trust information.
4. Both sides record explicit policy: which resources are exported, RX/TX
   rights, reservation duration/count limits, and expiry/revocation rules.
5. The new peer opens its outbound mTLS connection and receives only its
   authorized export catalog.

For the first engineering milestone, manual configuration of two known peer
certificates is safer and faster. Build the invite UX only after the protocol
and policy decisions work.

## Proposed new protocol surface

Create a federation-specific protobuf contract. Do not reuse `HostTunnel` as
the public peer protocol, and do not put the new contract in independently
copied proto files in every repository. Publish it as one versioned
`remoterf-protocol` package/repository and generate language bindings from the
same source.

An illustrative minimum API is:

```proto
service FederationPeer {
  rpc ListExports(ListExportsRequest) returns (ListExportsResponse);
  rpc RequestReservation(RemoteReservationRequest) returns (RemoteLease);
  rpc CancelReservation(CancelRemoteReservationRequest) returns (Empty);
  rpc OpenDelegatedSession(OpenDelegatedSessionRequest)
      returns (DelegatedSessionGrant);
  rpc WatchExports(WatchExportsRequest) returns (stream ExportEvent);
}
```

Important message fields:

| Message/field | Why it is required |
| --- | --- |
| `deployment_id` | Stable peer identity; do not infer this from an IP address. |
| `protocol_version` and capabilities | Enables additive rollouts and rejects incompatible peer versions. |
| `resource_ref` | Global resource identity: owner deployment + owner-local device ID. |
| `request_id` / `idempotency_key` | Retries across a dropped stream must not create two reservations. |
| `issued_at`, `expires_at`, UTC | Prevents indefinite grants and enables clock-skew validation. |
| `delegated_subject` | Owner audit record without sharing passwords. |
| `scope` | Explicit RX/TX, methods, data rate, reservation, and quota authority. |
| `lease_id` / session grant | Opaque owner-managed authorization. |
| monotonic export event version | Allows a consumer to resynchronize a stale directory cache. |

For Option 3, a separate `FederationTunnel.Connect(stream FederationFrame)`
may carry the peer messages through the relay. It should have heartbeats,
request correlation, cancellation, bounded queues, reconnect/backoff, and
explicit behavior on disconnect—features that can be adapted from Host Tunnel.

## Suggested repository changes

The following names are suggestions, not existing files:

```text
shared remoterf-protocol repository/package
  federation.proto
  grpc.proto                  # move/own existing canonical contracts here
  grpc_host.proto

RemoteRF-Server
  src/remoteRF_server/server/federation/
    identity.py               # deployment ID, certificate/key references
    peer_registry.py          # trusted peers + connection state
    exports.py                # per-peer resource export policy
    service.py                # FederationPeer gRPC service
    reservation_delegate.py   # owner-side remote reservation creation
    proxy.py                  # consumer-side Dynamic-v2 control proxy
    grants.py                 # issue/validate/revoke scoped session grants
  tests/test_federation_*.py
```

Required refactors before federation is safe:

1. Introduce `ResourceRef` and remove the assumption that every remote device
   is an `int` GID. `VirtualDevice` may be extended or a separate
   `FederatedDevice` type can be introduced.
2. Migrate owner reservation records to reference text/UUID resources and add
   peer/delegation/lease state. Owner-side conflict handling must be
   transactional and idempotent.
3. Add a peer trust store and export policy store; do not reuse host-token
   records for peer deployments.
4. Add a federation service/proxy, keeping it separate from the local client
   and host-tunnel interfaces.
5. Decide client routing: initially consumer-server proxy; later direct-to-owner
   session tickets for data-plane traffic.
6. Generate all protobuf bindings from one canonical source and add protocol
   compatibility tests.

## Phased implementation and test plan

### Phase 0 — architecture tests on the UCLA LAN

Run two isolated deployments with different config/database directories,
ports, certificates, deployment IDs, and test devices. This phase does not
need a public relay.

Deliverables:

- `deployment_id` config/identity exists;
- static peer configuration trusts A and B through TLS;
- B can retrieve one export from A;
- B can ask A for a reservation; A owns the result;
- A returns a lease and rejects overlap/retry correctly;
- an audit entry exists at A;
- a mocked/fake device verifies one remote Dynamic-v2 control operation.

Failure tests:

- unknown/disabled peer;
- unexported resource;
- request retry with the same idempotency key;
- competing reservations from A and B;
- expired lease;
- revoked export;
- owner restart and consumer reconnect;
- owner disconnection during a session.

### Phase 1 — real hardware and LAN separation

Use an approved ADALM-Pluto and a safe RX-only operation. Verify an owner can
restrict the consumer to RX-only, cap duration, revoke access, and still
enforce a local reservation. Do not enable delegated TX until explicit safety
policy, identity, and auditing are proven.

### Phase 2 — different network transport

Put the two test deployments on an encrypted overlay/private network. Verify
the same test matrix with different addresses and induced latency/disconnects.
This confirms that the federation implementation does not rely on one Ethernet
segment.

### Phase 3 — outbound relay

Build or deploy a relay with no device authority. Both deployments connect
outward. Test offline routing, reconnect, queue limits, duplicate requests,
and cancellation. The relay should be able to tell a peer is connected, but
should not need access to local account databases or SDR drivers.

### Phase 4 — data-plane design

Measure expected sample rates, RTT, loss behavior, and relay bandwidth.
Implement direct owner data sessions using scoped, expiring tickets when the
network path permits, and make any relay fallback bounded and observable.

## Non-negotiable design decisions

- Do not synchronize or share all SQLite databases across deployments.
- Do not use global integer device IDs as a federation identifier.
- Do not expose the current all-in-one server endpoint publicly as the final
  federation boundary.
- Do not forward user passwords or reusable local reservation tokens between
  deployments.
- Do not assume the federation relay is trusted to control hardware.
- Do not make high-rate IQ relay through a central service by default.
- Do not launch with delegated TX permissions until explicit scope/policy,
  auditing, revocation, and safety behavior have been tested.

## Open research/design questions

1. What identity system should represent a peer deployment: private PKI, a
   RemoteRF-operated CA, SPIFFE-like workload identity, or another model?
2. Should delegated grants be JWT/PASETO-like signed tokens or opaque,
   owner-validated lease IDs? What revocation latency is acceptable?
3. Which exact user attributes may a consumer deployment assert to an owner?
   Is a shared organization identity provider required, or are peer-scoped
   service accounts sufficient initially?
4. What operations belong in the peer proxy, and which must be direct client
   to owner? How are Dynamic-v2 session/handle IDs namespaced?
5. What bandwidth/latency targets are realistic for ADALM-Pluto RX and TX over
   WAN paths? Which sample formats and chunk sizes should be supported?
6. What owner-side transaction/locking approach prevents overlaps under
   concurrent peer retries and multi-process/multi-server scale?
7. How should peer export events resume after a disconnect: full snapshot,
   event log cursor, or both?
8. How are certificate/grant rotation, peer suspension, emergency TX revoke,
   and incident audit handled?
9. Is the intended network one trusted organization, multiple universities,
   course instances, or a public multi-tenant service? The answer changes the
   identity, policy, privacy, and operational requirements.

## Copy/paste research prompt

```text
I am designing a federated SDR-lab platform called RemoteRF. Each deployment
is an independently administered RemoteRF Server with its own users,
reservation database, policies, and physically attached or HostRF-attached SDR
hardware. I want a trusted deployment to invite another deployment so that its
users can reserve approved exported radios (for example UCLA ADALM-Plutos),
while the owning deployment remains the sole authority for resource policy,
reservation conflict detection, leases, revocation, and hardware control.

The current code is Python/gRPC. It has a TLS RemoteRF Server, DynamicControlV2
and bidirectional SampleDataV1 services, and a HostTunnel bidirectional stream
between one main server and HostRF hardware agents. HostTunnel supports hello,
device announcements, request IDs, RPC response routing, heartbeats,
cancellation, reconnect, host-token authentication, and in-memory device
routing. It is hierarchical, not federation. Current device identity is an
integer global GID; host device IDs must be canonical decimal strings. Current
reservations are local SQLite rows keyed by integer device ID and local user
identity. There is no peer protocol, global resource ID, export policy,
delegated user claim, or federation relay. The default current server TLS does
not require client certificates; host access uses an application-level token.

Two independent deployments can be tested on the same LAN now, but the desired
product must work across unrelated LANs/NAT/firewalls. The likely target is an
owner-authoritative federation with each deployment opening outbound mTLS
connections to a public relay. The relay routes peer messages but is not the
owner of devices/reservations. Control traffic may be proxied initially; high
rate IQ should eventually use a direct-to-owner session with a short-lived,
resource-scoped ticket, with a bounded relay fallback.

Please produce a rigorous architecture recommendation. Address: (1) protocol
and protobuf API design, (2) deployment identity/mTLS/enrollment/invitation,
(3) scoped delegated authorization and revocation, (4) owner-authoritative,
idempotent reservation/lease transactions, (5) global resource identity and
session/handle namespacing, (6) NAT/relay/overlay-network transport options,
(7) SDR data-plane bandwidth/latency/backpressure, (8) threat model and safe
TX authorization, (9) phased implementation/testing plan from two LAN servers
to cross-network deployment, and (10) which parts of the existing HostTunnel
design can be reused versus must be replaced. Be explicit about tradeoffs,
failure modes, and minimum viable first implementation.
```
