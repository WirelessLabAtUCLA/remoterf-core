# RemoteRF Global v1.0 — Server Setup

This document describes the server-side half of RemoteRF Global v1.0: what
this RemoteRF Server deployment does when it opts into RemoteRF Global, what
stays entirely local, and exactly what is (and is not) implemented.

See also:
- `docs/remoterf-global-enrollment.md` — enrollment flow, identity, local dev/test procedure.
- `docs/remoterf-global-security.md` — the full trust/verification model.
- `docs/remoterf-global-exports.md` — export config, reservation/operation policy.
- `FEDERATION_RESEARCH_BRIEF.md` — a separate, complementary research document
  about deployment-to-deployment federation (owner-authoritative peer
  federation). RemoteRF Global is a different, simpler thing: a centralized
  optional coordination layer, not peer-to-peer federation. Nothing in that
  brief is implemented by this work, and nothing here implements it either.

## 1. RemoteRF Global is optional

`REMOTERF_GLOBAL_ENABLED` defaults to `false`. With Global disabled:

- no connector thread starts;
- no outbound network request to Global is ever made;
- no Global identity or config file is required to exist;
- `GlobalAuthV1.ExchangeAssertion` is still registered on the gRPC server
  (additive, harmless) but always returns a structured `error.code =
  "global_disabled"` response;
- every existing LAN/local code path — accounts, login, reservations,
  groups, HostRF, DynamicControlV2, SampleDataV1, legacy GenericRPC —
  behaves exactly as it did before this feature existed.

This independence is load-bearing, not incidental: this deployment must
keep working even if `global.remoterf.net` is offline or never existed.

## 2. Owner-authoritative architecture

Global never becomes authoritative over anything this deployment owns.
Specifically, Global:

- does not own reservations — there is no Global reservation table, and
  Global is never called to check reservation conflicts;
- does not own devices — device export is entirely operator-configured
  (`global.yaml`'s `exports:` list) and enforced locally;
- does not store IQ data — no sample data ever crosses the Global control
  plane, only heartbeats/route/catalog metadata;
- does not receive local passwords or reusable local API/reservation
  tokens — see `docs/remoterf-global-security.md`;
- cannot create or elevate a local account beyond what this deployment's
  own reservation/group/perm systems already allow.

UCLA (or any operator deploying this) remains the final authority for
whether a device is exported, whether an identity may use it, reservation
creation/limits, session issuance/expiration/revocation, and hardware
safety enforcement.

## 3. What the outbound connector publishes

When enabled and enrolled, a single background thread
(`server/global_access/connector.py`) periodically:

- signs a short-lived (~2 minute) Ed25519 deployment JWT;
- publishes **route** metadata: the public relay hostname/ports and the
  active CA's SHA-256 fingerprint (derived from the real `ca.crt`, never
  hardcoded) — never an internal WireGuard/LAN address;
- publishes a **catalog** snapshot of only the explicitly-configured
  exports, with safe metadata only (no IPs, serials, filesystem paths,
  tokens);
- sends a **heartbeat** with safe metadata (deployment id, protocol/server/
  connector versions, catalog version, an ephemeral process instance id) —
  never passwords, tokens, account lists, or IQ.

See `docs/remoterf-global-exports.md` for the exact catalog fields, and the
"Connector" section below for lifecycle/backoff behavior.

## 4. Deployment enrollment (summary)

Full details: `docs/remoterf-global-enrollment.md`. In short: the operator
generates a local Ed25519 keypair (`serverrf --global init-identity`), then
exchanges a one-time Global-issued enrollment token plus the deployment's
public key for an immutable `deployment_id` (`serverrf --global enroll`).
The private key never leaves the machine; the enrollment token is never
persisted after use.

## 5. Deployment private-key storage

`~/.config/remoterf/global/` (or wherever `deployment_private_key_path`
points):

```
deployment-private.pem   0600, Ed25519 private key. Never printed, never logged.
deployment-public.pem    Ed25519 public key (safe to share/print).
deployment.json          non-secret: deployment_id, slug, display_name,
                          protocol_version, enrolled_at, issuer, api_base_url.
```

`serverrf --global init-identity` refuses to overwrite an existing identity.
Regenerating identity changes the deployment's cryptographic identity and
requires re-enrollment — it is a deliberate, manual, one-way operation.

## 6. Signed connector JWTs

Every connector request (heartbeat/route/catalog) is authenticated with a
freshly signed EdDSA JWT, not a long-lived bearer token:

```
iss = deployment:<deployment-uuid>
sub = <deployment-uuid>
aud = <base_url>/v1/deployment
iat, exp (~120s max lifetime), jti (fresh per request)
token_type = deployment_connector
```

No private key is ever transmitted; no JWT is ever logged.

## 7. Heartbeats

Sent every `heartbeat_seconds` (default 30) while the connector is running.
Global's own online/offline computation from heartbeat freshness (using
`offline_seconds`) is entirely Global-side — this deployment does not
implement or depend on that logic. Stopping the RemoteRF server stops
heartbeats naturally (the connector thread is `daemon=True` and is also
explicitly `stop()`-ed by `ServerRuntime.stop()`); starting it resumes them.

## 8. Route publication

See section 3. `server/global_access/route.py`'s `build_route_payload`
additionally **refuses to publish** if the configured `route.tls_server_name`
isn't actually present as a DNS SAN on the active `server.crt` — a route a
client's own TLS validation would reject is worse than not publishing at
all. Regenerate certs with the DNS SAN if this ever fires:

```bash
serverrf --gen-certs <lan-ip> --dns <your-public-hostname> --force
```

## 9. Catalog snapshots/versioning

Full-snapshot semantics: every successful publish sends the complete
current export list, not a diff. A monotonically increasing version number
is persisted locally (`GlobalCatalogState` in `global.db`); a canonical
(sorted-key, compact) JSON hash decides whether content actually changed —
unchanged content keeps the same version (safe to retry after a dropped
connection), changed content bumps it. `serverrf --global publish-now`
forces an out-of-band publish through the same code path used by the
background loop.

## 10. GlobalAuthV1.ExchangeAssertion

Additive gRPC service, registered on the existing TLS port (no new port).
Exchanges a short-lived RemoteRF Global user access assertion for local
RemoteRF authentication material — see
`docs/remoterf-global-security.md` for full verification rules and
`docs/remoterf-global-exports.md` for what happens after a successful
exchange (mapping, group assignment, policy).

## 11. JWKS verification

Assertions are verified against `https://global.remoterf.net/.well-known/jwks.json`
(EdDSA/Ed25519 only — symmetric keys and any other algorithm are always
rejected). See `docs/remoterf-global-security.md` for the cache/rotation
model.

## 12. Global principal mapping / external-only accounts / public group /
    relay-ingress / reservation quotas / operation policy / local
    disable+revocation / outage behavior

All covered in depth in `docs/remoterf-global-security.md` and
`docs/remoterf-global-exports.md`.

## Current v0 TCP relay

RemoteRF Global v0 (already shipped, unrelated to this v1.0 work) is a dumb
Layer-4 TCP relay: `ucla.global.remoterf.net` → DigitalOcean VPS (HAProxy,
`mode tcp`) → WireGuard → this RemoteRF Server, unmodified. v1.0 does not
change that transport at all — it adds an *entirely separate* control-plane
relationship (this server ↔ Global's API) alongside the existing data-plane
relay. A v1.0-enabled deployment's ordinary RemoteRF traffic still flows
exactly as it did under v0.

## Future P2P work — not implemented

Nothing in this codebase implements or depends on: NAT traversal, STUN/TURN,
direct peer-to-peer data transport, a new relay implementation, private
deployment-to-deployment federation, cross-deployment reservation
delegation, or synchronized/copied databases between deployments. Those
remain future work, tracked separately (see `FEDERATION_RESEARCH_BRIEF.md`
for the federation angle specifically).

## What the actual VPS API contract turned out to be

As of this work, `remoterf-vps-global` (inspected read-only, not modified)
implements only `GET /` and `GET /health` — none of the `/v1/deployment/*`
endpoints, the JWKS endpoint, or assertion issuance exist yet. Every
outbound HTTP call this deployment makes is isolated behind
`server/global_access/api_client.py`, and every assumption about the wire
format is documented there and in
`docs/remoterf-global-security.md`. When the real VPS-side contract is
built, expect to reconcile field names/shapes against that one file rather
than a scattered set of call sites.

## What still belongs to the client

The RemoteRF client (a separate repository) still needs to implement, none
of which exists yet and none of which this work built:

- Global device-code login (obtaining a Global user identity at all);
- deployment discovery/selection (finding "UCLA" via Global);
- retrieving the connection descriptor (the published route);
- requesting a UCLA-targeted access assertion from Global;
- calling `GlobalAuthV1.ExchangeAssertion`;
- storing and using the returned local RemoteRF session material
  (`local_username` + `local_session_token`) against the existing,
  unmodified `login`/`get_res`/`reserve_device`/etc. RPCs.

The VPS and client integration are explicitly out of scope for this task
and will be tested separately once they exist.
