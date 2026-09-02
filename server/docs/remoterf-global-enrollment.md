# RemoteRF Global v1.0 — Enrollment & Local Development

## Deployment identity

Each RemoteRF deployment has a durable Ed25519 keypair, independent of TLS
certificates, HostRF host tokens, Global user assertions, and local
RemoteRF account tokens:

```bash
serverrf --global init-identity
```

Creates (under `~/.config/remoterf/global/`, or the directory implied by
`global.yaml`'s `deployment_private_key_path` once that config exists):

```
deployment-private.pem   mode 0600, never printed/logged, never overwritten
                          by a later init-identity call.
deployment-public.pem     safe to print/share.
deployment.json           non-secret enrollment state (starts unenrolled).
```

```bash
serverrf --global show-public-key   # prints ONLY the public key
```

## Enrollment flow

```bash
serverrf --global enroll \
  --base-url https://global.remoterf.net \
  --slug ucla \
  --display-name "UCLA WirelessLab" \
  --token-stdin
```

1. Operator has already run `init-identity`.
2. A Global administrator issues a one-time enrollment token out of band.
3. This command sends: the enrollment token, intended slug/display name,
   this deployment's Ed25519 public key, and the protocol version — over
   normal HTTPS certificate validation (never `verify=False`).
4. Global returns: an immutable `deployment_id` (UUID), the assigned slug,
   the Global issuer URL, and the supported protocol version.
5. That non-secret state is written to `deployment.json`. The enrollment
   token is discarded — it is never written to disk, never logged, and
   `--token-stdin`/hidden-prompt input means it never needs to sit in shell
   history either.
6. Enrolling an already-enrolled deployment is refused — delete
   `deployment.json` manually first if re-enrollment is really intended.
7. A failed enrollment attempt (bad token, network error, non-2xx
   response) leaves any existing identity/state files untouched.

The deployment's cryptographic identity (its keypair) never changes across
DNS/IP changes — enrollment ties a slug/display name to that identity, not
the other way around.

## Other CLI commands

```bash
serverrf --global status              # enabled?, identity present/enrolled?, config OK?
serverrf --global validate-config     # strict global.yaml validation (see exports doc)
serverrf --global publish-now         # force one route+catalog+heartbeat publish
serverrf --global list-mappings       # list Global principal <-> local account mappings
serverrf --global disable-mapping <global-subject>
serverrf --global enable-mapping <global-subject>
serverrf --global revoke-sessions <global-subject>
```

`status` and `list-mappings` never print secrets (no tokens, no private
key material).

## Local development and test procedure

None of this requires the real production Global VPS — everything below
uses a local mock server and a locally-generated test issuer keypair.

### 1. Create an isolated test config root

```bash
export XDG_CONFIG_HOME=$(mktemp -d)
```

Every `serverrf`/`get_db_dir()`-based path (`~/.config/remoterf/...`)
follows `XDG_CONFIG_HOME` when set — this fully isolates the test run from
your real config. (`REMOTERF_CONFIG_DIR` is respected by the `serverrf`
port/device config paths but *not* by the underlying `db`/`certs` helpers —
use `XDG_CONFIG_HOME` for full isolation, matching the test suite's own
convention in `tests/test_global_*.py`.)

### 2. Initialize a deployment identity

```bash
serverrf --global init-identity
serverrf --global show-public-key
```

### 3. Enroll against a mock Global server

Run a trivial local HTTP server that answers `POST /v1/deployment/enroll`
with a JSON body containing `deployment_id`/`slug`/`issuer`/`api_base_url`/
`supported_protocol_version` (see `tests/test_global_principal_mapping.py`
and the enrollment test in `tests/test_global_accounts_migration.py`'s
sibling test files for a working `http.server`-based example), then:

```bash
serverrf --global enroll --base-url http://127.0.0.1:8765 \
  --slug ucla --display-name "Test Lab" --token test-token-123
```

(A `http://` base URL is only ever accepted because this is a local test
fixture reachable at `127.0.0.1` — the strict `https://`-only rule in
`global.yaml` validation has no test-only bypass exposed through the CLI;
local tests instead call `parse_global_config(..., allow_insecure_transport=True)`
directly, as `tests/test_global_config.py` does.)

### 4. Validate export configuration

Write a `global.yaml` (see `docs/remoterf-global-exports.md` for the full
schema), then:

```bash
serverrf --global validate-config
```

### 5. Start RemoteRF with Global enabled

```bash
REMOTERF_BIND_HOST=0.0.0.0 \
REMOTERF_GLOBAL_ENABLED=true \
REMOTERF_GLOBAL_CONFIG_PATH=$XDG_CONFIG_HOME/remoterf/global/global.yaml \
serverrf --serve --headless
```

### 6. Observe connector heartbeats

The connector logs a bounded `connector_heartbeat_ok` line (via
`server/global_access/audit.py`) on every successful publish cycle, and a
bounded `connector_publish_failed` warning on failure — never a raw
traceback, never a secret.

### 7. Exercise GlobalAuthV1 using a locally generated test issuer/key

Generate an Ed25519 keypair standing in for Global's own signing key, serve
it as a JWKS document (or just patch `requests.get` in a test, as
`tests/test_global_crypto.py` and `tests/test_global_principal_mapping.py`
do), mint a `deployment_access` token with `aud` = this deployment's
enrolled `deployment_id`, and call `GlobalAuthV1.ExchangeAssertion` with a
plain grpc Python client against `serverrf`'s existing TLS port.

### 8. Verify JIT local mapping

```bash
serverrf --global list-mappings
```

should show one row per distinct Global subject that has successfully
exchanged an assertion.

### 9. Verify relay-ingress password-login denial

With `REMOTERF_GLOBAL_ENABLED=true` and `relay_ingress.trusted_peer_cidrs`
configured, a `GenericRPC.Call` for `ACC:login` or `ACC:create_user` whose
`context.peer()` matches a trusted CIDR is rejected before it reaches
`rpc_manager` at all (see `tests/test_global_grpc_wiring.py` for a
same-process reproduction that doesn't require a real network peer).

### 10. Verify ordinary LAN login remains functional

The same `ACC:login` call from any peer address *not* in
`trusted_peer_cidrs` behaves exactly as it always has —
`tests/test_global_grpc_wiring.py::test_non_relay_peer_is_never_gated`
covers this directly.

### 11. Create a safe test reservation

Using the JIT-mapped local account's `local_username`/`local_session_token`
(from step 7-8) exactly like an ordinary RemoteRF client would use
`un`/`pw`, exercise the existing `reserve_device`/`get_res`/`cancel_res`
RPCs against one of the exported test devices. Local reservation
overlap/quota logic is unchanged and fully authoritative.

### 12. Test Global outage behavior

Stop the mock Global HTTP server (or point `base_url`/`jwks_url` at an
unreachable address) and confirm:

- the connector logs bounded `connector_publish_failed` warnings and keeps
  retrying with exponential backoff — it never crashes the process;
- local login/reservation/HostRF continue working throughout;
- `GlobalAuthV1.ExchangeAssertion` for a *brand-new* Global subject fails
  closed once the JWKS cache has no valid key to check against (see
  `docs/remoterf-global-security.md`'s JWKS section) — it does not fall
  back to trusting an unverifiable assertion.
