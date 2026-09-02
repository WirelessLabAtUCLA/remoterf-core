# RemoteRF Global v1.0 — Security Model

## Threat model summary

There are three distinct credentials in play, and this feature is careful
never to blur them together:

1. **Deployment identity** (Ed25519, `~/.config/remoterf/global/deployment-private.pem`) —
   proves *this deployment* to Global. Never sent anywhere; only used to
   sign short-lived connector JWTs.
2. **Global user access assertion** (Ed25519-signed JWT, minted by Global,
   presented by the future client) — proves *a Global user* to this
   deployment. Verified fully locally against Global's published JWKS;
   Global is never asked "is this valid?" over the wire.
3. **Local RemoteRF session token** (this deployment's own
   `generate_token()`/`validate_token()` primitive, minted by
   `GlobalAuthV1.ExchangeAssertion`) — proves a Global-derived local shadow
   account to *this deployment's own* RPC surface. Never sent to Global.

## GlobalAuthV1.ExchangeAssertion verification rules

Implemented in `server/global_access/assertion_verifier.py`. Every
condition below is checked; the assertion is rejected (structured error,
no mapping/account/session created) on the first failure:

| Claim / check | Requirement |
| --- | --- |
| `alg` (JWT header) | Must be `EdDSA`. Any other algorithm — including HMAC signed with a guessed/stolen secret, or `none` — is rejected before the signature is even checked. |
| `kid` (JWT header) | Must resolve to a cached or freshly-fetched Ed25519 key (see JWKS section). |
| `iss` | Must equal the configured `global.yaml` `issuer` exactly. |
| `aud` | Must equal *this deployment's own* enrolled `deployment_id`. An assertion minted for a different deployment is rejected — a UUID typo or a replay against the wrong deployment both fail here. |
| `token_type` | Must equal `deployment_access`. |
| `scope` | Must include `remoterf:connect`. |
| `email_verified` | Must be `true`. |
| `sub` | Must be a non-empty string (treated as an opaque Global user UUID — see "Why `sub`, not email" below). |
| `jti` | Must be present, non-empty, and *not already consumed* (see replay protection). |
| `iat`/`exp` | Standard time validation with a small (30s default) clock-skew allowance; `exp - iat` must be ≤ 120 seconds — a longer-lived assertion is rejected outright, regardless of whether it's otherwise still "valid." |
| `nbf` (if present) | Same clock-skew handling via the underlying JWT library's leeway. |

Verification is delegated to `PyJWT`'s `jwt.decode(..., algorithms=["EdDSA"], audience=..., issuer=...)` for the well-trodden checks (signature, `iss`, `aud`, `exp`/`iat`/`nbf` skew) rather than hand-rolled — the additional
RemoteRF-specific checks (`token_type`, `scope`, `email_verified`, lifetime
cap, non-empty `jti`/`sub`) are layered on top in
`server/global_access/assertion_verifier.py`.

### Why `sub`, not email

`sub` (an opaque Global user UUID) is the stable identity key for the local
mapping (`GlobalPrincipalMappings.global_subject`), never the email. Email
addresses can change or be reused; the opaque subject cannot.

## JWKS cache & key-rotation model

`server/global_access/jwks_cache.py` fetches
`https://global.remoterf.net/.well-known/jwks.json` over standard HTTPS
validation.

- Keys are cached by `kid`, for `ttl_seconds` (default 300s) — a normal
  request never refetches within that window.
- An assertion whose `kid` isn't in the cache triggers **exactly one**
  forced refresh; if the `kid` is still unknown afterward, verification
  fails closed (`unknown_kid`).
- Concurrent unknown-`kid` lookups collapse onto a single in-flight HTTP
  fetch (a lock, not per-caller requests) — many simultaneous new-user
  logins can't cause a thundering herd against Global.
- Only `kty: "OKP", crv: "Ed25519"` entries are ever accepted from the JWKS
  document — any other key type (including a symmetric `oct` key, which
  would otherwise be a dangerous algorithm-confusion vector) is silently
  skipped during parsing, never cached, never usable.
- If Global is unreachable but a previously-cached key is still fresh
  (within `ttl_seconds`), verification may continue using it. If there is
  no usable cached key at all and Global is unreachable, verification
  fails closed — it does not fall back to accepting anything.

## Assertion replay protection

`GlobalAssertionJTIs (issuer, jti)` in `global.db`, `UNIQUE(issuer, jti)`.
Consuming a `jti` is an atomic insert — a duplicate insert (same assertion
presented twice, e.g. because the client never saw the first response) is
the replay signal, handled as a clean `replayed` error rather than a crash.
Expired rows are pruned opportunistically on each exchange (bounded, no
unbounded growth). The complete JWT is never stored — only `(issuer, jti,
global_subject, expires_at, consumed_at)`.

## Global principal mapping

`GlobalPrincipalMappings (issuer, global_subject) UNIQUE`, in `global.db`.
On the first successful assertion for a given `(issuer, subject)`:

1. A deterministic, PII-free local username is derived:
   `global-<sha256(issuer|subject)[:20]>` — deterministic so a genuine
   concurrent first-login race converges on the *same* shadow account
   rather than creating duplicates (both `Accounts.username` and
   `GlobalPrincipalMappings(issuer, global_subject)` carry real SQL
   `UNIQUE` constraints; the losing side of any race simply re-reads the
   winner's row).
2. A JIT shadow `Accounts` row is created with `auth_type =
   'remoterf_global'` (see next section).
3. It is added to the operator-configured `public_group` (only) via the
   existing group membership table — never elevated beyond that.
4. Normal-User perms are assigned (`perms.set_user`), so the existing
   group-quota reservation logic (`acc_perms.py` / `user_group_handler.py`)
   applies uniformly to Global-derived accounts.

Every subsequent assertion for the same subject reuses that same mapping
and account — verified directly in
`tests/test_global_principal_mapping.py`.

## External-only local accounts

A Global-derived `Accounts` row can **never** authenticate via password:

- Its `pass_salt`/`pass_hash` are set once, at creation, to the hash of a
  32-byte random value that is immediately discarded and never returned to
  anyone — not a fake "reusable" password, not a deterministic function of
  the Global subject.
- `reservation.py`'s `login_user()` checks `auth_type` first: for
  `remoterf_global` accounts, the `password` field the client sends is
  checked against `global.db`'s `GlobalLocalSessions` table (a proper
  salted/hashed, expiring session credential minted only by
  `ExchangeAssertion`) — **never** against `Accounts.pass_hash`. A guessed
  real password can never match a live session-token hash.
- Its email is a `*.invalid` placeholder (RFC 2606-reserved TLD) — schema
  requires a non-null unique email, but nothing about it is a fabricated
  real-looking address.

This is also why no new RPC surface was needed to make the exchanged
credential usable: the future client calls the *existing, unmodified*
`login`/`get_res`/`reserve_device`/etc. RPCs with
`un=<local_username>, pw=<local_session_token>` — `login_user`'s one
additive branch (and nothing else in `reservation.py`'s dispatch) is what
makes that work.

## Public group

The operator must create the configured `public_group` themselves, using
the existing group CLI, *before* any Global user can successfully
authenticate — `ExchangeAssertion` returns a clear `public_group_missing`
error rather than silently granting broader access or skipping the group
assignment. See `docs/remoterf-global-exports.md`.

## Local session lifetime

`GlobalLocalSessions.expires_at`, controlled by
`REMOTERF_GLOBAL_LOCAL_SESSION_MINUTES` (default 60). A Global assertion
never creates an indefinitely valid local session:

- The local session expires on its own regardless of Global's own
  availability — an already-issued local session survives a Global outage
  (see "Global outage" below), it just can't be *renewed* without a fresh
  assertion from Global.
- The owning operator can revoke a subject's active sessions immediately:
  `serverrf --global revoke-sessions <global-subject>` — revocation takes
  effect on the next RPC that would validate that session (no polling
  delay; `GlobalLocalSessions.revoked_at` is checked directly).
- Ordinary LAN account sessions (there is no session concept for them at
  all — see the main doc) are completely unaffected by this setting.

## Relay-ingress restrictions

`server/global_access/ingress_policy.py` classifies `context.peer()`
against `REMOTERF_GLOBAL_RELAY_PEER_CIDRS` /
`global.yaml`'s `relay_ingress.trusted_peer_cidrs` (e.g. `10.77.0.1/32`,
the VPS's WireGuard address). This is the **only** use of peer-address
information anywhere in this feature, and it only ever *restricts*, never
*grants*, trust:

- From a trusted relay peer: `ACC:login` and `ACC:create_user` (password
  login, account creation) are refused outright — a legitimate LAN client
  never appears as the relay's WireGuard address, so any such attempt
  arriving that way is presumptively a public-Internet client trying to
  brute-force or mint UCLA-local credentials through the relay.
  `GlobalAuthV1.ExchangeAssertion` itself is *not* gated by this check (its
  own cryptographic verification is the real gate) — it's meant to be
  reachable from the relay.
- From any other peer (ordinary LAN clients, or Global disabled entirely):
  no behavior change whatsoever.
- If Global is enabled but `global.yaml` fails to load, this check simply
  cannot evaluate — it degrades to "not gated" (same as disabled), it
  never *opens* a hole by treating a misconfiguration as "everyone is
  trusted." (`tests/test_global_grpc_wiring.py::test_misconfigured_global_never_opens_a_hole`.)
- No header is ever trusted — only the actual gRPC peer address from
  `context.peer()`. PROXY protocol is not implemented in this task.

## Operation policy (TX/unsafe-operation denial)

See `docs/remoterf-global-exports.md` for the full allowlist mechanism.
Summary: every Global-principal session is deny-by-default for every
device operation, both on the legacy `GenericRPC` surface and
`DynamicControlV2.Invoke`, and TX/client-sample-upload is denied by default
on `SampleDataV1`. Ordinary LAN/local accounts never pass through any of
this — `is_global_principal(username)` (keyed off `Accounts.auth_type`) is
checked first, and the whole policy layer is a complete no-op when it's
`false` or when Global is disabled.

## Local disable / revocation

Two independent controls, not to be confused with each other:

- **Global disable** (at the issuer): would prevent Global from minting
  further assertions for that user. This deployment has no visibility into
  or control over that — it's Global's own responsibility.
- **UCLA-local disable** (`serverrf --global disable-mapping <subject>`):
  immediate, owner-side, and entirely independent of Global's own state.
  A locally-disabled mapping rejects `ExchangeAssertion` for that subject
  even if the presented assertion is cryptographically perfect — checked
  *before* any account/session work happens.
  `serverrf --global enable-mapping <subject>` reverses it.
  `serverrf --global revoke-sessions <subject>` additionally invalidates
  any already-issued local sessions immediately, independent of
  disable/enable state.

## Global outage behavior

| Failure | Local behavior |
| --- | --- |
| Global VPS unreachable | Server still starts; local login/reservations/HostRF unaffected; connector retries with exponential backoff (1s-60s, jittered, reset on next success); no key rotation, no data loss, no tight failure loop. |
| JWKS endpoint unreachable | A still-fresh cached key may continue to verify assertions; an assertion with an unknown key and no reachable JWKS endpoint fails closed. Local (non-Global) users are entirely unaffected either way. |
| `global.yaml` invalid/missing | Server still starts. Connector/catalog publication is disabled (logged clearly). `GlobalAuthV1.ExchangeAssertion` returns `global_misconfigured`. The relay-ingress restriction degrades to "not evaluated" (see above) — it never opens instead of closes. |
| Deployment disabled by Global (hypothetical, Global-side) | Future connector requests would presumably fail (401/403) once Global implements this; this deployment already treats any non-2xx connector response as a publish failure and retries with backoff — no unsafe fallback path exists locally regardless. |
| Local mapping disabled | New exchanges rejected immediately; already-issued sessions can be revoked separately with `revoke-sessions`. |
| Assertion expired/replayed/forged | Rejected; no mapping/account/session is ever created; no secret is logged. |
| Connector stopped (`ServerRuntime.stop()`) | RemoteRF server (LAN, HostRF, everything) keeps working; only Global publication stops. |

## Logging / audit

`server/global_access/audit.py` refuses (raises `ValueError`) if a caller
ever tries to pass a field literally named `jwt`, `token`, `assertion`,
`private_key`, `password`, `password_hash`, `enrollment_token`,
`reservation_token`, `bearer`, or `session_token` — a structural guard
against accidentally logging a secret, not just a promise. Safe events
recorded: enrollment, connector heartbeat success/failure, route/catalog
publication, valid assertion exchange, rejected-assertion category (the
`code`, never the assertion), JIT mapping creation, local mapping
disable/enable, session issuance/revocation. Identifiers used: deployment
UUID, Global subject UUID, local account/device/reservation id, request id,
event type — never the relay's source IP presented as if it identified the
end user (see next section).

## Known limitation: client attribution over the v0 relay

Every publicly-relayed connection appears at the TCP layer as the VPS's
WireGuard address (`10.77.0.1`), not the original Internet client's real
address — this is an accepted, documented limitation of the v0 relay, not
something this feature works around with PROXY protocol or similar. Use
the Global-subject ↔ local-account mapping for attribution instead of the
relay's source IP. Real per-client network-level attribution is future
RemoteRF Global identity/audit work.

## Current limitations (be precise about what this is)

- The real `remoterf-vps-global` API contract does not exist yet (as of
  this work) — everything here is built against a documented, isolated
  assumption (`server/global_access/api_client.py`) and will need
  reconciliation once it's built.
- No client-side implementation exists — see the main doc's "What still
  belongs to the client" section.
- `set_mapping_status`/`revoke_sessions_for_mapping` key off
  `global_subject` alone (not `(issuer, subject)`) for CLI convenience —
  correct for the expected v1.0 reality of one deployment enrolled with
  exactly one Global issuer; would need tightening if multi-issuer support
  is ever added.
- Legacy `GenericRPC` operation identifiers are matched as literal
  `prop:verb` strings against the operator's `allow_operations` list —
  there is no schema-driven capability introspection wired into that
  allowlist check (the operator is responsible for confirming real
  operation identifiers against each device's actual schema, per
  `docs/remoterf-global-exports.md`).
