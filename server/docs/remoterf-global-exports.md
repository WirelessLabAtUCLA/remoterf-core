# RemoteRF Global v1.0 — Exports, Quotas, and Operation Policy

## `global.yaml` — required vs. optional

Location: `REMOTERF_GLOBAL_CONFIG_PATH`, or
`~/.config/remoterf/global/global.yaml` by default. Loaded and strictly
validated by `server/global_access/config.py` (manual validation, in the
same style as this repo's existing `devices.yml` handling — no schema
library). Unknown keys anywhere in the document are a hard error.

```yaml
global:
  # ---- required ----
  enabled: true
  base_url: https://global.remoterf.net          # must be https:// (see note below)
  issuer: https://global.remoterf.net             # must be https://
  jwks_url: https://global.remoterf.net/.well-known/jwks.json   # must be https://
  deployment_state_path: /home/remoterf/.config/remoterf/global/deployment.json
  deployment_private_key_path: /home/remoterf/.config/remoterf/global/deployment-private.pem
  public_group: global-public                     # must already exist locally
  route:
    kind: tcp-relay                               # only supported kind today
    grpc_endpoint: ucla.global.remoterf.net:61005
    certificate_endpoint: ucla.global.remoterf.net:61006
    tls_server_name: ucla.global.remoterf.net

  # ---- optional (shown with defaults) ----
  heartbeat_seconds: 30
  offline_seconds: 90                             # must be >= heartbeat_seconds
  relay_ingress:
    trusted_peer_cidrs:
      - 10.77.0.1/32
  exports: []                                     # empty by default: nothing published
```

`base_url`/`issuer`/`jwks_url` reject `http://` unless a caller explicitly
passes `allow_insecure_transport=True` to `parse_global_config()` (there is
no CLI flag for this — it exists only for test fixtures, see
`docs/remoterf-global-enrollment.md`'s local dev procedure).

`deployment_private_key_path` and `deployment_state_path` are expected to
live in the same directory — the identity module always derives that
directory from `deployment_private_key_path.parent`.

## Real device IDs and allowed operations must be operator-confirmed

The example below is illustrative only — **do not copy these device IDs or
operation names into a real deployment.** Confirm:

- `local_device_id` against this deployment's *own* device inventory
  (`serverrf --device --show`), not against any example;
- `allow_operations` against the *actual* schema/capabilities of that
  specific device (`serverrf`'s device schema, or the IDL exposed over
  `IDL:get_drivers`), not against an assumed generic list.

```yaml
  exports:
    - local_device_id: "1"                   # must match a real local device id
      display_name: UCLA Pluto 1
      device_type: ADALM-Pluto
      visibility: public                     # only "public" is supported today

      reservation_policy:
        max_duration_minutes: 30
        max_active_reservations: 1
        max_daily_minutes: 120                # must be >= max_duration_minutes

      operation_policy:
        default: deny                         # always "deny" — not a real toggle
        allow_operations:                     # confirmed against the device's own schema
          - freq:GET
          - freq:SET
        allow_client_sample_upload: false      # TX/upload stays denied unless set true
```

## Validation (`serverrf --global validate-config`)

Checks, in addition to `config.py`'s structural rules (unknown keys,
duplicate `local_device_id`, invalid CIDRs, unsupported `visibility`/
`route.kind`, `operation_policy.default != "deny"`, an internal
WireGuard/LAN/loopback address used as a route endpoint, `offline_seconds <
heartbeat_seconds`, `max_daily_minutes < max_duration_minutes`):

- every exported `local_device_id` must match a currently-known local
  device (missing devices are reported clearly, all at once, not just the
  first one found);
- the configured `public_group` must already exist (create it with the
  existing group CLI first — this feature never creates it for you).

The safest-publication rule this validation exists to protect:

> A device is published/authorized for Global users **only if** it is
> explicitly listed in `exports:` **and** the configured `public_group`
> has local access to it. If either condition fails, nothing is published
> or authorized for it.

## Reservation policy enforcement

Applied on top of, not instead of, the existing local reservation system
(`acc_perms.py`'s `validate_reservation_request`, `reservation.py`'s
overlap check) — nothing about ordinary local-user reservation behavior
changes. For a Global-derived account, the export's own
`reservation_policy` values are the operative limits:
`max_duration_minutes`, `max_active_reservations`, `max_daily_minutes`.
Existing local overlap/conflict handling remains fully authoritative; a
Global outage never mutates or rewrites an existing local reservation row.
Removing a device from `exports:` (and republishing) means new Global
reservations for it are no longer possible — already-active ones are
unaffected by that change alone.

## Operation policy enforcement (this is real enforcement, not metadata)

`server/global_access/operation_policy.py`, wired into three call sites:

1. **Legacy GenericRPC** (`rpc_manager.py`'s `_handle_device_rpc`): after
   the device token resolves, if the owning account is a Global principal,
   the requested `prop:verb` (e.g. `freq:SET`) must be in that export's
   `allow_operations` — otherwise `RemoteRFPolicyError` is raised (caught
   by the existing handler, same response shape as any other legacy-RPC
   error).
2. **DynamicControlV2.Invoke**: same check against the requested `method`
   name, raised as `RemoteRFPolicyError` and flowing through the existing
   `ErrorEnvelope` mechanism unchanged.
3. **SampleDataV1** stream open: for `SAMPLE_DIRECTION_TX`, the export's
   `allow_client_sample_upload` flag gates it — `false` (the default) means
   TX/client-sample-upload is denied outright for Global principals,
   regardless of what the device itself would otherwise allow.

Ordinary LAN/local accounts (`Accounts.auth_type = 'local_password'`) never
reach any of this — `is_global_principal(username)` is the first check at
every one of these call sites, and it is a hard `false` for local accounts.
An unconfigured or unexported device is deny-by-default for Global
principals, not merely unlisted.

## Setting up the public group

Use the existing group CLI (unrelated to this feature) to create the group
your `global.yaml` names, then double check with `validate-config`:

```bash
serverrf --device --add --pluto 1:UCLA_Pluto_1:104473f6      # if not already added
# create the group via whatever this deployment's existing group commands are,
# granting it access to exactly the devices you intend to export
serverrf --global validate-config
```

## Production configuration example (illustrative — not a live deployment)

```bash
REMOTERF_BIND_HOST=0.0.0.0
REMOTERF_GLOBAL_ENABLED=true
REMOTERF_GLOBAL_CONFIG_PATH=/home/remoterf/.config/remoterf/global/global.yaml
REMOTERF_GLOBAL_RELAY_PEER_CIDRS=10.77.0.1/32
REMOTERF_GLOBAL_LOCAL_SESSION_MINUTES=60
```

`global.yaml` in that scenario points `route.grpc_endpoint`/
`certificate_endpoint` at `ucla.global.remoterf.net:61005`/`:61006` (the
already-live v0 relay ports), `base_url`/`issuer`/`jwks_url` at
`https://global.remoterf.net`, and `relay_ingress.trusted_peer_cidrs` at
the VPS's WireGuard address (`10.77.0.1/32`).

No private keys or enrollment tokens belong in this file or in
`global.yaml` — those live only in `deployment-private.pem` (0600) and are
consumed once, interactively, during `serverrf --global enroll`.

## Manual/tmux operation (unchanged)

```bash
REMOTERF_BIND_HOST=0.0.0.0 \
REMOTERF_GLOBAL_ENABLED=true \
REMOTERF_GLOBAL_CONFIG_PATH=/home/remoterf/.config/remoterf/global/global.yaml \
serverrf --serve --headless
```

This feature adds no systemd dependency and starts no second competing
RemoteRF process — the connector is one `daemon=True` background thread
inside the same `serverrf` process, started from `start_server_runtime()`
and stopped by the same `ServerRuntime.stop()` that already tears down
every other subsystem on shutdown.

## Migration and backup precautions

- The only schema change to a pre-existing table is `Accounts.auth_type`
  (idempotent `ALTER TABLE ... ADD COLUMN`, default `'local_password'`) —
  existing accounts, reservations, groups, and device records are
  untouched. See `tests/test_global_accounts_migration.py` for a seeded
  pre-v1.0 database exercised through this migration.
- `global.db` (new) holds only Global-specific state
  (`GlobalPrincipalMappings`, `GlobalAssertionJTIs`,
  `GlobalLocalSessions`, `GlobalCatalogState`) — deleting it entirely is
  safe and non-destructive to any local account/reservation/device data;
  it just forces every Global identity to re-map on next login and resets
  the catalog version counter.
- Back up `~/.config/remoterf/global/deployment-private.pem` if you ever
  want to preserve this deployment's Global identity across a machine
  migration — losing it means re-enrollment (a new `deployment_id`) is
  required, which Global would see as a brand-new deployment.
