# Gate H federated devices

Gate H lets an enrolled federated principal see, reserve, and drive this
Server's devices through its HOME. Nothing about native accounts, tokens, or
device drivers changes; the federation executor gains five actions.

## Contract capability

A bilateral contract must list `DEVICE_READ` (list devices and reservations),
`DEVICE_RESERVE` (reserve / cancel), and `DEVICE_CONTROL` (device RPC).
Existing Gate G contracts carry none, so they grant no hardware reach. Add the
capabilities to `allowed_capabilities` in the terms file of a new contract
version (`supersedes_version` set to the current one) and run the usual
`remoterf-federation-admin ... contract propose --terms-file ...` /
`export` / `import` / `accept` / `activate` exchange with the peer.

## What the destination enforces

Every action runs only after the executor has verified a one-time grant bound
to an active contract allowing that capability. Then, on this Server's own
tables:

- the remote subject must already be an active enrolled proxy
  (`FederatedPrincipals`); a device action never allocates one;
- visibility is the proxy's local role/group device permissions, exactly as
  `ACC:get_dev` computes it;
- `device_reserve` goes through `perms.validate_reservation_request()` (Policy
  B eligibility, quotas, duration) and the same overlap check as a native
  reservation, is idempotent by the grant's `request_id`, and records the
  authorization in `FederatedReservations` in the same commit as the
  `Reservations` row; the plaintext token is materialized onto the device and
  never returned;
- `device_cancel` removes only a federation-created reservation this proxy
  owns;
- `device_rpc` requires a federation-created reservation live now for exactly
  this proxy and device. The `a` bearer argument is stripped from the frame.
  `IDL:get_drivers` is the one function allowed with visibility alone, pinned
  to the granted device, so a driver can be installed ahead of time.

The RPC itself runs in `finalize()` after the owner transaction (grant JTI
consumption, receipt, audit) has committed, so a slow radio never holds the
federation write lock and a replayed grant is rejected before hardware is
touched. Hardware failures, unsupported function names, and oversized
responses become destination-signed errors with the empty payload for the
action; they are never ambiguous transport failures.

An out-of-band `Reservations` row on a proxy account without a matching
`FederatedReservations` row is ignored both by `device_rpc` and by
`update_devices()`.

## Migration

Gate H (schema version 7) rebuilds `FederationGrantJTIs` to admit the device
actions in its `CHECK`, copying every evidence row, and adds
`FederatedDeviceReceipts` (usergroups.db) and `FederatedReservations`
(reservations.db). It runs automatically from
`build_server_gate_h_executor()` and `ReservationHandler()`.

## Verification

`tests/test_gate_h_devices.py` drives the real executor, migration,
`ReservationHandler`, and permission tables. The cross-repository proof with
the actual Client, Global HOME, and broker is
`remoterf-vps-global/scripts/verify-gate-h-devices.py`.
