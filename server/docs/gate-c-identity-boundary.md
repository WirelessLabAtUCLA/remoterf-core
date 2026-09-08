# Gate C identity boundary

Gate C adds identity storage without enabling federation execution or resource
access. Direct/LAN Server behavior remains the default and requires no Global
service, Internet connection, deployment identity, or subject bootstrap.

## Native subjects

The protected integer `Accounts.acc_id` remains the authorization and group
key. `LocalAccountSubjects` adds one immutable UUID subject per native account.
Existing native rows are bootstrapped deterministically with UUIDv5 using the
deployment UUID and `account:<acc_id>`; new registrations receive UUIDv4.
Passwords, account IDs, groups, enrollment codes, reservations, and roles are
not rewritten. A removed and recreated account receives a new UUIDv4 subject.

Only `auth_type=local_password` reaches password verification. The only other
accepted value is `federated`; unknown and legacy values fail startup/runtime
checks. A federated proxy uses the deterministic full-SHA256 `fed-...` adapter,
the `.federation.invalid` email domain, deliberate non-password sentinels, and
an immutable `FederatedAccountBindings` tuple.

## Federated principal containment

`FederatedPrincipals` stores destination-local UUID state keyed uniquely by
`(issuer_deployment_id, remote_subject_id)`. Display metadata is bounded and
informational. Principal/proxy creation grants only an insert-if-absent Normal
role compatibility row. It grants no native login, destination session,
membership, reservation, device token, or resource access. Gate C has no
federation RPC, grant, contract, forwarding, or enrollment implementation.

The retired `GlobalAuthV1` protobuf/service, Global-v1 mapping/JTI/session
database reader, and resource operation-policy hooks are absent from runtime.
Connector catalog state, when explicitly enabled, uses a separate non-secret
JSON cursor and does not authenticate users.

## Offline Global-v1 state preflight

Never run the tool against a live Server. Quiesce all writers and use a copied
or otherwise explicitly selected database directory first.

```bash
python scripts/global-v1-state.py preflight \
  --db-dir /absolute/path/to/db \
  --manifest /absolute/path/to/review.json
```

The manifest records exact source hashes and exact candidate row IDs. It never
selects by username prefix, email suffix, group, or date. Any legacy mapping
ambiguity, missing protected database, unexpected Global table, orphan mapping,
unknown auth type, or active journal/WAL blocks apply. Every candidate starts
with `"delete": false`.

After external review, set top-level `"reviewed": true` and set `"delete":
true` on every listed candidate. Apply rechecks the unchanged source hashes,
creates a new private archive, performs only those exact deletions, removes the
archived disposable `global.db`, installs Gate C schemas, initializes native
subjects, and runs readiness validation:

```bash
python scripts/global-v1-state.py apply \
  --manifest /absolute/path/to/review.json \
  --archive-dir /absolute/path/to/new-restore-archive \
  --deployment-id 11111111-1111-4111-8111-111111111111
```

Apply refuses an existing archive directory. Retain the archive and reviewed
manifest as restore evidence. This is development tooling, not authorization
to touch production.
