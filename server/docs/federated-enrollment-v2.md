# Gate F federated enrollment

Gate F adds one state-changing action, `federated_enroll`, without enabling
remote device or reservation access. An owner creates a federation-bound code
for an existing group through the local federation admin command:

```text
remoterf-federation-admin --db <usergroups.db> --identity-dir <identity-dir> \
  enrollment create --group-id <id> --uses <n> --duration <seconds> \
  --federation-contract <uuid> --contract-version 1 \
  --allowed-issuer <peer-deployment-uuid>
```

The only output is a pasteable `rrf2.` invitation. Treat it as secret-bearing
user input even though it is untrusted routing information. Do not log it.
Plain codes continue through local create-user/`ACC:set_enroll`; bound codes
are accepted only by the federation action.

Runtime wiring uses `build_server_gate_f_executor(...)` for the destination
and injects `ServerFederatedEnrollmentHome(outbound)` into
`start_server_runtime(home_federation_enroller=...)` for a Server acting as a
home. The executor owns the `usergroups.db` transaction. Split-store
preparation may create only the passwordless proxy/binding and Normal role;
membership, code decrement, receipt, audit, and grant JTI commit together in
the owner transaction.

Retries use the durable receipt and a fresh grant. They do not require an
exhausted code row and never restore a membership removed by the owner.
`permissions_read` and all remote resource operations remain Gate G or later.
