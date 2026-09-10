# Agent-friendly RemoteRF CLI plan

## Recommendation

Extend the existing client `remoterf` executable. Do **not** build an LLM
feature, MCP server, daemon, remote-Python runner, new device API, or generic
`run experiment` command. The first release should make the existing client
configuration, account, reservation, IDL, and generated-driver paths usable
from a deterministic non-interactive shell. Experiments and signal processing
remain ordinary local Python.

The smallest coherent release is:

1. read-only configuration and connection diagnostics;
2. structured device, permission, reservation, and static API inspection;
3. secure direct-mode credentials and reservation-token references that work
   across shell processes;
4. explicit non-interactive reservation create/cancel; and
5. schema-derived local Python examples, initially receive-only.

This is an investigation and plan, not an implementation. No deployment,
credential, reservation, device, configuration, or radio operation was made.
Findings are static-source findings plus local mock/unit tests. “Verified”
means supported by the referenced checkout; proposed commands are labelled as
such and do not exist yet.

## Scope and evidence

The workspace has separate `RemoteRF-Server` and `RemoteRF-Client` checkouts.
This plan lives in the active server checkout, but most client/CLI work belongs
in the sibling client checkout. Paths below are repository-relative; client
paths are prefixed `RemoteRF-Client/`.

An *inspection* command must not reserve a device, open a native-device
session, change radio configuration, or transmit. Opening a Dynamic v2 session
is not called inspection: it consumes a reservation and a device session even
when it makes no configuration/TX call.

## A. Current-state map

### Entry points

| Surface | Verified current behavior | Consequence for a coding agent |
| --- | --- | --- |
| `remoterf` | The client package exposes one console script, `remoteRF.remoterf_cli:main` (`RemoteRF-Client/setup.py:49-65`). | Extend it; do not add a second executable. |
| `remoterf --config --addr` | Resolves DNS, prompts to accept ToS, fetches a CA cert, and writes `~/.config/remoterf-client/.env` (`RemoteRF-Client/src/remoteRF/config/config.py:176-244`). | Fresh direct setup cannot be unattended. There is no read-only config/diagnostic command. |
| `remoterf --login` | Checks config/channel readiness, then importing `core.acc_login` imports an account shell that starts immediately (`RemoteRF-Client/src/remoteRF/remoterf_cli.py:173-188`, `core/acc_login.py:16-19`, `core/app.py:962-1003`). | Login, discovery, and reservations are prompt-driven and process-local. |
| Account shell | Offers `getdev`, `getres`, `myres`, `perms`, `resdev`, `cancelres` (`RemoteRF-Client/src/remoteRF/core/app.py:148-159`, `962-999`). | Its coloured terminal text is not a stable machine interface. |
| Optional Global CLI | Existing `global`, `deployments`, and `use` subcommands have additive dispatch and selected `--json` output (`RemoteRF-Client/src/remoteRF/global_client/cli.py:91-431`). | A good precedent for new subcommands, exit codes, redacted status, and protected credentials. Its catalog is not owner-authoritative device state. |
| `serverrf` | A server-management console script (`pyproject.toml:31-32`). | Keep it separate from researcher-facing hardware use. |

### Verified client journey

1. **Install/configure/select.** Direct mode saves `REMOTERF_ADDR`,
   `REMOTERF_CA_CERT`, and profile data. The gRPC client lazily selects a
   Global profile or direct `.env`, reads its CA file, and builds a TLS channel
   (`RemoteRF-Client/src/remoteRF/core/grpc_client.py:53-146`).

2. **Authenticate/discover/reserve.** `RemoteRFAccount` makes `ACC:login`,
   `ACC:get_dev`, `ACC:get_res`, `ACC:get_perms`, `ACC:reserve_device`, and
   `ACC:cancel_res` calls (`RemoteRF-Client/src/remoteRF/core/grpc_acc.py:77-127`).
   Direct username/password are held by the interactive process; the server
   validates credentials for every account request
   (`src/remoteRF_server/server/reservation.py:110-155`).

3. **Use a reservation token.** The interactive shell prints a successful
   bearer token and warns it cannot be recovered (`RemoteRF-Client/src/remoteRF/core/app.py:371-379`).
   Server-side it is salted/hashed with a reservation and valid only during its
   active time (`src/remoteRF_server/server/reservation.py:466-504`,
   `src/remoteRF_server/server/device_manager.py:858-913`).

4. **Generate/use a local client.** `ensure_driver(token=…)` fetches IDL,
   checks the schema hash, and writes/updates a generated package
   (`RemoteRF-Client/src/remoteRF/drivers/dynamic_device.py:1509-1574`).
   The documented USRP path is ordinary local Python with NumPy buffers and
   context-manager cleanup (`RemoteRF-Client/README.md:38-82`). Legacy drivers
   exist for Pluto, RTL-SDR, HackRF, and TI mmWave.

5. **Schema-driven device API.** v1 `DeviceSchema` derives docs, parameter
   names/defaults/annotations and generated-client metadata from exposed
   methods, then content-addresses the schema
   (`src/remoteRF_server/common/idl/schema.py:596-691`, `981-1011`). Generic
   legacy dispatch invokes exposed GET/SET/CALL methods
   (`src/remoteRF_server/server/rpc_manager.py:181-214`).

6. **Dynamic v2 USRP API.** Its declarative schema has overloads, parameter
   kinds/types, return types, method execution placement, coverage, profiles,
   capability fields, protocol versions, and errors
   (`src/remoteRF_server/common/idl/v2.py:62-210`,
   `src/remoteRF_server/drivers/usrp/uhd_manifest.py:1560-1657`). The client
   validates it before building native-style bindings
   (`RemoteRF-Client/src/remoteRF/drivers/dynamic_v2.py:104-188`).

7. **Open, stream, close.** `OpenSession` returns opaque session/root-handle,
   schema, capability snapshot and native version data
   (`src/remoteRF_server/common/grpc/grpc.proto:150-166`,
   `src/remoteRF_server/server/dynamic_v2.py:576-663`). Generated device and
   handle proxies have `close()` and context-manager cleanup
   (`RemoteRF-Client/src/remoteRF/drivers/dynamic_v2.py:329-397`, `668-776`).
   Samples use binary gRPC frames, with a 4 MiB server payload cap—not JSON or
   base64 terminal output (`grpc.proto:215-235`, `dynamic_v2.py:1540-1555`).

### Reusable components

- The existing top-level client dispatcher returns exit codes and lazily
  imports subcommands (`RemoteRF-Client/src/remoteRF/remoterf_cli.py:165-288`).
- The Global client already keeps secrets in OS keyring or an explicitly
  protected-file fallback and its JSON status exposes expiry rather than tokens
  (`RemoteRF-Client/src/remoteRF/global_client/cli.py:179-244`,
  `global_client/local_sessions.py:76-98`). Reuse the storage mechanics, not
  the Global identity namespace, for direct credentials/tokens.
- `IDL:get_drivers` can resolve by token, device ID, or device name and return
  static v1/v2 schema, hash, type and driver version. A `device_id` fetch does
  not acquire a device I/O lock or open a native session
  (`src/remoteRF_server/server/rpc_manager.py:216-338`).
- A USRP v2 session exposes actual channels, ranges, sources, selected profile,
  transport, UHD version, stream format information, and resource limits
  (`src/remoteRF_server/drivers/usrp/usrp_schema.py:748-878`). That is the
  right source for runtime capability, not a static device list.
- Dynamic v2 errors preserve category, details, retryability and
  session-fatality (`grpc.proto:114-123`; `RemoteRF-Client/src/remoteRF/core/v2_errors.py:22-114`).
  Reservation end closes the associated session and makes handles stale
  (`src/remoteRF_server/server/dynamic_v2.py:665-675`, `1161-1162`).

### Current limitations

- `ACC:get_dev` returns display strings such as `name (online, reserved)`, not
  a stable typed inventory (`src/remoteRF_server/server/device_manager.py:175-189`,
  `src/remoteRF_server/server/reservation.py:579-595`). A new CLI must not
  parse punctuation to make availability/safety decisions.
- v1 IDL is useful but not uniform about units, constraints, idempotency,
  operation risk, or runtime capability. v2 is richer but currently the USRP
  implementation; static declaration is not physical-radio support.
- Generic `rpc_client()` prints errors and may call `input("Hit enter to
  continue…")` (`RemoteRF-Client/src/remoteRF/core/grpc_client.py:157-187`).
  It cannot be the unchanged basis for a noninteractive CLI.
- A v2 USRP allows one active session per reserved device and rejects stale
  schema/protocol, legacy-session conflict, or unsupported native version
  (`src/remoteRF_server/server/dynamic_v2.py:576-633`). Opaque sessions and
  handles cannot cross command processes.

### Local verification

`PYTHONPATH=src venv/bin/python -m unittest` passed 63 tests across
`test_idl_schema`, `test_dynamic_v2`, `test_default_usrp_schema`,
`test_default_rtl_sdr_schema`, `test_hackrf_schema`, and
`test_ti_mmwave_schema`. They use fakes/subprocess fixtures and did not access
hardware. Expected fixture messages mentioned unavailable optional Pluto
dependencies and deliberately invalid test inventory input.

## B. Gaps from a coding agent's perspective

| Failure in the target scenario | Why it happens today | Smallest useful home for the fix |
| --- | --- | --- |
| Cannot distinguish missing config, missing CA, DNS, TLS identity, gRPC outage, or active Global profile. | `--login` collapses config/readiness failure into “Please configure” (`remoterf_cli.py:37-59`, `173-188`). | **CLI/client:** read-only `doctor` and config status with layered results. |
| Cannot configure direct mode unattended. | ToS/config uses `input()` (`config.py:176-235`). | **CLI/client:** explicit `--non-interactive --accept-tos`; retain legacy flow. |
| Must drive a prompt UI or inspect source to list devices/permissions/reservations. | Shell prints tables/coloured text (`core/app.py:356-365`). | **Client:** pure account adapter. **Server:** typed inventory/reservation fields rather than terminal strings. |
| Cannot tell offline, reserved, forbidden, quota-limited, or available-for-interval apart. | `get_dev` is a string map; normal-user caps are a nested blob (`reservation.py:167-212`). | **Server:** owner-authoritative caller inventory/limits. **CLI:** show it; never infer availability. |
| Guesses methods/classes and assumes SDRs share features. | Docs are device snippets; schema is consumed only as part of driver use. | **CLI/client:** schema-based API help/example. **Schema:** fill only missing semantic facts. |
| Cannot distinguish static API from actual radio support. | Runtime capabilities require `OpenSession`. | **CLI:** static inspection stays reservation-free; clearly-labelled authorized runtime capability opens/closes a session. |
| Leaks bearer token into command line/source/transcript. | Current shell prints it once. | **Client:** protected token store keyed by a non-secret reservation reference. |
| Separate commands lose identity, token, session and handles. | Direct login is in-memory; sessions/handles are opaque/session-bound. | **Client:** persist credentials/tokens only. **Docs:** one Python process owns and closes one session. No daemon. |
| Repeats a mutation after a timeout. | Existing Global documentation forbids automatic retries; sample transport poisons session on failure (`RemoteRF-Client/docs/remoterf-global-client-v1.md:118-124`; `dynamic_v2_transport.py:246-299`). | **CLI/client:** classify mutations; report outcome unknown. **Future protocol:** status/dedup only when real semantics are defined. |
| Dumps IQ/logs into context. | Binary sample transport exists, but a CLI could accidentally render arrays. | **CLI:** never print samples; report summary/path. **Python:** owns NumPy/file data. |

## C. Recommended design

### Boundary

The CLI is a control-plane/comprehension tool: inspect local state, inspect
owner-authoritative availability, acquire/release a reservation when explicitly
asked, inspect schema, and write a minimal local Python starting point.

Python remains responsible for signal generation/analysis, array allocation,
file outputs, device/stream lifetime, and experiment-specific configuration.
The server remains responsible for access control, reservation enforcement,
native device operations, Global operation policy, and sample transfer. The
CLI must reuse the client/core code; it must not create a privileged path.

### Proposed command tree (new)

These additive commands are deliberately under existing `remoterf`:

```
remoterf doctor [--json]
remoterf config show [--json]
remoterf config set --addr HOST:PORT --accept-tos [--non-interactive]
remoterf auth status [--json]
remoterf auth login --username NAME --password-stdin [--non-interactive]
remoterf auth logout

remoterf devices list [--json]
remoterf device show DEVICE_ID [--json]
remoterf api show DEVICE_ID [--json] [--runtime RESERVATION_REF]
remoterf api example DEVICE_ID --recipe RECIPE [--output FILE]

remoterf reservations list [--json]
remoterf reservations create DEVICE_ID --start RFC3339 --end RFC3339 --confirm [--json]
remoterf reservations cancel RESERVATION_ID --confirm [--json]
```

`api show` fetches static IDL by device ID and never reserves/opens hardware.
`--runtime RESERVATION_REF` retrieves a local token, uses the normal session
path, emits live capabilities and closes in `finally`; help must call this
`session_open`, not “read-only.” The initial `api example` recipes are only:

- `connect-and-capabilities` for a documented close/context lifecycle;
- `usrp-rx-once` only after declared USRP stream API and runtime RX channel;
- driver-specific bounded receive/frame recipes only where schema/tests show
  the exact operation; and
- no TX recipe in release one.

No `run experiment` command: it adds no useful boundary over `python
project/experiment.py` and would force a remote-executor/lifecycle design the
current architecture does not need.

### Output and errors

`--json` is justified because current schemas are JSON and Global already has
machine-readable command output. It prints exactly one documented UTF-8 JSON
value to stdout: no banner, ANSI, progress, raw samples or secrets. Normal
human output is compact and derived from the same view model; diagnostics go
to stderr. `--verbose` remains redacted.

Use a command-specific object/list rather than a generic success envelope. A
proposed `device show` object is:

```json
{
  "device_id": 7,
  "name": "lab_usrp",
  "device_type": "usrp",
  "connection": "online",
  "reservation": {"state": "available"},
  "access": {"visible": true, "reservable": true, "max_duration_seconds": 1800},
  "api": {"schema_version": "2.0", "schema_hash": "sha256:…"}
}
```

The corresponding human view stays deliberately small and makes its effect
clear:

```text
$ remoterf device show 7
Device 7  lab_usrp (usrp)
  Connection   online
  Reservation  available to this account
  Limit        up to 30 min
  Static API   Dynamic v2, sha256:…
  Effect       inspection only; no reservation or device session opened
```

For `--json` errors, stdout contains one category/message/remediation object;
otherwise stdout is empty. Keep a small exit family: `0` success, `2` local
argument/config problem, `3` authentication, `4` authorization/reservation/
policy denial, `5` DNS/TLS/connectivity, `6` schema/protocol/version, `7`
remote device/session state, `8` timeout with unknown outcome, and `130`
local interrupt. Map Dynamic v2 error categories faithfully, preserving
retryable/fatal information rather than burying gRPC details in prose.

### Secrets and separate processes

Direct mode needs an explicit protected credential store. Factor a neutral
client credential abstraction using the existing keyring/protected-file
mechanics; do not make `global_client` the semantic home for local passwords.
`auth login --password-stdin` reads one secret, accepts no inline password,
and never prints/logs it. Existing interactive account creation/login stays
for human onboarding.

On `reservations create`, store the returned bearer token in the protected
store and return a non-secret `reservation_ref`, normally based on the server
reservation ID. Generated Python reads it locally, for example:

```python
from remoteRF.auth import load_reservation_token
token = load_reservation_token("rrf-res-381")
```

The helper fails clearly if this machine lacks the secret; it cannot recover a
lost token. Cancellation removes the local secret **after** confirmed server
cancellation. A list/status command never returns a token. An explicit
permission-restricted token export file can be considered later, but routine
token printing/environment injection should not be the workflow.

Persist profile/credential/token, but never a gRPC channel, session ID or
remote handle. A normal Python process owns one device session/streamers,
uses context/finally cleanup, and exits. A daemon would create a second token
store, long-lived locks, handle-sharing/expiry and recovery semantics without
a demonstrated need; do not introduce one.

### Minimal server contract repair

Do not parse `get_dev`, `get_res`, or `get_perms` display shapes. Add small,
authenticated `ACC` responses over the existing `GenericRPC` transport, not a
new REST/API stack:

- caller inventory with stable ID/name/type, online state, reservation state,
  caller visibility/reservability/limits, and static API identity if known;
- caller reservations with ID, device, interval/current state and whether the
  client has a local token—never the token;
- create/cancel validation/result fields, adding `reservation_id` additively
  alongside the legacy `Token` field if compatible; and
- an account/permission summary for `doctor`.

The server database/device manager remains authoritative. The client decodes
typed models and uses them for both text and JSON rendering. Existing ACC maps
and the interactive shell stay compatible.

### Schema rather than a hard-coded command catalogue

Render v1 docs/args/defaults and v2 overloads/types/execution/coverage from
the server-published schema. Optionally write the validated raw schema only
when requested. Extend schema metadata gradually only for facts an agent must
otherwise guess: units/ranges/enums, operation class (`inspect`, `configure`,
`receive`, `transmit`, `start_stop`, `destructive`), boundedness/idempotency,
and capability predicates. Validate additions in per-device schema tests.

Do not invent metadata for a legacy driver. Report `unknown` and its declared
doc instead. Examples are strict schema-gated templates, not heuristic method
guesses; static API, runtime capability, policy restriction, and coverage must
remain distinct concepts.

### Safety/lifecycle rules

| Resource/action | Owner/persistence | Required behavior |
| --- | --- | --- |
| Server/CA selection | local profile | `config show` is read-only; `config set` is explicit mutation. |
| Identity | protected local store | separate direct/Global providers; no credential args/output. |
| Device selection | CLI/Python value | never reserves by itself. |
| Reservation | server DB + local bearer secret | create/cancel requires fully specified input and `--confirm`; listing never leaks token. |
| Dynamic session/handles | server memory + one Python process | never persist/return through CLI; close best-effort. |
| Device config/TX/start | server/native device | ordinary Python only in phase 1; no arbitrary CLI invoke/TX. |
| Results | local research project | Python saves file; CLI reports metadata/path, not IQ contents. |

Read-only commands never make reservation/session/device RPCs. On Ctrl-C,
best-effort cancel/close only if connected. If no acknowledgement arrives,
state is **unknown**—never “not performed.” Retry only bounded read-only
probes. Never automatically retry config/set/start, reservation create/cancel,
TX/sample upload, or any operation with unknown idempotency. Current sample
transport failure already requires a fresh session/streamer
(`RemoteRF-Client/src/remoteRF/core/dynamic_v2_transport.py:246-299`).

## D. Target end-to-end walkthroughs

Commands here are proposed, not currently implemented.

### 1. Inspect configuration and discover without mutation

```
$ remoterf doctor --json
{"configuration":{"status":"ready"},"connectivity":{"dns":"ok","tls":"ok","grpc":"ready"},"authentication":{"status":"credentials_present"}}
$ remoterf devices list --json
[{"device_id":7,"device_type":"usrp","connection":"online","reservation":{"state":"available"},"access":{"reservable":true}}]
$ remoterf device show 7 --json
{"device_id":7,"api":{"schema_version":"2.0","schema_hash":"sha256:…"},…}
```

`doctor` does local config checks plus bounded DNS/TLS/gRPC readiness checks;
it does not reserve/open a device. `devices`/`device show` authenticate to the
owner deployment and read typed inventory only. If configuration is absent,
the researcher explicitly chooses the mutating bootstrap:

```
remoterf config set --addr lab.example:61005 --accept-tos --non-interactive
```

### 2. Inspect the correct API and generate local code

```
$ remoterf api show 7 --json > .remoterf/usrp-7-api.json
$ remoterf api example 7 --recipe usrp-rx-once --output experiments/rx_once.py
```

Static `api show` reaches the existing IDL endpoint but does not reserve/open
hardware. The file uses declared imports/signatures, reservation-reference
placeholder, finite sample count/timeout, capability preflight, local output
file, and `with`/`finally` cleanup. It contains no token and executes nothing.
For a different SDR, a recipe is produced only if that device schema declares
the needed bounded API; otherwise the CLI identifies the missing declaration.

### 3. Authorized bounded receive in normal Python

```
$ remoterf reservations create 7 --start 2026-09-05T10:00:00-07:00 \
    --end 2026-09-05T10:20:00-07:00 --confirm --json
{"reservation_id":381,"reservation_ref":"rrf-res-381","device_id":7,"state":"scheduled","token_stored":true}
$ python experiments/rx_once.py --reservation rrf-res-381 --output results/rx_once.npz
```

The first command changes server reservation state and securely stores its
token; it does not display it. The script reads the local reference, refreshes
the driver/schema through normal RemoteRF logic, opens a Dynamic session,
checks runtime capabilities, receives a finite number of samples with a finite
timeout, saves `.npz` plus small metadata JSON locally, and closes in `finally`.
The release-one recipe is receive-only: no TX, persistent receive, remote
experiment execution, or unapproved configuration action.

### 4. Diagnose/release safely

| Category | Agent action |
| --- | --- |
| `configuration_missing` | Explain missing profile/CA; use explicit configuration. No radio action occurred. |
| `connectivity_tls` | Show endpoint/identity redacted; do not disable verification. |
| `authentication_required` | Request normal login; do not guess credentials. |
| `reservation_denied` | Reinspect availability/limits; do not call it a transport issue. |
| `schema_incompatible` | Show expected/current version/hash and stop; do not guess legacy calls. |
| `capability_unsupported` | Static API exists but live profile/channel/format/policy does not; choose compatible code/device. |
| `timeout_unknown` on mutation/TX/start/cancel | It may have happened. Do not repeat; close best-effort, inspect state, then seek researcher direction. |
| `session_stale`/`reservation_ended` | Discard handles and open/configure a new session only if a current reservation exists. |

Normal script completion closes a device session but does not cancel its
reservation. `reservations cancel 381 --confirm` is a separate server mutation
and deletes the local token only after confirmed success.

## E. Phased implementation plan

### Phase 0: prepare a compatible contract

1. Catalogue each driver by v1/v2 schema and static/runtime capability source.
2. Add pure client account models/adapters with no prompting/printing; do not
   route the agent CLI through `rpc_client()`'s interactive behavior.
3. Add server tests and additive typed ACC account/inventory/reservation
   responses; retain legacy strings and interactive UI.
4. Factor protected-store mechanics into a neutral direct credential/token
   layer, separate from Global credential names.

Likely changes: `RemoteRF-Client/src/remoteRF/remoterf_cli.py`, new neutral
auth/account modules, `core/grpc_client.py`, profile/credential code; server
`src/remoteRF_server/server/reservation.py`, `acc_perms.py`,
`device_manager.py`, and their tests. No driver rewrite or new network service.

### Phase 1: useful agent CLI

1. Implement `doctor`, `config show`, `auth status`, `devices list`, `device
   show`, `reservations list`, `api show` with redaction, structured/human
   renderers, stdout/stderr separation and exit categories.
2. Add explicit noninteractive direct configuration/login while preserving
   legacy `--config`/`--login` behavior.
3. Add confirmed reservation create/cancel and secure token reference storage.
4. Render static v1/v2 schema accurately; make raw schema output opt-in.
5. Add `connect-and-capabilities` and one schema/runtime-gated USRP RX example
   plus the public Python reservation-reference helper.
6. Publish client documentation that labels inspection, reservation, session
   opening, and Python execution distinctly.

Compatibility: legacy flags/account shell, ACC methods, generated imports and
direct/Global profile behavior remain. Older server response shapes may be
displayed only where conversion is exact; never parse display strings for a
safety decision.

### Phase 2: richer capability help

1. Implement explicit `api show DEVICE --runtime REF` for v2 and only legacy
   drivers with an equally documented safe capability path.
2. Add validated units, constraints, operation/retry/boundedness metadata where
   each schema can substantiate it.
3. Add more receive-only examples only after their driver schema and tests
   establish exact limits and cleanup.
4. Add optional schema/capability cache keyed by endpoint/device/schema hash;
   it is advisory, dated, and never authorizes actions.

### Phase 3: defer until there is evidence of need

Only then consider a constrained inspect-only device operation or a server
operation-status/deduplication design. A UUID alone is not a queryable result
ledger; real remote-outcome semantics, retention and idempotency are required.
Hardware acceptance tests must be opt-in and owned by a deployment safety
configuration.

### Explicitly do not build

- `remoterf run`, remote Python, scheduler/notebook kernel, or arbitrary
  server computation;
- LLM dependency, agent framework, MCP server, or agent-only parallel API;
- generic `device call METHOD JSON`, IQ JSON/base64 terminal dumps;
- automatic reservation/TX/mutation retry/certificate-verification bypass;
- a persistent client session daemon; or
- cross-SDR hard-coded method templates.

## F. Acceptance criteria

### Mock/local tests

- `doctor --json` separately reports absent config, CA, DNS, TLS identity,
  gRPC readiness, direct profile and Global profile without reservation/device
  RPCs.
- JSON stdout is one parseable value with no ANSI/banner/secrets; human output
  is bounded; stdout/stderr/exit classes are deterministic.
- Noninteractive config/auth never prompts. Missing ToS/password-stdin/
  mutation confirmation changes no state and has a predictable error.
- Typed inventory distinguishes visibility, online state, reservation state,
  quota/interval denial and permission; no code parses legacy display strings.
- Static API output validates schema hash and correctly renders v1/v2 docs,
  parameters/defaults, overloads, execution, coverage/profiles/errors. Bad
  schema stops before example generation.
- Examples call only declared APIs, are syntactically valid, contain no token,
  include cleanup, and decline unsupported recipes.
- Reservation create stores only in protected mock storage and returns a ref;
  token is absent from list/show/status; cancel removes it only after server
  acknowledgement.
- Multi-process tests prove profiles/credentials/refs persist but session IDs
  and handles do not. Exception/normal paths close newly opened sessions.
- Fault tests prove no automatic retry for create/cancel/set/start/TX and
  produce `timeout_unknown`; read-only retries remain bounded.

Extend `RemoteRF-Client/tests/test_remoterf_cli.py`, `test_global_cli.py`,
`test_global_credentials.py`, and `test_dynamic_v2.py`; extend server
`tests/test_idl_schema.py`, `tests/test_dynamic_v2.py`,
`tests/test_reservation_timestamps.py`, and per-driver schema tests. Existing
Dynamic tests already cover hash validation, overload binding, binary sample
transfer and poisoned streams; retain that coverage.

### Future opt-in hardware tests

- A deployment-owned short reservation verifies discovery, static schema,
  explicit runtime capability inspection, and a small receive-only capture
  saved locally.
- Default/CI paths never transmit or change radio state. Any later TX test
  needs explicit safety policy, finite power/payload/time, independent
  observation and response-loss handling that reports unknown rather than
  retries.
- Exercise process kill, expiry, disconnect, stale handle, unsupported profile,
  older client/server, cancellation and cleanup.

## Final recommendation

Build the noninteractive **control-plane** extension first: diagnostics, typed
inventory/reservation/API inspection, protected local credential/token
references, and one schema-gated receive-only Python example. This removes the
two most serious coding-agent gaps—hidden setup/authorization state and
method/capability guessing—while preserving Python as the experiment surface.

Deliberately avoid an experiment runner, arbitrary invocation, TX automation,
daemon, and agent-specific integration. Those would broaden safety and
lifecycle problems before RemoteRF has a stable machine-readable inventory,
authority, static API and runtime capability story.
