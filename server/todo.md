# Latency/Performance

Debugging needed! (to determine what/why exactly causes the 'slowness') (could also just be the wifi speed, etc.)

# Proper `Gist` Server Information

Pull data from the main database (with some options to set, like whitelist for devices AND user groups + max timestamp/payload size)

Check for if gist isn't setup, no 'warning' or anything. + "Github device status" (grid)

Proper Reservation 'history'

# Interface Description Language `IDL`:

A device API “contract” that hosts/servers can publish, and clients can discover + bind to automatically, so adding a new device does not require shipping a new hard-coded client library for that device.

“Reflective IDL + Generic Invoke”

- Rewriting Pluto Stuff so that the client side is 'reflection' based.
- ^ Probably have a 'debug-remoterf-package' for this typa stuff!

## Server-Side

### Control plane: IDL (schema + discovery)

Add RPCs (or HTTP endpoints) like:

* ListDevices() -> [DeviceRef]
* GetDeviceSchema(device_gid) -> DeviceSchema
* GetDriverInfo(device_gid) -> {driver_name, driver_version, schema_hash, compat_ranges}

DeviceSchema is your IDL. It should describe:

* methods (name, docstring, side effects)
* args (names, types, units, defaults, ranges)
* return types
* exceptions / error codes
* streaming endpoints (more on this below)
* versioning metadata (api_version, schema_hash)

### Data plane: invocation + streaming

Send an IDL identifier (hash + version) on init, and only send the full “IDL package” if the client doesn’t already have it cached.

## Client-Side

Dynamic proxy (fastest shipping):

Client does:

* schema = GetDeviceSchema(gid)

* build a proxy object where proxy.some_method(...) maps to Invoke(gid, "some_method", ...) upon first connect (and caches based on hash/version)

no code generation pipeline,
always works for new devices instantly

## Plugin Ecosystem

The basic idea:

* Someone writes a driver plugin for a device (“support package”).
* They publish it as a normal Python package (PyPI or your own index).
* Any RemoteRF host/server can pip install it.
* The host auto-discovers the plugin, loads it, and exposes its schema (IDL) to clients.
* Clients don’t install the driver — they just bind via schema + generic invoke.

Testing wise, implement for a webcamera + maybe something more complicated?

# VPN/Multi-Network system `RemoteMesh`

L3-routed Mesh (Headscale, Tailscale, Nebula style)

All the network 'heads' (servers) would live in a single VPN plane with public VPN gateway server(s).

* Control Plane and Data Plane

you have:

- multiple sites/nodes
- each with its own local network
- connected through routed IP links
- where packets can move between sites based on routes

Example:

* HeadScale Control Plane
* WireGuard Data Plane

First simply allow these servers to talk to each other properly + Permissions, etc. 
Afterwords, to support '3rd party' individuals, I would implement seperate 'regional' nodes that exist as a L7 proxy (regular user) into the main net.


# Reflective IDL Implementation Plan

## Current Architecture (As-Is)

```
Client ──RPC──▶ RpcManager.run_rpc()
                   │
                   ├─ fn_type == "Pluto" ──▶ acquire_device(token)
                   │      ├─ VirtualDevice? ──▶ hts.handle_host_device(...)
                   │      └─ local?         ──▶ PlutoServer.handle_call(...)
                   │                                 ├─ GET  → getattr(dev, name)
                   │                                 ├─ SET  → setattr(dev, name, val)
                   │                                 ├─ CALL0 → dev.method()
                   │                                 └─ CALL1 → dev.method(arg)
                   │
                   ├─ fn_type == "ACC" ──▶ reservation_handler
                   └─ fn_type == "echo" ──▶ passthrough
```

### Key problems this creates

1. **PlutoServer is a hard-coded driver shim.** Every new device type (HackRF, webcam, etc.) requires a new `*_remote_server.py` with the same GET/SET/CALL boilerplate.
2. **The client must know the wire protocol** — `"Pluto:tx_freq:SET"` is baked into client code. Adding a method means editing both server *and* client.
3. **No discovery.** The client can't ask "what can this device do?" It just fires strings and hopes.
4. **The function_name encoding (`"Pluto:tx_freq:GET"`) conflates** device family, attribute name, and verb into a single colon-delimited string — fragile and unextensible.

---

## Target Architecture (To-Be)

```
Client                                Server
──────                                ──────
schema = GetDeviceSchema(gid)         ◀── returns DeviceSchema (JSON)
proxy  = DynamicProxy(schema)
proxy.tx_freq                         ──▶ Invoke(gid, "tx_freq", GET)
proxy.tx_freq = 2.4e9                 ──▶ Invoke(gid, "tx_freq", SET, {value: 2.4e9})
proxy.start_tx()                      ──▶ Invoke(gid, "start_tx", CALL, {})
proxy.transmit(samples)               ──▶ Invoke(gid, "transmit", CALL, {arg1: samples})
```

### New RPC surface (control plane)

| RPC                        | Returns                              | Purpose                        |
|---------------------------|--------------------------------------|--------------------------------|
| `IDL:ListDevices`         | `[{gid, name, driver, status}]`      | Discovery                      |
| `IDL:GetDeviceSchema`     | `DeviceSchema` (full JSON)           | Reflection                     |
| `IDL:GetDriverInfo`       | `{driver, version, schema_hash}`     | Cache-busting / compatibility  |
| `IDL:Invoke`              | `{result}` or `{error}`             | Generic call (replaces all per-device RPCs) |

### DeviceSchema shape

```jsonc
{
  "schema_version": "1.0",
  "schema_hash": "sha256:abcdef...",
  "driver": "adalm_pluto",
  "driver_version": "0.3.0",

  "properties": {
    "tx_freq": {
      "type": "float",
      "unit": "Hz",
      "access": "rw",
      "range": [70e6, 6e9],
      "doc": "Center TX frequency in Hz",
      "default": 2.4e9
    },
    "rx_gain": {
      "type": "float",
      "unit": "dB",
      "access": "rw",
      "range": [-3, 71],
      "doc": "RX gain"
    }
  },

  "methods": {
    "start_tx": {
      "args": [],
      "returns": "None",
      "doc": "Begin transmission with current buffer",
      "side_effects": true
    },
    "transmit": {
      "args": [
        {"name": "samples", "type": "ndarray_complex64", "doc": "IQ samples"}
      ],
      "returns": "None",
      "doc": "Load samples and transmit"
    },
    "receive": {
      "args": [
        {"name": "num_samples", "type": "int", "default": 1024}
      ],
      "returns": "ndarray_complex64",
      "doc": "Capture IQ samples from RX"
    }
  },

  "errors": {
    "DEVICE_BUSY": "Another session holds the device lock",
    "INVALID_RANGE": "Argument out of allowed range",
    "DRIVER_ERROR": "Underlying driver raised an exception"
  }
}
```

---

## Implementation Steps

### Phase 1 — Schema infrastructure (server-side, no wire changes yet)

**Goal:** Build the schema system and a Pluto "device wrapper" that can introspect itself, while keeping the existing RPC path working unchanged.

#### Step 1.1 — Define `DeviceSchema` dataclass + serialization

Create `src/remoteRF_server/common/idl/schema.py`:

```
DeviceSchema          (top-level container)
  ├─ PropertyDef      (one per get/set-able attribute)
  ├─ MethodDef        (one per callable)
  │    └─ ArgDef      (per-argument metadata)
  └─ ErrorDef         (per error code)
```

- Frozen dataclasses, JSON-serializable via a `.to_dict()` / `from_dict()` round-trip.
- Include `schema_hash` (SHA-256 of the canonical JSON) and `schema_version` string.
- Keep it pure Python, no external deps.

#### Step 1.2 — Write the `DeviceWrapper` base class

Create `src/remoteRF_server/common/idl/device_wrapper.py`:

```python
class DeviceWrapper(ABC):
    """
    A server-side author subclasses this per device type.
    The framework introspects it to auto-generate DeviceSchema.
    """
    @abstractmethod
    def driver_name(self) -> str: ...
    @abstractmethod
    def driver_version(self) -> str: ...

    # The wrapper exposes properties + methods via decorators:
    #   @idl_property(type="float", unit="Hz", access="rw", range=[70e6, 6e9])
    #   @idl_method(args=[ArgDef(...)], returns="ndarray_complex64")

    def get_schema(self) -> DeviceSchema:
        """Auto-build schema by reflecting on decorated attrs."""
        ...

    def invoke(self, method_name: str, args: dict) -> Any:
        """Generic dispatch: validates args against schema, calls impl."""
        ...

    def get_prop(self, name: str) -> Any: ...
    def set_prop(self, name: str, value: Any) -> None: ...
```

Key design decisions:
- **Decorators over config files.** The device author writes Python with `@idl_property` / `@idl_method` decorators. The schema is generated at wrapper-init time by reflecting on those decorators. No separate YAML/JSON to maintain.
- **Validation at the wrapper layer.** Range checks, type coercion, missing-arg detection all happen inside `invoke()` / `set_prop()` *before* touching the hardware driver. This means the driver itself stays dumb.

#### Step 1.3 — Port PlutoServer → `PlutoWrapper(DeviceWrapper)`

Create `src/remoteRF_server/drivers/adalm_pluto/pluto_wrapper.py`:

- Subclass `DeviceWrapper`.
- Move every `getattr` / `setattr` / `method()` currently in `PlutoServer.get()` / `.set()` / `.call_func()` into decorated wrapper methods.
- The wrapper holds a reference to the underlying `adi.Pluto` object (or `None` if disconnected).
- `PlutoServer` becomes a thin shim: `handle_call` just delegates to `wrapper.invoke()` / `.get_prop()` / `.set_prop()`. **Existing wire format unchanged at this point.**

This is the hardest migration step because you need to audit every property/method the current Pluto client uses and declare it in the wrapper. A good approach:
1. Grep the client codebase for every `"Pluto:XXX:GET"` / `"Pluto:XXX:SET"` / `"Pluto:XXX:CALL0"` string.
2. Build the decorator list from that.
3. Write a test that instantiates `PlutoWrapper(mock_adi_pluto)` and asserts `get_schema()` produces the expected JSON.

#### Step 1.4 — Store wrappers in `device_manager`

Currently `_DeviceState.dev` holds either a raw `adi.Pluto` object or a `VirtualDevice`. Change it so:

- For local devices: `dev` becomes a `DeviceWrapper` subclass instance (e.g. `PlutoWrapper`) which *owns* the raw driver handle internally.
- For host/virtual devices: `dev` stays as `VirtualDevice` (the host agent will run its own wrapper on the other side of the tunnel).

Add a `_DeviceState.wrapper: DeviceWrapper | None` field (or repurpose `dev`). The `acquire_device` context manager then yields `(gid, wrapper)` instead of `(gid, raw_dev)`.

**Checkpoint:** At this point the system works exactly as before, but internally every local device has a wrapper that can produce a schema. Nothing on the wire has changed.

---

### Phase 2 — New RPC endpoints (control plane)

**Goal:** Expose `ListDevices`, `GetDeviceSchema`, `GetDriverInfo`, and the generic `Invoke` through `RpcManager`, alongside the existing Pluto-specific path.

#### Step 2.1 — Add `IDL:*` handlers in `RpcManager.run_rpc()`

```python
if fn_type == "IDL":
    sub = function_name.split(':', 1)[1]   # "ListDevices", "GetDeviceSchema", ...
    return self._handle_idl(sub, args)
```

Implement:

- **`_handle_idl_list_devices`** — calls `get_all_devices()`, returns `[{gid, name, driver, online}]`.
- **`_handle_idl_get_schema`** — takes `gid` from args, finds the wrapper, calls `wrapper.get_schema().to_dict()`, returns it (with `schema_hash`).
- **`_handle_idl_get_driver_info`** — lightweight subset (driver name, version, hash) for cache checks.
- **`_handle_idl_invoke`** — takes `gid`, `method_or_prop`, `verb` (GET/SET/CALL), `call_args`. Does `acquire_device(token)`, then dispatches to `wrapper.invoke()` / `.get_prop()` / `.set_prop()`.

#### Step 2.2 — Schema caching protocol

On first connect (or reservation), the client calls `GetDriverInfo(gid)` and gets back `schema_hash`. If the client already has a cached schema with that hash, it skips `GetDeviceSchema`. Otherwise it pulls the full schema.

Server-side: compute `schema_hash` once at wrapper init and cache it. It only changes if the wrapper code changes (i.e. server restart / hot-reload).

#### Step 2.3 — Host/virtual device forwarding

For `VirtualDevice` entries, `IDL:GetDeviceSchema` needs to be forwarded through the host tunnel to the remote agent, which runs its own wrapper. Add a new tunnel message type (or reuse `hts.handle_host_device` with fn_type `"IDL"`).

The host agent on the other side receives the IDL request, introspects its local wrapper, and returns the schema JSON. This means the host agent also needs Phase 1 applied — but since it's the same codebase, that's just importing the same wrapper.

**Checkpoint:** Clients can now call `IDL:ListDevices`, get schemas, and invoke generically. The old `"Pluto:tx_freq:GET"` path still works in parallel.

---

### Phase 3 — Generic invoke replaces per-device handlers

**Goal:** Route all device calls through `IDL:Invoke` and deprecate the hard-coded `PlutoServer.handle_call` path.

#### Step 3.1 — Migrate RpcManager's Pluto branch

Change the `fn_type == "Pluto"` branch so it:
1. Still does `acquire_device(token)`.
2. Translates the old wire format (`"Pluto:tx_freq:GET"`) into a generic invoke call on the wrapper: `wrapper.get_prop("tx_freq")`.
3. This is a **backwards-compatible shim** — old clients keep working, but the server is now using the wrapper internally.

#### Step 3.2 — Remove PlutoServer

Once the shim is stable and tested, `PlutoServer` can be deleted entirely. All its logic now lives in `PlutoWrapper` + the generic invoke path.

#### Step 3.3 — Add new device wrappers

With the framework in place, adding a new device is:
1. Write `HackRFWrapper(DeviceWrapper)` with decorated properties/methods.
2. Register it in `_connect_from_record()` (i.e. `dtype == "hackrf"` → `HackRFWrapper(hackrf_handle)`).
3. Done. Clients discover it via `ListDevices`, fetch its schema, and invoke generically.

**Checkpoint:** The per-device RPC namespace (`"Pluto:..."`, `"HackRF:..."`) is gone. Everything goes through `IDL:Invoke`.

---

### Phase 4 — Client-side dynamic proxy

**Goal:** The client auto-builds a proxy object from the schema, so user code looks like `dev.tx_freq = 2.4e9` and it transparently becomes an RPC.

#### Step 4.1 — Python proxy (for debug / scripting)

```
debug-remoterf-package/
  remoterf_client/
    __init__.py
    proxy.py          # DynamicDeviceProxy
    connection.py     # RPC transport layer
    schema_cache.py   # local file cache keyed by schema_hash
```

`DynamicDeviceProxy`:
- On init: calls `GetDriverInfo(gid)`, checks local cache, pulls full schema if needed.
- Uses `__getattr__` / `__setattr__` to intercept property access → RPC.
- Methods are synthesized as callable wrappers that validate args client-side (from the schema) before sending.
- Includes docstrings from the schema, so `help(proxy.tx_freq)` works in IPython.

#### Step 4.2 — JS/TS proxy (for web client)

Same idea with ES6 `Proxy`:
```js
const schema = await rpc("IDL:GetDeviceSchema", {gid});
const dev = new Proxy({}, {
  get(_, prop) {
    if (schema.properties[prop]) return rpc("IDL:Invoke", {gid, name: prop, verb: "GET"});
    if (schema.methods[prop])    return (...args) => rpc("IDL:Invoke", {gid, name: prop, verb: "CALL", args});
  },
  set(_, prop, val) {
    if (schema.properties[prop]?.access.includes("w"))
      rpc("IDL:Invoke", {gid, name: prop, verb: "SET", value: val});
  }
});
```

#### Step 4.3 — Schema cache with versioning

Client caches schemas on disk keyed by `(driver_name, schema_hash)`. On connect:
1. `GetDriverInfo(gid)` → get hash.
2. Cache hit? Use cached schema. Miss? `GetDeviceSchema(gid)` → cache it.
3. If the server's hash changes mid-session (hot-reload), the next `Invoke` can return a `SCHEMA_STALE` error → client re-fetches.

---

### Phase 5 — Streaming & advanced features

#### Step 5.1 — Streaming endpoints in schema

For IQ data, video frames, etc., the schema declares streaming methods:

```jsonc
"methods": {
  "stream_rx": {
    "args": [{"name": "num_samples", "type": "int"}],
    "returns": "stream<ndarray_complex64>",
    "doc": "Continuous RX IQ stream",
    "streaming": true
  }
}
```

Transport: WebSocket upgrade from the existing RPC connection, or a dedicated streaming channel with a session token. The `Invoke` response for a streaming method returns a `stream_id` that the client subscribes to.

#### Step 5.2 — Custom scripting / test scripts

Since the schema is machine-readable, you can build:
- **Script recorder:** Client records a sequence of `Invoke` calls → saves as a JSON "test script".
- **Script player:** Replays a test script against any device whose schema is compatible (matched by schema_hash or property/method name overlap).
- **Auto-generated Jupyter notebooks:** From the schema, generate a notebook with cells pre-filled for each property/method.

#### Step 5.3 — Versioning & compatibility ranges

`GetDriverInfo` returns `compat_ranges`:
```jsonc
{
  "driver": "adalm_pluto",
  "driver_version": "0.3.0",
  "schema_hash": "sha256:...",
  "compat_ranges": {
    "min_client_version": "0.1.0",
    "deprecated_methods": ["old_start_tx"]
  }
}
```

Client checks its version against `min_client_version` and warns if using deprecated methods.

---

## File Map (new / modified)

```
src/remoteRF_server/
  common/
    idl/
      __init__.py
      schema.py              ← DeviceSchema, PropertyDef, MethodDef, ArgDef
      device_wrapper.py      ← DeviceWrapper ABC + decorators
      decorators.py          ← @idl_property, @idl_method
      type_coerce.py         ← schema-driven arg validation + coercion

  drivers/
    adalm_pluto/
      pluto_wrapper.py       ← PlutoWrapper(DeviceWrapper)  [NEW]
      pluto_remote_server.py ← becomes thin shim, then deleted

  server/
    device_manager.py        ← _DeviceState gains .wrapper field
    rpc_manager.py           ← adds IDL:* handlers
    idl_handler.py           ← extracted IDL RPC logic  [NEW]

debug-remoterf-package/      ← client-side package
  remoterf_client/
    proxy.py
    connection.py
    schema_cache.py
```

---

## Suggested Execution Order

| Step | What | Risk | Est. effort |
|------|------|------|-------------|
| 1.1  | `DeviceSchema` dataclasses | Low — pure data | Small |
| 1.2  | `DeviceWrapper` ABC + decorators | Med — API design matters | Medium |
| 1.3  | `PlutoWrapper` (port PlutoServer) | Med — need to audit every attr | Medium-Large |
| 1.4  | Wire wrapper into `device_manager` | Med — touches core state | Medium |
| 2.1  | `IDL:*` RPC handlers | Low — additive | Small |
| 2.2  | Schema caching protocol | Low | Small |
| 2.3  | Host tunnel forwarding for IDL | Med — tunnel complexity | Medium |
| 3.1  | Backwards-compat shim in RpcManager | Low — shim only | Small |
| 3.2  | Delete PlutoServer | Low — if tests pass | Small |
| 3.3  | HackRFWrapper / WebcamWrapper | Low — framework exists | Medium each |
| 4.1  | Python dynamic proxy | Low | Medium |
| 4.2  | JS proxy | Low | Medium |
| 5.*  | Streaming, scripting, versioning | Higher — design space | Large |

**Recommended first PR:** Steps 1.1 + 1.2 together (schema + wrapper ABC + decorators). This is the foundation and forces you to nail down the schema shape before anything else depends on it.

**Second PR:** Step 1.3 (PlutoWrapper) + 1.4 (wire into device_manager). This proves the abstraction works against a real device without changing any client behavior.

**Third PR:** Steps 2.1–2.2 (IDL endpoints) + 3.1 (backwards-compat shim). Now clients can *optionally* use the new path.

**Fourth PR:** Step 4.1 (Python proxy in `debug-remoterf-package`). First time a client can do `dev.tx_freq` and have it Just Work.

---

## Open Design Questions

1. **Arg serialization.** You currently use `map_arg` / `unmap_arg` which wraps values in protobuf-like `Value` messages. Should `IDL:Invoke` keep this, or switch to plain JSON with schema-driven type coercion? JSON is simpler for the reflection story but loses some type fidelity (e.g. `bytes` vs `string`, `complex64` arrays).

2. **Granularity of `Invoke`.** Single dispatch (`Invoke(gid, "tx_freq", GET)`) is simple but chatty for "set 5 properties then call start_tx". Consider a batched variant: `InvokeBatch(gid, [{SET, tx_freq, 2.4e9}, {SET, rx_gain, 30}, {CALL, start_tx}])`.

3. **Error propagation.** Currently errors come back as `{'Error': map_arg(str(e))}`. The IDL should define structured error codes so the client proxy can raise typed exceptions (e.g. `DeviceBusyError`, `InvalidRangeError`).

4. **Hot-reload.** If a server admin edits a wrapper and restarts, `schema_hash` changes. Do you want hot-reload without restart? That's doable (importlib.reload + re-introspect) but adds complexity.

5. **Auth in IDL calls.** Currently the token is in `args['a']`. For `IDL:Invoke`, you probably want it as a first-class field rather than mixed into the args dict — cleaner separation of transport-level auth from application-level args.