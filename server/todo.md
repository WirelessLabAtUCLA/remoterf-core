# Latency/Performance

Debugging needed! (to determine what/why exactly causes the 'slowness') (could also just be the wifi speed, etc.)

<!-- Currently, all calls route through TCP. (handshaking, might be slow).

Implement parallel UDP port with multiplexed streams, so that some actions can be implemented as 'lossy' (packets may be lost) BUT at a much higher data rate.

Optional argument in each function that specifies that (like remoteRF_is_lossy: True, etc.), determines the stream transport (TCP vs UDP). -->

# Proper `Gist` Server Information

Pull data from the main database (with some options to set, like whitelist for devices AND user groups + max timestamp/payload size)

Check for if gist isn't setup, no 'warning' or anything.

# Interface Description Language `IDL`:

A device API “contract” that hosts/servers can publish, and clients can discover + bind to automatically, so adding a new device does not require shipping a new hard-coded client library for that device.

“Reflective IDL + Generic Invoke”

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

All the network 'heads' (servers) would live in a single VPN plane with a VPN gateway server.

* Control Plane and Data Plane

Example:

* HeadScale Control Plane
* WireGuard Data Plane

First simply allow these servers to talk to each other properly + Permissions, etc. 

Afterwords, to support '3rd party' individuals, I would implement seperate 'regional' nodes that exist as a L7 proxy into the main net.