# remoterf-device-core

The parts of RemoteRF that a lab Server (`remoteRF-server`) and a Host (`remoterf-host`) share, kept as one copy:

- the gRPC protocol (`grpc.proto`, `grpc_host.proto`) and the Dynamic v2 codec;
- the device IDL (`DeviceSchema`, `idl_expose`, `idl_register`) and the schema v2 builder;
- the built-in driver schemas: ADALM-Pluto (incl. PoE), Pluto MIMO, HackRF, RTL-SDR, TI mmWave, USRP and USRP Phaser;
- `schemas.json`, the built-in drivers' schema hashes, and `schema_digest()`, the one hash rule;
- the ICE/QUIC helpers for direct device paths (install with the `direct` extra).

Server and Host pin the same version, so a host running a built-in driver reports exactly the hash its lab knows.

You rarely install it directly: `remoteRF-server` and `remoterf-host` pull it in as a dependency.

License: GPL-3.0-or-later.
