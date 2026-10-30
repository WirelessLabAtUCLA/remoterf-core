# RemoteRF

Remote access to real software-defined radios, from the Wireless Lab at UCLA.

This repository holds the code that runs on users' machines and in labs:

| Path | Package | What it is |
|---|---|---|
| `client/` | `remoterf` | CLI and Python SDK (`pip install remoterf`) |
| `server/` | `remoteRF-server` | Lab server: owns radios, accounts and reservations |
| `host/` | `remoterf-host` | Host agent that attaches remote radios (e.g. a Pi) to a lab |
| `packages/remoterf-federation-core/` | `remoterf-federation-core` | Shared protocol library (lab ↔ Global) |
| `packages/remoterf-device-core/` | `remoterf-device-core` | Shared device/driver library |

> Status: being assembled. Code is moving here from the RemoteRF-Client, RemoteRF-Server and
> RemoteRF-Host repositories, with history. Until that lands, those repositories stay authoritative.

## Contributing

Work happens through GitHub issues and pull requests into `main`. Every PR runs the tests for
the packages it touches and needs a maintainer's review before it can merge. Releases to PyPI are
published by CI, never by hand.

## Security

See [SECURITY.md](SECURITY.md). Please do not open public issues for vulnerabilities.

## License

GPL-3.0, see [LICENSE](LICENSE).
