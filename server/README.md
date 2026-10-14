# Remote RF Server Guide (Linux)

## Environment and setup

This guide installs Miniconda, installs **mamba**, creates a conda env named `remoterf`, installs dependencies, and verifies the install on Ubuntu Server 24.04 LTS.

* This guide is done **APT-based** distro (Ubuntu/Debian/Raspberry Pi OS 64-bit).

### 1) System Prerequisites

```bash
sudo apt update
sudo apt install -y curl ca-certificates bzip2 git build-essential
sudo apt install -y libusb-1.0-0 udev
```

Optional: confirm architecture:

```bash
uname -m
```

* `x86_64` → Intel/AMD
* `aarch64` → ARM64 (Raspberry Pi 64-bit, some servers)

---

### 2) Install Miniconda

### 2.1 Download the installer

#### x86_64

```bash
cd /tmp
curl -fsSLO https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
```

#### ARM64 (aarch64)

```bash
cd /tmp
curl -fsSLO https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-aarch64.sh
```

### 2.2 Install (non-interactive, recommended)

#### x86_64

```bash
bash Miniconda3-latest-Linux-x86_64.sh -b -p "$HOME/miniconda3"
```

#### ARM64 (aarch64)

```bash
bash Miniconda3-latest-Linux-aarch64.sh -b -p "$HOME/miniconda3"
```

### 2.3 Enable conda in your current shell

```bash
source "$HOME/miniconda3/etc/profile.d/conda.sh"
conda --version
```

> If you want conda available automatically in new terminals:
>
> ```bash
> "$HOME/miniconda3/bin/conda" init bash
> source ~/.bashrc
> ```

### 2.4 Install **mamba** (default solver)

```bash
conda install -n base -c conda-forge -y mamba
mamba --version
```

Might have to accept anaconda TOS.
```bash
conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main

conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r
```

### 3) Create the Environment

```bash
mamba create -n remoterf -y -c conda-forge -c defaults  python=3.10 pip setuptools wheel grpcio protobuf python-dotenv numpy scipy libiio pylibiio libusb

conda activate remoterf
python -m pip install -U pip
python -m pip install remoterf-server
```

The base `remoterf-server` package installs the Python runtimes for every
packaged device driver, including ADALM-Pluto, RTL-SDR, and HackRF. No device
extras are required.

## Server Config

Depending on your IT/ISP setup, this will vary, but regardless, you will need a static dial name, whether that be a IP address or a DNS.

### Generate CA Certificates

If direct IP connection: (force overrides existing)
```bash
serverrf --gen-certs 192.168.1.50 --days 3650 --force
```

If using DNS: (todo: DNS on client side)
```bash
serverrf --gen-certs 192.168.1.50 --dns remoterf.local --days 3650 --force
```

Confirm/View:
```bash
serverrf --show-certs
```

### Specify Outward facing Ports

By default, the users expect to adjacent ports. Thus, it is recommended to do the following:

```bash
# examples
serverrf --config --main-port 61000 --cert-port 61001
serverrf --config --main-port 20000 --cert-port 20001
serverrf --config --main-port 32000 --cert-port 32001
```

Confirm/View:
```bash
serverrf --config --show
```

## Testing Connection

The server now should be functional in its most basic form. In the same conda env:

```bash
serverrf --serve
```

If you see something along the lines of: self.socket.bind(self.server_address) PermissionError: [Errno 13] Permission Denied, make sure the ports you are using are not OS reserved (<1024)

### Confirm it works locally

<!-- In a new terminal:

```bash
mamba create -n local_testing -y python=3.10 pip
conda activate local_testing
pip install remoterf
```

Testing: In the remoterf env run: -->

Start the server:
```bash
serverrf -s
```

For a loopback-only development server, explicitly bind both services to
localhost:

```bash
REMOTERF_BIND_HOST=127.0.0.1 GRPC_PORT=55051 CERT_PORT=55052 \
  serverrf --serve --headless
```

Headless and interactive shutdown both stop accepting RPCs, close all Dynamic
v2 sessions/handles and native devices, stop the certificate provider, and
terminate the reservation-update worker.

Take note of the Local IP and Local Port, for example, if you see:

```bash
Local IP: 164.67.195.210
Local Port: 61000
```

then run the below on a seperate terminal (make sure to keep serverrf -s RUNNING!)

Confirm that its reachable:

```bash
nc -vz 164.67.195.210 61000
nc -vz 164.67.195.210 61001
```

<!-- ```bash
remoterf -c -a 164.67.195.210:61000
```

If sucessful, it should look something like this:

```bash
gRPC target : 164.67.195.210:61000
cert port   : 164.67.195.210:61001
CA cert     : /home/remoterf-dev/.config/remoterf/certs/default.crt
env file    : /home/remoterf-dev/.config/remoterf/.env
```

If it fails, please troubleshoot, and make sure that the serverrf -s is actually running, and that you have no firewalls, etc.

Cleanup:
```bash
conda env remove -n local_testing
``` -->

### Network Testing

Same test, but on a different computer. Works for UNIX based machines:

Confirm that the Server is reachable:
```bash
nc -vz 164.67.195.210 61000
nc -vz 164.67.195.210 61001
```

You most likely will need to port forward, etc.

Troubleshooting:
Some distros come with default firewall settings that block traffic on specific ports. Make sure that your firewall settings permit traffic to and from the server. Depending on the setup, you may also have ISP firewalls.

## RemoteRF federation v2 Phase 1

The `global-dev` branch implements the development-only Phase-1 federation
boundary. A Server can issue and verify participant-signed
`federated_enroll` and `permissions_read` actions under explicit bilateral
contracts. Destination permission reads use current local membership and
expiry state; unknown principals return signed empty membership without
allocation, while disabled principals return a signed error.

Ordinary `ACC:get_perms` remains the native permission operation. When a
federation HOME aggregator is configured, its exact local/federation summary
is additive in `details.home_permissions`; local output survives remote
failure and is safe with zero devices.

Gate H (`remoterf-federation-core==0.10.1`) adds the federated device plane:
`device_list`, `device_reservations`, `device_reserve`, `device_cancel`, and
`device_rpc` under the `DEVICE_READ`, `DEVICE_RESERVE`, and `DEVICE_CONTROL`
contract capabilities. A contract without them still grants no hardware
reach. The destination decides everything from its own tables (enrolled proxy,
local device permissions, quotas, overlap, a federation-created reservation
that is live now) and runs the RPC after the grant transaction commits through
the ordinary `RpcManager` dispatch; the reservation's bearer token never leaves
this Server. See [federated devices](docs/federated-devices-gate-h.md).

Streaming, the sample plane, and DynamicControlV2 are not federated. The old
Global-v1 connector/catalog and relay-ingress account gate have been removed
from the Server runtime. Production remains unchanged until a separate cutover
is authorized.

See [federated enrollment](docs/federated-enrollment-v2.md); the cross-project
runtime boundary is documented in `remoterf-vps-global/docs/phase1-runtime.md`.

## RemoteRF Global v0 — Server Setup

RemoteRF Global v0 is an **optional, external** networking proof of concept. It
lets a public client reach this server through a relay, without this server
implementing, depending on, or even knowing about RemoteRF Global:

```
Public RemoteRF Client
        |  existing RemoteRF protocol (unmodified)
        v
ucla.global.remoterf.net
        |  transparent Layer-4 TCP forwarding
        v
DigitalOcean VPS
        |  WireGuard
        v
UCLA RemoteRF Server   <-- this repo, unchanged behavior
        |
        v
       SDRs
```

The VPS never terminates or interprets RemoteRF traffic — it forwards raw TCP
bytes. The TLS relationship stays exactly what it already is:

```
RemoteRF Client  <-- existing RemoteRF TLS -->  UCLA RemoteRF Server
```

This server remains a completely normal, independent RemoteRF deployment. If
`global.remoterf.net` is offline or never existed, this server and ordinary
LAN clients are unaffected. Nothing in this repository implements WireGuard,
global accounts, or federation — that all lives in the separate
`remoterf-vps-global` infrastructure project.

**Inspection finding:** the existing server already supports this path through
configuration alone. No server source changes were required for v0 — see
"How this was verified" below.

### Required configuration on the UCLA server

1. **Bind to all local interfaces** so both the LAN and the WireGuard
   interface (`wg0`, `10.77.0.2`) can reach the gRPC and certificate services:

   ```bash
   serverrf --config --main-port 61005 --cert-port 61006   # unless already set
   REMOTERF_BIND_HOST=0.0.0.0 serverrf --serve --headless
   ```

   `REMOTERF_BIND_HOST` already takes precedence over this server's normal
   LAN-address auto-discovery (see `_get_bind_host()` in
   `src/remoteRF_server/server/grpc_server.py`). Setting it to `0.0.0.0` does
   **not** expose the server to the public Internet by itself — see
   "Security model" below.

2. **Add a DNS SAN for the public hostname**, alongside the existing LAN IP
   SAN, so a client dialing `ucla.global.remoterf.net` can validate this
   server's real certificate:

   ```bash
   serverrf --gen-certs <LAN-static-ip> \
     --dns ucla.global.remoterf.net \
     --force
   ```

   `gen_certs.py` already supports a repeatable `--dns` flag alongside the
   required IP SAN — both land in the same certificate, and existing LAN
   clients keep working off the IP SAN. This is a certificate **regeneration**
   (existing files must be replaced with `--force`), so any device/host that
   trusts the old `server.crt`/`ca.crt` needs the new `ca.crt` too.

### Optional recommendation (not required for v0)

- Restrict inbound access to the RemoteRF ports (`61005`/`61006`, or whatever
  `serverrf --config --show` reports) at the host firewall to the WireGuard
  peer `10.77.0.1` and the UCLA LAN/subnet, if you want a tighter posture than
  "listen on 0.0.0.0 and rely on there being no public route to this host."
  Do **not** apply this automatically — a wrong rule can lock out LAN clients.
  Never expose the RemoteRF ports directly to the public Internet; the VPS is
  the only public ingress point.

### WireGuard (host OS, not this repository)

WireGuard is configured entirely outside this Python package, at the UCLA
host OS level (see `remoterf-vps-global` for the VPS/tunnel setup). This
server only needs to know:

- UCLA host tunnel address: `10.77.0.2` (interface `wg0`)
- VPS peer address: `10.77.0.1`

RemoteRF Server does not manage WireGuard keys, does not depend on a
WireGuard library, and does not need to distinguish whether a client arrived
via the LAN, via `wg0`, or via the VPS relay — all three are just TCP
connections to the same bound socket.

### Security model

```
UCLA LAN        ------> RemoteRF Server
WireGuard wg0   ------> RemoteRF Server
public Internet   X     (no direct inbound path)
```

- Binding to `0.0.0.0` means the *application* listens on all local
  interfaces; it is host/firewall policy that decides where it is actually
  *reachable*.
- There is still no direct public inbound exposure of UCLA. Public traffic
  only reaches this server after the VPS relay forwards it across WireGuard.
- Existing TLS/mTLS, account, and reservation authorization are unchanged.
  Nothing about this setup weakens application authentication.

### Known limitation: client source IP

With the v0 TCP relay, this server sees the WireGuard peer address
(`10.77.0.1`) as the source for every publicly-relayed connection, not the
original Internet client's address. This is expected and acceptable for v0 —
no PROXY protocol or custom IP-forwarding mechanism is introduced. Real
per-client attribution is future RemoteRF Global identity/audit work, not
part of this proof of concept.

### End-to-end verification

On the UCLA host:

```bash
# 1. Confirm WireGuard is up (expect 10.77.0.2)
ip addr show wg0
wg show

# 2. Confirm RemoteRF is listening on both the LAN and wg0 addresses
ss -lntp | grep -E ':61005|:61006'
```

From the VPS:

```bash
# 3. Confirm connectivity to both RemoteRF services over WireGuard
nc -vz 10.77.0.2 61005   # gRPC
nc -vz 10.77.0.2 61006   # certificate bootstrap
```

Verify the certificate identity (run from anywhere that can reach the port):

```bash
# 4. Confirm the DNS SAN is present, e.g. dialing over the WireGuard address
openssl s_client -connect 10.77.0.2:61005 -servername ucla.global.remoterf.net </dev/null 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName
```

From a laptop outside UCLA, using the existing RemoteRF client, unmodified:

```bash
# 5. Dial the public hostname through the VPS relay
remoterf -c -a ucla.global.remoterf.net:61005
```

Then use the existing account/login/config/reservation/device flow and
perform one harmless device operation. Success is the existing RemoteRF
client reaching this unmodified server through
`ucla.global.remoterf.net -> VPS -> WireGuard -> RemoteRF Server`, over the
same RemoteRF protocol and TLS relationship as any LAN client.

### How this was verified (no source changes required)

- **Bind address**: `_get_bind_host()` reads `REMOTERF_BIND_HOST` first and
  only falls back to LAN auto-discovery (a UDP "connect" trick, then
  `127.0.0.1`) when it is unset. The result is passed straight into
  `grpc.server(...).add_secure_port(f"{bind_host}:{port}", ...)` as a plain
  string, so `0.0.0.0` binds normally. Covered by `tests/test_bind_host.py`.
- **Ports**: `GRPC_PORT` and `CERT_PORT` (default `61005`/`61006` in this
  repo's `.env.server`, overridable via `serverrf --config`) are the only two
  ports an ordinary client needs.
- **Certificate/bootstrap flow**: `cert_provider.py` binds to the *same*
  `bind_host` as the gRPC service and serves `ca.crt` verbatim (raw TCP or a
  minimal HTTP GET) — it contains no LAN-only metadata, redirects, or
  IP-literal assumptions. Clients trust `ca.crt`; the server presents
  `server.crt`, which is self-signed by that CA (not a public CA).
- **TLS SANs**: `gen_certs.py` already builds `subjectAltName` from *both* an
  IP entry and any number of `--dns` entries in one certificate, so DNS and
  LAN IP identities coexist. Covered by `tests/test_gen_certs.py`.
- **HostRF**: `HostTunnelServicer` is registered on the *same* `grpc.server`
  instance as the main RPC services in `start_server_runtime()` — it shares
  the same bind address and port, so it needs no separate v0 configuration
  and nothing here changes its behavior.

## Server Device Configuration

ADALM-Pluto, RTL-SDR, TI mmWave, and local or HostRF-owned UHD inventories are supported.
Every USRP remains registered as device type `usrp`; a structured profile
selects the UHD transport and runtime capabilities report the model actually
opened.

To connect plutos to the server:

```bash
iio_info -s
```

If the pluto doesn't show up, yet the below works:

```bash
sudo iio_info -s
```

Run the below and reboot after: 

```bash
sudo groupadd -f plugdev
sudo usermod -aG plugdev "$USER"

sudo tee /etc/udev/rules.d/53-adi-usb.rules >/dev/null <<'EOF'
# Type the below in
SUBSYSTEM=="usb", ATTR{idVendor}=="0456", MODE="0660", GROUP="plugdev"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger
sudo reboot now
```

The below should work as intended now:
```bash
iio_info -s
```

Look for 'serial='. Take note of this serial.

```bash
serverrf --device --add --pluto <device_id:name:serial>

# example
serverrf --device --add --pluto 0:pluto_0:104473f6
serverrf --device --add --pluto "1:Pluto SDR (OTA):58472j"
```

Run the below to check if this new device exists:
```bash
serverrf --device --show
```

Run the below to edit names of existing devices:
```bash
serverrf -d --edit-name 0 "New Name"
```

Note that all device and server config parameters need a 'restart' to take affect (ctrl + c -> serverrf -s).

### RTL-SDR

RTL-SDR is a packaged receive-only schema driver. Its Python wrapper and
packaged native library are required dependencies of `remoterf-server`; clients
do not need either dependency. Install the optional command-line tools only if
you want to run the local `rtl_test` diagnostic:

```bash
conda install -c conda-forge rtl-sdr
```

`pyrtlsdrlib` supplies a matching native library for PyRtlSdr. This avoids
loading an incompatible system `librtlsdr` that is missing optional symbols.
For RTL-SDR Blog V4 hardware, use a native library with V4/R828D support.

Confirm discovery before adding the inventory entry:

```bash
rtl_test -t
```

Add by stable USB serial when possible, or by zero-based index when a device
has no useful serial:

```bash
serverrf --device --add --rtl-sdr 4:rtl_fm:serial=00000001
serverrf --device --add --rtl-sdr 4:rtl_fm:index=0
serverrf --device --show
```

The canonical YAML form is:

```yaml
devices:
  - device_id: 4
    device_type: rtl_sdr
    name: rtl_fm
    init:
      serial: "00000001"
```

The schema exposes center frequency (`center_freq`/`fc`), sample rate
(`sample_rate`/`rs`), gain, valid gains, frequency correction, bandwidth, AGC,
bias tee, direct sampling, offset tuning, dithering, bounded `read_samples`,
bounded `read_bytes`, buffer reset, and identity.
Optional native controls are probed at runtime. An unsupported control remains
discoverable but raises a clear `NotImplementedError`. Remote async callbacks
are intentionally not exposed because callbacks cannot cross an RPC boundary;
clients perform repeated bounded synchronous reads instead.

Ubuntu may load the DVB kernel driver for the dongle. A compatible
`librtlsdr` can detach it while opening the device. If that is disabled in the
installed native build, blacklist `dvb_usb_rtl28xxu` or unload it before
starting RemoteRF.

### HackRF

HackRF is a packaged schema driver backed by `pyhackrf2`, which is installed by
the base `remoterf-server` package. Install the native HackRF runtime and tools
on the server that owns the radio:

```bash
sudo apt-get install hackrf
hackrf_info
```

Add each device to `~/.config/remoterf/devices.yml` by stable serial when
possible:

```yaml
devices:
  - device_id: 10
    device_type: hackrf
    name: HackRF One
    init:
      serial: "0000000000000000719031ac235bb14a"
```

The generated `HackRF` client exposes center frequency, sample rate, filter
bandwidth, LNA/VGA/TXVGA gains, front-end amplifier state, bias tee state,
receive sample-count limit, bounded synchronous IQ reads, TX-buffer loading,
enumeration, and serial-number access. The wrapper also compensates for the
recursive LNA getter and stale amplifier state in `pyhackrf2` 1.0.3.

### TI mmWave radar

The packaged `ti_mmwave` v1 schema initially targets xWR68xx out-of-box demo
firmware using a Silicon Labs CP2105 dual-UART bridge. Runtime control uses the
Enhanced interface at 115200 baud. Binary TLV output uses the Standard
interface at 921600 baud. `pyserial` is installed with `remoterf-server`.

On macOS, install the official
[Silicon Labs CP210x VCP driver](https://www.silabs.com/software-and-tools/usb-to-uart-bridge-vcp-drivers)
first. Reconnect the radar and verify that two serial device nodes exist:

```bash
ls /dev/cu.*
python -m serial.tools.list_ports -v
```

Add the device by the stable CP2105 bridge serial printed by the second command:

```bash
serverrf --device --add --ti-mmwave 20:ti_radar:00DF4F69
serverrf --device --show
```

The canonical inventory supports explicit port overrides when an operating
system does not publish the Enhanced/Standard interface names:

```yaml
devices:
  - device_id: 20
    device_type: ti_mmwave
    name: ti_radar
    init:
      serial: "00DF4F69"
      firmware_profile: xwr68xx_oob_sdk3
      cli_baud: 115200
      data_baud: 921600
      frame_queue_depth: 8
      # cli_port: /dev/cu.SLAB_USBtoUART-enhanced
      # data_port: /dev/cu.SLAB_USBtoUART-standard
```

RemoteRF owns both UART handles while the server is running. The schema exposes
runtime CLI commands, ordered `.cfg` application, sensor start/stop, version
query, queue health, and bounded complete-frame reads. Firmware flashing and
board SOP-mode changes are intentionally outside the remote API.

Unit tests do not require hardware. After both UARTs enumerate, run the opt-in
hardware smoke test without starting `serverrf` or another serial application:

```bash
REMOTERF_TI_MMWAVE_SERIAL=00DF4F69 \
  python -m unittest tests.test_ti_mmwave_hardware
```

If interface-name discovery is unavailable, also set
`REMOTERF_TI_MMWAVE_CLI_PORT` and `REMOTERF_TI_MMWAVE_DATA_PORT`.
To extend the smoke test through configuration, sensor start, and one complete
binary frame, set `REMOTERF_TI_MMWAVE_CONFIG` to a board-compatible TI `.cfg`
file. `REMOTERF_TI_MMWAVE_FRAME_TIMEOUT` optionally changes the five-second
frame deadline.

### Structured USRP profiles

The NI USRP-2901, Ettus Research USRP B205-mini, and USRP N210 are
hardware-qualified native profiles in the packaged RemoteRF server and client.
They do not require a custom schema in
<code>~/.config/remoterf/drivers/</code>. A fresh server installs one shared
<code>usrp</code> schema for all of them and for generic UHD families.

Profiles are data, not separate drivers. Each entry declares its canonical ID,
aliases, UHD family/type, transport, selector, qualification level, and live
identity match terms. The current registry contains:

| Profile | Transport | Support level | Examples |
| --- | --- | --- | --- |
| `usrp2901` | USB | `qualified_native` | NI USRP-2901 |
| `b205mini` | USB | `qualified_native` | Ettus Research USRP B205-mini/B205mini-i |
| `n210` | Ethernet | `qualified_native` | USRP N210 |
| `b2xx` | USB | `generic_uhd` | B200, B210, B200mini |
| `n2xx` | Ethernet | `generic_uhd` | N200 and unqualified N2xx variants |
| `x3xx` | Ethernet | `generic_uhd` | X300, X310 |
| `n3xx` | Ethernet | `generic_uhd` | N300, N310, N320, N321 |
| `x4xx` | Ethernet | `generic_uhd` | X410, X440 |
| `e3xx` | Embedded | `generic_uhd` | E310, E320 |
| `generic_usrp` | Runtime-detected | `generic_uhd` | UHD fallback |

`generic_uhd` means the device uses the same native `uhd.usrp.MultiUSRP`
control and streaming path, but RemoteRF has not yet run that model's physical
qualification suite. Frequency ranges, gains, channels, sensors, clocks, and
OTW support are still read/probed from the live device instead of copied from
the profile.

The server automatically installs and registers its complete USRP v1/v2
schema on first startup, so clients can discover the API even when UHD is not
installed locally. Existing custom `usrp` drivers in
`~/.config/remoterf/drivers/` take precedence over that default.

Opening a real USRP session requires the server or HostRF machine that owns the hardware to
have the exact supported UHD Python API, UHD `4.10.0.0`, installed. The
server does not open the device while loading inventory. It opens the
reservation's exact `type=b200,serial=...` device only when the authenticated
client opens a v2 session.

Add a qualified serial-bound NI USRP-2901:

```bash
serverrf --device --add --usrp-2901 7:usrp2901_lab:31A2B3C
serverrf --device --show
```

The older `--usrp2901` and `--usrp` spellings remain accepted as aliases for
`--usrp-2901` so existing provisioning scripts continue to work.

Add a qualified serial-bound Ettus Research USRP B205-mini:

```bash
serverrf --device --add --usrp-b205-mini 9:b205mini_lab:31E9F48
serverrf --device --show
```

The `--usrp-b205mini` and `--b205mini` spellings are accepted as aliases.
Registration stores the explicit `b205mini` profile, UHD `type=b200`, and the
device serial, so it remains distinct from an NI USRP-2901 on the same server.

Add a qualified address-bound N210 on a dedicated Ethernet interface:

```bash
serverrf --device --add --usrp-n210 8:n210_lab:192.168.137.21
serverrf --device --show
```

Add another registered family through the generic profile command:

```bash
serverrf --device --add --usrp-profile \
  10:x310_lab:x3xx:192.168.10.2
```

The final value is interpreted according to the profile's `selector`: serial
for USB profiles, address for network profiles, or raw UHD device arguments for
the generic/embedded profiles. Alias names such as `x310`, `b210`, and `usrp2`
are normalized to their canonical family profile.

The canonical inventory is `~/.config/remoterf/devices.yml`:

```yaml
devices:
  - device_id: 7
    device_type: usrp
    name: usrp2901_lab
    init:
      profile: usrp2901
      type: b200
      serial: 31A2B3C
  - device_id: 8
    device_type: usrp
    name: n210_lab
    init:
      profile: n210
      type: usrp2
      addr: 192.168.137.21
  - device_id: 9
    device_type: usrp
    name: b205mini_lab
    init:
      profile: b205mini
      type: b200
      serial: 31E9F48
```

The NI USRP-2901 and B205-mini inventories each use an explicit profile plus
their unique `type=b200,serial=...` selector. The N210 inventory is independently
constrained to `type=usrp2,addr=...`, preventing a reservation from opening a
different UHD transport. All profiles publish the same generated
`uhd.usrp.MultiUSRP` API. `device_profile` contains the resolved structured
definition, while `profile_resolution` shows whether it came from live native
identity or inventory and flags a configured/live profile mismatch.

To add a newly qualified USRP model, add one `USRPProfile` entry in
`remoteRF_server/drivers/usrp/profiles.py`, give it identity terms and the
correct UHD selector/type, and add a read-only hardware qualification test.
No new server driver, gRPC service, or client API implementation is required.

When a USRP session opens, RemoteRF asks native UHD to construct inactive RX
streamers for UHD 4.10's default, `sc16`, `sc12`, and `sc8` wire formats. No
stream command is issued and no samples are received. Successful probes are
cached for that hardware session, populate `stream_format_capabilities.rx`,
and determine the backward-compatible `supported_otw_formats` list. TX formats
are not probed during capability discovery. Set
`REMOTERF_USRP_PROBE_RX_OTW_FORMATS=0` before starting the server to disable
the RX probe; clients may still leave `StreamArgs.otw_format` empty and let UHD
select its default.

All USRP operations exposed by the Dynamic v2 schema are available without a
separate policy file. This includes transmit controls, transmit streaming,
GPIO/register methods, and property-tree writes. `usrp_policy.yml` is not read
or required by the current server.

RemoteRF forces `UHD_LOG_CONSOLE_LEVEL=off` before importing UHD so native UHD
messages do not overwrite the interactive `serverrf` prompt. To temporarily
restore UHD diagnostics, explicitly set `REMOTERF_UHD_CONSOLE_LEVEL` to a level
such as `warning`, `info`, or `debug` before starting the server:

```bash
REMOTERF_UHD_CONSOLE_LEVEL=warning serverrf -s
```

On every qualified target, generate the introspection record and enforce the
pinned API gate:

```bash
python -m remoteRF_server.tools.introspect_uhd \
  --output uhd-4.10.0.0-target.json
```

The command exits nonzero for a version mismatch, a missing required member,
an unclassified public `MultiUSRP` member, or any still-deferred schema entry.
Hardware differential,
two-channel/full-duplex, USB 2/3, external clock/PPS, policy-bypass, and
qualified-LAN performance tests remain mandatory release gates; they cannot
be completed on a checkout without UHD and a physical NI USRP-2901.

To qualify the actual two-channel RX path through both checkouts on the Linux
USRP host, run the opt-in localhost client/server test from the server repo:

```bash
REMOTERF_TEST_USRP_SERIAL=31A2B3C \
REMOTERF_CLIENT_SRC=../RemoteRF-Client/src \
python -m unittest discover -s tests \
  -p test_usrp_client_server_hardware.py -v
```

This opens the serial-bound device, negotiates the v2 schema over a real
localhost gRPC socket, configures both RX channels through the client API,
receives raw binary IQ, restores the prior RX settings, and closes the remote
stream/session. It is RX-only and does not enable transmit.

Dynamic v2 control and `SampleDataV1.SampleStream` run on the existing TLS
gRPC channel. For HostRF-owned devices, the server proxies the same protobuf
operations through the authenticated host tunnel and releases the remote
session if that tunnel disconnects. IQ samples are carried as bounded raw binary payloads with
dtype/shape/channel metadata; JSON/base64 and repeated-float sample transport
are not used.

## Server Runtime Configuration

After running `serverrf --serve`, you’ll enter the **RemoteRF Server Shell**. This interactive shell is used for runtime administration: users, devices, reservations, user groups, enrollment codes, and live host-tunnel state.

---

### Server

* `help` / `h` / `?` — Show help
* `clear` / `cls` — Clear the screen
* `status` / `server status` — Show server status (start time / uptime / bind + cert ports)
* `quit` / `exit` / `q` — Exit the server shell

---

### Users

* `users list` — List all accounts (this lab's own first, then visitors from partner labs)
* `users manage` — Manage a specific user (perms / delete / reservations)
* `users purge` — Delete **all** users
* `users perms` — Show permissions table
* `users prune-proxies [--stale DAYS] [-y]` — List federated proxies whose home lab is gone (dry run); `-y` removes them

---

### Devices

* `devices list` — List all devices, with the host each is on (`local` for this server's own) and when it was last seen

---

### Reservations

* `reservations list` — List all reservations
* `reservations purge` — Delete **all** reservations

---

### Groups

* `groups list` — List user groups
* `groups create` — Create a user group *(interactive)*
* `groups edit` — Edit a user group *(interactive)*
* `groups delete` — Delete a user group *(interactive)*
* `groups csv` — Export all groups as a CSV

---

### Enrollment Codes

* `codes list` — List enrollment codes
* `codes create` — Create enrollment codes *(interactive)*
* `codes delete` — Delete an enrollment code *(interactive)*
* `codes csv` — Export all codes as a CSV

---

### Host Tunnel

* `hosts status` — Show live host online/last_seen and associated devices
* `hosts wipe` — Wipe persisted host directory state and clear in-memory registry *(prompts for confirmation)*
* `hosts wipe -y` / `hosts wipe --yes` — Same as above, no prompt

---

### Database

* `db purge` — Remove all database entries
* `wipe` — Factory reset: delete the whole config dir (devices, drivers, databases, certs) and the Global identity keys; the next `serverrf -s` runs first-time setup *(server must be stopped; prompts for confirmation, `-y` skips)*


## Adding Hosts

You will need, for each host, to run this first on the server CLI:

```bash
serverrf --host --token-create host-name --length 8
```

Which will return the corresponding command to run on the respective host to give that host access to the server. Below are some other related commands (ie: 'whitelists' hosts)

```bash
serverrf --host --show
serverrf --host --delete host-name
serverrf --host --wipe
```

## Status (Optional)

If you desire to pull the server information (ie: live updates of reservation, server usage parameters, etc.)

It uses GitHub Gists to push the status updates.

Create public gist on your github. Keep note of the file name: (example)
https://gist.github.com/ethange1/2a35e08a90bf88a70dfe7f42a55685ed

The last one is the "GIST_ID" part of the URL, e.g. "2a35e08a90bf88a70dfe7f42a55685ed"

Creating the GitHub PAT Token

* GitHub → Settings
* Developer settings
* Personal access tokens → Fine-grained tokens
* Generate new token
* Set repository access to "Public Respositories"
* Permissions: enable Gists: Read and write
* Generate + copy the token (you only see it once)

```bash
serverrf --gist --set --id <gist_id> --file <filename>
```

Run the server normally, and you should see your gist change every minute!

```bash
serverrf -s
```

<!-- todo: -->
<!-- Adding plutos via the CLI -->
<!-- Testing functionality (disregarding Host pipeline) -->
<!-- Clean up serverrf CLI + basic documentation for all commands, usergroups, export codes by CSV. -->

<!-- HostRF meta data -> push upon connection + retry connection on host side. -->

<!-- Host ID (NEEDS TO BE UNIQUE AND TELL THE HOST THAT) (or if device also does it as well.) -->

<!-- ServerRF display meta data as part of devices list / reservation  -->

<!-- + online/activity status (appended into device name) + (plus host side warning if the device id is NOT globally unique!)

Test local pluto on server (to make sure nothing broke!)

set_device token (virtual devices) + routing/relay to proper host (multiplexed) + host side pipeline

Test local pluto on server (to make sure nothing broke!)

User side testing + integration

hostrf side CLI/server (basically just device list)

edge case testing (disconnected hosts, disconnected server, many users using multiple devices, multi-host) -->

<!-- HostRF integration -> Host directory, device routing, dynamic reservation pulling, with activity/status (online, offline, etc.)  -->

<!-- Cleanup code comments. -->

<!-- Update Ian with installation demo (try myself first on the NUC once!) for both server and host.

Nice to have (later):
Activity/stats?
Ability to remotely manage groups and codes as admin.
Choice to choose usergroup/code by either int id or string name. (too lazy)

todo: Specify/Pull user side --config CLI pointing to this server + debug for connection sake (later) -->


<!-- # Remote RF Linux Server

A python codebase to host the remoteRF Platform. 

Courtesy of Wireless Lab @ UCLA. - Ethan Ge

## Prerequisites

- **Local Linux Computer**: You will need a linux based machine to run the server, along with the networking that goes along with it.

- **Python 3.12**: Honestly I am not sure what minimum version is required. But 3.12 for sure works. If you don’t have Python installed, you can download it from the [official Python website](https://www.python.org/downloads/).
To check your current Python version, open a terminal and run:

```bash
python --version
```

- **Adalm Pluto Python Drivers**: You will need to install this if you wish to use the adalm pluto SDR. [Adalm Pluto Python Drivers](https://pysdr.org/content/pluto.html).

- **Other Devices**: At the moment, although a couple other devices are loosely supported, the Pluto is the only 'full support' device. More can be easily added though.

## Installation

### **Note**: 
These instructions are confirmed to be working on Fedora LTS Server build. Although nothing should need changing on different distros, I cannot confirm nor deny that.

### **Clone Repo**: 
First clone the server repo [here](https://github.com/WirelessLabAtUCLA/RemoteRF-Server).

### **Python Dependencies**: 
Navigate to the cloned repo. Run the below commands. Mind that a python virtual environment `VENV` is recommended, although given device drivers, it may not be the easiest.

```bash
    python3 -m venv venv        # Create venv folder
    source venv/bin/activate    # Activate venv

    pip install setuptools -e . # Auto installs dependencies

    RRRFserver                  # Run Remote RF Server
```
If you have errors, such as `ModuleNotFoundError: No module named 'adi'`, yet you are able to use the adi package elsewhere, such as in the global interpreter, you will need to update your python path to include the adi package, which you should've installed earlier from [here](https://pysdr.org/content/pluto.html).

If you are too lazy to do so, you can just repeat the same steps but on the global python interpreter, which should solve the issue, albeit a less clean solution.

## Configuration

Now onto the configuration of the server for use. Server script needs to be restarted for config to take place.

### Network parameters:
The server requires a specified port as well as a manual IP to be set. You can do an online search for "how to input manual IP address for OS TYPE".

Navigate to `src/remoteRF_server/certs` directory.
```bash
    cd src/remoteRF_server/certs    # From repo root

    openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt -subj "/CN=XXX.XX.XXX.XXX" -addext "subjectAltName=IP:XXX.XX.XXX.XXX"    # Generate the certs. Replace XXX.XX.XXX.XXX with the server IP.
```
Navigate to `src/remoteRF_server/server/.env.server`.
```bash
    GRPC_PORT='XXXXX'   # Replace XXXXX with the server port.
```
Copy the internals of `/certs`, and replace the remoteRF-Client cert folder with these new certificates. This is done as **BOTH** the client and server need to have access to the same generated certificates for secure HTTPs transfer.

### Device parameters:

Navigate to `src/remoteRF_server/server/device_manager.py`. Scroll down until you see:
```python
    devices = { # device, salt, hash
        0: (connect_pluto(usb='1.6.5'), '', ''),
        1: (connect_pluto(usb='1.7.5'), '', ''),
        # ...
    }
```
To add more devices, simply duplicate the item and increment the device id. You also need to configure the usb port. To find this value, run this in the terminal once you have connected your desired devices.
```bash
    iio_info -s # displays usb port info
```
```bash
    Available contexts:
    	0: (jc42,coretemp,pch_skylake,nouveau,acpitz,jc42,dell_smm,hidpp_battery_0,nvme on Dell Inc.) [local:]
    	1: 0456:b673 (Analog Devices Inc. PlutoSDR (ADALM-PLUTO)), serial=10447392da110010f9ff1500612ff8ecb0 [usb:1.6.5]    
        # Use this `usb:1.6.5` as the input for the device init
```
Under `devices` there is also `device_info`. Update this accordingly. This is what is displayed when users request to see what devices there are.

Remember to update default permissions and the like! Otherwise users won't be able to add the new devices.

### Permission parameters:

In the repo, navigate to `src/remoteRF_server/server/acc_perms.py`. You should see:
```python
    class userperms:
        def __init__(self): # default user perms settings
            self.id = 'user'
            self.max_reservations = 1
            self.max_reservation_time_sec = 3600
            self.devices_allowed = [0, 1]   # device ID
```
Here, you can set the default user perms. This default is given to all 'normal users', and is also the permission level when users first make their accounts. For the other two tiers of users, they are configured on run time when the server is running. The server saves all run time changes so no data hypothetically can be lost.

### .Proto regen:
Only needed if, well, you need to update the base networking.
```bash
pip install --upgrade grpcio grpcio-tools protobuf

cd src/remoteRF_server/common/grpc
python -m grpc_tools.protoc \
      -I=. \
      --python_out=. \
      --grpc_python_out=. \
      grpc.proto
```

## Time to Serve!

Once your basic config is setup, you can begin testing the basics of the server! 

```bash
    RRRFserver  # Start the server
```

Given my weird setup, this is what I did to make it work:
New Terminal
cd Documents/GitHub/RemoteRF-Server
sudo pip install -e . (don't use pip3)
sudo RRRFserver

IF the changes you make don't seem to apply ...
which RRRFserver
What worked for me (if u accidently use pip3)
sudo python3 -m pip uninstall RemoteRF-Server (destroy pip3)

Bruh ....

python3 -m pip uninstall -y remoteRF_server RRRFserver || true
rm -f ~/.local/bin/RRRFserver
hash -r

python3 -m pip install -e . --user --force-reinstall
hash -r

Type `help` to see the list of commands. They are pretty self explanatory. Run them and try it out! You can use arrow keys to cycle commands.

```bash
'exit' - Stop server.
'help' - Help.
'clear' - Clear terminal screen.
'printa' - Print all accounts
'printd' - Print all devices
'printp' - Print all perms
'printr' - Print all reservations
'rm aa' - Remove all accounts
'rm a' - Remove one account
```

Follow the [README](https://github.com/WirelessLabAtUCLA/RemoteRF-Client/blob/main/README.md) on this repo to configure the client side.

I would suggest first trying to connect locally (on the same machine), and then remotely. You do not need the VPN if you are testing locally or on LAN. If all goes well, the server should be now ready for use! 

**WARNING**: The current system distributes the private certificates. It is safe as UCLA wraps the network in a VPN, however if you open the server to all of the internet, this approach can be very dangerous.

## Troubleshooting
I had a variety of issues setting up the server. Here is a list of steps to take if the server refuses to connect:

### Server Certificates:
Confirm that the server certs were generated with the right IPs, and that the existing server certs weren't expired. If you are not sure how to check them, just regenerate them. Remember that if you do regenerate you will need to give the client a exact copy of those certs as well.

### Local Firewall: 
Some distros come with default firewall settings that block traffic on specific ports. Make sure that your firewall settings permit traffic to and from the server.

- **ISP Firewall**: If doing this on UCLA Campus, they block and manage much of the traffic. You will need to submit a [Firewall Access Form](https://www.seasnet.ucla.edu/firewall-access-request/). -->
