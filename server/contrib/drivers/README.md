# Contributed device drivers

Drivers maintained here but **not** shipped or seeded by `remoteRF-server`:
nothing in this folder is installed automatically. A deployment that has the hardware
copies the file it needs into its drivers directory and restarts the server.

| File | `device_type` | Hardware | Host packages |
|---|---|---|---|
| `bluetooth_schema.py` | `bluetooth` | ZEXMTE CSR8510 USB dongle (any BlueZ adapter with `allow_fallback`) | `bleak`, `dbus-fast`, `bluetooth-numbers` (optional: vendor and service names) |
| `gps_schema.py` | `gps` | u-blox 7 / VFAN UG-353 USB receiver (any NMEA-0183 serial receiver) | `pynmea2`, `pyserial` |
| `pluto_plus_schema.py` | `pluto_plus` | Pluto+ (2R2T AD9361/AD9363) over Ethernet or PoE | `pyadi-iio` + libiio (as the built-in Pluto) |
| `kraken_sdr_schema.py` | `kraken_sdr` | KrakenSDR (five RTL-SDR tuners, one clock) | `pyrtlsdr` + librtlsdr (as the built-in `rtl_sdr`) |
| `rfbeam_kmd7_schema.py` | `rfbeam_kmd7` | RFbeam K-MD7 24 GHz radar on its FTDI USB-UART | `pyserial` |

Both are Linux-only in practice: Bluetooth needs BlueZ on the system D-Bus, and
the GPS reads a serial port (`/dev/ttyACM*`).

## Install

Into the Python environment the server runs in:

```bash
pip install bleak dbus-fast bluetooth-numbers   # Bluetooth
pip install pynmea2 pyserial                    # GPS
```

Then copy (or symlink) the driver and restart the server:

```bash
cp contrib/drivers/gps_schema.py ~/.config/remoterf/drivers/
cp contrib/drivers/bluetooth_schema.py ~/.config/remoterf/drivers/
```

## `~/.config/remoterf/devices.yml`

```yaml
devices:
  - device_id: 10
    device_type: bluetooth
    name: Bluetooth CSR8510
    init: {}                        # auto-detect the CSR dongle

  - device_id: 20
    device_type: gps
    name: USB GPS
    init:
      port: /dev/serial/by-id/usb-u-blox_AG_-_www.u-blox.com_u-blox_7_-_GPS_GNSS_Receiver-if00
      baud: 9600

  - device_id: 120
    device_type: pluto_plus
    name: Pluto Plus 01
    init:
      ip: 192.168.4.201          # the board's static ipaddr_eth
      poe: true                  # optional: powered from a PoE switch port
      poe_port: ether23

  - device_id: 60
    device_type: kraken_sdr
    name: KrakenSDR
    init:
      serials: ["1000", "1001", "1002", "1003", "1004"]   # the default

  - device_id: 70
    device_type: rfbeam_kmd7
    name: K-MD7 Radar
    init:
      port: /dev/serial/by-id/usb-FTDI_FT230X_Basic_UART_<serial>-if00-port0
```

Pluto+: the built-in `adalm_pluto_mimo` controls (both channels) over the network;
the board must be in 2R2T mode (`fw_printenv mode` = 2r2t). PoE works as for a
PoE `adalm_pluto`: off until a reservation starts, password in `poe_switch_password`.

KrakenSDR: settings apply to all five tuners and `read_samples(n)` returns five
arrays. The reads start together but are not sample-aligned or phase-calibrated;
coherent direction finding needs KrakenSDR's Heimdall DAQ firmware. Its tuners
are plain RTL-SDRs to librtlsdr, so they shift the `device_index` of any
`rtl_sdr` configured by index: give those a `serial` where you can.

K-MD7: payloads (RPST, PDAT, TDAT, ...) come back raw; the K-MD7 datasheet
describes their layout. GNFD flag bits seen on K-MD7_APP-RFB-0205: 0x01 RADC
(6144 bytes), 0x02 RFFT (2048), 0x04 PDAT (8 bytes per detection), 0x08 TDAT,
0x20 DONE (frame counter); 0x10, 0x40 and 0x80 return nothing. `command(header, value)` sends any
other command (value: int32, bytes or none); INIT and GBYE stay with the driver.

Bluetooth `init` keys:
- `adapter` (optional, e.g. `hci1`): pin one adapter by name. Leave it out so
  the CSR's current `hciN` is looked up each time the device is opened, and
  again when BlueZ no longer knows the old object (a replug renumbers it).
- `allow_fallback` (default `false`): without `adapter`, the device stays
  offline when no CSR dongle is present rather than taking another adapter
  (the machine's built-in one, say). Set `true` to accept any adapter.

GPS `init` keys: `port` (default: auto-detect a u-blox / ttyACM port), `baud`
(9600), `timeout` (1.0 s). After an unplug the driver reopens the **same port
path** every second, so prefer a `/dev/serial/by-id/...` path: `ttyACMn` can
change on a replug. Until a new fix arrives the last position is kept and
reported with `stale: true` (`connected` says whether the receiver is there).

## Versions

`driver_version` 0.1.2. The Bluetooth driver wraps its lists of dicts (scan
results) in `_JsonList` so that servers up to 1.3.0 send them as JSON; servers
from 1.3.1 do that themselves, and the wrapper stays for the older ones.
