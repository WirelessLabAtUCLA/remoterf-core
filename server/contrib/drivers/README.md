# Contributed device drivers

Drivers maintained here but **not** shipped or seeded by `remoteRF-server`:
nothing in this folder is installed automatically. A deployment that has the hardware
copies the file it needs into its drivers directory and restarts the server.

| File | `device_type` | Hardware | Host packages |
|---|---|---|---|
| `bluetooth_schema.py` | `bluetooth` | ZEXMTE CSR8510 USB dongle (any BlueZ adapter with `allow_fallback`) | `bleak`, `dbus-fast`, `bluetooth-numbers` (optional: vendor and service names) |
| `gps_schema.py` | `gps` | u-blox 7 / VFAN UG-353 USB receiver (any NMEA-0183 serial receiver) | `pynmea2`, `pyserial` |

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
```

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
