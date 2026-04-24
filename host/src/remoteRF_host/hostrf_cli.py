# src/remoteRF_host/hostrf_cli.py

from __future__ import annotations

import sys
import shutil
import os
import json
from pathlib import Path
from typing import Optional, Tuple, Dict, List, Any

from .config.cert_fetcher import fetch_and_save_ca_cert
from .common.utils.db_location import get_host_config_dir, get_remoterf_root

# -----------------------------
# Host config locations (~/.config/remoterf/host by default)
# -----------------------------

def _cfg_dir() -> Path:
    return get_host_config_dir()

def _ca_path() -> Path:
    return _cfg_dir() / "ca.crt"

def _net_env_path() -> Path:
    return _cfg_dir() / "net.env"

def _host_env_path() -> Path:
    return _cfg_dir() / "host.env"

def _devices_yaml_path() -> Path:
    return _cfg_dir() / "devices.yml"


# -----------------------------
# Help (serverrf-style, host subset)
# -----------------------------

def print_help() -> None:
    print(
        "RemoteRF Host CLI Help\n"
        "\n"
        "Usage:\n"
        "  hostrf -h | --help\n"
        "\n"
        "Serve:\n"
        "  hostrf -s | --serve              Run host tunnel agent (NOTE: only when -s/--serve is the FIRST arg)\n"
        "\n"
        "Network:\n"
        "  hostrf -c | --config [options]\n"
        "\n"
        "Network options:\n"
        "  --addr <host:port>               Set REMOTERF_ADDR and fetch CA cert\n"
        "  --show | -s                      Show current network config\n"
        "  -w | --wipe [-y]                 Wipe ONLY network config (net.env + ca.crt)\n"
        "\n"
        "Host:\n"
        "  hostrf --host --set <host_id> <token>      Set HOST_ID + HOST_TOKEN\n"
        "  hostrf --host --show [--secrets]           Show host config\n"
        "  hostrf --host --wipe [-y]                  Wipe ONLY host config (host.env)\n"
        "\n"
        "Devices:\n"
        "  hostrf -d | --device [options]\n"
        "\n"
        "Device options:\n"
        "  --add --pluto <id:name:iio_serial>  Add device (fails if gid OR serial already used)\n"
        "  --remove <id>                       Remove device\n"
        "  --edit-name <id> <name>             Override device NAME for existing device\n"
        "  --show | -s                         Show all devices\n"
        "  -w | --wipe [-y]                    Wipe ONLY device config (devices.yml)\n"
        "\n"
        "Global:\n"
        "  -y, --yes                           Skip wipe confirmation prompts\n"
        "\n"
        "Wipe all:\n"
        "  hostrf --wipe [-y]                  Wipe ALL host config\n"
        "\n"
        "Examples:\n"
        "  hostrf --config --addr 1.2.3.4:61007\n"
        "  hostrf --config --show\n"
        "  hostrf --config --wipe -y\n"
        "\n"
        "  hostrf --host --set lab-host-01 \"my-host-token\"\n"
        "  hostrf --host --show\n"
        "  hostrf --host --show --secrets\n"
        "  hostrf --host --wipe -y\n"
        "\n"
        "  hostrf --device --add --pluto 0:pluto_aaa:123123\n"
        "  hostrf --device --edit-name 0 \"New Pluto Name\"\n"
        "  hostrf --device --remove 0\n"
        "  hostrf --device --show\n"
        "  hostrf --device --wipe -y\n"
        "\n"
        "  hostrf --serve\n"
        "\n"
    )


# -----------------------------
# Tiny env utils
# -----------------------------

def _parse_hostport(s: str) -> Tuple[str, int]:
    s = (s or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    if ":" not in s:
        raise ValueError("Expected format host:port")
    host, port_str = s.rsplit(":", 1)
    host = host.strip()
    port = int(port_str.strip())
    if not host:
        raise ValueError("Host is empty")
    if port <= 0 or port > 65535:
        raise ValueError("Port out of range")
    return host, port

def _write_env_kv(path: Path, kv: Dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: List[str] = []
    for k, v in kv.items():
        v = str(v)
        if any(c.isspace() for c in v) or any(c in v for c in ['"', "'"]):
            v = v.replace('"', '\\"')
            lines.append(f'{k}="{v}"')
        else:
            lines.append(f"{k}={v}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

def _read_env_kv(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _redact(s: str) -> str:
    s = (s or "").strip()
    if len(s) <= 8:
        return "****"
    return f"{s[:4]}...{s[-4:]}"


# -----------------------------
# Device storage — devices.yml (same schema as server)
#
#   devices:
#     - device_id: 0
#       device_type: pluto
#       name: pluto_aaa
#       init:
#         serial: 123123
# -----------------------------

def _parse_pluto_add_spec(tok: str) -> Tuple[int, str, str]:
    # <gid:name:iio_serial>
    parts = [p.strip() for p in (tok or "").split(":")]
    if len(parts) != 3:
        raise ValueError("Expected <gid:name:iio_serial>")
    gid_s, name, iio_serial = parts
    gid = int(gid_s)
    if gid < 0:
        raise ValueError("gid must be >= 0")
    if not name:
        raise ValueError("name is empty")
    if not iio_serial:
        raise ValueError("iio_serial is empty")
    return gid, name, iio_serial


def _read_device_records() -> Dict[int, Dict[str, Any]]:
    """Load devices.yml and return {gid: record_dict}."""
    path = _devices_yaml_path()
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
        try:
            data = json.loads(text) or {}
        except json.JSONDecodeError:
            try:
                import yaml  # type: ignore
            except ImportError:
                print(
                    f"ERROR: Failed to read {path}: install PyYAML or rewrite devices.yml as JSON.",
                    file=sys.stderr,
                )
                return {}
            data = yaml.safe_load(text) or {}
    except Exception as e:
        print(f"ERROR: Failed to read {path}: {e}", file=sys.stderr)
        return {}

    devices = data.get("devices") or []
    if not isinstance(devices, list):
        print(f"ERROR: {path}: 'devices' must be a list", file=sys.stderr)
        return {}

    recs: Dict[int, Dict[str, Any]] = {}
    for item in devices:
        if not isinstance(item, dict):
            continue
        try:
            gid = int(item["device_id"])
        except Exception:
            continue
        recs[gid] = item
    return recs


def _write_device_records(recs: Dict[int, Dict[str, Any]]) -> None:
    """Write {gid: record_dict} back to devices.yml as JSON (valid YAML)."""
    path = _devices_yaml_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    devices_list = []
    for gid in sorted(recs.keys()):
        item = recs[gid]
        # Normalise to canonical server schema order
        entry: Dict[str, Any] = {
            "device_id": int(gid),
            "device_type": str(item.get("device_type", "pluto")),
            "name": str(item.get("name", f"device-{gid}")),
            "init": dict(item.get("init") or {}),
        }
        devices_list.append(entry)

    doc: Dict[str, Any] = {"devices": devices_list}
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


# -----------------------------
# Actions (ONLY the ones listed)
# -----------------------------
def _configure_addr(addr: str) -> int:
    try:
        host, grpc_port = _parse_hostport(addr)
    except Exception as e:
        print(f"ERROR: addr must be in 'host:port' form: {e}", file=sys.stderr)
        return 2

    cert_port = int(grpc_port) + 1

    # Ensure <repo>/config/remoteRF_host exists
    cfg_dir = _cfg_dir()
    cfg_dir.mkdir(parents=True, exist_ok=True)

    # With your new cert_fetcher.py, the cert + .env live in cfg_dir
    ok = fetch_and_save_ca_cert(
        host,
        cert_port,
        env_dir=cfg_dir,                 # writes ca.crt + updates cfg_dir/.env
        env_filename="net.env",
        cert_filename="ca.crt",
        grpc_addr=f"{host}:{grpc_port}", # also upserts REMOTERF_ADDR
        timeout_sec=3.0,
        overwrite=True,
    )
    if not ok:
        print(f"Failed to fetch CA cert from {host}:{cert_port}.", file=sys.stderr)
        return 1
    
    print("Configured network:")
    print(f"  {_net_env_path()}")
    return 0


def _show_addr() -> int:
    p = _net_env_path()
    if not p.exists():
        print(f"No network config found (missing {p}).")
        return 0

    kv = _read_env_kv(p)
    if not kv:
        print("Network config is empty.")
        return 0

    print(f"Network config: {p}")
    if "REMOTERF_ADDR" in kv:
        print(f"  REMOTERF_ADDR={kv['REMOTERF_ADDR']}")
    if "REMOTERF_CA_CERT" in kv:
        print(f"  REMOTERF_CA_CERT={kv['REMOTERF_CA_CERT']}")
    return 0

def _configure_host_pair(host_id: str, token: str) -> int:
    host_id = (host_id or "").strip()
    token = (token or "").strip()

    if not host_id:
        print("ERROR: host_id is empty", file=sys.stderr)
        return 2
    if not token:
        print("ERROR: token is empty", file=sys.stderr)
        return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)

    kv = _read_env_kv(_host_env_path())  # preserve anything else
    kv["HOST_ID"] = host_id
    kv["HOST_TOKEN"] = token
    _write_env_kv(_host_env_path(), kv)

    print("Configured host:")
    print(f"  {_host_env_path()}")
    return 0

def _configure_host(host_id: str) -> int:
    host_id = (host_id or "").strip()
    if not host_id:
        print("ERROR: host name is empty", file=sys.stderr)
        return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)

    kv = _read_env_kv(_host_env_path())  # preserve existing keys like HOST_TOKEN
    kv["HOST_ID"] = host_id
    _write_env_kv(_host_env_path(), kv)

    print("Configured host:")
    print(f"  {_host_env_path()}")
    return 0

def _set_token(token: str) -> int:
    tok = (token or "").strip()
    if not tok:
        print("ERROR: token is empty", file=sys.stderr)
        return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)

    p = _host_env_path()
    kv = _read_env_kv(p)

    # Optional but recommended: require HOST_ID to exist so tokens are never “floating”
    hid = (kv.get("HOST_ID", "") or "").strip()
    if not hid:
        print(f"ERROR: HOST_ID is not configured yet (missing/empty {p}).", file=sys.stderr)
        print("Run: hostrf -c -h <host_id>", file=sys.stderr)
        return 2

    kv["HOST_TOKEN"] = tok
    _write_env_kv(p, kv)

    print("Configured host token:")
    print(f"  {p}")
    return 0

def _show_host(*, show_secrets: bool = False) -> int:
    p = _host_env_path()
    if not p.exists():
        print(f"No host config found (missing {p}).")
        return 0

    kv = _read_env_kv(p)
    if not kv or "HOST_ID" not in kv:
        print("Host config is empty.")
        return 0

    print(f"Host config: {p}")
    print(f"  HOST_ID={kv.get('HOST_ID','')}")
    tok = kv.get("HOST_TOKEN", "")
    if tok:
        if show_secrets:
            print(f"  HOST_TOKEN={tok}")
        else:
            print(f"  HOST_TOKEN={_redact(tok)}  (use --secrets to show)")
    return 0

def _device_add_pluto(spec: str) -> int:
    gid, name, iio_serial = _parse_pluto_add_spec(spec)

    _cfg_dir().mkdir(parents=True, exist_ok=True)

    recs = _read_device_records()

    # "appends IF id is available"
    if gid in recs:
        print(f"ERROR: global_id {gid} already exists", file=sys.stderr)
        return 2

    # Prevent duplicate iio_serial across existing devices
    for other_gid, r in recs.items():
        existing_serial = str((r.get("init") or {}).get("serial", "")).strip()
        if existing_serial and existing_serial == iio_serial:
            print(f"ERROR: iio_serial already used by global_id={other_gid}", file=sys.stderr)
            return 2

    recs[gid] = {
        "device_id": gid,
        "device_type": "pluto",
        "name": name,
        "init": {"serial": iio_serial},
    }
    _write_device_records(recs)

    print(f"Added device: {gid} type=pluto name={name} iio_serial={iio_serial}")
    return 0

def _device_edit_name(global_id_str: str, new_name: str) -> int:
    try:
        gid = int((global_id_str or "").strip())
    except Exception:
        print("ERROR: --edit-name expects <gid:int> <new_name>", file=sys.stderr)
        return 2

    new_name = (new_name or "").strip()
    if not new_name:
        print("ERROR: new_name is empty", file=sys.stderr)
        return 2

    recs = _read_device_records()
    if gid not in recs:
        print(f"ERROR: global_id {gid} not present; cannot edit name.", file=sys.stderr)
        return 2

    recs[gid]["name"] = new_name
    _write_device_records(recs)

    print(f"Updated device name: {gid} name={new_name}")
    return 0

def _device_remove(global_id_str: str) -> int:
    try:
        gid = int((global_id_str or "").strip())
    except Exception:
        print("ERROR: --remove expects <gid:int>", file=sys.stderr)
        return 2

    recs = _read_device_records()
    if gid not in recs:
        print(f"WARNING: global_id {gid} not present; nothing to remove.")
        return 0

    recs.pop(gid, None)
    _write_device_records(recs)
    print(f"Removed device: {gid}")
    return 0

def _device_show() -> int:
    p = _devices_yaml_path()
    if not p.exists():
        print(f"No devices configured (missing {p}).")
        return 0

    recs = _read_device_records()
    print(f"Devices: {p}")
    if not recs:
        print("  (none)")
        return 0

    for gid in sorted(recs.keys()):
        r = recs[gid]
        dtype = r.get("device_type", "")
        name = r.get("name", "")
        init = r.get("init") or {}
        serial = init.get("serial", "")
        print(f"  {gid}: type={dtype} name={name} iio_serial={serial}")
    return 0

def _wipe_all(*, yes: bool) -> int:
    root = get_remoterf_root()
    host_dir = Path(os.getenv("REMOTERF_CONFIG_DIR", str(root / "host"))).expanduser()
    drivers_dir = Path(os.getenv("REMOTERF_DRIVERS_DIR", str(root / "drivers"))).expanduser()
    targets = [host_dir, drivers_dir]

    if not any(path.exists() for path in targets):
        print("No config found:")
        for path in targets:
            print(f"  {path}")
        return 0
    if not yes:
        try:
            prompt = "This will delete ALL hostrf config at:\n" + "\n".join(f"  {path}" for path in targets)
            if input(f"{prompt}\nType 'wipe' to confirm: ").strip().lower() != "wipe":
                print("Wipe aborted.")
                return 1
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 1

    removed: List[Path] = []
    for path in targets:
        if path.exists():
            shutil.rmtree(path)
            removed.append(path)

    if root.exists() and not any(root.iterdir()):
        root.rmdir()

    print("Wiped ALL config:")
    for path in removed:
        print(f"  {path}")
    return 0

def _wipe_addr_only(*, yes: bool) -> int:
    if not yes:
        try:
            if input("This will delete net.env + ca.crt. Type 'wipe' to confirm: ").strip().lower() != "wipe":
                print("Wipe aborted.")
                return 1
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 1

    if _net_env_path().exists():
        _net_env_path().unlink()
    if _ca_path().exists():
        _ca_path().unlink()

    print("Wiped address config (net.env + ca.crt).")
    return 0

def _wipe_host_only(*, yes: bool) -> int:
    if not yes:
        try:
            if input("This will delete host.env. Type 'wipe' to confirm: ").strip().lower() != "wipe":
                print("Wipe aborted.")
                return 1
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 1

    if _host_env_path().exists():
        _host_env_path().unlink()
    print("Wiped host config (host.env).")
    return 0

def _wipe_devices_only(*, yes: bool) -> int:
    if not yes:
        try:
            if input("This will delete devices.yml. Type 'wipe' to confirm: ").strip().lower() != "wipe":
                print("Wipe aborted.")
                return 1
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 1

    p = _devices_yaml_path()
    if p.exists():
        p.unlink()
    print("Wiped device config (devices.yml).")
    return 0


def _normalize_legacy_mode_aliases(argv: List[str]) -> List[str]:
    if not argv or argv[0] not in ("--config", "-c", "-config"):
        return argv

    i = 1
    prefix: List[str] = []
    while i < len(argv):
        tok = argv[i]
        if tok in ("-y", "--yes", "-yes"):
            prefix.append(tok)
            i += 1
            continue
        if tok in ("--host", "-host", "-h"):
            return prefix + ["--host"] + argv[i + 1 :]
        return argv

    return argv


# -----------------------------
# CLI parser (serverrf-style, host subset)
# -----------------------------

def main() -> int:
    argv = _normalize_legacy_mode_aliases(list(sys.argv[1:]))

    if len(argv) == 0:
        print("invalid args, expect hostrf <args>, run hostrf --help for more info", file=sys.stderr)
        return 2

    # help
    if argv[0] in ("--help", "-h", "-help", "--h"):
        print_help()
        return 0

    if argv[0] in ("-s", "--serve", "--server"):
        if len(argv) != 1:
            print("ERROR: -s/--serve cannot be combined with other commands. Run it alone.", file=sys.stderr)
            return 2
        from .server.tunnel_agent import main as tunnel_main
        tunnel_main()
        return 0

    yes = False
    show_secrets = False

    # config commands
    config_mode = False
    addr_value: Optional[str] = None
    config_show = False
    config_wipe = False

    # host commands
    host_mode = False
    host_set_id: Optional[str] = None
    host_set_token: Optional[str] = None
    host_show = False
    host_wipe = False

    # device commands
    device_mode = False
    device_show = False
    device_wipe = False
    device_add_type: Optional[str] = None
    device_add_spec: Optional[str] = None
    device_remove_gid: Optional[str] = None
    device_edit_gid: Optional[str] = None
    device_edit_name: Optional[str] = None

    # wipe-all
    wipe_all = False

    i = 0
    while i < len(argv):
        tok = argv[i]

        if tok in ("-y", "--yes", "-yes"):
            yes = True
            i += 1
            continue

        if tok in ("--config", "-c", "-config"):
            config_mode = True
            i += 1
            continue

        if tok in ("--host", "-host"):
            host_mode = True
            if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                if i + 2 >= len(argv) or argv[i + 2].startswith("-"):
                    print("ERROR: --host requires BOTH <host_id> and <token> when setting host config.", file=sys.stderr)
                    print("Example: hostrf --host lab-host-01 \"snofeogs\"", file=sys.stderr)
                    return 2
                host_set_id = argv[i + 1].strip()
                host_set_token = argv[i + 2].strip()
                i += 3
                continue
            i += 1
            continue

        if tok in ("--device", "-device", "-d"):
            device_mode = True
            i += 1
            continue

        if host_mode and tok == "--set":
            if i + 2 >= len(argv):
                print("ERROR: --host --set expects <host_id> <token>", file=sys.stderr)
                return 2
            host_set_id = argv[i + 1].strip()
            host_set_token = argv[i + 2].strip()
            i += 3
            continue

        if config_mode and tok in ("-a", "--addr", "-addr"):
            if i + 1 >= len(argv) or argv[i + 1].startswith("-"):
                print("ERROR: --addr expects <host:port>", file=sys.stderr)
                return 2
            addr_value = argv[i + 1].strip()
            i += 2
            continue

        if config_mode and tok in ("--show", "-show", "-s"):
            config_show = True
            i += 1
            continue

        if host_mode and tok in ("--list", "-list", "--show", "-show"):
            host_show = True
            i += 1
            continue

        if host_mode and tok in ("--secrets", "-secrets"):
            show_secrets = True
            i += 1
            continue

        if device_mode and tok in ("--show", "-show", "-s"):
            device_show = True
            i += 1
            continue

        if config_mode and tok in ("-w", "--wipe", "-wipe"):
            config_wipe = True
            i += 1
            continue

        if host_mode and tok in ("--wipe", "-wipe", "-w"):
            host_wipe = True
            i += 1
            continue

        if device_mode and tok in ("-w", "--wipe", "-wipe"):
            device_wipe = True
            i += 1
            continue

        if not config_mode and not host_mode and not device_mode and tok in ("-w", "--wipe", "-wipe"):
            wipe_all = True
            i += 1
            continue

        if device_mode and tok in ("--add", "-add", "-a"):
            if i + 1 >= len(argv):
                print("ERROR: missing device type after --device --add (expected --pluto)", file=sys.stderr)
                return 2
            dt = argv[i + 1].strip()
            if dt != "--pluto":
                print("ERROR: only '--device --add --pluto <gid:name:iio_serial>' is supported", file=sys.stderr)
                return 2
            if i + 2 >= len(argv):
                print("ERROR: missing spec after --device --add --pluto", file=sys.stderr)
                return 2
            device_add_type = "pluto"
            device_add_spec = argv[i + 2].strip()
            i += 3
            continue

        if device_mode and tok in ("--edit-name", "-edit-name", "--rename", "-rename"):
            if i + 2 >= len(argv):
                print("ERROR: --device --edit-name expects <gid> <new_name>", file=sys.stderr)
                return 2
            device_edit_gid = argv[i + 1].strip()
            device_edit_name = argv[i + 2]  # user can quote spaces in the shell
            i += 3
            continue

        if device_mode and tok in ("--remove", "-remove", "-r"):
            if i + 1 >= len(argv):
                print("ERROR: missing value after --device --remove <gid>", file=sys.stderr)
                return 2
            device_remove_gid = argv[i + 1].strip()
            i += 2
            continue

        print(f"ERROR: unknown option: {tok!r}", file=sys.stderr)
        return 2

    if device_mode and (config_mode or host_mode):
        print("ERROR: --device cannot be combined with config/host commands. Run them separately.", file=sys.stderr)
        return 2

    if host_mode and config_mode:
        print("ERROR: --host cannot be combined with config commands. Run them separately.", file=sys.stderr)
        return 2

    if wipe_all and (config_mode or host_mode or device_mode):
        print("ERROR: --wipe cannot be combined with config/host/device commands. Run it alone.", file=sys.stderr)
        return 2

    if wipe_all:
        return int(_wipe_all(yes=yes))

    if host_mode:
        actions = int(host_show) + int(host_wipe) + int(host_set_id is not None or host_set_token is not None)
        if actions == 0:
            print_help()
            return 2
        if actions > 1:
            print("ERROR: host commands are mutually exclusive. Use exactly one of: --set, --show/--list, --wipe", file=sys.stderr)
            return 2

        if host_set_id is not None or host_set_token is not None:
            if not host_set_id or not host_set_token:
                print("ERROR: --host set requires <host_id> and <token>", file=sys.stderr)
                return 2
            if len(host_set_token) < 4:
                print("ERROR: host token too short (min length = 4).", file=sys.stderr)
                return 2
            return int(_configure_host_pair(host_set_id, host_set_token))

        if host_show:
            return int(_show_host(show_secrets=show_secrets))

        if host_wipe:
            return int(_wipe_host_only(yes=yes))

        print_help()
        return 2

    if device_mode:
        if device_wipe and (
            device_show
            or device_add_spec is not None
            or device_remove_gid is not None
            or device_edit_gid is not None
        ):
            print("ERROR: cannot combine device add/remove/show/edit with device wipe. Use '-d -w' only.", file=sys.stderr)
            return 2

        if device_wipe:
            return int(_wipe_devices_only(yes=yes))

        did_any = False

        if device_show:
            rc = _device_show()
            if rc != 0:
                return rc
            did_any = True

        if device_add_type == "pluto" and device_add_spec is not None:
            rc = _device_add_pluto(device_add_spec)
            if rc != 0:
                return rc
            did_any = True

        if device_edit_gid is not None:
            rc = _device_edit_name(device_edit_gid, device_edit_name or "")
            if rc != 0:
                return rc
            did_any = True

        if device_remove_gid is not None:
            rc = _device_remove(device_remove_gid)
            if rc != 0:
                return rc
            did_any = True

        if not did_any:
            print_help()
            return 2

        return 0

    if config_mode:
        if config_wipe and (config_show or addr_value is not None):
            print("ERROR: cannot combine --wipe with --show or --addr. Use '-c -w' only.", file=sys.stderr)
            return 2

        if config_wipe:
            return int(_wipe_addr_only(yes=yes))

        did_any = False

        if config_show:
            rc = _show_addr()
            if rc != 0:
                return rc
            did_any = True

        if addr_value is not None:
            rc = _configure_addr(addr_value)
            if rc != 0:
                return rc
            did_any = True

        if not did_any:
            print_help()
            return 2

        return 0

    print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
