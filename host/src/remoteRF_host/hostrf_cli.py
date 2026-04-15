# src/remoteRF_host/hostrf_cli.py

from __future__ import annotations

import sys
import shutil
import yaml
from pathlib import Path
from typing import Optional, Tuple, Dict, List, Any

from .config.cert_fetcher import fetch_and_save_ca_cert
from .common.utils import get_remoterf_root

# -----------------------------
# Repo-local host config locations
# -----------------------------

import os
from pathlib import Path

def _cfg_dir() -> Path:
    p = Path(os.getenv("REMOTERF_CONFIG_DIR", get_remoterf_root()))
    p.mkdir(parents=True, exist_ok=True)
    return p

def _ca_path() -> Path:
    return _cfg_dir() / "ca.crt"

def _net_env_path() -> Path:
    return _cfg_dir() / "net.env"

def _host_env_path() -> Path:
    return _cfg_dir() / "host.env"

def _devices_yaml_path() -> Path:
    return _cfg_dir() / "devices.yml"


# -----------------------------
# Help (exact commands only)
# -----------------------------

def print_help() -> None:
    print(
        "RemoteRF Host CLI Help\n"
        "\n"
        "Usage:\n"
        "  hostrf -h | --help                   Show this help\n"
        "\n"
        "  hostrf -s | --server                 Run hostrf server\n"
        "\n"
        "  hostrf -c | --config [options]\n"
        "\n"
        "Network option:\n"
        "  -a, --addr <host:port>               Set target server\n"
        "  -a --show                            Show current target\n"
        "  -a -w [-y]                           Wipe ONLY address stuff (net.env + ca.crt)\n"
        "\n"
        "Host option:\n"
        "  --host <host_id> \"<token>\"       Set HOST_ID + HOST_TOKEN (both required)\n"
        "  --host --show                      Show host config (host.env)\n"
        "  --host --wipe [-y]                 Wipe ONLY host config (host.env)\n"
        "\n"
        "Device option:\n"
        "  --device --add --pluto <gid:\"name\":serial>  Add device (fails if gid OR serial already used)\n"
        "  --device --edit-name <gid> \"<new_name>\"     Edit device name\n"
        "  --device --remove <gid>                   Remove device\n"
        "  --device --show                           Show all devices\n"
        "  --device --wipe [-y]                      Wipe ONLY device config (devices.yml)\n"
        "\n"
        "Wipe all:\n"
        "  -w, --wipe [-y]                      Wipe ALL config\n"
        "\n"
        "Examples:\n"
        "  hostrf -c -a 1.2.3.4:61007\n"
        "  hostrf -c -a --show\n"
        "  hostrf -c -a -w -y\n"
        "\n"
        "  hostrf -c -h lab-host-01 \"my-host-token\"\n"
        "  hostrf -c -h --show\n"
        "  hostrf -c -h --wipe -y\n"
        "\n"
        "  hostrf -d --add --pluto 0:pluto_aaa:123123\n"
        "  hostrf -d --remove 0\n"
        "  hostrf -d --show\n"
        "  hostrf -d --wipe -y\n"
        "\n"
        "  hostrf -c -w -y\n"
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
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
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
    """Write {gid: record_dict} back to devices.yml in server-compatible format."""
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
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(doc, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


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

def _show_host() -> int:
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
    root = _cfg_dir()
    if not root.exists():
        print(f"No config found at: {root}")
        return 0
    if not yes:
        try:
            if input(f"This will delete ALL hostrf config at:\n  {root}\nType 'wipe' to confirm: ").strip().lower() != "wipe":
                print("Wipe aborted.")
                return 1
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 1
    shutil.rmtree(root)
    print(f"Wiped ALL config: {root}")
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


# -----------------------------
# CLI parser (ONLY commands in help)
# -----------------------------

def main() -> int:
    argv = list(sys.argv[1:])
    
    if len(argv) > 0 and argv[0] in ("--device", "-device", "-d"):
        argv = ["-c", "--device"] + argv[1:]

    # help
    if len(argv) == 0 or argv[0] in ("--help", "-help", "-h"):
        print_help()
        return 0
    
    if argv[0] in ("-s", "--server"):
        from .server.tunnel_agent import main as tunnel_main
        tunnel_main()          # blocks until Ctrl+C
        return 0

    # config
    if argv[0] not in ("--config", "-config", "-c"):
        print(f"ERROR: unknown command: {argv[0]!r}", file=sys.stderr)
        return 2

    yes = False

    # addr scope/actions
    addr_selected = False
    addr_value: Optional[str] = None
    addr_show = False
    addr_wipe = False

    # host scope/actions
    host_selected = False
    host_value: Optional[str] = None
    host_token_value: Optional[str] = None
    host_show = False
    host_wipe = False

    # device scope/actions
    device_selected = False
    device_show = False
    device_wipe = False
    device_add_type: Optional[str] = None
    device_add_spec: Optional[str] = None
    device_remove_gid: Optional[str] = None
    device_edit_gid: Optional[str] = None
    device_edit_name: Optional[str] = None

    # wipe-all (only when no scope is selected at wipe time)
    wipe_all = False

    i = 1
    while i < len(argv):
        tok = argv[i]

        if tok in ("-y", "--yes", "-yes"):
            yes = True
            i += 1
            continue

        # addr scope
        if tok in ("-a", "--addr", "-addr"):
            addr_selected = True
            # optional value
            if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                addr_value = argv[i + 1].strip()
                i += 2
            else:
                i += 1
            continue

        # host scope (NOTE: -h means host ONLY inside -c mode)
        if tok in ("--host", "-host", "-h"):
            host_selected = True

            # If next token is missing or is another flag, we don't set values here.
            # That allows: -h --show  /  -h --wipe
            if i + 1 >= len(argv) or argv[i + 1].startswith("-"):
                i += 1
                continue

            # Otherwise we got a host_id, and we REQUIRE a token right after it.
            host_value = argv[i + 1].strip()

            if i + 2 >= len(argv) or argv[i + 2].startswith("-"):
                print("ERROR: --host requires BOTH <host_id> and <token> when setting host config.", file=sys.stderr)
                print("Example: hostrf --host lab-host-01 \"snofeogs\"", file=sys.stderr)
                return 2

            host_token_value = argv[i + 2].strip()
            i += 3
            continue

        # device scope
        if tok in ("--device", "-device", "-d"):
            device_selected = True
            i += 1
            continue

        # show (scope-dependent)
        if tok in ("--show", "-show", "-s"):
            if device_selected:
                device_show = True
                i += 1
                continue
            if host_selected:
                host_show = True
                i += 1
                continue
            if addr_selected:
                addr_show = True
                i += 1
                continue
            print("ERROR: --show must be used with -a/--addr, -h/--host, or --device", file=sys.stderr)
            return 2

        # wipe (scope-dependent OR wipe-all)
        if tok in ("-w", "--wipe", "-wipe"):
            if device_selected:
                device_wipe = True
            elif host_selected:
                host_wipe = True
            elif addr_selected:
                addr_wipe = True
            else:
                wipe_all = True
            i += 1
            continue

        # device add/remove
        if device_selected and tok in ("--add", "-add", "-a"):
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
        
        if device_selected and tok in ("--edit-name", "-edit-name", "--rename", "-rename"):
            if i + 2 >= len(argv):
                print("ERROR: --device --edit-name expects <gid> <new_name>", file=sys.stderr)
                return 2
            device_edit_gid = argv[i + 1].strip()
            device_edit_name = argv[i + 2]  # user can quote spaces in the shell
            i += 3
            continue

        if device_selected and tok in ("--remove", "-remove", "-r"):
            if i + 1 >= len(argv):
                print("ERROR: missing value after --device --remove <gid>", file=sys.stderr)
                return 2
            device_remove_gid = argv[i + 1].strip()
            i += 2
            continue

        print(f"ERROR: unknown option: {tok!r}", file=sys.stderr)
        return 2

    # ---- conflict checks (keep it strict) ----
    if (addr_wipe or host_wipe or device_wipe or wipe_all) and (addr_show or host_show or device_show):
        print("ERROR: cannot combine --show with --wipe", file=sys.stderr)
        return 2

    if addr_wipe and addr_value is not None:
        print("ERROR: cannot use '--addr <host:port>' with wipe. Use '-a -w' to wipe address config.", file=sys.stderr)
        return 2

    if host_wipe and host_value is not None:
        print("ERROR: cannot use '--host <name>' with wipe. Use '-h --wipe' to wipe host config.", file=sys.stderr)
        return 2

    if device_wipe and (device_add_spec is not None or device_remove_gid is not None):
        print("ERROR: cannot combine device add/remove with device wipe. Use '--device --wipe' only.", file=sys.stderr)
        return 2
    
    if host_selected and (host_value is not None or host_token_value is not None):
        if not host_value or not host_token_value:
            print("ERROR: --host set requires <host_id> and <token>", file=sys.stderr)
            return 2

        # Optional: enforce minimum token length (recommended)
        if len(host_token_value) < 4:
            print("ERROR: host token too short (min length = 4).", file=sys.stderr)
            return 2

    # ---- wipe execution ----
    if wipe_all or addr_wipe or host_wipe or device_wipe:
        if wipe_all:
            return int(_wipe_all(yes=yes))
        if addr_wipe:
            return int(_wipe_addr_only(yes=yes))
        if host_wipe:
            return int(_wipe_host_only(yes=yes))
        if device_wipe:
            return int(_wipe_devices_only(yes=yes))
        return 2

    # ---- non-wipe actions ----
    did_any = False

    if addr_show:
        rc = _show_addr()
        if rc != 0:
            return rc
        did_any = True

    if host_show:
        rc = _show_host()
        if rc != 0:
            return rc
        did_any = True

    if device_show:
        rc = _device_show()
        if rc != 0:
            return rc
        did_any = True

    if addr_value is not None:
        rc = _configure_addr(addr_value)
        if rc != 0:
            return rc
        did_any = True

    if host_value is not None:
        rc = _configure_host_pair(host_value, host_token_value or "")
        if rc != 0:
            return rc
        did_any = True

    if device_add_type == "pluto" and device_add_spec is not None:
        rc = _device_add_pluto(device_add_spec)
        if rc != 0:
            return rc
        did_any = True

    if device_remove_gid is not None:
        rc = _device_remove(device_remove_gid)
        if rc != 0:
            return rc
        did_any = True

    if device_edit_gid is not None:
        rc = _device_edit_name(device_edit_gid, device_edit_name or "")
        if rc != 0:
            return rc
        did_any = True
        
    if not did_any:
        print_help()
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
