# src/remoteRF_host/hostrf_cli.py

from __future__ import annotations

import sys
import shutil
from pathlib import Path
from typing import Optional, Tuple, Dict, List

from .config.cert_fetcher import fetch_and_save_ca_cert


# -----------------------------
# Repo-local host config locations
# -----------------------------

def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]  # <repo>

def _cfg_dir() -> Path:
    # <repo>/config/remoteRF_host/
    return _repo_root() / "config" / "remoteRF_host"

def _ca_path() -> Path:
    return _cfg_dir() / "ca.crt"

def _net_env_path() -> Path:
    return _cfg_dir() / "net.env"

def _host_env_path() -> Path:
    return _cfg_dir() / "host.env"

def _devices_env_path() -> Path:
    return _cfg_dir() / "devices.env"


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
        "  hostrf -c | --config [options]\n"
        "\n"
        "Network option:\n"
        "  -a, --addr <host:port>               Set target server\n"
        "  -a --show                            Show current target\n"
        "\n"
        "Host option:\n"
        "  -h, --host <str>                     Set host name\n"
        "  -h --show                            Show host name\n"
        "\n"
        "Device option:\n"
        "  --device --add <global_id:name>      Add local device\n"
        "  --device --remove <global_id>        Remove device\n"
        "  --device --show                      Show all devices\n"
        "\n"
        "Wipe option:\n"
        "  -w, --wipe                           Wipe all config\n"
        "\n"
        "Examples:\n"
        "  hostrf -c -a 1.2.3.4:61007\n"
        "  hostrf -c -a -w -y\n"
        "  hostrf -c --device --add 0:pluto_aaa\n"
        "  hostrf -c --device --remove 0\n"
        "  hostrf -c --device --wipe\n"
        "  hostrf -c -a --show\n"
        "  hostrf -c -h --show\n"
        "  hostrf -c --device --show\n"
        "  hostrf -c --host lab-host-01\n"
        "  hostrf -c --host --wipe\n"
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

def _parse_device_pair(tok: str) -> Tuple[int, str]:
    # "<int:str>" => "0:pluto_aaa"
    if ":" not in tok:
        raise ValueError("Expected <int:str> like 0:pluto_aaa")
    a, b = tok.split(":", 1)
    local_id = int(a.strip())
    device_id = b.strip()
    if local_id < 0:
        raise ValueError("local_id must be >= 0")
    if not device_id:
        raise ValueError("device_id is empty")
    return local_id, device_id

def _read_devices() -> Dict[int, str]:
    kv = _read_env_kv(_devices_env_path())
    out: Dict[int, str] = {}
    for k, v in kv.items():
        if not k.upper().startswith("DEVICE_") or not k.upper().endswith("_ID"):
            continue
        mid = k.strip()[7:-3]  # between DEVICE_ and _ID
        try:
            lid = int(mid)
        except Exception:
            continue
        out[lid] = str(v).strip()
    return out

def _write_devices(mapping: Dict[int, str]) -> None:
    kv: Dict[str, str] = {}
    for lid in sorted(mapping.keys()):
        kv[f"DEVICE_{lid}_ID"] = mapping[lid]
    _write_env_kv(_devices_env_path(), kv)


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

    _cfg_dir().mkdir(parents=True, exist_ok=True)

    ca_out = _ca_path()
    ok = fetch_and_save_ca_cert(
        host,
        cert_port,
        out_path=ca_out,
        timeout_sec=3.0,
        overwrite=True,
    )
    if not ok:
        print(f"Failed to fetch CA cert from {host}:{cert_port}.", file=sys.stderr)
        return 1

    _write_env_kv(_net_env_path(), {
        "REMOTERF_ADDR": f"{host}:{grpc_port}",
        "REMOTERF_CA_CERT": str(ca_out.resolve()),
    })

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

def _configure_host(host_id: str) -> int:
    host_id = (host_id or "").strip()
    if not host_id:
        print("ERROR: host name is empty", file=sys.stderr)
        return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)
    _write_env_kv(_host_env_path(), {"HOST_ID": host_id})

    print("Configured host:")
    print(f"  {_host_env_path()}")
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

def _device_add(pair: str) -> int:
    lid, did = _parse_device_pair(pair)

    _cfg_dir().mkdir(parents=True, exist_ok=True)

    mapping = _read_devices()

    # "appends IF id is available"
    if lid in mapping:
        print(f"ERROR: local_id {lid} already exists (DEVICE_{lid}_ID={mapping[lid]!r})", file=sys.stderr)
        return 2
    if did in mapping.values():
        used_by = [k for k, v in mapping.items() if v == did]
        print(f"ERROR: device_id {did!r} already used (local_id={used_by[0]})", file=sys.stderr)
        return 2

    mapping[lid] = did
    _write_devices(mapping)

    print(f"Added device: {lid}:{did}")
    return 0

def _device_remove(local_id_str: str) -> int:
    try:
        lid = int(local_id_str.strip())
    except Exception:
        print("ERROR: --remove expects <int>", file=sys.stderr)
        return 2

    mapping = _read_devices()
    if lid not in mapping:
        print(f"WARNING: local_id {lid} not present; nothing to remove.")
        return 0

    old = mapping.pop(lid)
    _write_devices(mapping)
    print(f"Removed device: {lid} (was {old})")
    return 0

def _device_show() -> int:
    p = _devices_env_path()
    if not p.exists():
        print(f"No devices configured (missing {p}).")
        return 0

    mapping = _read_devices()
    print(f"Devices: {p}")
    if not mapping:
        print("  (none)")
        return 0

    for lid in sorted(mapping.keys()):
        print(f"  {lid}: {mapping[lid]}")
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
            if input("This will delete devices.env. Type 'wipe' to confirm: ").strip().lower() != "wipe":
                print("Wipe aborted.")
                return 1
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 1

    if _devices_env_path().exists():
        _devices_env_path().unlink()
    print("Wiped device config (devices.env).")
    return 0


# -----------------------------
# CLI parser (ONLY commands in help)
# -----------------------------

def main() -> int:
    argv = list(sys.argv[1:])

    # help
    if len(argv) == 0 or argv[0] in ("--help", "-help", "-h"):
        print_help()
        return 0

    # config
    if argv[0] not in ("--config", "-config", "-c"):
        print(f"ERROR: unknown command: {argv[0]!r}", file=sys.stderr)
        return 2

    yes = False

    # scopes + values / actions
    addr_selected = False
    addr_value: Optional[str] = None
    addr_show = False

    host_selected = False
    host_value: Optional[str] = None
    host_show = False

    device_selected = False
    device_add_value: Optional[str] = None
    device_remove_value: Optional[str] = None
    device_show = False
    device_wipe = False

    wipe_flag = False

    i = 1
    while i < len(argv):
        tok = argv[i]

        if tok in ("-y", "--yes", "-yes"):
            yes = True
            i += 1
            continue

        if tok in ("-w", "--wipe", "-wipe"):
            wipe_flag = True
            i += 1
            continue

        # network option
        if tok in ("-a", "--addr", "-addr"):
            addr_selected = True
            # optional value (only required when setting addr)
            if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                addr_value = argv[i + 1].strip()
                i += 2
            else:
                i += 1
            continue

        # host option (NOTE: -h means host ONLY inside -c mode)
        if tok in ("--host", "-host", "-h"):
            host_selected = True
            if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                host_value = argv[i + 1].strip()
                i += 2
            else:
                i += 1
            continue

        # device option
        if tok in ("--device", "-device", "-d"):
            device_selected = True
            i += 1
            continue

        # shared "--show" for the currently selected scope
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

        if device_selected and tok in ("--add", "-add", "-a"):
            if i + 1 >= len(argv):
                print("ERROR: missing value after --device --add", file=sys.stderr)
                return 2
            device_add_value = argv[i + 1].strip()
            i += 2
            continue

        if device_selected and tok in ("--remove", "-remove", "-r"):
            if i + 1 >= len(argv):
                print("ERROR: missing value after --device --remove", file=sys.stderr)
                return 2
            device_remove_value = argv[i + 1].strip()
            i += 2
            continue

        if device_selected and tok in ("--wipe", "-wipe", "-w"):
            device_wipe = True
            i += 1
            continue

        print(f"ERROR: unknown option: {tok!r}", file=sys.stderr)
        return 2

    # ---- Wipe behavior ----
    # - hostrf -c -a -w -y          => wipe ONLY address stuff
    # - hostrf -c --device --wipe   => wipe ONLY devices
    # - hostrf -c --host --wipe     => wipe ONLY host
    # - hostrf -c -w                => wipe ALL config
    if wipe_flag:
        if addr_show or host_show or device_show:
            print("ERROR: cannot combine --show with --wipe", file=sys.stderr)
            return 2

        # scoped wipes have priority
        if device_wipe:
            return int(_wipe_devices_only(yes=yes))
        if host_selected and host_value is None:
            return int(_wipe_host_only(yes=yes))
        if addr_selected and addr_value is None:
            return int(_wipe_addr_only(yes=yes))

        # if they didn't select a scope, wipe everything
        if not addr_selected and not host_selected and not device_selected:
            return int(_wipe_all(yes=yes))

        # if they selected a scope but provided a value, that's ambiguous -> reject
        if addr_selected and addr_value is not None:
            print("ERROR: cannot use --addr <host:port> together with --wipe. Use '-a -w' to wipe address config.", file=sys.stderr)
            return 2
        if host_selected and host_value is not None:
            print("ERROR: cannot use --host <name> together with --wipe. Use '--host --wipe' to wipe host config.", file=sys.stderr)
            return 2
        if device_selected and (device_add_value or device_remove_value):
            print("ERROR: cannot combine device add/remove with --wipe. Use '--device --wipe' instead.", file=sys.stderr)
            return 2

        print("ERROR: wipe requested but no valid wipe target selected.", file=sys.stderr)
        return 2

    # ---- Non-wipe actions ----
    did_any = False

    # show first (can be combined with other non-wipe actions if you want)
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
        rc = _configure_host(host_value)
        if rc != 0:
            return rc
        did_any = True

    if device_add_value is not None:
        rc = _device_add(device_add_value)
        if rc != 0:
            return rc
        did_any = True

    if device_remove_value is not None:
        rc = _device_remove(device_remove_value)
        if rc != 0:
            return rc
        did_any = True

    if not did_any:
        print_help()
        return 2

    return 0
