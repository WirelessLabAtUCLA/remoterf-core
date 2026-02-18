from __future__ import annotations

import sys
import os
import subprocess
import shutil
import re
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timezone


def _x509_notafter_utc(cert_path: Path) -> Optional[datetime]:
    # openssl output: notAfter=Feb 16 23:12:02 2027 GMT
    rc, out = _run_capture(["openssl", "x509", "-in", str(cert_path), "-noout", "-enddate"])
    if rc != 0 or not out:
        return None

    line = out.strip()
    if not line.startswith("notAfter="):
        return None

    s = line.split("=", 1)[1].strip()
    if s.endswith(" GMT"):
        s = s[:-4].strip()

    try:
        dt = datetime.strptime(s, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _fmt_remaining(na_utc: datetime) -> str:
    now = datetime.now(timezone.utc)
    delta = na_utc - now
    secs = int(delta.total_seconds())

    if secs <= 0:
        return "EXPIRED"

    days = secs // 86400
    secs %= 86400
    hours = secs // 3600
    secs %= 3600
    mins = secs // 60

    return f"{days}d {hours}h {mins}m"


# -----------------------------
# Repo-local server config locations
# -----------------------------

def _repo_root() -> Path:
    # <repo>/src/remoteRF_server/serverrf_cli.py -> parents[2] == <repo>
    return Path(__file__).resolve().parents[2]


def _xdg_config_home() -> Path:
    return Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config"))


def _cfg_dir() -> Path:
    # default: ~/.config/remoterf
    return Path(os.getenv("REMOTERF_CONFIG_DIR", _xdg_config_home() / "remoterf"))


def _certs_dir() -> Path:
    # allow override via REMOTERF_CERT_DIR (matches your server runtime)
    return Path(os.getenv("REMOTERF_CERT_DIR", _cfg_dir() / "certs"))


def _server_env_path() -> Path:
    return _cfg_dir() / "server.env"


def _devices_env_path() -> Path:
    # server-side device config storage (same schema as hostrf)
    return _cfg_dir() / "devices.env"


def _gen_certs_path() -> Path:
    """
    Prefer repo-local tools next to this module, but allow repo-root /tools fallback.
      - <repo>/src/remoteRF_server/tools/gen_certs.py
      - <repo>/tools/gen_certs.py
    """
    here = Path(__file__).resolve().parent
    p1 = (here / "tools" / "gen_certs.py").resolve()
    if p1.exists():
        return p1
    return (_repo_root() / "tools" / "gen_certs.py").resolve()


# -----------------------------
# Help (exact commands only)
# -----------------------------

def print_help() -> None:
    print(
        "RemoteRF Server CLI Help\n"
        "\n"
        "Usage:\n"
        "  serverrf -h | --help\n"
        "\n"
        "Serve:\n"
        "  serverrf -s | --serve              Run server (NOTE: only when -s/--serve is the FIRST arg)\n"
        "\n"
        "Certs:\n"
        "  serverrf --gen-certs <static_ip> [options]\n"
        "  serverrf --show-certs [-v]\n"
        "  serverrf --wipe-certs [-y]\n"
        "\n"
        "Ports:\n"
        "  serverrf -c | --config [options]\n"
        "\n"
        "Port options:\n"
        "  --main-port <int>                  Set GRPC_PORT\n"
        "  --cert-port <int>                  Set CERT_PORT\n"
        "  --show | -s                        Show current ports\n"
        "  -w | --wipe [-y]                   Wipe ONLY port config (server.env)\n"
        "\n"
        "Devices:\n"
        "  serverrf -d | --device [options]\n"
        "\n"
        "Device options:\n"
        "  --add --pluto <id:name:iio_serial>  Add device (fails if gid OR serial already used)\n"
        "  --remove <id>                       Remove device\n"
        "  --edit-name <id> <name>             Override device NAME for existing device\n"
        "  --show | -s                          Show all devices\n"
        "  -w | --wipe [-y]                     Wipe ONLY device config (devices.env)\n"

        "\n"
        "Cert options (for --gen-certs):\n"
        "  --days <int>        Server cert validity in days (default: 365)\n"
        "  --ca-days <int>     CA cert validity in days (default: 3650)\n"
        "  --bits <int>        RSA key size (default: 2048)\n"
        "  --dns <name>        DNS SAN entry (repeatable)\n"
        "  --cn <name>         Common Name (defaults to first SAN entry)\n"
        "  --force             Overwrite existing certs/keys\n"
        "  --no-detect-ip      Do not auto-detect IP when none provided\n"
        "\n"
        "Global:\n"
        "  -y, --yes           Skip wipe confirmation prompts\n"
        "  -v, --verbose       With --show-certs, also print x509 details (requires openssl)\n"
        "\n"
        "Examples:\n"
        "  serverrf --gen-certs 192.168.1.24 --dns rrf2 --dns rrf2.local --force\n"
        "  serverrf --gen-certs 192.168.1.50 --days 3650 --force\n"
        "  serverrf --show-certs -v\n"
        "  serverrf --wipe-certs -y\n"
        "\n"
        "  serverrf --config --main-port 61005\n"
        "  serverrf --config --cert-port 61006\n"
        "  serverrf --config --show\n"
        "  serverrf -c -s\n"
        "  serverrf --config --wipe -y\n"
        "\n"
        "  serverrf --device --add --pluto 0:pluto_aaa:123123\n"
        "  serverrf --device --edit-name 0 \"New Pluto Name\"\n"
        "  serverrf --device --remove 0\n"
        "  serverrf --device --show\n"
        "  serverrf --device --wipe -y\n"
        "\n"
        "  serverrf -s\n"
        "  serverrf --serve\n"
        "\n"
    )


# -----------------------------
# Serve
# -----------------------------

def _serve() -> int:
    """
    Alias for the RRRFserver entrypoint.
    Equivalent to running the RRRFserver console_script.
    """
    from remoteRF_server.server.grpc_server import main as grpc_main
    grpc_main()
    return 0


# -----------------------------
# Tiny env utils (same style as hostrf)
# -----------------------------

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


def _validate_port(n: int, *, name: str) -> Optional[str]:
    if n <= 0 or n > 65535:
        return f"{name} out of range (1..65535)"
    return None


# -----------------------------
# Subprocess utils
# -----------------------------

def _run(cmd: List[str]) -> int:
    try:
        subprocess.run(cmd, check=True)
        return 0
    except subprocess.CalledProcessError as e:
        return int(e.returncode)


def _run_capture(cmd: List[str]) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        return 0, p.stdout
    except subprocess.CalledProcessError as e:
        out = ""
        if getattr(e, "stdout", None):
            out = e.stdout if isinstance(e.stdout, str) else e.stdout.decode(errors="replace")
        return int(e.returncode), out


# -----------------------------
# Cert actions
# -----------------------------

def _looks_like_pem_cert(p: Path) -> bool:
    try:
        data = p.read_bytes()
    except Exception:
        return False
    return b"BEGIN CERTIFICATE" in data and b"END CERTIFICATE" in data


def _show_certs(*, verbose: bool) -> int:
    d = _certs_dir()
    print(f"Certs dir: {d}")
    if not d.exists():
        print("  (missing)")
        return 1

    files = sorted([p for p in d.iterdir() if p.is_file()])
    if not files:
        print("  (empty)")
        return 1

    for p in files:
        try:
            size = p.stat().st_size
        except Exception:
            size = -1

        tag = ""
        if p.suffix in (".crt", ".pem") and _looks_like_pem_cert(p):
            tag = " [cert]"
        elif p.suffix == ".key":
            tag = " [key]"
        print(f"  - {p.name} ({size} bytes){tag}")

    rc, _ = _run_capture(["openssl", "version"])
    if rc != 0:
        print("\n(openssl not available; install it to view cert expiry)")
    else:
        candidates: List[Path] = []
        ca = d / "ca.crt"
        srv = d / "server.crt"
        if ca.exists():
            candidates.append(ca)
        if srv.exists():
            candidates.append(srv)

        for p in files:
            if p in candidates:
                continue
            if p.suffix in (".crt", ".pem") and _looks_like_pem_cert(p):
                candidates.append(p)

        if candidates:
            print("\nExpiry:")
            for p in candidates:
                na = _x509_notafter_utc(p)
                if not na:
                    print(f"  {p.name}: (could not read notAfter)")
                    continue
                remaining = _fmt_remaining(na)
                local = na.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
                print(f"  {p.name}: expires {local}  ({remaining})")
        else:
            print("\nExpiry / Remaining:\n  (no cert files found)")

    if not verbose:
        return 0

    if rc != 0:
        print("\n(openssl not available; install it to view cert details)")
        return 0

    print("\nCertificate details (openssl):")
    for p in files:
        if p.suffix not in (".crt", ".pem"):
            continue
        if not _looks_like_pem_cert(p):
            continue

        print(f"\n== {p.name} ==")
        rc2, out2 = _run_capture(["openssl", "x509", "-in", str(p), "-noout", "-subject", "-issuer", "-dates"])
        if rc2 == 0 and out2.strip():
            print(out2.rstrip())
        else:
            print("  (failed to parse with openssl)")

        rc2, out2 = _run_capture(["openssl", "x509", "-in", str(p), "-noout", "-ext", "subjectAltName"])
        if rc2 == 0 and out2.strip():
            print(out2.rstrip())

    return 0


def _wipe_certs(*, yes: bool) -> int:
    d = _certs_dir()
    if not d.exists():
        print(f"No cert output found at: {d}")
        return 0

    if not yes:
        try:
            if input(f"This will delete ALL cert outputs at:\n  {d}\nType 'wipe' to confirm: ").strip().lower() != "wipe":
                print("Wipe aborted.")
                return 1
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 1

    shutil.rmtree(d)
    print(f"Wiped cert output: {d}")
    return 0


def _gen_certs(
    *,
    static_ip: str,
    days: int,
    ca_days: int,
    bits: int,
    dns: List[str],
    cn: Optional[str],
    force: bool,
    no_detect_ip: bool,
) -> int:
    gen_path = _gen_certs_path()
    if not gen_path.exists():
        print(f"ERROR: cert generator not found: {gen_path}", file=sys.stderr)
        return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)

    cmd: List[str] = [
        sys.executable,
        str(gen_path),
        "--days", str(days),
        "--ca-days", str(ca_days),
        "--bits", str(bits),
        "--config-dir", str(_cfg_dir()),
        "--out-subdir", "certs",
        "--ip", static_ip,
    ]

    if force:
        cmd.append("--force")
    if no_detect_ip:
        cmd.append("--no-detect-ip")
    for d in dns:
        cmd += ["--dns", d]
    if cn:
        cmd += ["--cn", cn]

    rc = _run(cmd)
    if rc == 0:
        print("Generated certs:")
        print(f"  {_certs_dir()}")

    print("\nUsers/Hosts must reconfigure each time new certs are generated.")
    return rc


# -----------------------------
# Port config actions
# -----------------------------

def _config_show_ports() -> int:
    p = _server_env_path()
    if not p.exists():
        print(f"No port config found (missing {p}).")
        return 0

    kv = _read_env_kv(p)
    if not kv:
        print("Port config is empty.")
        return 0

    print(f"Port config: {p}")
    if "GRPC_PORT" in kv:
        print(f"  GRPC_PORT={kv['GRPC_PORT']}")
    if "CERT_PORT" in kv:
        print(f"  CERT_PORT={kv['CERT_PORT']}")
    return 0


def _config_set_ports(*, main_port: Optional[int], cert_port: Optional[int]) -> int:
    if main_port is None and cert_port is None:
        print("ERROR: expected --main-port <int> and/or --cert-port <int>", file=sys.stderr)
        return 2

    if main_port is not None:
        err = _validate_port(main_port, name="main-port")
        if err:
            print(f"ERROR: {err}", file=sys.stderr)
            return 2

    if cert_port is not None:
        err = _validate_port(cert_port, name="cert-port")
        if err:
            print(f"ERROR: {err}", file=sys.stderr)
            return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)
    p = _server_env_path()
    kv = _read_env_kv(p)

    if main_port is not None:
        kv["GRPC_PORT"] = str(main_port)
    if cert_port is not None:
        kv["CERT_PORT"] = str(cert_port)

    _write_env_kv(p, kv)
    print("Configured ports:")
    print(f"  {p}")
    if main_port is not None:
        print(f"  GRPC_PORT={main_port}")
    if cert_port is not None:
        print(f"  CERT_PORT={cert_port}")
    return 0


def _config_wipe_ports(*, yes: bool) -> int:
    p = _server_env_path()
    if not p.exists():
        print(f"No port config found at: {p}")
        return 0

    if not yes:
        try:
            if input("This will delete server.env (ports). Type 'wipe' to confirm: ").strip().lower() != "wipe":
                print("Wipe aborted.")
                return 1
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 1

    p.unlink()
    print("Wiped port config (server.env).")
    return 0


# -----------------------------
# Device storage/actions
# -----------------------------

_DEVICE_KEY_RE = re.compile(r"^DEVICE_(\d+)_(.+)$", re.IGNORECASE)

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

def _device_edit_name(global_id_str: str, new_name: str) -> int:
    try:
        gid = int((global_id_str or "").strip())
    except Exception:
        print("ERROR: --edit-name expects <gid:int> <new_name>", file=sys.stderr)
        return 2

    name = (new_name or "").strip()
    if not name:
        print("ERROR: new_name is empty", file=sys.stderr)
        return 2

    recs = _read_device_records()
    if gid not in recs:
        print(f"ERROR: global_id {gid} not present; cannot edit name.", file=sys.stderr)
        return 2

    recs[gid]["NAME"] = name
    _write_device_records(recs)
    print(f"Updated device name: {gid} name={name}")
    return 0

def _read_device_records() -> Dict[int, Dict[str, str]]:
    kv = _read_env_kv(_devices_env_path())
    recs: Dict[int, Dict[str, str]] = {}
    for k, v in kv.items():
        m = _DEVICE_KEY_RE.match(k.strip())
        if not m:
            continue
        gid = int(m.group(1))
        field = m.group(2).upper().strip()
        recs.setdefault(gid, {})[field] = str(v).strip()
    return recs


def _write_device_records(recs: Dict[int, Dict[str, str]]) -> None:
    out: Dict[str, str] = {}
    for gid in sorted(recs.keys()):
        fields = recs[gid]
        order = ["TYPE", "NAME", "IDENT_KIND", "IDENT"]
        for f in order:
            if f in fields and fields[f] != "":
                out[f"DEVICE_{gid}_{f}"] = fields[f]
        for f in sorted(fields.keys()):
            if f in order:
                continue
            if fields[f] != "":
                out[f"DEVICE_{gid}_{f}"] = fields[f]
    _write_env_kv(_devices_env_path(), out)


def _device_add_pluto(spec: str) -> int:
    try:
        gid, name, iio_serial = _parse_pluto_add_spec(spec)
    except Exception as e:
        print(f"ERROR: invalid pluto spec: {e}", file=sys.stderr)
        return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)
    recs = _read_device_records()

    if gid in recs:
        print(f"ERROR: global_id {gid} already exists", file=sys.stderr)
        return 2

    for other_gid, r in recs.items():
        if r.get("IDENT_KIND", "") == "iio_serial" and r.get("IDENT", "") == iio_serial:
            print(f"ERROR: iio_serial already used by global_id={other_gid}", file=sys.stderr)
            return 2

    recs[gid] = {
        "TYPE": "pluto",
        "NAME": name,
        "IDENT_KIND": "iio_serial",
        "IDENT": iio_serial,
    }
    _write_device_records(recs)

    print(f"Added device: {gid} type=pluto name={name} iio_serial={iio_serial}")
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
    p = _devices_env_path()
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
        dtype = r.get("TYPE", "")
        name = r.get("NAME", "")
        ik = r.get("IDENT_KIND", "")
        ident = r.get("IDENT", "")
        print(f"  {gid}: type={dtype} name={name} {ik}={ident}")
    return 0


def _wipe_devices_only(*, yes: bool) -> int:
    p = _devices_env_path()
    if not p.exists():
        print(f"No device config found at: {p}")
        return 0

    if not yes:
        try:
            if input("This will delete devices.env. Type 'wipe' to confirm: ").strip().lower() != "wipe":
                print("Wipe aborted.")
                return 1
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 1

    p.unlink()
    print("Wiped device config (devices.env).")
    return 0

# -----------------------------
# CLI parser (ONLY commands in help)
# -----------------------------
def main() -> int:
    argv = list(sys.argv[1:])

    # help
    if len(argv) == 0 or argv[0] in ("--help", "-h", "-help", "--h"):
        print_help()
        return 0

    # IMPORTANT: ONLY "serverrf -s/--serve" (first arg) starts the server.
    if argv[0] in ("--serve", "-s"):
        if len(argv) != 1:
            print("ERROR: -s/--serve cannot be combined with other commands. Run it alone.", file=sys.stderr)
            return 2
        return _serve()

    yes = False
    verbose = False

    # cert commands
    gen_ip: Optional[str] = None
    show_certs = False
    wipe_certs = False

    # gen-certs options
    days = 365
    ca_days = 3650
    bits = 2048
    dns: List[str] = []
    cn: Optional[str] = None
    force = False
    no_detect_ip = False

    # config commands
    config_mode = False
    config_show = False
    config_wipe = False
    main_port: Optional[int] = None
    cert_port: Optional[int] = None

    # device commands
    device_mode = False
    device_show = False
    device_wipe = False
    device_add_type: Optional[str] = None
    device_add_spec: Optional[str] = None
    device_remove_gid: Optional[str] = None
    device_edit_gid: Optional[str] = None
    device_edit_new_name: Optional[str] = None

    i = 0
    while i < len(argv):
        tok = argv[i]

        if tok in ("-y", "--yes", "-yes"):
            yes = True
            i += 1
            continue

        if tok in ("-v", "--verbose", "-verbose"):
            verbose = True
            i += 1
            continue

        # enter config mode
        if tok in ("--config", "-c", "-config"):
            config_mode = True
            i += 1
            continue

        # enter device mode
        if tok in ("--device", "-d", "-device"):
            device_mode = True
            i += 1
            continue

        # cert verbs
        if tok == "--show-certs":
            show_certs = True
            i += 1
            continue

        if tok == "--wipe-certs":
            wipe_certs = True
            i += 1
            continue

        if tok == "--gen-certs":
            if i + 1 >= len(argv):
                print("ERROR: missing value after --gen-certs <static_ip>", file=sys.stderr)
                return 2
            gen_ip = argv[i + 1].strip()
            i += 2
            continue

        # config verbs/options
        if config_mode and tok in ("--show", "-show", "-s"):
            config_show = True
            i += 1
            continue

        if config_mode and tok in ("-w", "--wipe", "-wipe"):
            config_wipe = True
            i += 1
            continue

        if config_mode and tok == "--main-port":
            if i + 1 >= len(argv):
                print("ERROR: missing value after --main-port <int>", file=sys.stderr)
                return 2
            try:
                main_port = int(argv[i + 1].strip())
            except Exception:
                print("ERROR: --main-port expects an int", file=sys.stderr)
                return 2
            i += 2
            continue

        if config_mode and tok == "--cert-port":
            if i + 1 >= len(argv):
                print("ERROR: missing value after --cert-port <int>", file=sys.stderr)
                return 2
            try:
                cert_port = int(argv[i + 1].strip())
            except Exception:
                print("ERROR: --cert-port expects an int", file=sys.stderr)
                return 2
            i += 2
            continue

        # device verbs/options
        if device_mode and tok in ("--show", "-show", "-s"):
            device_show = True
            i += 1
            continue

        if device_mode and tok in ("-w", "--wipe", "-wipe"):
            device_wipe = True
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

        if device_mode and tok in ("--remove", "-remove", "-r"):
            if i + 1 >= len(argv):
                print("ERROR: missing value after --device --remove <gid>", file=sys.stderr)
                return 2
            device_remove_gid = argv[i + 1].strip()
            i += 2
            continue

        if device_mode and tok in ("--edit-name", "-edit-name"):
            if i + 2 >= len(argv):
                print("ERROR: --edit-name expects <gid> <new_name>", file=sys.stderr)
                return 2
            device_edit_gid = argv[i + 1].strip()
            device_edit_new_name = argv[i + 2].strip()
            i += 3
            continue

        # gen-certs options
        if tok == "--days":
            if i + 1 >= len(argv):
                print("ERROR: missing value after --days <int>", file=sys.stderr)
                return 2
            try:
                days = int(argv[i + 1].strip())
            except Exception:
                print("ERROR: --days expects an int", file=sys.stderr)
                return 2
            i += 2
            continue

        if tok == "--ca-days":
            if i + 1 >= len(argv):
                print("ERROR: missing value after --ca-days <int>", file=sys.stderr)
                return 2
            try:
                ca_days = int(argv[i + 1].strip())
            except Exception:
                print("ERROR: --ca-days expects an int", file=sys.stderr)
                return 2
            i += 2
            continue

        if tok == "--bits":
            if i + 1 >= len(argv):
                print("ERROR: missing value after --bits <int>", file=sys.stderr)
                return 2
            try:
                bits = int(argv[i + 1].strip())
            except Exception:
                print("ERROR: --bits expects an int", file=sys.stderr)
                return 2
            i += 2
            continue

        if tok == "--dns":
            if i + 1 >= len(argv):
                print("ERROR: missing value after --dns <name>", file=sys.stderr)
                return 2
            dns.append(argv[i + 1].strip())
            i += 2
            continue

        if tok == "--cn":
            if i + 1 >= len(argv):
                print("ERROR: missing value after --cn <name>", file=sys.stderr)
                return 2
            cn = argv[i + 1].strip()
            i += 2
            continue

        if tok == "--force":
            force = True
            i += 1
            continue

        if tok == "--no-detect-ip":
            no_detect_ip = True
            i += 1
            continue

        print(f"ERROR: unknown option: {tok!r}", file=sys.stderr)
        return 2

    # ----------------
    # Enforce single-mode semantics (device vs config vs cert)
    # ----------------
    if device_mode and (config_mode or show_certs or wipe_certs or (gen_ip is not None)):
        print("ERROR: --device cannot be combined with config/cert commands. Run them separately.", file=sys.stderr)
        return 2

    # ----------------
    # Device mode execution
    # ----------------
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
            rc = _device_edit_name(device_edit_gid, device_edit_new_name or "")
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

    # ----------------
    # Config mode execution
    # ----------------
    if config_mode:
        if config_wipe and (config_show or main_port is not None or cert_port is not None):
            print("ERROR: cannot combine --wipe with --show or port. Use '-c -w' only.", file=sys.stderr)
            return 2

        if config_wipe:
            return int(_config_wipe_ports(yes=yes))

        did_any = False

        if config_show:
            rc = _config_show_ports()
            if rc != 0:
                return rc
            did_any = True

        if main_port is not None or cert_port is not None:
            rc = _config_set_ports(main_port=main_port, cert_port=cert_port)
            if rc != 0:
                return rc
            did_any = True

        if not did_any:
            print_help()
            return 2

        return 0

    # ----------------
    # Cert mode execution
    # ----------------
    if wipe_certs and show_certs:
        print("ERROR: cannot combine --show-certs with --wipe-certs", file=sys.stderr)
        return 2

    if wipe_certs:
        return int(_wipe_certs(yes=yes))

    if show_certs and gen_ip is None:
        return int(_show_certs(verbose=verbose))

    if gen_ip is None:
        print_help()
        return 2

    rc = _gen_certs(
        static_ip=gen_ip,
        days=days,
        ca_days=ca_days,
        bits=bits,
        dns=dns,
        cn=cn,
        force=force,
        no_detect_ip=no_detect_ip,
    )
    if rc != 0:
        return rc

    if show_certs:
        return int(_show_certs(verbose=verbose))

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
