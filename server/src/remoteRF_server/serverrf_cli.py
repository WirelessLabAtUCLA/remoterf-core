#!/usr/bin/env python3
# src/remoteRF_server/serverrf_cli.py

from __future__ import annotations

import sys
import os
import subprocess
import shutil
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
    # strip trailing timezone token if it's "GMT"
    if s.endswith(" GMT"):
        s = s[:-4].strip()

    try:
        # Example: "Feb 16 23:12:02 2027"
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

# def _cfg_dir() -> Path:
#     # <repo>/.config
#     return _repo_root() / ".config"

# def _certs_dir() -> Path:
#     # <repo>/.config/certs
#     return _cfg_dir() / "certs"

# def _server_env_path() -> Path:
#     # <repo>/.config/server.env
#     return _cfg_dir() / "server.env"

import os
from pathlib import Path

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
        "  --show                             Show current ports\n"
        "  -w | --wipe [-y]                   Wipe ONLY port config (server.env)\n"
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
        "Where things live:\n"
        f"  Ports file:  {_server_env_path()}\n"
        f"  Certs dir:   {_certs_dir()}\n"
        "\n"
        "Examples:\n"
        "  serverrf --config --main-port 61005\n"
        "  serverrf --config --cert-port 61006\n"
        "  serverrf --config --main-port 61005 --cert-port 61006\n"
        "  serverrf --config --show\n"
        "  serverrf --config --wipe -y\n"
        "\n"
        "  serverrf --gen-certs 192.168.1.24 --dns rrf2 --dns rrf2.local --force\n"
        "  serverrf --show-certs -v\n"
        "  serverrf --wipe-certs -y\n"
        "\n"
    )


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

    # ---- expiry / remaining (non-verbose too) ----
    rc, _ = _run_capture(["openssl", "version"])
    if rc != 0:
        print("\n(openssl not available; install it to view cert expiry)")
    else:
        # Prefer showing CA + Server explicitly if present
        candidates: List[Path] = []
        ca = d / "ca.crt"
        srv = d / "server.crt"
        if ca.exists():
            candidates.append(ca)
        if srv.exists():
            candidates.append(srv)

        # Also include any other cert-like files (avoid duplicates)
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

    # ---- existing verbose dump ----
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
# CLI parser (ONLY commands in help)
# -----------------------------

def main() -> int:
    argv = list(sys.argv[1:])

    # help
    if len(argv) == 0 or argv[0] in ("--help", "-h", "-help", "--h"):
        print_help()
        return 0

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
        if config_mode and tok in ("--show", "-show"):
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
    # Config mode execution
    # ----------------
    if config_mode:
        # conflict checks
        if config_wipe and (config_show or main_port is not None or cert_port is not None):
            print("ERROR: cannot combine --wipe with --show or port सेट. Use '--config --wipe' only.", file=sys.stderr)
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

    # allow: gen + show
    if show_certs:
        return int(_show_certs(verbose=verbose))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
