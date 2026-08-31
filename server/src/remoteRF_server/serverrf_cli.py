# Copyright (C) 2026 RemoteRF
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from __future__ import annotations

import sys
import os
import subprocess
import shutil
import re
import ssl
import ipaddress
from pathlib import Path
from typing import Any, Optional, Dict, List, Tuple
from datetime import datetime, timezone
import base64
import secrets
import hashlib
import getpass
import yaml

from remoteRF_server.drivers.usrp.profiles import (
    get_usrp_profile,
    inventory_for_profile,
)

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


_STATIC_IP_ENV_KEYS: Tuple[str, ...] = ("STATIC_IP", "SERVER_IP")


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def _x509_static_ip(cert_path: Path) -> str:
    if not cert_path.exists():
        raise FileNotFoundError(f"server cert not found: {cert_path}")

    try:
        cert = ssl._ssl._test_decode_cert(str(cert_path))
    except FileNotFoundError:
        raise
    except Exception as e:
        raise ValueError(f"could not parse server cert {cert_path}: {e}") from e

    for name, value in cert.get("subjectAltName", []):
        if name.lower() == "ip address":
            ip = (value or "").strip()
            if ip:
                return ip

    for group in cert.get("subject", []):
        for name, value in group:
            if name.lower() != "commonname":
                continue
            cn = (value or "").strip()
            if _is_ip_address(cn):
                return cn

    raise ValueError(f"server cert does not contain an IP SAN or IP common name: {cert_path}")


def _resolve_static_ip(kv: Dict[str, str]) -> Tuple[Optional[str], str, Optional[str]]:
    env_path = _server_env_path()
    for key in _STATIC_IP_ENV_KEYS:
        value = (kv.get(key, "") or "").strip()
        if value:
            return value, f"{env_path} ({key})", None

    cert_path = _certs_dir() / "server.crt"
    try:
        return _x509_static_ip(cert_path), str(cert_path), None
    except (FileNotFoundError, ValueError) as e:
        return None, str(cert_path), str(e)


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
    # Read-only migration source for pre-YAML installations.
    return _cfg_dir() / "devices.env"


def _devices_yaml_path() -> Path:
    return _cfg_dir() / "devices.yml"


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

def _gist_env_path() -> Path:
    # Stored alongside server.env/devices.yml under ~/.config/remoterf by default
    return _cfg_dir() / "gist.env"

def _tos_ack_path() -> Path:
    # Stored alongside server.env/devices.yml under ~/.config/remoterf by default
    return _cfg_dir() / "tos.env"


_TOS_VERSION = "2026"
_TOS_URL = "https://remoterf.net/tos"
BANNER_CREDIT = "Created by the Wireless Lab at UCLA"


def _tos_acknowledged() -> bool:
    kv = _read_env_kv(_tos_ack_path())
    accepted = kv.get("REMOTERF_TOS_ACKNOWLEDGED", "").strip().lower()
    version = kv.get("REMOTERF_TOS_VERSION", "").strip()
    return accepted in {"1", "true", "yes", "y"} and version == _TOS_VERSION


def _print_tos_acknowledgement() -> None:
    print(
        "\n"
        "RemoteRF 2026\n"
        "Terms of Service Acknowledgement\n"
        "\n"
        "By continuing, you confirm that you have reviewed and agree to the\n"
        "RemoteRF Terms of Service and understand that use of the client and\n"
        "service is at your own risk. RemoteRF is not liable for losses or\n"
        "damages arising from use of the platform.\n"
        "\n"
        f"Terms of Service: {_TOS_URL}\n"
    )


def _ensure_tos_acknowledged() -> bool:
    if _tos_acknowledged():
        return True

    _print_tos_acknowledgement()
    while True:
        try:
            answer = input("Do you agree to the RemoteRF Terms of Service? (yes/no): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nTerms of Service acknowledgement is required before starting the server.")
            return False

        if answer in {"y", "yes"}:
            break
        if answer in {"n", "no"}:
            print("Terms of Service not accepted. Server startup cancelled.")
            return False
        print("Please answer yes or no.")

    _write_env_kv(
        _tos_ack_path(),
        {
            "REMOTERF_TOS_ACKNOWLEDGED": "true",
            "REMOTERF_TOS_VERSION": _TOS_VERSION,
            "REMOTERF_TOS_URL": _TOS_URL,
            "REMOTERF_TOS_ACKNOWLEDGED_AT": datetime.now(timezone.utc).isoformat(),
            "REMOTERF_TOS_ACKNOWLEDGED_BY": getpass.getuser(),
        },
    )
    print(f"Terms of Service acknowledgement saved to: {_tos_ack_path()}")
    return True

# -----------------------------
# Help (exact commands only)
# -----------------------------

def print_help() -> None:
    print(
        "RemoteRF Server CLI Help\n"
        f"{BANNER_CREDIT}\n"
        "\n"
        "Usage:\n"
        "  serverrf -h | --help\n"
        "\n"
        "Serve:\n"
        "  serverrf -s | --serve              Run server (NOTE: only when -s/--serve is the FIRST arg)\n"
        "  serverrf --serve --headless         Run without the interactive administration shell\n"
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
        "  --show | -s                        Show current ports and static IP\n"
        "  -w | --wipe [-y]                   Wipe ONLY port config (server.env)\n"
        "\n"
        "Hosts:\n"
        "  serverrf --host --token-create <host_id> [--length <int>]   Create/rotate host token\n"
        "  serverrf --host --show                     Show all host token records\n"
        "  serverrf --host --delete <host_id>         Delete host token record\n"
        "  serverrf --host --wipe [-y]                Wipe ALL host token records\n"
        "  serverrf --host --list --secrets           (optional) include salt/hash\n"
        "\n"
        "Devices:\n"
        "  serverrf -d | --device [options]\n"
        "  Inventory: ~/.config/remoterf/devices.yml (canonical YAML)\n"
        "\n"
        "Device options:\n"
        "  --add --pluto <id:name:iio_serial>  Add an ADALM-Pluto\n"
        "  --add --pluto-mimo <id:name:iio_serial>\n"
        "                                      Add an ADALM-Pluto MIMO (all channels enabled)\n"
        "  --add --rtl-sdr <id:name:selector>   Add an RTL-SDR by serial or index=N\n"
        "  --add --ti-mmwave <id:name:cp2105_serial>\n"
        "                                      Add a TI mmWave dual-UART radar\n"
        "  --add --usrp-2901 <id:name:serial>  Add a serial-bound NI USRP-2901\n"
        "  --add --usrp2901 <id:name:serial>   Legacy alias for --usrp-2901\n"
        "  --add --usrp <id:name:serial>       Legacy alias for --usrp-2901\n"
        "  --add --usrp-b205-mini <id:name:serial>\n"
        "                                      Add a serial-bound USRP B205-mini\n"
        "  --add --usrp-n210 <id:name:addr>    Add an address-bound N210\n"
        "  --add --usrp-profile <id:name:profile:selector>\n"
        "                                      Add any registered USRP profile\n"
        "  --remove <id>                       Remove device\n"
        "  --edit-name <id> <name>             Override device name\n"
        "  --show | -s                         Show all devices\n"
        "  -w | --wipe [-y]                    Wipe device inventory\n"

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
        "Gist Status:\n"
        "  serverrf --gist --set --id <gist_id> --file <filename> [--token <tok> | --token-stdin]\n"
        "  serverrf --gist --show [--secrets]\n"
        "  serverrf --gist --wipe [-y]\n"
        "\n"
        "Examples:\n"
        "  serverrf --gist --set --id 2a35e0... --file ucla-wlab-remoterf-status.json\n"
        "  serverrf --gist --set --id 2a35e0... --file status.json --token-stdin\n"
        "  serverrf --gist --show\n"
        "  serverrf --gist --wipe -y\n"
        "\n"
        # "  serverrf --gen-certs 192.168.1.24 --dns rrf2 --dns rrf2.local --force\n"
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
        "  serverrf --host --token-create lab-host-01 --length 8 --force\n"
        "  serverrf --host --show\n"
        "  serverrf --host --delete lab-host-01\n"
        "  serverrf --host --wipe -y\n"
        "\n"
        "  serverrf --device --add --pluto 0:pluto_aaa:123123\n"
        "  serverrf --device --add --pluto-mimo 1:pluto_mimo:104473f6\n"
        "  serverrf --device --add --rtl-sdr 4:rtl_fm:serial=00000001\n"
        "  serverrf --device --add --ti-mmwave 5:ti_radar:00DF4F69\n"
        "  serverrf --device --add --usrp-2901 1:usrp2901_lab:31A2B3C\n"
        "  serverrf --device --add --usrp-b205-mini 3:b205mini_lab:31E9F48\n"
        "  serverrf --device --add --usrp-n210 2:n210_lab:192.168.137.21\n"
        "  serverrf --device --add --usrp-profile 4:x310_lab:x3xx:192.168.10.2\n"
        "  serverrf --device --show\n"
        "  serverrf --device --wipe -y\n"
        "\n"
        "  serverrf -s\n"
        "  serverrf --serve\n"
        "  serverrf --serve --headless\n"
        "\n"
    )


# -----------------------------
# Serve
# -----------------------------

def _serve(*, headless: bool = False) -> int:
    """
    Alias for the RRRFserver entrypoint.
    Equivalent to running the RRRFserver console_script.
    """
    if not _ensure_tos_acknowledged():
        return 1

    # UHD writes native log messages to stderr/std::clog. Set this before the
    # server imports device drivers so those messages cannot corrupt the
    # interactive prompt. RemoteRF keeps this off even when the surrounding
    # shell has a noisy UHD default; diagnostics require an explicit RemoteRF
    # opt-in.
    os.environ["UHD_LOG_CONSOLE_LEVEL"] = os.getenv(
        "REMOTERF_UHD_CONSOLE_LEVEL",
        "off",
    )

    from remoteRF_server.server.grpc_server import (
        headless_main,
        main as interactive_main,
    )
    grpc_main = headless_main if headless else interactive_main
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

def _redact(s: str) -> str:
    s = (s or "").strip()
    if len(s) <= 8:
        return "****"
    return f"{s[:4]}...{s[-4:]}"


def _gist_show(*, show_secrets: bool = False) -> int:
    p = _gist_env_path()
    if not p.exists():
        print(f"No gist config found (missing {p}).")
        return 0

    kv = _read_env_kv(p)
    print(f"Gist config: {p}")
    gid = kv.get("STATUS_GIST_ID", "")
    fn = kv.get("STATUS_GIST_FILENAME", "")
    tok = kv.get("GITHUB_TOKEN", "")

    print(f"  STATUS_GIST_ID={gid}")
    print(f"  STATUS_GIST_FILENAME={fn}")
    if show_secrets:
        print(f"  GITHUB_TOKEN={tok}")
    else:
        print(f"  GITHUB_TOKEN={_redact(tok)}  (use --secrets to show)")
    return 0


def _gist_set(*, gist_id: str, filename: str, token: str) -> int:
    gist_id = (gist_id or "").strip()
    filename = (filename or "").strip()
    token = (token or "").strip()

    if not gist_id:
        print("ERROR: missing --id <gist_id>", file=sys.stderr)
        return 2
    if not filename:
        print("ERROR: missing --file <filename>", file=sys.stderr)
        return 2
    if not token:
        print("ERROR: missing token (use prompt or --token-stdin or --token)", file=sys.stderr)
        return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)
    p = _gist_env_path()

    kv = _read_env_kv(p)
    kv["STATUS_GIST_ID"] = gist_id
    kv["STATUS_GIST_FILENAME"] = filename
    kv["GITHUB_TOKEN"] = token

    _write_env_kv(p, kv)

    try:
        os.chmod(p, 0o600)
    except Exception:
        pass

    print("Configured gist status env:")
    print(f"  {p}")
    print(f"  STATUS_GIST_ID={gist_id}")
    print(f"  STATUS_GIST_FILENAME={filename}")
    print(f"  GITHUB_TOKEN={_redact(token)}")
    return 0


def _gist_wipe(*, yes: bool) -> int:
    p = _gist_env_path()
    if not p.exists():
        print(f"No gist config found at: {p}")
        return 0

    if not yes:
        try:
            if input("This will delete gist.env (gist status config). Type 'wipe' to confirm: ").strip().lower() != "wipe":
                print("Wipe aborted.")
                return 1
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 1

    p.unlink()
    print("Wiped gist config (gist.env).")
    return 0

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
    kv = _read_env_kv(p)

    print(f"Port config: {p}")
    if not p.exists():
        print("  (missing)")
    elif not kv:
        print("  (empty)")

    if "GRPC_PORT" in kv:
        print(f"  MAIN_PORT={kv['GRPC_PORT']}")
    if "CERT_PORT" in kv:
        print(f"  CERT_PORT={kv['CERT_PORT']}")

    static_ip, source, err = _resolve_static_ip(kv)
    if static_ip:
        print(f"  STATIC_IP={static_ip}")
        if source != f"{p} (STATIC_IP)":
            print(f"  STATIC_IP_SOURCE={source}")
    else:
        print("  STATIC_IP=(not set)")
        print(f"  STATIC_IP_ERROR={err or f'could not resolve from {source}'}")
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


def _parse_serial_add_spec(tok: str, *, serial_label: str) -> Tuple[int, str, str]:
    parts = [p.strip() for p in (tok or "").split(":")]
    if len(parts) != 3:
        raise ValueError(f"Expected <gid:name:{serial_label}>")
    gid_s, name, serial = parts
    gid = int(gid_s)
    if gid < 0:
        raise ValueError("gid must be >= 0")
    if not name:
        raise ValueError("name is empty")
    if not serial:
        raise ValueError(f"{serial_label} is empty")
    return gid, name, serial


def _parse_pluto_add_spec(tok: str) -> Tuple[int, str, str]:
    return _parse_serial_add_spec(tok, serial_label="iio_serial")


def _parse_address_add_spec(tok: str) -> Tuple[int, str, str]:
    gid, name, address = _parse_serial_add_spec(tok, serial_label="addr")
    if not _is_ip_address(address):
        raise ValueError("addr must be an IPv4 or IPv6 address")
    return gid, name, address


def _parse_rtl_sdr_add_spec(tok: str) -> Tuple[int, str, str, Any]:
    gid, name, selector = _parse_serial_add_spec(tok, serial_label="selector")
    if selector.startswith("index="):
        raw_index = selector.partition("=")[2].strip()
        try:
            device_index = int(raw_index)
        except ValueError as exc:
            raise ValueError("index selector must be an integer") from exc
        if device_index < 0:
            raise ValueError("index selector must be >= 0")
        return gid, name, "device_index", device_index
    if selector.startswith("serial="):
        selector = selector.partition("=")[2].strip()
    if not selector:
        raise ValueError("serial selector is empty")
    return gid, name, "serial", selector


def _parse_usrp_profile_add_spec(tok: str) -> Tuple[int, str, str, str]:
    parts = [part.strip() for part in (tok or "").split(":", 3)]
    if len(parts) != 4:
        raise ValueError("Expected <gid:name:profile:selector>")
    gid_s, name, profile_name, selector = parts
    gid = int(gid_s)
    if gid < 0:
        raise ValueError("gid must be >= 0")
    if not name:
        raise ValueError("name is empty")
    if not selector:
        raise ValueError("selector is empty")
    profile = get_usrp_profile(profile_name)
    if profile.selector == "address" and not _is_ip_address(selector):
        raise ValueError("selector must be an IPv4 or IPv6 address")
    return gid, name, profile.profile_id, selector

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

    try:
        recs = _read_device_records()
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if gid not in recs:
        print(f"ERROR: global_id {gid} not present; cannot edit name.", file=sys.stderr)
        return 2

    recs[gid]["NAME"] = name
    _write_device_records(recs)
    print(f"Updated device name: {gid} name={name}")
    return 0

def _read_device_records() -> Dict[int, Dict[str, Any]]:
    yaml_path = _devices_yaml_path()
    if yaml_path.exists() and yaml_path.stat().st_size:
        try:
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
            devices = data.get("devices") or []
            if not isinstance(devices, list):
                raise ValueError("'devices' must be a list")
            recs: Dict[int, Dict[str, Any]] = {}
            for item in devices:
                if not isinstance(item, dict):
                    continue
                gid = int(item["device_id"])
                dtype = str(item.get("device_type") or "").strip().lower()
                if not dtype:
                    raise ValueError(f"device {gid} has no device_type")
                init = item.get("init") or {}
                if not isinstance(init, dict):
                    raise ValueError(f"device {gid} init must be a mapping")
                address = str(init.get("addr") or "").strip()
                serial = str(init.get("serial") or "").strip()
                device_args = str(init.get("args") or "").strip()
                device_index = (
                    str(init.get("device_index")).strip()
                    if "device_index" in init
                    else ""
                )
                ident = address or serial or device_args or device_index
                recs[gid] = {
                    "TYPE": dtype,
                    "NAME": str(item.get("name") or f"device-{gid}").strip(),
                    "IDENT_KIND": (
                        "address"
                        if address
                        else "device_args"
                        if device_args
                        else "device_index"
                        if device_index
                        else "iio_serial"
                        if dtype in {"pluto", "adalm_pluto", "adalm_pluto_mimo"}
                        else "serial"
                    ),
                    "IDENT": ident,
                    "INIT": dict(init),
                }
            return recs
        except Exception as exc:
            raise ValueError(f"invalid device inventory {yaml_path}: {exc}") from exc

    kv = _read_env_kv(_devices_env_path())
    recs: Dict[int, Dict[str, Any]] = {}
    for k, v in kv.items():
        m = _DEVICE_KEY_RE.match(k.strip())
        if not m:
            continue
        gid = int(m.group(1))
        field = m.group(2).upper().strip()
        recs.setdefault(gid, {})[field] = str(v).strip()
    return recs


def _write_device_records(recs: Dict[int, Dict[str, Any]]) -> None:
    devices: List[Dict[str, Any]] = []
    for gid in sorted(recs.keys()):
        fields = recs[gid]
        dtype = str(fields.get("TYPE") or "").strip().lower()
        ident = str(fields.get("IDENT") or "").strip()
        init = fields.get("INIT") or {}
        if not isinstance(init, dict):
            init = {}
        init = dict(init)
        if ident:
            ident_kind = str(fields.get("IDENT_KIND") or "")
            if ident_kind == "address":
                init["addr"] = ident
                init.pop("serial", None)
                init.pop("args", None)
                init.pop("device_index", None)
            elif ident_kind == "device_args":
                init["args"] = ident
                init.pop("addr", None)
                init.pop("serial", None)
                init.pop("device_index", None)
            elif ident_kind == "device_index":
                init["device_index"] = int(ident)
                init.pop("addr", None)
                init.pop("serial", None)
                init.pop("args", None)
            else:
                init["serial"] = ident
                init.pop("addr", None)
                init.pop("args", None)
                init.pop("device_index", None)
        devices.append(
            {
                "device_id": int(gid),
                "device_type": dtype,
                "name": str(fields.get("NAME") or f"device-{gid}"),
                "init": init,
            }
        )
    _cfg_dir().mkdir(parents=True, exist_ok=True)
    _devices_yaml_path().write_text(
        yaml.safe_dump({"devices": devices}, sort_keys=False),
        encoding="utf-8",
    )
    # Once a legacy inventory has been migrated successfully, remove it so
    # there is exactly one authoritative device manifest.
    _devices_env_path().unlink(missing_ok=True)


def _device_add_pluto(spec: str) -> int:
    try:
        gid, name, iio_serial = _parse_pluto_add_spec(spec)
    except Exception as e:
        print(f"ERROR: invalid pluto spec: {e}", file=sys.stderr)
        return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)
    try:
        recs = _read_device_records()
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if gid in recs:
        print(f"ERROR: global_id {gid} already exists", file=sys.stderr)
        return 2

    for other_gid, r in recs.items():
        if r.get("IDENT_KIND", "") == "iio_serial" and r.get("IDENT", "") == iio_serial:
            print(f"ERROR: iio_serial already used by global_id={other_gid}", file=sys.stderr)
            return 2

    recs[gid] = {
        "TYPE": "adalm_pluto",
        "NAME": name,
        "IDENT_KIND": "iio_serial",
        "IDENT": iio_serial,
    }
    _write_device_records(recs)

    print(f"Added device: {gid} type=adalm_pluto name={name} iio_serial={iio_serial}")
    return 0


def _device_add_pluto_mimo(spec: str) -> int:
    try:
        gid, name, iio_serial = _parse_pluto_add_spec(spec)
    except Exception as exc:
        print(f"ERROR: invalid pluto-mimo spec: {exc}", file=sys.stderr)
        return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)
    try:
        recs = _read_device_records()
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if gid in recs:
        print(f"ERROR: global_id {gid} already exists", file=sys.stderr)
        return 2

    for other_gid, record in recs.items():
        if (
            record.get("IDENT_KIND", "") == "iio_serial"
            and record.get("IDENT", "") == iio_serial
        ):
            print(
                f"ERROR: iio_serial already used by global_id={other_gid}",
                file=sys.stderr,
            )
            return 2

    recs[gid] = {
        "TYPE": "adalm_pluto_mimo",
        "NAME": name,
        "IDENT_KIND": "iio_serial",
        "IDENT": iio_serial,
        "INIT": {
            "rx_enabled_channels": [0, 1],
            "tx_enabled_channels": [0, 1],
        },
    }
    _write_device_records(recs)

    print(
        f"Added device: {gid} type=adalm_pluto_mimo name={name} "
        f"iio_serial={iio_serial} rx_channels=0,1 tx_channels=0,1"
    )
    return 0


def _device_add_rtl_sdr(spec: str) -> int:
    try:
        gid, name, selector_kind, selector = _parse_rtl_sdr_add_spec(spec)
    except Exception as exc:
        print(f"ERROR: invalid rtl-sdr spec: {exc}", file=sys.stderr)
        return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)
    try:
        recs = _read_device_records()
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if gid in recs:
        print(f"ERROR: global_id {gid} already exists", file=sys.stderr)
        return 2
    selector_text = str(selector)
    for other_gid, record in recs.items():
        if (
            str(record.get("TYPE") or "") == "rtl_sdr"
            and str(record.get("IDENT_KIND") or "") == selector_kind
            and str(record.get("IDENT") or "") == selector_text
        ):
            print(
                f"ERROR: RTL-SDR {selector_kind} already used by "
                f"global_id={other_gid}",
                file=sys.stderr,
            )
            return 2

    recs[gid] = {
        "TYPE": "rtl_sdr",
        "NAME": name,
        "IDENT_KIND": selector_kind,
        "IDENT": selector_text,
        "INIT": {selector_kind: selector},
    }
    _write_device_records(recs)
    print(
        f"Added device: {gid} type=rtl_sdr name={name} "
        f"{selector_kind}={selector}"
    )
    return 0


def _device_add_ti_mmwave(spec: str) -> int:
    try:
        gid, name, serial = _parse_serial_add_spec(
            spec,
            serial_label="cp2105_serial",
        )
    except Exception as exc:
        print(f"ERROR: invalid ti-mmwave spec: {exc}", file=sys.stderr)
        return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)
    try:
        recs = _read_device_records()
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if gid in recs:
        print(f"ERROR: global_id {gid} already exists", file=sys.stderr)
        return 2

    for other_gid, record in recs.items():
        if (
            str(record.get("TYPE") or "") == "ti_mmwave"
            and str(record.get("IDENT") or "") == serial
        ):
            print(
                f"ERROR: TI mmWave serial already used by global_id={other_gid}",
                file=sys.stderr,
            )
            return 2

    recs[gid] = {
        "TYPE": "ti_mmwave",
        "NAME": name,
        "IDENT_KIND": "serial",
        "IDENT": serial,
        "INIT": {
            "serial": serial,
            "firmware_profile": "xwr68xx_oob_sdk3",
            "cli_baud": 115200,
            "data_baud": 921600,
            "frame_queue_depth": 8,
        },
    }
    _write_device_records(recs)
    print(
        f"Added device: {gid} type=ti_mmwave name={name} "
        f"cp2105_serial={serial}"
    )
    return 0


def _device_add_usrp(spec: str) -> int:
    try:
        gid, name, serial = _parse_serial_add_spec(spec, serial_label="serial")
    except Exception as e:
        print(f"ERROR: invalid usrp spec: {e}", file=sys.stderr)
        return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)
    try:
        recs = _read_device_records()
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if gid in recs:
        print(f"ERROR: global_id {gid} already exists", file=sys.stderr)
        return 2

    for other_gid, record in recs.items():
        if str(record.get("IDENT", "")) == serial:
            print(f"ERROR: serial already used by global_id={other_gid}", file=sys.stderr)
            return 2

    recs[gid] = {
        "TYPE": "usrp",
        "NAME": name,
        "IDENT_KIND": "serial",
        "IDENT": serial,
        "INIT": inventory_for_profile("usrp2901", serial),
    }
    _write_device_records(recs)
    print(f"Added device: {gid} type=usrp name={name} serial={serial}")
    return 0


def _device_add_usrp_n210(spec: str) -> int:
    try:
        gid, name, address = _parse_address_add_spec(spec)
    except Exception as exc:
        print(f"ERROR: invalid usrp-n210 spec: {exc}", file=sys.stderr)
        return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)
    try:
        recs = _read_device_records()
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if gid in recs:
        print(f"ERROR: global_id {gid} already exists", file=sys.stderr)
        return 2
    for other_gid, record in recs.items():
        if (
            str(record.get("IDENT_KIND") or "") == "address"
            and str(record.get("IDENT") or "") == address
        ):
            print(f"ERROR: address already used by global_id={other_gid}", file=sys.stderr)
            return 2

    recs[gid] = {
        "TYPE": "usrp",
        "NAME": name,
        "IDENT_KIND": "address",
        "IDENT": address,
        "INIT": inventory_for_profile("n210", address),
    }
    _write_device_records(recs)
    print(f"Added device: {gid} type=usrp profile=n210 addr={address}")
    return 0


def _device_add_usrp_b205mini(spec: str) -> int:
    try:
        gid, name, serial = _parse_serial_add_spec(
            spec,
            serial_label="serial",
        )
    except Exception as exc:
        print(f"ERROR: invalid usrp-b205-mini spec: {exc}", file=sys.stderr)
        return 2
    return _device_add_usrp_profile(f"{gid}:{name}:b205mini:{serial}")


def _device_add_usrp_profile(spec: str) -> int:
    try:
        gid, name, profile_name, selector = _parse_usrp_profile_add_spec(spec)
        profile = get_usrp_profile(profile_name)
        init = inventory_for_profile(profile_name, selector)
    except Exception as exc:
        print(f"ERROR: invalid usrp-profile spec: {exc}", file=sys.stderr)
        return 2

    _cfg_dir().mkdir(parents=True, exist_ok=True)
    try:
        recs = _read_device_records()
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if gid in recs:
        print(f"ERROR: global_id {gid} already exists", file=sys.stderr)
        return 2
    for other_gid, record in recs.items():
        if (
            str(record.get("IDENT_KIND") or "") == profile.selector
            and str(record.get("IDENT") or "") == selector
        ):
            print(
                f"ERROR: {profile.selector} already used by global_id={other_gid}",
                file=sys.stderr,
            )
            return 2

    recs[gid] = {
        "TYPE": "usrp",
        "NAME": name,
        "IDENT_KIND": profile.selector,
        "IDENT": selector,
        "INIT": init,
    }
    _write_device_records(recs)
    print(
        f"Added device: {gid} type=usrp profile={profile.profile_id} "
        f"{profile.selector}={selector}"
    )
    return 0


def _device_remove(global_id_str: str) -> int:
    try:
        gid = int((global_id_str or "").strip())
    except Exception:
        print("ERROR: --remove expects <gid:int>", file=sys.stderr)
        return 2

    try:
        recs = _read_device_records()
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if gid not in recs:
        print(f"WARNING: global_id {gid} not present; nothing to remove.")
        return 0

    recs.pop(gid, None)
    _write_device_records(recs)
    print(f"Removed device: {gid}")
    return 0


def _device_show() -> int:
    p = _devices_yaml_path()
    if not p.exists() and not _devices_env_path().exists():
        print(f"No devices configured (missing {p}).")
        return 0

    try:
        recs = _read_device_records()
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
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
    paths = [
        p
        for p in (_devices_yaml_path(), _cfg_dir() / "devices.yaml", _devices_env_path())
        if p.exists()
    ]
    if not paths:
        print(f"No device config found at: {_devices_yaml_path()}")
        return 0

    if not yes:
        try:
            if input("This will delete the device inventory. Type 'wipe' to confirm: ").strip().lower() != "wipe":
                print("Wipe aborted.")
                return 1
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 1

    for path in paths:
        path.unlink()
    print("Wiped device inventory.")
    return 0

# -----------------------------
# CLI parser (ONLY commands in help)
# -----------------------------
def main() -> int:
    argv = list(sys.argv[1:])

    if len(argv) == 0:
        print("invalid args, expect serverrf <args>, run serverrf --help for more info", file=sys.stderr)
        return 2

    # help
    if argv[0] in ("--help", "-h", "-help", "--h"):
        print_help()
        return 0

    # IMPORTANT: ONLY "serverrf -s/--serve" (first arg) starts the server.
    if argv[0] in ("--serve", "-s"):
        if len(argv) == 1:
            return _serve()
        if len(argv) == 2 and argv[1] == "--headless":
            return _serve(headless=True)
        else:
            print(
                "ERROR: -s/--serve accepts only the optional --headless flag.",
                file=sys.stderr,
            )
            return 2

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
    
    # host commands
    host_mode = False
    host_token_create_id: Optional[str] = None
    host_delete_id: Optional[str] = None
    host_list = False
    host_wipe = False
    host_show_secrets = False  # optional
    host_token_length: Optional[int] = None
    host_force = False  # host-only overwrite/rotate
    
    # gist commands
    gist_mode = False
    gist_show = False
    gist_wipe = False
    gist_set = False
    gist_show_secrets = False

    gist_id: Optional[str] = None
    gist_filename: Optional[str] = None
    gist_token: Optional[str] = None
    gist_token_stdin = False

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
        
        # enter host mode
        if tok in ("--host", "-host"):
            host_mode = True
            i += 1
            continue

        # host verbs
        if host_mode and tok in ("--token-create", "-token-create"):
            if i + 1 >= len(argv):
                print("ERROR: --token-create expects <host_id>", file=sys.stderr)
                return 2
            host_token_create_id = argv[i + 1].strip()
            i += 2
            continue
        
        if host_mode and tok in ("--length", "-length", "--token-length"):
            if i + 1 >= len(argv):
                print("ERROR: --length expects <int>", file=sys.stderr)
                return 2
            try:
                host_token_length = int(argv[i + 1].strip())
            except Exception:
                print("ERROR: --length expects an int", file=sys.stderr)
                return 2
            if host_token_length < 4 or host_token_length > 64:
                print("ERROR: --length out of range (4..64)", file=sys.stderr)
                return 2
            i += 2
            continue

        if host_mode and tok in ("--delete", "-delete", "--token-delete", "-token-delete"):
            if i + 1 >= len(argv):
                print("ERROR: --delete expects <host_id>", file=sys.stderr)
                return 2
            host_delete_id = argv[i + 1].strip()
            i += 2
            continue

        if host_mode and tok in ("--list", "-list", "--show", "-show"):
            host_list = True
            i += 1
            continue

        if host_mode and tok in ("--wipe", "-wipe", "-w"):
            host_wipe = True
            i += 1
            continue

        if host_mode and tok in ("--secrets", "-secrets"):
            host_show_secrets = True
            i += 1
            continue
        
        if host_mode and tok in ("--force", "-f", "--rotate"):
            host_force = True
            i += 1
            continue
        
        # enter gist mode
        if tok in ("--gist", "-gist"):
            gist_mode = True
            i += 1
            continue

        # gist verbs/options
        if gist_mode and tok in ("--show", "-show", "-s"):
            gist_show = True
            i += 1
            continue

        if gist_mode and tok in ("--wipe", "-wipe", "-w"):
            gist_wipe = True
            i += 1
            continue

        if gist_mode and tok in ("--set", "-set", "--config", "--configure"):
            gist_set = True
            i += 1
            continue

        if gist_mode and tok in ("--secrets", "-secrets"):
            gist_show_secrets = True
            i += 1
            continue

        if gist_mode and tok == "--id":
            if i + 1 >= len(argv):
                print("ERROR: --id expects <gist_id>", file=sys.stderr)
                return 2
            gist_id = argv[i + 1].strip()
            i += 2
            continue

        if gist_mode and tok in ("--file", "--filename"):
            if i + 1 >= len(argv):
                print("ERROR: --file expects <filename>", file=sys.stderr)
                return 2
            gist_filename = argv[i + 1].strip()
            i += 2
            continue

        # Not recommended (shell history), but provided anyway
        if gist_mode and tok == "--token":
            if i + 1 >= len(argv):
                print("ERROR: --token expects <token>", file=sys.stderr)
                return 2
            gist_token = argv[i + 1].strip()
            i += 2
            continue

        if gist_mode and tok == "--token-stdin":
            gist_token_stdin = True
            i += 1
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
                print(
                    "ERROR: missing device type after --device --add "
                    "(expected --pluto, --pluto-mimo, --rtl-sdr, "
                    "--ti-mmwave, --usrp-2901, "
                    "--usrp-b205-mini, --usrp-n210, or --usrp-profile)",
                    file=sys.stderr,
                )
                return 2
            dt = argv[i + 1].strip()
            if dt not in (
                "--pluto",
                "--pluto-mimo",
                "--rtl-sdr",
                "--ti-mmwave",
                "--usrp-2901",
                "--usrp2901",
                "--usrp",
                "--usrp-b205-mini",
                "--usrp-b205mini",
                "--b205mini",
                "--usrp-n210",
                "--usrp-profile",
            ):
                print(
                    "ERROR: device type must be --pluto, --pluto-mimo, "
                    "--rtl-sdr, --ti-mmwave, "
                    "--usrp-2901, --usrp-b205-mini, --usrp-n210, or "
                    "--usrp-profile",
                    file=sys.stderr,
                )
                return 2
            if i + 2 >= len(argv):
                print(f"ERROR: missing spec after --device --add {dt}", file=sys.stderr)
                return 2
            if dt in ("--usrp-2901", "--usrp2901", "--usrp"):
                device_add_type = "usrp2901"
            elif dt in ("--usrp-b205-mini", "--usrp-b205mini", "--b205mini"):
                device_add_type = "usrp-b205-mini"
            else:
                device_add_type = dt[2:]
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
    
    if host_mode and (device_mode or config_mode or show_certs or wipe_certs or (gen_ip is not None)):
        print("ERROR: --host cannot be combined with device/config/cert commands. Run them separately.", file=sys.stderr)
        return 2
    
    if host_force and host_token_create_id is None:
        print("ERROR: --force is only valid with --host --token-create <host_id>", file=sys.stderr)
        return 2
    
    if host_mode:
        actions = int(host_token_create_id is not None) + int(host_delete_id is not None) + int(host_list) + int(host_wipe)
        if actions == 0:
            print_help()
            return 2
        if actions > 1:
            print("ERROR: host commands are mutually exclusive. Use exactly one of: --token-create, --delete, --list, --wipe", file=sys.stderr)
            return 2

        if host_wipe and not yes:
            # mimic your other wipe confirmations
            try:
                if input("This will delete ALL host tokens. Type 'wipe' to confirm: ").strip().lower() != "wipe":
                    print("Wipe aborted.")
                    return 1
            except KeyboardInterrupt:
                print("\nCancelled.")
                return 1
            
    if gist_mode and (device_mode or config_mode or host_mode or show_certs or wipe_certs or (gen_ip is not None)):
        print("ERROR: --gist cannot be combined with device/config/host/cert commands. Run them separately.", file=sys.stderr)
        return 2
    
    # ----------------
    # Gist mode execution
    # ----------------
    if gist_mode:
        actions = int(gist_show) + int(gist_wipe) + int(gist_set)
        if actions == 0:
            print_help()
            return 2
        if actions > 1:
            print("ERROR: gist commands are mutually exclusive. Use exactly one of: --set, --show, --wipe", file=sys.stderr)
            return 2

        if gist_show:
            return int(_gist_show(show_secrets=gist_show_secrets))

        if gist_wipe:
            return int(_gist_wipe(yes=yes))

        # gist_set
        if gist_id is None or gist_filename is None:
            print("ERROR: --gist --set requires --id <gist_id> and --file <filename>", file=sys.stderr)
            return 2

        tok = gist_token or ""
        if gist_token_stdin:
            tok = sys.stdin.read().strip()
        if not tok:
            # secure prompt (no echo)
            tok = getpass.getpass("GitHub token (won't echo): ").strip()

        return int(_gist_set(gist_id=gist_id, filename=gist_filename, token=tok))
            
    # ----------------
    # Host mode execution
    # ----------------
    if host_mode:
        from .host.host_auth_token import create_host_token, delete_host_token, wipe_all_host_tokens, show_host_tokens

        # 1) list
        if host_list:
            show_host_tokens(include_secrets=host_show_secrets, file=sys.stdout)
            return 0

        # 2) delete
        if host_delete_id is not None:
            try:
                ok = delete_host_token(host_delete_id)
            except Exception as e:
                print(f"ERROR: {e}", file=sys.stderr)
                return 2

            if ok:
                print(f"Deleted host token: {host_delete_id}")
                return 0
            else:
                print(f"No host token found for: {host_delete_id}")
                return 1

        # 3) wipe all
        if host_wipe:
            try:
                n = wipe_all_host_tokens()
            except Exception as e:
                print(f"ERROR: {e}", file=sys.stderr)
                return 2
            print(f"Wiped {n} host token record(s).")
            return 0

        # 4) token create
        if host_token_create_id is None:
            print_help()
            return 2

        try:
            token_len = host_token_length if host_token_length is not None else 8
            token = create_host_token(host_token_create_id, length=token_len, overwrite=host_force)
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2

        print("Host token created and stored at ~/.config/remoterf/db/hosts_auth.env")
        print("First start the server with 'serverrf -s'.")
        print(f'Then, on the host you want to set up, run the following:\n  hostrf --config --host {host_token_create_id} "{token}"')
        return 0

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
        elif device_add_type == "pluto-mimo" and device_add_spec is not None:
            rc = _device_add_pluto_mimo(device_add_spec)
            if rc != 0:
                return rc
            did_any = True
        elif device_add_type == "rtl-sdr" and device_add_spec is not None:
            rc = _device_add_rtl_sdr(device_add_spec)
            if rc != 0:
                return rc
            did_any = True
        elif device_add_type == "ti-mmwave" and device_add_spec is not None:
            rc = _device_add_ti_mmwave(device_add_spec)
            if rc != 0:
                return rc
            did_any = True
        elif device_add_type == "usrp2901" and device_add_spec is not None:
            rc = _device_add_usrp(device_add_spec)
            if rc != 0:
                return rc
            did_any = True
        elif device_add_type == "usrp-b205-mini" and device_add_spec is not None:
            rc = _device_add_usrp_b205mini(device_add_spec)
            if rc != 0:
                return rc
            did_any = True
        elif device_add_type == "usrp-n210" and device_add_spec is not None:
            rc = _device_add_usrp_n210(device_add_spec)
            if rc != 0:
                return rc
            did_any = True
        elif device_add_type == "usrp-profile" and device_add_spec is not None:
            rc = _device_add_usrp_profile(device_add_spec)
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
