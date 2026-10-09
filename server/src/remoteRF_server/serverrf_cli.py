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

def _status_push_env_path() -> Path:
    return _cfg_dir() / "status_push.env"

def _tos_ack_path() -> Path:
    # Stored alongside server.env/devices.yml under ~/.config/remoterf by default
    return _cfg_dir() / "tos.env"


DEFAULT_GRPC_PORT = 61005
_TOS_VERSION = "2026"
_TOS_URL = "https://remoterf.net/tos"
BANNER_CREDIT = "Created by the Wireless Lab at UCLA"


def _tos_acknowledged() -> bool:
    kv = _read_env_kv(_tos_ack_path())
    accepted = kv.get("REMOTERF_TOS_ACKNOWLEDGED", "").strip().lower()
    version = kv.get("REMOTERF_TOS_VERSION", "").strip()
    return accepted in {"1", "true", "yes", "y"} and version == _TOS_VERSION


def _print_tos_acknowledgement() -> None:
    from remoteRF_server.common.utils.panel import marker, print_panel

    print()
    print_panel(
        "Terms of Service",
        [
            f"{marker()} RemoteRF 2026",
            "",
            "By continuing, you confirm that you have reviewed and agree",
            "to the RemoteRF Terms of Service and understand that use of",
            "the client and service is at your own risk. RemoteRF is not",
            "liable for losses or damages arising from use of the",
            "platform.",
            "",
            f"Terms of Service: {_TOS_URL}",
        ],
    )
    print()


def _ensure_tos_acknowledged() -> bool:
    if _tos_acknowledged():
        return True

    from remoteRF_server.common.utils.panel import confirm

    _print_tos_acknowledgement()
    # No default: accepting terms is never something a bare Enter should do.
    accepted = confirm("Do you agree to the RemoteRF Terms of Service?")
    if accepted is None:
        print("\n  Terms of Service acknowledgement is required before starting the server.")
        return False
    if not accepted:
        print("  Terms of Service not accepted. Server startup cancelled.")
        return False

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
    from remoteRF_server.common.utils.ansi_codes import Sty, printf

    printf(f"  Saved to {_tos_ack_path()}", Sty.GRAY)
    return True

# -----------------------------
# First-run setup
# -----------------------------

def _detect_lan_address() -> str:
    import socket

    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("192.0.2.1", 1))
            return probe.getsockname()[0]
        finally:
            probe.close()
    except OSError:
        return "127.0.0.1"


def _ensure_network_configured() -> bool:
    """Ask for the address and ports on first run, instead of failing later.

    Runs before the RemoteRF Global question so the address this deployment
    reports to Global is the one the operator actually chose.
    """
    from remoteRF_server.common.utils.panel import marker, print_panel

    kv = _read_env_kv(_server_env_path())
    if kv.get("GRPC_PORT") and kv.get("CERT_PORT"):
        return True

    detected = _detect_lan_address()
    print()
    print_panel(
        "Network setup",
        [f"{marker()} Where clients reach this server. Enter keeps the default."],
    )
    print()
    try:
        address = input(f"  Address on your network [{detected}]: ").strip() or detected
        grpc_raw = input(f"  gRPC port [{DEFAULT_GRPC_PORT}]: ").strip() or str(
            DEFAULT_GRPC_PORT
        )
        cert_raw = input(f"  Certificate port [{int(grpc_raw) + 1}]: ").strip() or str(
            int(grpc_raw) + 1
        )
    except (EOFError, KeyboardInterrupt, ValueError):
        print("\n  Setup cancelled.")
        return False

    try:
        grpc_port, cert_port = int(grpc_raw), int(cert_raw)
    except ValueError:
        print("  Ports must be whole numbers.")
        return False
    for port, name in ((grpc_port, "gRPC port"), (cert_port, "certificate port")):
        if _validate_port(port, name=name):
            print(f"  {name} is out of range.")
            return False
    if grpc_port == cert_port:
        print("  The two ports must differ.")
        return False

    kv.update(GRPC_PORT=str(grpc_port), CERT_PORT=str(cert_port), STATIC_IP=address)
    _write_env_kv(_server_env_path(), kv)
    from remoteRF_server.common.utils.ansi_codes import Sty, printf

    printf(f"  Saved to {_server_env_path()}", Sty.GRAY)
    return True


def _ensure_certificates() -> bool:
    """Issue the deployment's TLS material on first run.

    Deliberately after the RemoteRF Global question: if this deployment asked
    for a public name, that name belongs in the certificate from the start.
    Adding it later means reissuing the CA, which breaks every enrolled client.
    """
    from remoteRF_server.common.utils.ansi_codes import Sty, printf
    from remoteRF_server.common.utils.panel import marker, print_panel

    certs = _certs_dir()
    if (certs / "server.crt").exists() and (certs / "server.key").exists():
        return True

    kv = _read_env_kv(_server_env_path())
    address = (kv.get("STATIC_IP") or "").strip() or _detect_lan_address()
    names: List[str] = []
    try:
        from remoteRF_server.server.global_onboarding import hostname, participating

        if participating() and hostname():
            names.append(hostname())
    except Exception:  # noqa: BLE001 - certificates must not depend on Global
        pass

    print()
    print_panel(
        "Certificates",
        [f"{marker()} Issuing TLS for " + ", ".join([address, *names]) + "."],
    )
    print()
    result = _gen_certs(
        static_ip=address,
        days=365,
        ca_days=3650,
        bits=2048,
        dns=names,
        cn=None,
        force=False,
        no_detect_ip=True,
        quiet=True,
    )
    if result not in (None, 0):
        return False
    printf(f"  Saved to {certs}", Sty.GRAY)
    return True


def _ensure_certificate_names() -> None:
    """A Global hostname chosen after the certificates were issued goes into
    server.crt now, under the existing CA, so enrolled clients keep their trust."""
    from remoteRF_server.common.utils.ansi_codes import Sty, printf

    try:
        from remoteRF_server.server.global_onboarding import hostname, participating
        from remoteRF_server.tools.gen_certs import ensure_certificate_names

        name = hostname() if participating() else None
        if name and ensure_certificate_names(_certs_dir(), [name]):
            printf(f"  Server certificate now also covers {name} (CA unchanged).", Sty.GRAY)
    except Exception as exc:  # noqa: BLE001 - never block startup on this
        printf(f"  Could not add the Global hostname to the server certificate: {exc}", Sty.YELLOW)


# -----------------------------
# Help (exact commands only)
# -----------------------------

def print_help() -> None:
    from remoteRF_server.server.commands import cmd_help

    cmd_help([])


def _serve(*, headless: bool = False) -> int:
    """
    Alias for the RRRFserver entrypoint.
    Equivalent to running the RRRFserver console_script.
    """
    if not _ensure_tos_acknowledged():
        return 1

    # Network first: the address reported to RemoteRF Global has to be the one
    # the operator chose, not a guess made before they were asked.
    if not _ensure_network_configured():
        return 1

    from remoteRF_server.server.global_onboarding import ensure_consent, start_agent
    if not ensure_consent():
        return 1

    if not _ensure_certificates():
        return 1
    _ensure_certificate_names()
    start_agent()

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
    from remoteRF_server.common.utils.panel import marker, print_panel

    p = _gist_env_path()
    if not p.exists():
        print(f"No gist config found (missing {p}).")
        return 0

    kv = _read_env_kv(p)
    tok = kv.get("GITHUB_TOKEN", "")
    rows = [
        f"{marker()} {p}",
        "",
        f"gist id   {kv.get('STATUS_GIST_ID', '')}",
        f"filename  {kv.get('STATUS_GIST_FILENAME', '')}",
        f"token     {tok if show_secrets else _redact(tok) + '  (use --secrets to show)'}",
    ]
    print()
    print_panel("Gist status", rows, literal=True)
    print()
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


def _status_push_show() -> int:
    from remoteRF_server.common.utils.panel import marker, print_panel

    p = _status_push_env_path()
    if not p.exists():
        print(f"No status push config found (missing {p}).")
        return 0

    rows = [f"{marker()} {p}", ""] + [f"{k}={v}" for k, v in _read_env_kv(p).items()]
    print()
    print_panel("Status push", rows, literal=True)
    print()
    return 0


def _status_push_set(*, host: str, key: Optional[str], remote: Optional[str]) -> int:
    host = (host or "").strip()
    if not host:
        print("ERROR: missing --vps <host>", file=sys.stderr)
        return 2

    p = _status_push_env_path()
    kv = _read_env_kv(p)
    kv["STATUS_PUSH_HOST"] = host
    if key:
        kv["STATUS_PUSH_KEY"] = key
    if remote:
        kv["STATUS_PUSH_FILE"] = remote
    _write_env_kv(p, kv)

    print("Configured status push env:")
    print(f"  {p}")
    for k, v in kv.items():
        print(f"  {k}={v}")
    return 0


def _status_push_wipe(*, yes: bool) -> int:
    p = _status_push_env_path()
    if not p.exists():
        print(f"No status push config found at: {p}")
        return 0

    if not yes:
        try:
            if input("This will delete status_push.env (disables status push). Type 'wipe' to confirm: ").strip().lower() != "wipe":
                print("Wipe aborted.")
                return 1
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 1

    p.unlink()
    print("Wiped status push config (status_push.env).")
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
    from remoteRF_server.common.utils.panel import marker, print_panel

    d = _certs_dir()
    if not d.exists():
        print(f"Certs dir: {d}\n  (missing)")
        return 1

    files = sorted([p for p in d.iterdir() if p.is_file()])
    if not files:
        print(f"Certs dir: {d}\n  (empty)")
        return 1

    rows = [f"{marker()} {d}", ""]
    for p in files:
        try:
            size = p.stat().st_size
        except Exception:
            size = -1
        tag = ""
        if p.suffix in (".crt", ".pem") and _looks_like_pem_cert(p):
            tag = "  [cert]"
        elif p.suffix == ".key":
            tag = "  [key]"
        rows.append(f"{p.name} ({size} bytes){tag}")

    rc, _ = _run_capture(["openssl", "version"])
    if rc != 0:
        rows += ["", "(openssl not available; install it to view cert expiry)"]
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

        rows += ["", "Expiry:"]
        if not candidates:
            rows.append("  (no cert files found)")
        for p in candidates:
            na = _x509_notafter_utc(p)
            if not na:
                rows.append(f"  {p.name}: (could not read notAfter)")
                continue
            remaining = _fmt_remaining(na)
            local = na.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
            rows.append(f"  {p.name}: expires {local}  ({remaining})")
    print()
    print_panel("Certificates", rows, literal=True)
    print()

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
    quiet: bool = False,
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

    if quiet:
        from remoteRF_server.common.utils.ansi_codes import Sty, printf

        rc, output = _run_capture(cmd)
        for line in output.splitlines():
            printf("  " + line.rstrip() if line.strip() else "", Sty.GRAY)
        return rc

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
    from remoteRF_server.common.utils.panel import marker, print_panel

    p = _server_env_path()
    kv = _read_env_kv(p)
    rows = [f"{marker()} {p}" + ("" if p.exists() else "  (missing)"), ""]
    fields = []
    if "GRPC_PORT" in kv:
        fields.append(("main port", kv["GRPC_PORT"]))
    if "CERT_PORT" in kv:
        fields.append(("cert port", kv["CERT_PORT"]))
    static_ip, source, err = _resolve_static_ip(kv)
    if static_ip:
        fields.append(("static ip", static_ip))
        if source != f"{p} (STATIC_IP)":
            fields.append(("ip source", source))
    else:
        fields.append(("static ip", f"(not set) {err or f'could not resolve from {source}'}"))
    width = max(len(k) for k, _ in fields)
    rows += [f"{k:<{width}}  {v}" for k, v in fields]
    print()
    print_panel("Config", rows, literal=True)
    print()
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
# Clients read a label ending in " [word]" as a handle tag (Server 1.2.0 labels).
_HANDLE_LIKE_NAME = re.compile(r" \[\S+\]$")
_HANDLE_LIKE_NAME_MSG = "name must not end in ' [<word>]': clients read that as a handle tag"


def _name_problem(name: str, gid: Optional[int] = None) -> Optional[str]:
    """Why device `gid` (None: one not added yet) cannot be named `name`. A name is
    also the device's handle, so it must be addressable and unique, with spaces
    and '_' alike (device_name_key)."""
    from remoterf_federation_core import is_device_handle
    from remoteRF_server.common.utils import device_name_key

    if _HANDLE_LIKE_NAME.search(name):
        return _HANDLE_LIKE_NAME_MSG
    key = device_name_key(name)
    if not is_device_handle(key):
        return (f"name {name!r} cannot be typed as a handle: names can't contain '@', ':' or invisible "
                "characters, need a visible character, and can't start with 'rfg_' or 'bridge-'")
    try:
        recs = _read_device_records()
    except ValueError as exc:
        return str(exc)
    other = next((g for g, r in sorted(recs.items())
                  if g != gid and device_name_key(str(r.get("NAME") or "")) == key), None)
    if other is not None:
        return f"a device named {recs[other]['NAME']!r} already exists (#{other})"
    return None


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
    problem = _name_problem(name)
    if problem:
        raise ValueError(problem)
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
    problem = _name_problem(name)
    if problem:
        raise ValueError(problem)
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
    problem = _name_problem(name, gid)
    if problem:
        print(f"ERROR: {problem}", file=sys.stderr)
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
        entry: Dict[str, Any] = {
            "device_id": int(gid),
            "device_type": dtype,
            "name": str(fields.get("NAME") or f"device-{gid}"),
        }
        entry["init"] = init
        devices.append(entry)
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
    from remoteRF_server.common.utils.panel import print_table

    p = _devices_yaml_path()
    if not p.exists() and not _devices_env_path().exists():
        print(f"No devices configured (missing {p}).")
        return 0

    try:
        recs = _read_device_records()
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    from remoterf_federation_core import is_device_handle
    from remoteRF_server.common.utils import device_name_key

    seen: set = set()
    handles: Dict[int, str] = {}
    for gid, r in sorted(recs.items()):
        h = device_name_key(str(r.get("NAME") or ""))
        if is_device_handle(h):
            handles[gid] = h if h not in seen else f"{h} ignored (duplicate name)"
            seen.add(h)
    rows = [
        {"id": gid, "type": r.get("TYPE", ""), "name": r.get("NAME", ""),
         "handle": handles.get(gid, "-"),
         r.get("IDENT_KIND", "ident") or "ident": r.get("IDENT", "")}
        for gid, r in sorted(recs.items())
    ]
    columns = list(dict.fromkeys(k for row in rows for k in row))
    print_table("Devices", rows, columns, empty=f"(none) -- {p}")
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

# -----------------------------
# The command table (server/commands.py) calls these by name. Each works from
# a shell and from the console prompt; missing arguments are asked for.
# -----------------------------

def _flag(argv: List[str], name: str) -> Optional[str]:
    for i, tok in enumerate(argv):
        if tok == f"--{name}" and i + 1 < len(argv):
            return argv[i + 1]
        if tok.startswith(f"--{name}="):
            return tok.split("=", 1)[1]
    return None


def _flags(argv: List[str], name: str) -> List[str]:
    return [argv[i + 1] for i, tok in enumerate(argv) if tok == f"--{name}" and i + 1 < len(argv)]


def _positional(argv: List[str]) -> List[str]:
    out, skip = [], False
    for tok in argv:
        if skip:
            skip = False
            continue
        if tok.startswith("--") and "=" not in tok:
            skip = True
            continue
        if not tok.startswith("-"):
            out.append(tok)
    return out


def _yes(argv: List[str]) -> bool:
    return "-y" in argv or "--yes" in argv


def _ask(prompt: str, default: str = "") -> str:
    try:
        value = input(f"  {prompt}{f' [{default}]' if default else ''}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""
    return value or default


def _prompt_session():
    """A prompt for the interactive group/code editors: the console's own when
    inside the server, a fresh one from a shell."""
    from remoteRF_server.server import commands

    if commands._IN_DAEMON:
        from remoteRF_server.server.grpc_server import session

        return session
    from prompt_toolkit import PromptSession

    return PromptSession()


def _device_add_hackrf(spec: str) -> int:
    try:
        gid, name, serial = _parse_serial_add_spec(spec, serial_label="serial")
    except Exception as e:
        print(f"ERROR: invalid hackrf spec: {e}", file=sys.stderr)
        return 2
    recs = _read_device_records()
    if gid in recs:
        print(f"ERROR: global_id {gid} already exists", file=sys.stderr)
        return 2
    recs[gid] = {"TYPE": "hackrf", "NAME": name, "IDENT_KIND": "serial", "IDENT": serial}
    _write_device_records(recs)
    print(f"Added device: {gid} type=hackrf name={name} serial={serial}")
    return 0


_DEVICE_TYPES: Dict[str, Tuple[str, Any]] = {
    "pluto": ("iio serial", lambda spec: _device_add_pluto(spec)),
    "pluto-mimo": ("iio serial", lambda spec: _device_add_pluto_mimo(spec)),
    "rtl-sdr": ("serial (or index=N)", lambda spec: _device_add_rtl_sdr(spec)),
    "hackrf": ("serial", _device_add_hackrf),
    "ti-mmwave": ("CP2105 serial", lambda spec: _device_add_ti_mmwave(spec)),
    "usrp-2901": ("serial", lambda spec: _device_add_usrp(spec)),
    "usrp-b205-mini": ("serial", lambda spec: _device_add_usrp_b205mini(spec)),
    "usrp-n210": ("address", lambda spec: _device_add_usrp_n210(spec)),
    "usrp-profile": ("profile:selector", lambda spec: _device_add_usrp_profile(spec)),
}


def cmd_devices_list(argv: List[str]) -> int:
    from remoteRF_server.server import commands, control

    if commands._IN_DAEMON:
        from remoteRF_server.server.grpc_server import get_devices

        get_devices()
        return 0
    reply = control.call(["devices", "list"])
    if reply is not None:
        sys.stdout.write(reply[1])
        return reply[0]
    return _device_show()


def cmd_devices_add(argv: List[str]) -> int:
    pos = _positional(argv)
    dtype = (pos[0] if pos else _ask(f"Type ({', '.join(_DEVICE_TYPES)})")).lower()
    if dtype not in _DEVICE_TYPES:
        print(f"ERROR: unknown device type {dtype!r}; one of: {', '.join(_DEVICE_TYPES)}", file=sys.stderr)
        return 2
    label, add = _DEVICE_TYPES[dtype]
    name = pos[1] if len(pos) > 1 else _ask("Name")
    problem = _name_problem(name) if name else None
    if problem:
        print(f"ERROR: {problem}", file=sys.stderr)
        return 2
    ident = (
        _flag(argv, "serial") or _flag(argv, "addr")
        or (f"index={_flag(argv, 'index')}" if _flag(argv, "index") else None)
        or (f"{_flag(argv, 'profile')}:{_flag(argv, 'selector')}" if _flag(argv, "profile") else None)
        or (pos[2] if len(pos) > 2 else None)
        or _ask(label)
    )
    if not name or not ident:
        print("ERROR: a name and an identifier are required", file=sys.stderr)
        return 2
    gid = _flag(argv, "id")
    if gid is None:
        recs = _read_device_records()
        gid = str(max(recs) + 1 if recs else 0)
    return int(add(f"{gid}:{name}:{ident}"))


def cmd_devices_remove(argv: List[str]) -> int:
    pos = _positional(argv)
    return _device_remove(pos[0] if pos else _ask("Device id"))


def cmd_devices_rename(argv: List[str]) -> int:
    pos = _positional(argv)
    gid = pos[0] if pos else _ask("Device id")
    name = " ".join(pos[1:]) if len(pos) > 1 else _ask("New name")
    return _device_edit_name(gid, name)


def cmd_devices_wipe(argv: List[str]) -> int:
    return _wipe_devices_only(yes=_yes(argv))


def cmd_groups_list(argv):
    from remoteRF_server.server.user_group_cli import list_user_groups_local

    list_user_groups_local(_prompt_session())


def cmd_groups_create(argv):
    from remoteRF_server.server.user_group_cli import make_user_group_local

    make_user_group_local(_prompt_session())


def cmd_groups_edit(argv):
    from remoteRF_server.server.user_group_cli import edit_user_group_local

    edit_user_group_local(_prompt_session())


def cmd_groups_remove(argv):
    from remoteRF_server.server.user_group_cli import remove_user_group_local

    remove_user_group_local(_prompt_session())


def cmd_groups_csv(argv):
    from remoteRF_server.server.user_group_cli import export_user_groups_csv_local

    export_user_groups_csv_local()


def cmd_codes_list(argv):
    from remoteRF_server.server.user_group_cli import list_enrollment_codes_local

    list_enrollment_codes_local(_prompt_session())


def cmd_codes_create(argv):
    from remoteRF_server.server.user_group_cli import make_enrollment_codes_local

    make_enrollment_codes_local(_prompt_session())


def cmd_codes_remove(argv):
    from remoteRF_server.server.user_group_cli import remove_enrollment_code_local

    remove_enrollment_code_local(_prompt_session())


def cmd_codes_csv(argv):
    from remoteRF_server.server.user_group_cli import export_enrollment_codes_csv_local

    export_enrollment_codes_csv_local()


def cmd_hosts_token(argv: List[str]) -> int:
    from .host.host_auth_token import create_host_token

    pos = _positional(argv)
    host_id = pos[0] if pos else _ask("Host id")
    if not host_id:
        return 2
    length = int(_flag(argv, "length") or 8)
    try:
        token = create_host_token(host_id, length=length, overwrite="--force" in argv)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print("Host token created and stored at ~/.config/remoterf/db/hosts_auth.env")
    print(f'On the host, run:\n  hostrf --host --set {host_id} "{token}"')
    return 0


def cmd_hosts_tokens(argv: List[str]) -> int:
    from .host.host_auth_token import show_host_tokens, wipe_all_host_tokens

    if "wipe" in argv:
        if not _yes(argv) and _ask("This deletes ALL host tokens. Type 'wipe' to confirm") != "wipe":
            print("  Cancelled.")
            return 1
        print(f"Wiped {wipe_all_host_tokens()} host token record(s).")
        return 0
    show_host_tokens(include_secrets="--secrets" in argv, file=sys.stdout)
    return 0


def cmd_hosts_forget(argv: List[str]) -> int:
    from .host import host_tunnel_server as hts
    from .host.host_auth_token import _validate_host_id, delete_host_token

    pos = _positional(argv)
    try:
        host_id = _validate_host_id(pos[0] if pos else _ask("Host id"))
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    from .server import commands, control

    # A running server owns the directory files (they are not written atomically): let it do the forget.
    if not commands._IN_DAEMON:
        reply = control.call(["hosts", "forget", host_id])
        if reply is not None:
            sys.stdout.write(reply[1])
            return reply[0]
    # In the server process this is the live registry; from a shell, a copy loaded from the same files.
    live = hts.get_tunnel_registry(create=False)
    try:
        dids = (live or hts.HostTunnelRegistry()).forget_host(host_id)
    except RuntimeError:
        print(f"Host {host_id} is connected. Stop it first, then run: hosts forget {host_id}")
        return 1
    had_token = delete_host_token(host_id)
    if had_token:
        print(f"Deleted host token: {host_id}")
    if dids is None:
        if not had_token:
            print(f"No host token or directory entry found for: {host_id}")
            return 1
        return 0
    print(f"Removed host {host_id} and its devices from the directory: {', '.join(dids) or 'none'}")
    if live is not None:
        from .server import device_manager

        device_manager.forget_host_devices(dids)
    return 0


def cmd_certs_show(argv: List[str]) -> int:
    return _show_certs(verbose="-v" in argv or "--verbose" in argv)


def cmd_certs_reset(argv: List[str]) -> int:
    pos = _positional(argv)
    kv = _read_env_kv(_server_env_path())
    ip = pos[0] if pos else ((kv.get("STATIC_IP") or "").strip() or _detect_lan_address())
    if not _yes(argv):
        print("  This replaces the CA: every enrolled client must re-run `remoterf -c` afterwards.")
        if _ask("Type 'reset' to continue") != "reset":
            print("  Cancelled.")
            return 1
    return _gen_certs(
        static_ip=ip, days=int(_flag(argv, "days") or 365), ca_days=int(_flag(argv, "ca-days") or 3650),
        bits=2048, dns=_flags(argv, "dns"), cn=None, force=True, no_detect_ip=True,
    )


def cmd_config_show(argv: List[str]) -> int:
    return _config_show_ports()


def cmd_config_wipe(argv: List[str]) -> int:
    return _config_wipe_ports(yes=_yes(argv))


def cmd_db_export(argv: List[str]) -> int:
    """Archive the whole config root (databases, devices, keys, certs) into ~/Downloads."""
    import sqlite3
    import tarfile
    import tempfile

    root = _cfg_dir()
    pos = _positional(argv)
    out_dir = Path(pos[0]).expanduser() if pos else Path.home() / "Downloads"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    archive = out_dir / f"remoterf-export-{stamp}.tgz"
    with tempfile.TemporaryDirectory() as tmp, tarfile.open(archive, "w:gz") as tar:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix == ".sock" or path.name.endswith("-journal"):
                continue
            arcname = str(Path("remoterf") / path.relative_to(root))
            if path.suffix == ".db":
                # A consistent snapshot even while the server is writing.
                snapshot = Path(tmp) / path.name
                with sqlite3.connect(path) as src, sqlite3.connect(snapshot) as dst:
                    src.backup(dst)
                tar.add(snapshot, arcname=arcname)
            else:
                tar.add(path, arcname=arcname)
    os.chmod(archive, 0o600)
    print(f"Exported {root} -> {archive}")
    return 0


def cmd_wipe(argv: List[str]) -> int:
    """Factory reset: delete the config root, certs and the deployment identity."""
    from remoteRF_server.server import control, global_onboarding

    if control.running():
        print("ERROR: the server is running. Stop it first: serverrf stop", file=sys.stderr)
        return 1

    roots = list(dict.fromkeys((_cfg_dir(), _certs_dir(), global_onboarding.identity_dir())))
    targets = [p for p in roots if p.exists() and not any(p != q and p.is_relative_to(q) for q in roots)]
    if not targets:
        print("Nothing to wipe.")
        return 0

    print("This deletes all RemoteRF server config and data (devices, drivers, databases, certs, keys):")
    for p in targets:
        print(f"  {p}")
    if not _yes(argv):
        try:
            if input("Type 'wipe' to confirm: ").strip().lower() != "wipe":
                print("Wipe aborted.")
                return 1
        except KeyboardInterrupt:
            print("\nCancelled.")
            return 1

    # Release the Global name while the key that signs the request still exists.
    if global_onboarding.participating() and global_onboarding.state() not in ("unregistered", *global_onboarding.TERMINAL_STATES):
        global_onboarding.cmd_leave()

    for p in targets:
        shutil.rmtree(p)
    print("Wiped. The next `serverrf -s` runs first-time setup.")
    return 0


def cmd_certs_wipe(argv: List[str]) -> int:
    return _wipe_certs(yes=_yes(argv))


def cmd_config_ports(argv: List[str]) -> int:
    pos = _positional(argv)
    grpc = pos[0] if pos else _ask("gRPC port", str(DEFAULT_GRPC_PORT))
    cert = pos[1] if len(pos) > 1 else _ask("Certificate port", str(int(grpc) + 1))
    try:
        return _config_set_ports(main_port=int(grpc), cert_port=int(cert))
    except ValueError:
        print("ERROR: ports must be whole numbers", file=sys.stderr)
        return 2


def cmd_global(argv: List[str]) -> int:
    from remoteRF_server.server.global_onboarding import main as global_main

    rc = global_main(list(argv))
    if rc == 0:
        _ensure_certificate_names()
    return rc


def cmd_federation(argv: List[str]) -> int:
    from remoteRF_server.server.federation.cli import main as federation_main

    return federation_main(list(argv))


def cmd_gist_show(argv: List[str]) -> int:
    return _gist_show(show_secrets="--secrets" in argv)


def cmd_gist_set(argv: List[str]) -> int:
    import getpass

    pos = _positional(argv)
    gist_id = pos[0] if pos else _ask("Gist id")
    filename = pos[1] if len(pos) > 1 else _ask("File name")
    token = sys.stdin.readline().strip() if "--token-stdin" in argv else getpass.getpass("  GitHub token: ").strip()
    if not (gist_id and filename and token):
        print("ERROR: gist id, file name and token are required", file=sys.stderr)
        return 2
    return _gist_set(gist_id=gist_id, filename=filename, token=token)


def cmd_gist_wipe(argv: List[str]) -> int:
    return _gist_wipe(yes=_yes(argv))


def _status_or_usage() -> int:
    from remoteRF_server.server import control

    reply = control.call(["status"])
    if reply is None:
        print("The server is not running. Start it with: serverrf -s")
    else:
        sys.stdout.write(reply[1])
    print("Commands: serverrf help")
    return 0


def main() -> int:
    from remoteRF_server.common.utils.ansi_codes import Sty, printf

    argv = list(sys.argv[1:])

    if len(argv) == 0:
        return _status_or_usage()

    # help
    if argv[0] in ("--help", "-h", "-help", "--h"):
        print_help()
        return 0

    # IMPORTANT: ONLY "serverrf -s/--serve" (first arg) starts the server.
    if argv[0] in ("--serve", "-s"):
        from remoteRF_server.server import console

        flags = set(argv[1:])
        if not flags <= {"--headless", "--foreground", "--daemon"} or len(flags) > 1:
            print(
                "ERROR: -s/--serve accepts one of --headless, --foreground or --daemon.",
                file=sys.stderr,
            )
            return 2
        if "--headless" in flags:
            return _serve(headless=True)
        # The console: attach to the running server, or start one. Inside the
        # console this same command runs the server for real.
        if console.attached() or "--foreground" in flags or not console.available():
            if not console.available() and not console.attached():
                printf("tmux is not installed; running in the foreground (Ctrl-C stops the server).", Sty.GRAY)
            return _serve()
        if "--daemon" in flags:
            return 0 if console.start_detached(_cfg_dir(), ["--serve"]) else 1
        return console.attach_or_start(_cfg_dir(), ["--serve"])

    if not argv[0].startswith("-"):
        from remoteRF_server.server.commands import dispatch

        return dispatch(argv, in_daemon=False)

    printf("  (old flag form; `serverrf help` shows the current commands)", Sty.GRAY)
    return _legacy_main(argv)


def _legacy_main(argv: List[str]) -> int:
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

    # status-push commands
    push_mode = False
    push_show = False
    push_wipe = False
    push_set = False
    push_opts: Dict[str, str] = {}

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

        # enter status-push mode
        if tok in ("--status-push", "-status-push"):
            push_mode = True
            i += 1
            continue

        if push_mode and tok in ("--show", "-show", "-s"):
            push_show = True
            i += 1
            continue

        if push_mode and tok in ("--wipe", "-wipe", "-w"):
            push_wipe = True
            i += 1
            continue

        if push_mode and tok in ("--set", "-set"):
            push_set = True
            i += 1
            continue

        if push_mode and tok in ("--vps", "--key", "--file"):
            if i + 1 >= len(argv):
                print(f"ERROR: {tok} expects a value", file=sys.stderr)
                return 2
            push_opts[tok] = argv[i + 1].strip()
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
            
    if push_mode and (gist_mode or device_mode or config_mode or host_mode or show_certs or wipe_certs or (gen_ip is not None)):
        print("ERROR: --status-push cannot be combined with other commands. Run them separately.", file=sys.stderr)
        return 2

    if push_mode:
        if int(push_show) + int(push_wipe) + int(push_set) != 1:
            print("ERROR: use exactly one of: --status-push --set | --show | --wipe", file=sys.stderr)
            return 2
        if push_show:
            return int(_status_push_show())
        if push_wipe:
            return int(_status_push_wipe(yes=yes))
        return int(_status_push_set(host=push_opts.get("--vps", ""), key=push_opts.get("--key"), remote=push_opts.get("--file")))

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
        print(f'Then, on the host you want to set up, run the following:\n  hostrf --host --set {host_token_create_id} "{token}"')
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
