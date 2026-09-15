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

import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import time
from datetime import datetime, timezone

def _x509_dates(cert_path: Path) -> tuple[datetime | None, datetime | None]:
    # openssl prints:
    #   notBefore=Feb 16 23:12:02 2026 GMT
    #   notAfter=Feb 16 23:12:02 2027 GMT
    p = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-startdate", "-enddate"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if p.returncode != 0:
        return None, None

    nb = na = None
    for line in p.stdout.splitlines():
        line = line.strip()
        if line.startswith("notBefore="):
            s = line.split("=", 1)[1].strip()
            s = s.removesuffix(" GMT").strip()
            try:
                nb = datetime.strptime(s, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
            except Exception:
                nb = None
        elif line.startswith("notAfter="):
            s = line.split("=", 1)[1].strip()
            s = s.removesuffix(" GMT").strip()
            try:
                na = datetime.strptime(s, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
            except Exception:
                na = None

    return nb, na


def _run(cmd: list[str]) -> None:
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"\nCommand failed:\n  {' '.join(cmd)}\n", file=sys.stderr)
        raise SystemExit(e.returncode)


def _ensure_openssl() -> None:
    if shutil.which("openssl") is None:
        raise SystemExit("openssl not found on PATH. Install OpenSSL and try again.")


def _default_config_dir() -> Path:
    return Path.home() / ".config" / "remoterf"


def _global_hostname() -> str | None:
    """The deployment's public relay hostname, once Global has approved it."""
    try:
        from remoteRF_server.server.global_onboarding import hostname, participating

        # As soon as a name has been chosen, not only once approved: adding it
        # later would mean reissuing the CA and re-enrolling every client.
        return hostname() if participating() else None
    except Exception:
        return None


def _detect_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def generate_certs(
    *,
    static_ip: str | None,
    days: int = 365,
    ca_days: int = 3650,
    bits: int = 2048,
    config_dir: Path | None = None,
    out_subdir: str = "certs",
    dns: list[str] | None = None,
    cn: str | None = None,
    force: bool = False,
) -> None:
    _ensure_openssl()

    base_dir = (config_dir or _default_config_dir()).expanduser().resolve()
    out_dir = (base_dir / out_subdir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    ips: list[str] = []
    if static_ip and static_ip.strip():
        ips.append(static_ip.strip())
    else:
        ips.append(_detect_local_ip())

    dns = [d.strip() for d in (dns or []) if d and d.strip()]
    # An approved RemoteRF Global deployment is also reached at its public
    # relay hostname, and TLS stays end-to-end through that relay — so the
    # name has to be in this certificate or clients cannot verify it.
    global_name = _global_hostname()
    if global_name and global_name not in dns:
        dns.append(global_name)
    sans: list[str] = [f"IP:{ip}" for ip in ips] + [f"DNS:{d}" for d in dns]
    san_line = ",".join(sans)
    cn = cn or (dns[0] if dns else ips[0])

    ca_key = out_dir / "ca.key"
    ca_crt = out_dir / "ca.crt"
    srv_key = out_dir / "server.key"
    srv_csr = out_dir / "server.csr"
    srv_crt = out_dir / "server.crt"

    targets = [ca_key, ca_crt, srv_key, srv_csr, srv_crt]

    if not force:
        existing = [p for p in targets if p.exists()]
        if existing:
            raise SystemExit(
                "Refusing to overwrite existing files:\n  "
                + "\n  ".join(str(p) for p in existing)
                + "\nRe-run with --force to replace them."
            )
    else:
        for p in targets:
            if p.exists():
                p.unlink()
        extra = out_dir / "ca.srl"
        if extra.exists():
            extra.unlink()

    _run(["openssl", "genrsa", "-out", str(ca_key), str(bits)])
    _run([
        "openssl", "req", "-x509", "-new", "-nodes",
        "-key", str(ca_key),
        "-sha256",
        "-days", str(ca_days),
        "-subj", "/CN=remoteRF Local CA",
        "-out", str(ca_crt),
    ])

    _run(["openssl", "genrsa", "-out", str(srv_key), str(bits)])

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)

        csr_cnf = td_path / "csr.cnf"
        csr_cnf.write_text(
            f"""\
[ req ]
default_bits       = {bits}
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
CN = {cn}

[ req_ext ]
subjectAltName = {san_line}
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
""",
            encoding="utf-8",
        )

        _run([
            "openssl", "req", "-new",
            "-key", str(srv_key),
            "-out", str(srv_csr),
            "-config", str(csr_cnf),
        ])

        sign_cnf = td_path / "sign.cnf"
        sign_cnf.write_text(
            f"""\
[ v3_req ]
basicConstraints = CA:FALSE
subjectAltName = {san_line}
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
""",
            encoding="utf-8",
        )

        _run([
            "openssl", "x509", "-req",
            "-in", str(srv_csr),
            "-CA", str(ca_crt),
            "-CAkey", str(ca_key),
            "-CAcreateserial",
            "-out", str(srv_crt),
            "-days", str(days),
            "-sha256",
            "-extfile", str(sign_cnf),
            "-extensions", "v3_req",
        ])

    print("\nGenerated certs/keys:")
    print(f"  Output dir: {out_dir}")
    print(f"  CA cert:    {ca_crt}")
    print(f"  Server cert:{srv_crt}")
    print(f"  Server key: {srv_key}")
    print("\nSANs:")
    for s in sans:
        print(f"  - {s}")
    print("\nClient trust:")
    print("  Clients should trust ca.crt (NOT server.crt).")
    print("  Clients must dial an address that matches one of the SANs.\n")
    
    ca_nb, ca_na = _x509_dates(ca_crt)
    srv_nb, srv_na = _x509_dates(srv_crt)

    if srv_nb and srv_na:
        now = datetime.now(timezone.utc)
        remaining = srv_na - now
        # clamp negative (if clock skew or already expired)
        if remaining.total_seconds() < 0:
            rem_str = "EXPIRED"
        else:
            days_left = remaining.days
            hours_left = (remaining.seconds // 3600)
            mins_left = (remaining.seconds % 3600) // 60
            rem_str = f"{days_left}d {hours_left}h {mins_left}m"

        print("  Server:")
        print(f"    notBefore (UTC): {srv_nb.isoformat(timespec='seconds')}")
        print(f"    notAfter  (UTC): {srv_na.isoformat(timespec='seconds')}")
        print(f"    expires (local): {srv_na.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}")
        print(f"    expires in:      {rem_str}")
    else:
        print("  Server: (failed to parse dates)")



import argparse

def main() -> int:
    ap = argparse.ArgumentParser(prog="gen_certs.py", description="Generate RemoteRF TLS certs")
    ap.add_argument("--ip", dest="static_ip", default=None, help="Static IP to include in SAN (if omitted, auto-detect unless --no-detect-ip)")
    ap.add_argument("--no-detect-ip", action="store_true", help="Require --ip; do not auto-detect")

    ap.add_argument("--days", type=int, default=365)
    ap.add_argument("--ca-days", type=int, default=3650)
    ap.add_argument("--bits", type=int, default=2048)

    ap.add_argument("--config-dir", default=None, help="Base config dir (default: ~/.config/remoterf)")
    ap.add_argument("--out-subdir", default="certs", help="Subdir under config dir (default: certs)")

    ap.add_argument("--dns", action="append", default=[], help="DNS SAN entry (repeatable)")
    ap.add_argument("--cn", default=None, help="Common Name (default: first SAN entry)")
    ap.add_argument("--force", action="store_true", help="Overwrite existing certs/keys")

    args = ap.parse_args()

    if args.no_detect_ip and not (args.static_ip and args.static_ip.strip()):
        print("ERROR: --no-detect-ip set but no --ip provided", file=sys.stderr)
        return 2

    cfg = Path(args.config_dir).expanduser().resolve() if args.config_dir else None

    generate_certs(
        static_ip=args.static_ip,
        days=args.days,
        ca_days=args.ca_days,
        bits=args.bits,
        config_dir=cfg,
        out_subdir=args.out_subdir,
        dns=args.dns,
        cn=args.cn,
        force=args.force,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
