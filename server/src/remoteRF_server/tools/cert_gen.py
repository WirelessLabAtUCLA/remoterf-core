#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path


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
    # ~/.config/remoterf (matches your cert_fetcher convention)
    return Path.home() / ".config" / "remoterf"


def _detect_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No packets need to actually leave; this forces route selection
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def main() -> None:
    _ensure_openssl()

    ap = argparse.ArgumentParser(
        prog="RRRFcerts",
        description="Generate a local CA and server TLS cert/key with proper SANs into ~/.config/remoterf/certs",
    )
    ap.add_argument("--config-dir", default=str(_default_config_dir()), help="Base config dir (default: ~/.config/remoterf)")
    ap.add_argument("--out-subdir", default="certs", help="Subdir under config-dir (default: certs)")
    ap.add_argument("--ip", action="append", default=[], help="IP to include in SAN (repeatable)")
    ap.add_argument("--dns", action="append", default=[], help="DNS name to include in SAN (repeatable)")
    ap.add_argument("--cn", default=None, help="Common Name (defaults to first SAN entry)")
    ap.add_argument("--days", type=int, default=365, help="Server cert validity in days")
    ap.add_argument("--ca-days", type=int, default=3650, help="CA cert validity in days")
    ap.add_argument("--bits", type=int, default=2048, help="RSA key size")
    ap.add_argument("--force", action="store_true", help="Overwrite existing certs/keys")
    ap.add_argument("--no-detect-ip", action="store_true", help="Do not auto-detect IP when none provided")
    args = ap.parse_args()

    base_dir = Path(args.config_dir).expanduser().resolve()
    out_dir = (base_dir / args.out_subdir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # If no SANs specified, auto-detect local IP unless disabled
    ips = [x.strip() for x in args.ip if x and x.strip()]
    dns = [x.strip() for x in args.dns if x and x.strip()]

    if not ips and not dns and not args.no_detect_ip:
        ips = [_detect_local_ip()]

    if not ips and not dns:
        raise SystemExit("Provide at least one --ip and/or --dns (or omit --no-detect-ip).")

    sans: list[str] = [f"IP:{ip}" for ip in ips] + [f"DNS:{d}" for d in dns]
    san_line = ",".join(sans)
    cn = args.cn or (dns[0] if dns else ips[0])

    # Filenames
    ca_key = out_dir / "ca.key"
    ca_crt = out_dir / "ca.crt"

    srv_key = out_dir / "server.key"
    srv_csr = out_dir / "server.csr"
    srv_crt = out_dir / "server.crt"

    targets = [ca_key, ca_crt, srv_key, srv_csr, srv_crt]

    if not args.force:
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

        # openssl may have left-over serial files from previous runs
        for extra in (out_dir / "ca.srl",):
            if extra.exists():
                extra.unlink()

    # 1) CA key + self-signed cert
    _run(["openssl", "genrsa", "-out", str(ca_key), str(args.bits)])
    _run([
        "openssl", "req", "-x509", "-new", "-nodes",
        "-key", str(ca_key),
        "-sha256",
        "-days", str(args.ca_days),
        "-subj", "/CN=remoteRF Local CA",
        "-out", str(ca_crt),
    ])

    # 2) Server key
    _run(["openssl", "genrsa", "-out", str(srv_key), str(args.bits)])

    # 3) CSR with SANs, then sign with CA including v3 extensions
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)

        csr_cnf = td_path / "csr.cnf"
        csr_cnf.write_text(
            f"""\
[ req ]
default_bits       = {args.bits}
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
            "-days", str(args.days),
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

if __name__ == "__main__":
    main()
