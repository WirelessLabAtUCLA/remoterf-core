from __future__ import annotations

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
    return Path.home() / ".config" / "remoterf"


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
