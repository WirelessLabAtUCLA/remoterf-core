#!/usr/bin/env python3
# src/remoteRF_server/serverrf_cli.py

from __future__ import annotations

import sys
import subprocess
import shutil
import os
from pathlib import Path
from typing import Optional, List, Tuple


# -----------------------------
# Repo-local server config locations
# -----------------------------

def _repo_root() -> Path:
    # <repo>/src/remoteRF_server/serverrf_cli.py -> parents[2] == <repo>
    return Path(__file__).resolve().parents[2]

def _cfg_dir() -> Path:
    # <repo>/.config/
    return _repo_root() / ".config"

def _certs_dir() -> Path:
    # <repo>/.config/certs/
    return _cfg_dir() / "certs"


def _gen_certs_path() -> Path:
    """
    Prefer repo-local tools next to this module, but allow repo-root /tools as fallback.
      - <repo>/src/remoteRF_server/tools/gen_certs.py
      - <repo>/tools/gen_certs.py
    """
    here = Path(__file__).resolve().parent
    p1 = (here / "tools" / "gen_certs.py").resolve()
    if p1.exists():
        return p1
    p2 = (_repo_root() / "tools" / "gen_certs.py").resolve()
    return p2


# -----------------------------
# Help (exact commands only)
# -----------------------------

def print_help() -> None:
    print(
        "RemoteRF Server CLI Help\n"
        "\n"
        "Usage:\n"
        "  serverrf -h | --help                       Show this help\n"
        "\n"
        "  serverrf --gen-certs <static_ip> [options] Generate TLS certs (repo-local)\n"
        "  serverrf --show-certs [-v]                 Show generated certs/keys\n"
        "  serverrf --wipe-certs [-y]                 Wipe ONLY cert output dir\n"
        "\n"
        "Notes:\n"
        f"  Cert output directory:\n"
        f"    {_certs_dir()}\n"
        "\n"
        "Options (for --gen-certs):\n"
        "  --days <int>        Server cert validity in days (default: 365)\n"
        "  --ca-days <int>     CA cert validity in days (default: 3650)\n"
        "  --bits <int>        RSA key size (default: 2048)\n"
        "  --dns <name>        DNS SAN entry (repeatable)\n"
        "  --cn <name>         Common Name (defaults to first SAN entry)\n"
        "  --force             Overwrite existing certs/keys\n"
        "  --no-detect-ip      Do not auto-detect IP when none provided\n"
        "\n"
        "Global options:\n"
        "  -y, --yes           Skip wipe confirmation prompts\n"
        "  -v, --verbose       With --show-certs, also print x509 details (requires openssl)\n"
        "\n"
        "Examples:\n"
        "  serverrf --gen-certs 192.168.1.24\n"
        "  serverrf --gen-certs 192.168.1.24 --dns rrf2 --dns rrf2.local --force\n"
        "  serverrf --show-certs\n"
        "  serverrf --show-certs -v\n"
        "  serverrf --wipe-certs -y\n"
        "\n"
    )


# -----------------------------
# Tiny subprocess utils
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
# Show / wipe actions
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

    if not verbose:
        return 0

    rc, _ = _run_capture(["openssl", "version"])
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
        rc, out = _run_capture(["openssl", "x509", "-in", str(p), "-noout", "-subject", "-issuer", "-dates"])
        if rc == 0 and out.strip():
            print(out.rstrip())
        else:
            print("  (failed to parse with openssl)")

        rc, out = _run_capture(["openssl", "x509", "-in", str(p), "-noout", "-ext", "subjectAltName"])
        if rc == 0 and out.strip():
            print(out.rstrip())

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


# -----------------------------
# Gen-certs action
# -----------------------------

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
    return rc


# -----------------------------
# CLI parser (ONLY commands in help)
# -----------------------------

def main() -> int:
    argv = list(sys.argv[1:])

    if len(argv) == 0 or argv[0] in ("--help", "-h", "-help", "--h"):
        print_help()
        return 0

    yes = False
    verbose = False

    # command-ish flags
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

    # ---- conflict checks ----
    if wipe_certs and show_certs:
        print("ERROR: cannot combine --show-certs with --wipe-certs", file=sys.stderr)
        return 2

    # ---- wipe ----
    if wipe_certs:
        return int(_wipe_certs(yes=yes))

    # ---- show ----
    if show_certs and gen_ip is None:
        return int(_show_certs(verbose=verbose))

    # ---- gen ----
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
