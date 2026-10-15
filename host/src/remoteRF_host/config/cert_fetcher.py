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

# cert_fetcher.py

from __future__ import annotations

import hashlib
import os
import re
import socket
import sys
import urllib.request
from pathlib import Path
from typing import Optional, Tuple, List


CERT_FILENAME_DEFAULT = "ca.crt"


def _ensure_parent_dir(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)


def _looks_like_pem_cert(data: bytes) -> bool:
    return b"BEGIN CERTIFICATE" in data and b"END CERTIFICATE" in data


def sha256_fingerprint_pem(pem_bytes: bytes) -> str:
    h = hashlib.sha256(pem_bytes).hexdigest()
    return ":".join(h[i:i+2] for i in range(0, len(h), 2))


def normalize_sha256(value: str) -> str:
    """'sha256:AB:CD..' / 'abcd..' -> 'abcd..'; '' when it is not a sha256."""
    v = (value or "").strip().lower()
    if v.startswith("sha256:"):
        v = v[len("sha256:"):]
    v = v.replace(":", "")
    return v if re.fullmatch(r"[0-9a-f]{64}", v) else ""


def pin_ca(env_path: Path, digest: str) -> None:
    _write_env_lines(env_path, _upsert_env_key(_read_env_lines(env_path), "REMOTERF_CA_SHA256", digest))


def _fetch_http(host: str, port: int, timeout_sec: float) -> bytes:
    url = f"http://{host}:{port}/ca.crt"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
        return resp.read()


def _fetch_raw_tcp(host: str, port: int, timeout_sec: float) -> bytes:
    chunks: list[bytes] = []
    with socket.create_connection((host, port), timeout=timeout_sec) as s:
        s.settimeout(timeout_sec)
        while True:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
    return b"".join(chunks)


def _read_env_lines(env_path: Path) -> List[str]:
    if not env_path.exists():
        return []
    return env_path.read_text(encoding="utf-8").splitlines()


def _upsert_env_key(lines: List[str], key: str, value: str) -> List[str]:
    """
    Replace KEY=... if present, else append KEY=value.
    Preserves comments/blank lines and unknown keys.
    """
    out: List[str] = []
    found = False
    prefix = f"{key}="
    for ln in lines:
        if ln.strip().startswith(prefix):
            out.append(f"{key}={value}")
            found = True
        else:
            out.append(ln)
    if not found:
        if out and out[-1].strip() != "":
            out.append("")  # spacer
        out.append(f"{key}={value}")
    return out


def _write_env_lines(env_path: Path, lines: List[str]) -> None:
    _ensure_parent_dir(env_path)
    env_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def fetch_and_save_ca_cert(
    host: str,
    bootstrap_port: int,
    *,
    # NEW: point at the directory that contains the .env you want to update
    env_dir: str | Path = ".",
    env_filename: str = ".env",

    # cert filename written into env_dir
    cert_filename: str = CERT_FILENAME_DEFAULT,

    # OPTIONAL: if you want to also write REMOTERF_ADDR for the TLS gRPC port
    grpc_addr: Optional[str] = None,  # e.g. "your.server.edu:61007"

    timeout_sec: float = 3.0,
    expected_sha256: Optional[str] = None,
) -> bool:
    """
    Fetch CA cert from server bootstrap endpoint and save it into `env_dir`,
    then upsert REMOTERF_CA_CERT into env_dir/.env (and optionally REMOTERF_ADDR).

    Writes:
      REMOTERF_CA_CERT=./ca.crt   (relative path, portable)
      REMOTERF_ADDR=host:port    (if grpc_addr provided)

    Args:
        host: server host/ip running cert_provider
        bootstrap_port: cert_provider port (NOT the TLS gRPC port)
        env_dir: directory containing the .env file to update (and where cert is written)
        env_filename: name of the env file (default ".env")
        cert_filename: filename for the cert saved in env_dir (default "ca.crt")
        grpc_addr: optional value for REMOTERF_ADDR
        timeout_sec: network timeout
        expected_sha256: the lab's CA fingerprint; without it the CA pinned
            by an earlier fetch (REMOTERF_CA_SHA256) must still match.

    Returns:
        True on success, False on any failure.
    """
    try:
        bootstrap_port = int(bootstrap_port)

        env_dir_p = Path(env_dir).expanduser().resolve()
        env_path = env_dir_p / env_filename
        cert_path = env_dir_p / cert_filename

        _ensure_parent_dir(cert_path)

        if expected_sha256 is not None and not normalize_sha256(expected_sha256):
            print(f"Not a sha256 fingerprint: {expected_sha256!r}", file=sys.stderr)
            return False

        # Fetch (HTTP first, then raw TCP fallback)
        try:
            data = _fetch_http(host, bootstrap_port, timeout_sec)
        except Exception:
            data = _fetch_raw_tcp(host, bootstrap_port, timeout_sec)

        if not data or not _looks_like_pem_cert(data):
            return False

        # The fetch is plain HTTP: trust only a fingerprint from the lab admin,
        # or the one pinned on first use.
        lines = _read_env_lines(env_path)
        digest = hashlib.sha256(data).hexdigest()
        pinned = next((ln.split("=", 1)[1].strip() for ln in lines if ln.strip().startswith("REMOTERF_CA_SHA256=")), "")
        want = normalize_sha256(expected_sha256 if expected_sha256 is not None else pinned)
        if want and digest != want:
            print(
                f"CA fingerprint mismatch: got {digest}, expected {want}. "
                "If the lab changed its CA, pass the new one with --ca-sha256 (from `hosts token`).",
                file=sys.stderr,
            )
            return False

        # Save cert next to .env
        cert_path.write_bytes(data)

        # Update the .env in the same directory
        lines = _upsert_env_key(lines, "REMOTERF_CA_SHA256", digest)
        lines = _upsert_env_key(lines, "REMOTERF_CA_CERT", f"./{cert_filename}")
        if grpc_addr:
            lines = _upsert_env_key(lines, "REMOTERF_ADDR", grpc_addr)
        _write_env_lines(env_path, lines)

        return True

    except Exception:
        return False
