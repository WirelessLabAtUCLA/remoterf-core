# cert_fetcher.py

from __future__ import annotations

import hashlib
import os
import socket
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
    overwrite: bool = True,
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
        overwrite: overwrite existing cert file if present

    Returns:
        True on success, False on any failure.
    """
    try:
        bootstrap_port = int(bootstrap_port)

        env_dir_p = Path(env_dir).expanduser().resolve()
        env_path = env_dir_p / env_filename
        cert_path = env_dir_p / cert_filename

        _ensure_parent_dir(cert_path)

        if cert_path.exists() and not overwrite:
            # Still ensure .env has correct pointer
            lines = _read_env_lines(env_path)
            lines = _upsert_env_key(lines, "REMOTERF_CA_CERT", f"./{cert_filename}")
            if grpc_addr:
                lines = _upsert_env_key(lines, "REMOTERF_ADDR", grpc_addr)
            _write_env_lines(env_path, lines)
            return True

        # Fetch (HTTP first, then raw TCP fallback)
        try:
            data = _fetch_http(host, bootstrap_port, timeout_sec)
        except Exception:
            data = _fetch_raw_tcp(host, bootstrap_port, timeout_sec)

        if not data or not _looks_like_pem_cert(data):
            return False

        # Save cert next to .env
        cert_path.write_bytes(data)

        # Update the .env in the same directory
        lines = _read_env_lines(env_path)
        lines = _upsert_env_key(lines, "REMOTERF_CA_CERT", f"./{cert_filename}")
        if grpc_addr:
            lines = _upsert_env_key(lines, "REMOTERF_ADDR", grpc_addr)
        _write_env_lines(env_path, lines)

        return True

    except Exception:
        return False
