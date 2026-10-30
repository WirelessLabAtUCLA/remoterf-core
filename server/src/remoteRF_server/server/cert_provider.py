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

# cert_provider.py

from __future__ import annotations

import argparse
import hashlib
import socketserver
import threading
import os
from pathlib import Path
from typing import Optional, Tuple

CERT_NAME = "ca.crt"

def resolve_ca_path(ca_path: Optional[str | Path] = None) -> Path:
    """
    Resolve the CA certificate path.

    Priority:
      1) explicit ca_path
      2) $REMOTERF_CERT_DIR/ca.crt
      3) $XDG_CONFIG_HOME/remoterf/certs/ca.crt (or ~/.config/...)
      4) fallback to repo-relative candidates (for dev)
    """
    if ca_path is not None:
        p = Path(ca_path).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"CA cert not found at: {p}")
        return p

    # --- preferred: user config location ---
    xdg_config = Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config"))
    cert_dir = Path(os.getenv("REMOTERF_CERT_DIR", xdg_config / "remoterf" / "certs"))
    p = (cert_dir / CERT_NAME).expanduser().resolve()
    if p.exists():
        return p

    # --- fallback: repo-relative for local dev ---
    here = Path(__file__).resolve()
    candidates = [
        here.parent / "certs" / CERT_NAME,
        here.parent.parent / "core" / "certs" / CERT_NAME,
        here.parent.parent / "certs" / CERT_NAME,
    ]
    for c in candidates:
        if c.exists():
            return c

    raise FileNotFoundError(
        f"Could not find {CERT_NAME}. Tried:\n  "
        + "\n  ".join([str(p)] + [str(c) for c in candidates])
    )

def load_ca_pem(ca_path: Optional[str | Path] = None) -> bytes:
    p = resolve_ca_path(ca_path)
    data = p.read_bytes()
    if b"BEGIN CERTIFICATE" not in data:
        raise ValueError(f"{p} does not look like a PEM certificate.")
    return data

def sha256_fingerprint_pem(pem_bytes: bytes) -> str:
    h = hashlib.sha256(pem_bytes).hexdigest()
    return ":".join(h[i:i+2] for i in range(0, len(h), 2))

# Server implementation

class _CertProviderHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            self.request.settimeout(1.0)
            first = b""
            try:
                first = self.request.recv(4096)
            except Exception:
                first = b""

            pem = self.server.ca_pem  # type: ignore[attr-defined]

            if first.startswith(b"GET "):
                self._handle_http(first, pem)
            else:
                self._handle_raw(pem)
        except Exception:
            return

    def _handle_raw(self, pem: bytes) -> None:
        self.request.sendall(pem)

    def _handle_http(self, first: bytes, pem: bytes) -> None:
        # Drain headers best-effort
        try:
            self.request.settimeout(0.2)
            while b"\r\n\r\n" not in first and len(first) < 65536:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                first += chunk
        except Exception:
            pass

        # Parse request line
        try:
            line = first.split(b"\r\n", 1)[0].decode("utf-8", "replace")
        except Exception:
            line = "GET / HTTP/1.1"

        parts = line.split()
        path = parts[1] if len(parts) >= 2 else "/"

        if path not in ("/", f"/{CERT_NAME}", "/ca.pem", "/ca.crt"):
            body = b"Not Found\n"
            resp = (
                b"HTTP/1.1 404 Not Found\r\n"
                b"Content-Type: text/plain\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"\r\n"
                + body
            )
            self.request.sendall(resp)
            return

        body = pem
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/x-pem-file\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Cache-Control: no-store\r\n"
            + b"\r\n"
            + body
        )
        self.request.sendall(resp)


class _ThreadingCertServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address: Tuple[str, int], ca_pem: bytes):
        super().__init__(server_address, _CertProviderHandler)
        self.ca_pem = ca_pem


def start_cert_provider(
    *,
    host: str,
    port: int,
    ca_path: Optional[str | Path] = None,
    daemon: bool = True,
) -> Tuple[_ThreadingCertServer, threading.Thread]:
    ca_pem = load_ca_pem(ca_path)
    server = _ThreadingCertServer((host, port), ca_pem=ca_pem)

    t = threading.Thread(target=server.serve_forever, daemon=daemon)
    t.start()
    return server, t

def stop_cert_provider(server: _ThreadingCertServer) -> None:
    server.shutdown()
    server.server_close()

# Optional standalone mode 

def main() -> None:
    parser = argparse.ArgumentParser(description="RemoteRF CA certificate bootstrap provider.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--ca", type=str, default=None, help="Path to ca.crt (PEM).")
    args = parser.parse_args()

    ca_pem = load_ca_pem(args.ca)
    fp = sha256_fingerprint_pem(ca_pem)
    print(f"[cert_provider] Listening on {args.host}:{args.port}")
    print(f"[cert_provider] CA SHA256 fingerprint: {fp}")
    print(f"[cert_provider] CA path: {resolve_ca_path(args.ca)}")

    server = _ThreadingCertServer((args.host, args.port), ca_pem=ca_pem)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_cert_provider(server)

if __name__ == "__main__":
    main()
