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

"""
Builds the route payload published to RemoteRF Global: the public relay
hostname/ports plus the active CA's SHA-256 fingerprint, computed from the
actual configured ca.crt rather than hardcoded anywhere. Never publishes an
internal (WireGuard/LAN) address — config.py's RouteConfig already rejects
those at load time.
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .config import RouteConfig


class RouteConsistencyError(RuntimeError):
    pass


def compute_ca_sha256(ca_crt_path: Path) -> str:
    data = Path(ca_crt_path).read_bytes()
    cert = x509.load_pem_x509_certificate(data)
    der = cert.public_bytes(encoding=serialization.Encoding.DER)
    import hashlib

    digest = hashlib.sha256(der).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2)).upper()


def _server_cert_dns_sans(server_crt_path: Path) -> list[str]:
    data = Path(server_crt_path).read_bytes()
    cert = x509.load_pem_x509_certificate(data)
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return list(ext.value.get_values_for_type(x509.DNSName))


def build_route_payload(route: RouteConfig, *, ca_crt_path: Path, server_crt_path: Path) -> dict:
    """
    Raises RouteConsistencyError if the configured tls_server_name isn't
    actually present as a DNS SAN on the active server certificate — a
    published route that a client's certificate validation would reject is
    worse than not publishing at all.
    """
    dns_sans = _server_cert_dns_sans(server_crt_path)
    if route.tls_server_name not in dns_sans:
        raise RouteConsistencyError(
            f"configured route.tls_server_name {route.tls_server_name!r} is not a DNS SAN "
            f"on {server_crt_path} (SANs present: {dns_sans!r}); regenerate the server "
            f"certificate with 'serverrf --gen-certs <ip> --dns {route.tls_server_name} --force' "
            "before publishing this route"
        )

    return {
        "kind": route.kind,
        "grpc_endpoint": route.grpc_endpoint,
        "certificate_endpoint": route.certificate_endpoint,
        "tls_server_name": route.tls_server_name,
        "ca_sha256": compute_ca_sha256(ca_crt_path),
    }
