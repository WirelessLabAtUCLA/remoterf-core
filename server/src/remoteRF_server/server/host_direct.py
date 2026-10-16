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

"""Direct-path signaling for devices served by a Host tunnel."""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ..host import host_tunnel_server as hts
from . import global_onboarding
from .federation.identity import load_private_key, load_state, public_key_pem

logger = logging.getLogger(__name__)
_REFRESH_SECONDS = 240
_refreshers: dict[tuple[str, int], tuple[object, object, threading.Timer]] = {}
_refresh_lock = threading.Lock()


def _cert_dir() -> Path:
    return Path(os.getenv("REMOTERF_CERT_DIR", global_onboarding.cfg_dir() / "certs"))


def _identity():
    state_dir = global_onboarding.identity_dir()
    state = load_state(state_dir)
    if not state.enrolled or not state.deployment_id or not state.slug:
        raise RuntimeError("deployment is not enrolled on RemoteRF Global")
    return state_dir, state


def _certificate(server_name: str, tls_public_key: str) -> str:
    cert_dir = _cert_dir()
    ca_cert = x509.load_pem_x509_certificate((cert_dir / "ca.crt").read_bytes())
    ca_key = serialization.load_pem_private_key((cert_dir / "ca.key").read_bytes(), password=None)
    if ca_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    ) != ca_cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    ):
        raise ValueError("CA certificate and key do not match")
    host_key = serialization.load_pem_public_key(tls_public_key.encode("utf-8"))
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(host_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(server_name)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    algorithm = None if isinstance(ca_key, Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(ca_key, algorithm).public_bytes(serialization.Encoding.PEM).decode("utf-8")


def lab_info(host_id: str, tls_public_key: str) -> dict | None:
    """Build the host's direct-path trust bundle, or skip unavailable setup."""
    try:
        state_dir, state = _identity()
        load_private_key(state_dir)
        server_name = f"{host_id}--{state.slug}.global.remoterf.net"
        return {
            "deployment_id": state.deployment_id,
            "grant_key": public_key_pem(state_dir),
            "server_name": server_name,
            "cert_pem": _certificate(server_name, tls_public_key),
            "ca_pem": (_cert_dir() / "ca.crt").read_text(encoding="utf-8"),
        }
    except Exception as exc:  # optional capability: normal labs continue without it
        logger.warning("host direct path unavailable for %s: %s", host_id, exc)
        return None


def issue_grant(host_id: str, gid: int, exp: float) -> str:
    state_dir, state = _identity()
    now = time.time()
    claims = {
        "iss": state.deployment_id,
        "aud": str(host_id),
        "gid": int(gid),
        "jti": uuid4().hex,
        "iat": now,
        "exp": int(min(float(exp), now + 600)),
    }
    return jwt.encode(
        claims, load_private_key(state_dir), algorithm="EdDSA",
        headers={"typ": "remoterf-host-grant"},
    )


def _start_refresher(host_id: str, gid: int, reservation_end: float, still_live, session) -> None:
    key = (host_id, int(gid))
    with _refresh_lock:
        old = _refreshers.pop(key, None)
        if old is not None:
            old[2].cancel()

    marker = object()
    def refresh() -> None:
        with _refresh_lock:
            current = _refreshers.get(key)
            if current is None or current[0] is not marker:
                return
        registry = hts.get_tunnel_registry(create=False)
        if registry is None or not still_live() or registry.session_for_host(host_id) is not session or not session.alive:
            return
        try:
            grant = issue_grant(host_id, gid, reservation_end)
        except Exception as exc:
            logger.warning("host direct grant refresh unavailable for %s: %s", host_id, exc)
            return
        if not registry.send_control(host_id, kind="grant", device_id=str(gid), payload={"grant": grant}):
            return
        with _refresh_lock:
            current = _refreshers.get(key)
            if current is None or current[0] is not marker:
                return
            timer = threading.Timer(_REFRESH_SECONDS, refresh)
            timer.daemon = True
            _refreshers[key] = (marker, session, timer)
            timer.start()

    timer = threading.Timer(_REFRESH_SECONDS, refresh)
    timer.daemon = True
    with _refresh_lock:
        _refreshers[key] = (marker, session, timer)
    timer.start()


def offer(device, ice: str, *, reservation_end: float, still_live) -> dict | None:
    """Ask the owning Host to answer ICE, leaving callers to use lab fallback."""
    host_id = str(getattr(device, "host_id", "") or "")
    gid = int(getattr(device, "gid"))
    registry = hts.get_tunnel_registry(create=False)
    if registry is None:
        return None
    session = registry.session_for_host(host_id)
    if (
        session is None or not session.alive or "direct" not in session.capabilities
        or not session.tls_public_key or not session.direct_ready
    ):
        return None
    try:
        response = registry.request_control(
            host_id, kind="direct_offer", device_id=str(gid), timeout=20,
            payload={"ice": ice, "grant": issue_grant(host_id, gid, reservation_end)},
        )
    except Exception as exc:
        logger.warning("host direct offer unavailable for %s: %s", host_id, exc)
        return None
    if not isinstance(response, dict) or response.get("error") or not isinstance(response.get("answer"), dict):
        return None
    _start_refresher(host_id, gid, reservation_end, still_live, session)
    return response["answer"]
