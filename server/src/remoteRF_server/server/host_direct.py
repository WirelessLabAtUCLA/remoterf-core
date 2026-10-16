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

import json
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
_REFRESH_SECONDS = 45
_LAB_INFO_MAX_AGE_SECONDS = 15 * 24 * 60 * 60
_OFFER_COOLDOWN_SECONDS = 60
_OFFER_TIMEOUT_SECONDS = 8
_refreshers: dict[tuple[str, int], tuple[object, object, threading.Timer]] = {}
_refresh_lock = threading.Lock()
_offer_inflight: dict[str, int] = {}
_offer_cooldowns: dict[str, float] = {}
_offer_lock = threading.Lock()
_invalid_name_warnings: set[tuple[str, str]] = set()
_invalid_name_lock = threading.Lock()


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
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RemoteRF host")]))
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
        if "--" in host_id or "--" in state.slug or len(f"{host_id}--{state.slug}") > 63:
            key = (host_id, state.slug)
            with _invalid_name_lock:
                first_warning = key not in _invalid_name_warnings
                _invalid_name_warnings.add(key)
            if first_warning:
                logger.warning("host direct path unavailable for %s: invalid direct DNS name", host_id)
            return None
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


def issue_grant(host_id: str, gid: int, rid: str, reservation_end: float) -> str:
    state_dir, state = _identity()
    now = time.time()
    claims = {
        "iss": state.deployment_id,
        "aud": str(host_id),
        "gid": int(gid),
        "rid": str(rid),
        "jti": uuid4().hex,
        "iat": now,
        "exp": int(min(float(reservation_end), now + 120)),
    }
    return jwt.encode(
        claims, load_private_key(state_dir), algorithm="EdDSA",
        headers={"typ": "remoterf-host-grant"},
    )


def _start_refresher(host_id: str, gid: int, rid: str, reservation_end: float, still_live, session) -> None:
    key = (host_id, int(gid))
    with _refresh_lock:
        old = _refreshers.pop(key, None)
        if old is not None:
            old[2].cancel()

    marker = object()

    def schedule() -> None:
        with _refresh_lock:
            current = _refreshers.get(key)
            if current is None or current[0] is not marker:
                return
            timer = threading.Timer(_REFRESH_SECONDS, refresh)
            timer.daemon = True
            _refreshers[key] = (marker, session, timer)
            timer.start()

    def stop() -> None:
        with _refresh_lock:
            current = _refreshers.get(key)
            if current is not None and current[0] is marker:
                _refreshers.pop(key, None)

    def refresh() -> None:
        with _refresh_lock:
            current = _refreshers.get(key)
            if current is None or current[0] is not marker:
                return
        registry = hts.get_tunnel_registry(create=False)
        try:
            live = still_live()
        except Exception as exc:
            logger.warning("host direct liveness check failed for %s: %s", host_id, exc)
            schedule()
            return
        if not live:
            try:
                if registry is not None and not registry.send_control(
                    host_id, kind="revoke", device_id=str(gid),
                    payload={"rid": str(rid), "at": time.time()},
                ):
                    logger.warning("host direct revoke unavailable for %s", host_id)
            except Exception as exc:
                logger.warning("host direct revoke unavailable for %s: %s", host_id, exc)
            stop()
            return
        if registry is None:
            logger.warning("host direct grant refresh unavailable for %s: no tunnel", host_id)
            schedule()
            return
        try:
            grant = issue_grant(host_id, gid, rid, reservation_end)
        except Exception as exc:
            logger.warning("host direct grant refresh unavailable for %s: %s", host_id, exc)
            schedule()
            return
        try:
            sent = registry.send_control(
                host_id, kind="grant", device_id=str(gid), payload={"grant": grant},
            )
        except Exception as exc:
            logger.warning("host direct grant refresh unavailable for %s: %s", host_id, exc)
            schedule()
            return
        if not sent:
            logger.warning("host direct grant refresh unavailable for %s", host_id)
        schedule()

    timer = threading.Timer(_REFRESH_SECONDS, refresh)
    timer.daemon = True
    with _refresh_lock:
        _refreshers[key] = (marker, session, timer)
    timer.start()


def _start_offer(host_id: str) -> bool:
    now = time.time()
    with _offer_lock:
        if _offer_cooldowns.get(host_id, 0) > now or _offer_inflight.get(host_id, 0) >= 2:
            return False
        _offer_inflight[host_id] = _offer_inflight.get(host_id, 0) + 1
        return True


def _finish_offer(host_id: str, *, failed: bool) -> None:
    with _offer_lock:
        count = _offer_inflight.get(host_id, 0) - 1
        if count > 0:
            _offer_inflight[host_id] = count
        else:
            _offer_inflight.pop(host_id, None)
        if failed:
            _offer_cooldowns[host_id] = time.time() + _OFFER_COOLDOWN_SECONDS


def _valid_answer(answer: object) -> bool:
    if not isinstance(answer, dict):
        return False
    if any(type(answer.get(key)) is not str or len(answer[key]) > 256 for key in ("ufrag", "pwd")):
        return False
    candidates = answer.get("candidates")
    if not isinstance(candidates, list) or len(candidates) > 32:
        return False
    if any(type(candidate) is not str or len(candidate) > 512 for candidate in candidates):
        return False
    relay = answer.get("relay")
    if relay is not None and (
        not isinstance(relay, dict)
        or type(relay.get("session")) is not str
        or len(relay["session"]) > 64
    ):
        return False
    try:
        return len(json.dumps(answer).encode("utf-8")) <= 16 * 1024
    except (TypeError, ValueError):
        return False


def offer(device, ice: str, *, rid: str, reservation_end: float, still_live) -> dict | None:
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
    issued_at = getattr(session, "direct_lab_info_issued_at", None)
    if issued_at is not None and time.time() - issued_at > _LAB_INFO_MAX_AGE_SECONDS:
        if not hts._send_lab_info(registry, session):
            return None
    pin = getattr(session, "direct_lab_info", None)
    if not isinstance(pin, dict) or type(pin.get("server_name")) is not str or type(pin.get("ca_pem")) is not str:
        return None
    if not _start_offer(host_id):
        return None
    failed = False
    try:
        response = registry.request_control(
            host_id, kind="direct_offer", device_id=str(gid), timeout=_OFFER_TIMEOUT_SECONDS,
            payload={"ice": ice, "grant": issue_grant(host_id, gid, rid, reservation_end)},
        )
    except Exception as exc:
        logger.warning("host direct offer unavailable for %s: %s", host_id, exc)
        failed = True
        response = None
    try:
        if not isinstance(response, dict) or response.get("error") or not _valid_answer(response.get("answer")):
            failed = True
            return None
        answer = dict(response["answer"])
        answer["server_name"] = pin["server_name"]
        answer["ca_pem"] = pin["ca_pem"]
        relay = answer.pop("relay", None)
        slot = getattr(registry, "relay_slot_for_host", lambda _host_id: None)(host_id)
        if isinstance(relay, dict) and slot is not None:
            answer["relay"] = {"session": relay["session"], "endpoint": slot["endpoint"]}
        _start_refresher(host_id, gid, rid, reservation_end, still_live, session)
        return answer
    finally:
        _finish_offer(host_id, failed=failed)
