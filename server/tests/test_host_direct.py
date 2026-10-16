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

import threading
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from remoterf_federation_core import verify_eddsa_jwt

from remoteRF_server.host import host_tunnel_server as hts
from remoteRF_server.server.device_manager import VirtualDevice
from remoteRF_server.server import host_direct
from remoteRF_server.server.federation.identity import DeploymentState, init_identity, load_private_key, save_state


def _ca(cert_dir):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    (cert_dir / "ca.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (cert_dir / "ca.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    return cert


def _enrolled(tmp_path, monkeypatch):
    identity_dir = tmp_path / "identity"
    init_identity(identity_dir)
    save_state(identity_dir, DeploymentState(deployment_id="deployment-1", slug="lab"))
    monkeypatch.setenv("REMOTERF_FEDERATION_IDENTITY_DIR", str(identity_dir))
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    ca = _ca(cert_dir)
    monkeypatch.setenv("REMOTERF_CERT_DIR", str(cert_dir))
    return identity_dir, ca


def test_lab_info_and_grant_use_lab_identity(tmp_path, monkeypatch):
    identity_dir, ca = _enrolled(tmp_path, monkeypatch)
    host_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    info = host_direct.lab_info("lab-host", host_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode())

    assert info is not None
    assert info["server_name"] == "lab-host--lab.global.remoterf.net"
    cert = x509.load_pem_x509_certificate(info["cert_pem"].encode())
    assert cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == host_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == [info["server_name"]]
    ca.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm,
    )

    monkeypatch.setattr(host_direct.time, "time", lambda: 1000.25)
    claims = verify_eddsa_jwt(host_direct.issue_grant("lab-host", 7, 5000), load_private_key(identity_dir).public_key())
    assert claims == {
        "iss": "deployment-1", "aud": "lab-host", "gid": 7, "jti": claims["jti"],
        "iat": 1000.25, "exp": 1600,
    }
    assert len(claims["jti"]) == 32


def test_lab_info_skips_unenrolled_or_missing_direct_capability(tmp_path, monkeypatch):
    monkeypatch.setenv("REMOTERF_FEDERATION_IDENTITY_DIR", str(tmp_path / "identity"))
    assert host_direct.lab_info("lab-host", "not a key") is None

    registry = hts.HostTunnelRegistry()
    session = hts.HostSession("lab-host", tls_public_key="a key")
    assert not hts._send_lab_info(registry, session)
    assert session.out_q.empty()


def test_control_waiter_resolves_and_close_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(hts, "cfg_dir_from_file", lambda _path: tmp_path)
    registry = hts.HostTunnelRegistry()
    session = hts.HostSession("lab-host")
    registry.register_host("lab-host", session)
    received = []

    def request():
        received.append(registry.request_control("lab-host", kind="direct_offer", device_id="7", payload={}, timeout=1))

    thread = threading.Thread(target=request)
    thread.start()
    frame = session.out_q.get(timeout=1)
    assert session.resolve_control(frame.control.req_id, {"answer": {"ok": True}})
    thread.join(1)
    assert received == [{"answer": {"ok": True}}]

    thread = threading.Thread(target=request)
    thread.start()
    session.out_q.get(timeout=1)
    session.close()
    thread.join(1)
    assert received[-1] is None


def test_offer_times_out_to_the_lab_fallback(monkeypatch):
    session = hts.HostSession("lab-host", capabilities={"direct"}, tls_public_key="key")
    session.direct_ready = True

    class Registry:
        def session_for_host(self, host_id):
            return session

        def request_control(self, *args, **kwargs):
            return None

    monkeypatch.setattr(hts, "get_tunnel_registry", lambda create=False: Registry())
    monkeypatch.setattr(host_direct, "issue_grant", lambda *args: "grant")
    assert host_direct.offer(
        VirtualDevice(gid=7, host_id="lab-host", device_id="7"), "{}",
        reservation_end=2000, still_live=lambda: True,
    ) is None
