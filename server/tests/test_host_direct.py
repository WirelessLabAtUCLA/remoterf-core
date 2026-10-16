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

import json
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
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "RemoteRF host"

    monkeypatch.setattr(host_direct.time, "time", lambda: 1000.25)
    claims = verify_eddsa_jwt(
        host_direct.issue_grant("lab-host", 7, "reservation-9", 5000),
        load_private_key(identity_dir).public_key(),
    )
    assert claims == {
        "iss": "deployment-1", "aud": "lab-host", "gid": 7, "rid": "reservation-9", "jti": claims["jti"],
        "iat": 1000.25, "exp": 1120,
    }
    assert len(claims["jti"]) == 32


def test_lab_info_skips_unenrolled_or_missing_direct_capability(tmp_path, monkeypatch):
    monkeypatch.setenv("REMOTERF_FEDERATION_IDENTITY_DIR", str(tmp_path / "identity"))
    assert host_direct.lab_info("lab-host", "not a key") is None

    registry = hts.HostTunnelRegistry()
    session = hts.HostSession("lab-host", tls_public_key="a key")
    assert not hts._send_lab_info(registry, session)
    assert session.out_q.empty()


def test_lab_info_skips_invalid_direct_dns_names(tmp_path, monkeypatch):
    identity_dir, _ = _enrolled(tmp_path, monkeypatch)
    assert host_direct.lab_info("x" * 61, "not a key") is None
    assert host_direct.lab_info("host--part", "not a key") is None
    save_state(identity_dir, DeploymentState(deployment_id="deployment-1", slug="part--two"))
    assert host_direct.lab_info("host-a", "not a key") is None


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
    session.direct_lab_info = {"server_name": "host.global.remoterf.net", "ca_pem": "ca"}

    class Registry:
        def session_for_host(self, host_id):
            return session

        def request_control(self, *args, **kwargs):
            return None

    monkeypatch.setattr(hts, "get_tunnel_registry", lambda create=False: Registry())
    monkeypatch.setattr(host_direct, "issue_grant", lambda *args: "grant")
    assert host_direct.offer(
        VirtualDevice(gid=7, host_id="lab-host", device_id="7"), "{}",
        rid="reservation-9", reservation_end=2000, still_live=lambda: True,
    ) is None


def test_refresher_retries_then_revokes_when_reservation_ends(monkeypatch):
    scheduled = []
    sent = []
    liveness = iter((True, True, False))

    class Timer:
        def __init__(self, _seconds, function):
            self.function = function
            self.daemon = False
            scheduled.append(self)

        def start(self):
            pass

        def cancel(self):
            pass

    class Registry:
        def send_control(self, _host_id, *, kind, device_id, payload):
            sent.append((kind, device_id, payload))
            return kind != "grant" or len([item for item in sent if item[0] == "grant"]) > 1

    monkeypatch.setattr(host_direct.threading, "Timer", Timer)
    monkeypatch.setattr(hts, "get_tunnel_registry", lambda create=False: Registry())
    monkeypatch.setattr(host_direct, "issue_grant", lambda *args: "grant")
    monkeypatch.setattr(host_direct.time, "time", lambda: 1000)
    host_direct._start_refresher("host-a", 7, "reservation-9", 2000, lambda: next(liveness), object())
    scheduled.pop(0).function()
    scheduled.pop(0).function()
    scheduled.pop(0).function()

    assert sent == [
        ("grant", "7", {"grant": "grant"}),
        ("grant", "7", {"grant": "grant"}),
        ("revoke", "7", {"rid": "reservation-9", "at": 1000}),
    ]
    assert ("host-a", 7) not in host_direct._refreshers


def test_offer_pins_and_validates_host_answer(monkeypatch):
    host_direct._offer_cooldowns.clear()
    session = hts.HostSession("host-a", capabilities={"direct"}, tls_public_key="key")
    session.direct_ready = True
    session.direct_lab_info = {"server_name": "host-a.global.remoterf.net", "ca_pem": "lab-ca"}

    class Registry:
        response = {"answer": {"ufrag": "u", "pwd": "p", "candidates": [], "server_name": "wrong", "ca_pem": "wrong"}}

        def session_for_host(self, _host_id):
            return session

        def request_control(self, *args, **kwargs):
            return self.response

    registry = Registry()
    monkeypatch.setattr(hts, "get_tunnel_registry", lambda create=False: registry)
    monkeypatch.setattr(host_direct, "issue_grant", lambda *args: "grant")
    monkeypatch.setattr(host_direct, "_start_refresher", lambda *args: None)
    device = VirtualDevice(gid=7, host_id="host-a", device_id="7")

    answer = host_direct.offer(device, "{}", rid="reservation-9", reservation_end=2000, still_live=lambda: True)
    assert answer["server_name"] == "host-a.global.remoterf.net"
    assert answer["ca_pem"] == "lab-ca"

    host_direct._offer_cooldowns.clear()
    registry.response = {"answer": {"ufrag": "u", "pwd": "p", "candidates": ["x" * 513]}}
    assert host_direct.offer(device, "{}", rid="reservation-9", reservation_end=2000, still_live=lambda: True) is None

    host_direct._offer_cooldowns.clear()
    registry.response = {"answer": {"ufrag": "u", "pwd": "p", "candidates": [], "padding": "x" * (16 * 1024)}}
    assert host_direct.offer(device, "{}", rid="reservation-9", reservation_end=2000, still_live=lambda: True) is None


def test_offer_sanitizes_host_relay_answer(monkeypatch):
    host_direct._offer_cooldowns.clear()
    session = hts.HostSession("relay-node", capabilities={"direct", "relay"}, tls_public_key="key")
    session.direct_ready = True
    session.direct_lab_info = {"server_name": "relay-node--lab.global.remoterf.net", "ca_pem": "lab-ca"}

    class Registry:
        response = {"answer": {
            "ufrag": "u", "pwd": "p", "candidates": [],
            "relay": {"session": "one-use", "untrusted": "drop-me"},
        }}

        def session_for_host(self, _host_id):
            return session

        def request_control(self, *args, **kwargs):
            return self.response

        def relay_slot_for_host(self, _host_id):
            return {"endpoint": "relay-node--lab.global.remoterf.net:12321"}

    registry = Registry()
    monkeypatch.setattr(hts, "get_tunnel_registry", lambda create=False: registry)
    monkeypatch.setattr(host_direct, "issue_grant", lambda *args: "grant")
    monkeypatch.setattr(host_direct, "_start_refresher", lambda *args: None)
    device = VirtualDevice(gid=7, host_id="relay-node", device_id="7")

    answer = host_direct.offer(device, "{}", rid="reservation-9", reservation_end=2000, still_live=lambda: True)
    assert answer["relay"] == {"session": "one-use", "endpoint": "relay-node--lab.global.remoterf.net:12321"}

    registry.relay_slot_for_host = lambda _host_id: None
    host_direct._offer_cooldowns.clear()
    answer = host_direct.offer(device, "{}", rid="reservation-9", reservation_end=2000, still_live=lambda: True)
    assert "relay" not in answer

    registry.response = {"answer": {
        "ufrag": "u", "pwd": "p", "candidates": [], "relay": {"session": "x" * 65},
    }}
    host_direct._offer_cooldowns.clear()
    assert host_direct.offer(device, "{}", rid="reservation-9", reservation_end=2000, still_live=lambda: True) is None


def test_relay_hello_syncs_sorted_slots_and_sends_info(tmp_path, monkeypatch):
    from remoteRF_server.server import global_onboarding

    monkeypatch.setattr(hts, "cfg_dir_from_file", lambda _path: tmp_path)
    monkeypatch.setattr(global_onboarding, "state", lambda: "unregistered")
    registry = hts.HostTunnelRegistry()
    queued = []
    monkeypatch.setattr(registry, "_schedule_relay_sync", lambda **kwargs: queued.append(kwargs))
    monkeypatch.setattr(global_onboarding, "state", lambda: "active")
    monkeypatch.setattr(global_onboarding, "lab_slug", lambda: "lab")
    monkeypatch.setattr(global_onboarding, "load", lambda: {
        "GLOBAL_RELAY_TUNNEL_HOST": "global.remoterf.net",
        "GLOBAL_RELAY_TUNNEL_PORT": "2222",
        "GLOBAL_RELAY_TUNNEL_USER": "remoterf-relay",
        "GLOBAL_RELAY_HOST_KEY": "ssh-ed25519 AAAAtunnel",
    })
    calls = []

    def broker(method, path, payload):
        calls.append((method, path, payload))
        return {"host_relays": [{
            "host_id": "relay-00", "port": 62005,
            "server_name": "relay-00--lab.global.remoterf.net",
            "endpoint": "relay-00--lab.global.remoterf.net:12321",
        }]}

    monkeypatch.setattr(global_onboarding, "call", broker)
    for number in range(9):
        hello = hts.host_tunnel_pb2.HostHello(
            host_id=f"relay-{number:02d}", capabilities=["relay"],
            relay_ssh_public_key=f"ssh-ed25519 AAAA{number:02d}",
        )
        registry.persist_host_meta_from_hello(hello)
    assert len(queued) == 9
    assert registry.sync_relay_hosts()
    assert calls == [("POST", global_onboarding.ME_PATH, {
        "hosts": [
            {"host_id": f"relay-{number:02d}", "ssh_public_key": f"ssh-ed25519 AAAA{number:02d}"}
            for number in range(8)
        ],
    })]
    assert "RELAY_SSH_PUBLIC_KEY=ssh-ed25519 AAAA00" in (tmp_path / "host_directory_meta.env").read_text()

    session = hts.HostSession("relay-00", capabilities={"direct", "relay"}, tls_public_key="key")
    registry.register_host("relay-00", session)
    monkeypatch.setattr(host_direct, "lab_info", lambda *_args: {
        "server_name": "relay-00--lab.global.remoterf.net", "ca_pem": "ca",
    })
    assert hts._send_lab_info(registry, session)
    assert session.out_q.get_nowait().control.kind == "lab_info"
    relay_info = session.out_q.get_nowait().control
    assert relay_info.kind == "relay_info"
    assert json.loads(relay_info.payload)["endpoint"] == "relay-00--lab.global.remoterf.net:12321"

    no_slot = hts.HostSession("relay-01", capabilities={"direct", "relay"}, tls_public_key="key")
    registry.register_host("relay-01", no_slot)
    assert hts._send_lab_info(registry, no_slot)
    assert no_slot.out_q.get_nowait().control.kind == "lab_info"
    assert no_slot.out_q.empty()


def test_relay_sync_skips_labs_not_active_on_global(tmp_path, monkeypatch):
    from remoteRF_server.server import global_onboarding

    monkeypatch.setattr(hts, "cfg_dir_from_file", lambda _path: tmp_path)
    monkeypatch.setattr(global_onboarding, "state", lambda: "unregistered")
    registry = hts.HostTunnelRegistry()
    monkeypatch.setattr(global_onboarding, "call", lambda *args: (_ for _ in ()).throw(AssertionError("broker call")))
    registry.persist_host_meta_from_hello(hts.host_tunnel_pb2.HostHello(
        host_id="relay-node", capabilities=["relay"], relay_ssh_public_key="ssh-ed25519 AAAAkey",
    ))
    assert registry.sync_relay_hosts()


def test_offer_refreshes_old_lab_info(monkeypatch):
    now = 15 * 24 * 60 * 60 + 1
    host_direct._offer_cooldowns.clear()
    session = hts.HostSession("host-a", capabilities={"direct"}, tls_public_key="key")
    session.direct_ready = True
    session.direct_lab_info = {"server_name": "old", "ca_pem": "old"}
    session.direct_lab_info_issued_at = 0
    refreshed = []

    class Registry:
        def session_for_host(self, _host_id):
            return session

        def request_control(self, *args, **kwargs):
            return {"answer": {"ufrag": "u", "pwd": "p", "candidates": []}}

    registry = Registry()

    def resend(_registry, _session):
        refreshed.append(True)
        session.direct_lab_info = {"server_name": "fresh", "ca_pem": "fresh"}
        session.direct_lab_info_issued_at = now
        return True

    monkeypatch.setattr(host_direct.time, "time", lambda: now)
    monkeypatch.setattr(hts, "get_tunnel_registry", lambda create=False: registry)
    monkeypatch.setattr(hts, "_send_lab_info", resend)
    monkeypatch.setattr(host_direct, "issue_grant", lambda *args: "grant")
    monkeypatch.setattr(host_direct, "_start_refresher", lambda *args: None)

    answer = host_direct.offer(
        VirtualDevice(gid=7, host_id="host-a", device_id="7"), "{}",
        rid="reservation-9", reservation_end=2000, still_live=lambda: True,
    )
    assert refreshed == [True]
    assert answer["server_name"] == "fresh"

def test_offer_uses_short_wait_cooldown_and_inflight_cap(monkeypatch):
    now = [1000]
    host_direct._offer_cooldowns.clear()
    host_direct._offer_inflight.clear()
    session = hts.HostSession("host-a", capabilities={"direct"}, tls_public_key="key")
    session.direct_ready = True
    session.direct_lab_info = {"server_name": "host-a.global.remoterf.net", "ca_pem": "lab-ca"}
    calls = []

    class Registry:
        response = None

        def session_for_host(self, _host_id):
            return session

        def request_control(self, *args, **kwargs):
            calls.append(kwargs["timeout"])
            return self.response

    registry = Registry()
    monkeypatch.setattr(hts, "get_tunnel_registry", lambda create=False: registry)
    monkeypatch.setattr(host_direct, "issue_grant", lambda *args: "grant")
    monkeypatch.setattr(host_direct.time, "time", lambda: now[0])
    device = VirtualDevice(gid=7, host_id="host-a", device_id="7")

    assert host_direct.offer(device, "{}", rid="reservation-9", reservation_end=2000, still_live=lambda: True) is None
    assert calls == [8]
    assert host_direct.offer(device, "{}", rid="reservation-9", reservation_end=2000, still_live=lambda: True) is None
    assert calls == [8]
    now[0] += 60

    blocked = threading.Event()
    both_blocked = threading.Event()
    release = threading.Event()
    entered = [0]
    entered_lock = threading.Lock()
    registry.response = {"answer": {"ufrag": "u", "pwd": "p", "candidates": []}}

    def wait_for_answer(*args, **kwargs):
        with entered_lock:
            entered[0] += 1
            blocked.set()
            if entered[0] == 2:
                both_blocked.set()
        release.wait(1)
        return registry.response

    registry.request_control = wait_for_answer
    monkeypatch.setattr(host_direct, "_start_refresher", lambda *args: None)
    workers = [threading.Thread(target=host_direct.offer, args=(device, "{}"), kwargs={
        "rid": "reservation-9", "reservation_end": 2000, "still_live": lambda: True,
    }) for _ in range(2)]
    for worker in workers:
        worker.start()
    assert blocked.wait(1)
    assert both_blocked.wait(1)
    assert host_direct.offer(device, "{}", rid="reservation-9", reservation_end=2000, still_live=lambda: True) is None
    release.set()
    for worker in workers:
        worker.join(1)
