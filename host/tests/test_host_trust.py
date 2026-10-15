from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from remoteRF_host.config import cert_fetcher  # noqa: E402

PEM_A = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
PEM_B = b"-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n"


def _fetch(tmp: str, served: bytes, expected=None) -> bool:
    with mock.patch.object(cert_fetcher, "_fetch_http", return_value=served):
        return cert_fetcher.fetch_and_save_ca_cert(
            "lab.example.org", 61006, env_dir=tmp, env_filename="net.env",
            grpc_addr="lab.example.org:61005", expected_sha256=expected,
        )


class CaPinTests(unittest.TestCase):
    def test_fingerprint_from_the_lab_must_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(_fetch(tmp, PEM_A, expected=hashlib.sha256(PEM_B).hexdigest()))
            self.assertFalse((Path(tmp) / "ca.crt").exists())
            colons = cert_fetcher.sha256_fingerprint_pem(PEM_A).upper()
            self.assertTrue(_fetch(tmp, PEM_A, expected=f"sha256:{colons}"))
            env = (Path(tmp) / "net.env").read_text()
            self.assertIn(f"REMOTERF_CA_SHA256={hashlib.sha256(PEM_A).hexdigest()}", env)

    def test_a_garbled_fingerprint_is_refused_not_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            for bad in ("", "sha256:", ":", "  ", "abc123"):
                self.assertFalse(_fetch(tmp, PEM_A, expected=bad), bad)
            self.assertFalse((Path(tmp) / "ca.crt").exists())

    def test_first_fetch_pins_and_a_changed_ca_needs_the_new_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(_fetch(tmp, PEM_A))
            self.assertFalse(_fetch(tmp, PEM_B))
            self.assertEqual((Path(tmp) / "ca.crt").read_bytes(), PEM_A)
            self.assertTrue(_fetch(tmp, PEM_B, expected=hashlib.sha256(PEM_B).hexdigest()))
            self.assertEqual((Path(tmp) / "ca.crt").read_bytes(), PEM_B)


def _run(cfg: Path, code: str, timeout: float = 60) -> subprocess.CompletedProcess:
    env = dict(os.environ, REMOTERF_CONFIG_DIR=str(cfg), REMOTERF_DRIVERS_DIR=str(cfg / "drivers"),
               PYTHONPATH=str(PROJECT_ROOT / "src"))
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code)], env=env,
                          capture_output=True, text=True, timeout=timeout)


class TunnelTrustTests(unittest.TestCase):
    def test_no_ca_means_no_connection(self):
        with tempfile.TemporaryDirectory() as raw:
            cfg = Path(raw)
            (cfg / "net.env").write_text("REMOTERF_ADDR=lab.example.org:61005\n")
            result = _run(cfg, "from remoteRF_host.server import tunnel_agent; tunnel_agent.main()")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("only connects over TLS", result.stderr + result.stdout)

    def test_ca_file_must_match_the_pin(self):
        with tempfile.TemporaryDirectory() as raw:
            cfg = Path(raw)
            (cfg / "ca.crt").write_bytes(PEM_B)
            (cfg / "net.env").write_text(
                "REMOTERF_ADDR=lab.example.org:61005\nREMOTERF_CA_CERT=./ca.crt\n"
                f"REMOTERF_CA_SHA256={hashlib.sha256(PEM_A).hexdigest()}\n"
            )
            result = _run(cfg, "from remoteRF_host.server import tunnel_agent; tunnel_agent.main()")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("does not match the pinned", result.stderr + result.stdout)

    def test_an_unpinned_ca_from_an_older_host_is_pinned_at_start(self):
        with tempfile.TemporaryDirectory() as raw:
            cfg = Path(raw)
            (cfg / "ca.crt").write_bytes(PEM_A)
            (cfg / "net.env").write_text("REMOTERF_ADDR=127.0.0.1:9\nREMOTERF_CA_CERT=./ca.crt\n")
            (cfg / "host.env").write_text("HOST_ID=h1\nHOST_TOKEN=t\n")
            try:
                _run(cfg, "from remoteRF_host.server import tunnel_agent; tunnel_agent.main()", timeout=4)
            except subprocess.TimeoutExpired:
                pass  # it pinned, then kept retrying the unreachable lab
            self.assertIn(f"REMOTERF_CA_SHA256={hashlib.sha256(PEM_A).hexdigest()}", (cfg / "net.env").read_text())

    def test_reservation_end_closes_sessions_then_resets(self):
        with tempfile.TemporaryDirectory() as raw:
            result = _run(Path(raw), """
                from remoteRF_host.common.grpc import grpc_host_pb2 as pb
                from remoteRF_host.server import device_manager as dm
                from remoteRF_host.server.tunnel_agent import HostTunnelAgent

                events = []
                class Schema:
                    def reset_for_next_holder(self):
                        events.append("reset")
                dm._devices[200] = dm._DeviceState(schema=Schema(), name="p", ident="", dtype="adalm_pluto", init={})
                dm.register_reservation_end_callback(lambda gid: events.append(("closed", gid)))
                agent = HostTunnelAgent.__new__(HostTunnelAgent)
                agent._devices = {200: {}}
                agent._handle_control(pb.Control(kind="reservation_end", device_id="200"))
                agent._handle_control(pb.Control(kind="reservation_end", device_id="999"))
                agent._handle_control(pb.Control(kind="something_new", device_id="200"))
                assert events == [("closed", 200), "reset"], events
                print("ok")
            """)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
