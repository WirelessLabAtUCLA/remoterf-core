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

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from remoteRF_server.tools.gen_certs import generate_certs


def _san_text(cert_path: Path) -> str:
    out = subprocess.run(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-ext", "subjectAltName"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True,
    )
    return out.stdout


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class GenCertsSanTests(unittest.TestCase):
    """
    RemoteRF Global v0 needs the server certificate to identify
    ucla.global.remoterf.net (a DNS SAN) *alongside* the existing LAN IP SAN,
    so a client dialing through the public hostname can still validate the
    real UCLA certificate. gen_certs.py already supports this via a
    repeatable --dns flag; these tests pin down that existing behavior.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.config_dir = Path(self._tmp.name)

    def test_dns_san_is_added_alongside_existing_ip_san(self):
        generate_certs(
            static_ip="203.0.113.10",
            dns=["ucla.global.remoterf.net"],
            config_dir=self.config_dir,
            force=True,
        )

        san = _san_text(self.config_dir / "certs" / "server.crt")
        self.assertIn("IP Address:203.0.113.10", san)
        self.assertIn("DNS:ucla.global.remoterf.net", san)

    def test_lan_only_generation_still_has_no_dns_san(self):
        generate_certs(
            static_ip="192.168.1.50",
            dns=[],
            config_dir=self.config_dir,
            force=True,
        )

        san = _san_text(self.config_dir / "certs" / "server.crt")
        self.assertIn("IP Address:192.168.1.50", san)
        self.assertNotIn("DNS:", san)

    def test_multiple_dns_sans_are_all_preserved(self):
        generate_certs(
            static_ip="192.168.1.50",
            dns=["ucla.global.remoterf.net", "remoterf.local"],
            config_dir=self.config_dir,
            force=True,
        )

        san = _san_text(self.config_dir / "certs" / "server.crt")
        self.assertIn("IP Address:192.168.1.50", san)
        self.assertIn("DNS:ucla.global.remoterf.net", san)
        self.assertIn("DNS:remoterf.local", san)


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class EnsureCertificateNamesTests(unittest.TestCase):
    """A Global hostname chosen after the certs exist is added to server.crt
    under the existing CA, so already-enrolled clients keep their trust."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.config_dir = Path(self._tmp.name)
        self.certs = self.config_dir / "certs"
        generate_certs(static_ip="192.168.1.50", dns=[], config_dir=self.config_dir, force=True, days=3650)

    def _verify(self):
        return subprocess.run(
            ["openssl", "verify", "-CAfile", str(self.certs / "ca.crt"), str(self.certs / "server.crt")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )

    def test_missing_hostname_is_added_without_touching_ca_or_key(self):
        from remoteRF_server.tools.gen_certs import _x509_dates, ensure_certificate_names

        ca = (self.certs / "ca.crt").read_bytes()
        key = (self.certs / "server.key").read_bytes()
        _, old_na = _x509_dates(self.certs / "server.crt")

        self.assertTrue(ensure_certificate_names(self.certs, ["lab.global.remoterf.net"]))

        san = _san_text(self.certs / "server.crt")
        self.assertIn("IP Address:192.168.1.50", san)
        self.assertIn("DNS:lab.global.remoterf.net", san)
        self.assertEqual((self.certs / "ca.crt").read_bytes(), ca)
        self.assertEqual((self.certs / "server.key").read_bytes(), key)
        verified = self._verify()
        self.assertEqual(verified.returncode, 0, verified.stdout)
        _, new_na = _x509_dates(self.certs / "server.crt")
        self.assertLess(abs((new_na - old_na).total_seconds()), 2 * 86400)

    def test_present_hostname_is_a_noop(self):
        from remoteRF_server.tools.gen_certs import ensure_certificate_names

        ensure_certificate_names(self.certs, ["lab.global.remoterf.net"])
        crt = (self.certs / "server.crt").read_bytes()
        self.assertFalse(ensure_certificate_names(self.certs, ["lab.global.remoterf.net"]))
        self.assertEqual((self.certs / "server.crt").read_bytes(), crt)

    def test_without_certs_nothing_is_issued(self):
        from remoteRF_server.tools.gen_certs import ensure_certificate_names

        empty = self.config_dir / "none"
        empty.mkdir()
        self.assertFalse(ensure_certificate_names(empty, ["lab.global.remoterf.net"]))
        self.assertEqual(sorted(p.name for p in empty.iterdir()), [])

    def test_serverrf_adds_the_global_hostname_from_global_env(self):
        from unittest import mock

        from remoteRF_server import serverrf_cli
        from remoteRF_server.server import global_onboarding as g

        env = {
            "REMOTERF_CONFIG_DIR": str(self.config_dir),
            "REMOTERF_GLOBAL_DOMAIN": "global.remoterf.net",
        }
        with mock.patch.dict("os.environ", env):
            g.update(GLOBAL_CONSENT="yes", GLOBAL_NAME="lab", GLOBAL_STATE="requested")
            serverrf_cli._ensure_certificate_names()
            san = _san_text(self.certs / "server.crt")
            self.assertIn("DNS:lab.global.remoterf.net", san)
            # Global may bind a different final name: that one is added too.
            g.update(GLOBAL_FINAL_NAME="lab-2", GLOBAL_STATE="active")
            serverrf_cli._ensure_certificate_names()
        san = _san_text(self.certs / "server.crt")
        self.assertIn("DNS:lab.global.remoterf.net", san)
        self.assertIn("DNS:lab-2.global.remoterf.net", san)
        self.assertEqual(self._verify().returncode, 0)
