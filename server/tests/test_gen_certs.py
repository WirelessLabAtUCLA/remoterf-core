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
