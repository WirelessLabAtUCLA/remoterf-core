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
import tempfile
import unittest
from pathlib import Path

from remoteRF_server.server.global_access.catalog import build_catalog_payload, content_hash
from remoteRF_server.server.global_access.config import RouteConfig, parse_global_config
from remoteRF_server.server.global_access.route import (
    RouteConsistencyError,
    build_route_payload,
    compute_ca_sha256,
)
from remoteRF_server.tools.gen_certs import generate_certs

from tests.test_global_config import _BASE as _BASE_CONFIG


def _cfg():
    import copy

    return parse_global_config(copy.deepcopy(_BASE_CONFIG))


class CatalogTests(unittest.TestCase):
    def test_known_device_reports_online(self):
        payload = build_catalog_payload(_cfg(), known_device_ids={"1", "2"})
        self.assertEqual(payload["resources"][0]["status"], "online")

    def test_unknown_device_reports_offline_but_is_still_published(self):
        payload = build_catalog_payload(_cfg(), known_device_ids={"2", "3"})
        self.assertEqual(payload["resources"][0]["status"], "offline")
        self.assertEqual(payload["resources"][0]["local_resource_id"], "1")

    def test_unconfigured_device_never_appears_in_the_catalog(self):
        payload = build_catalog_payload(_cfg(), known_device_ids={"1", "999"})
        ids = {r["local_resource_id"] for r in payload["resources"]}
        self.assertNotIn("999", ids)

    def test_payload_never_includes_ip_addresses_or_serials(self):
        payload = build_catalog_payload(_cfg(), known_device_ids={"1"})
        rendered = str(payload)
        self.assertNotIn("192.168", rendered)
        self.assertNotIn("10.77.0", rendered)

    def test_identical_payload_hashes_deterministically(self):
        h1 = content_hash(build_catalog_payload(_cfg(), known_device_ids={"1"}))
        h2 = content_hash(build_catalog_payload(_cfg(), known_device_ids={"1"}))
        self.assertEqual(h1, h2)

    def test_changed_payload_changes_the_hash(self):
        h1 = content_hash(build_catalog_payload(_cfg(), known_device_ids={"1"}))
        h2 = content_hash(build_catalog_payload(_cfg(), known_device_ids={}))
        self.assertNotEqual(h1, h2)


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class RouteTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.config_dir = Path(self._tmp.name)
        generate_certs(
            static_ip="203.0.113.10",
            dns=["ucla.global.remoterf.net"],
            config_dir=self.config_dir,
            force=True,
        )
        self.certs_dir = self.config_dir / "certs"
        self.route = RouteConfig(
            kind="tcp-relay",
            grpc_endpoint="ucla.global.remoterf.net:61005",
            certificate_endpoint="ucla.global.remoterf.net:61006",
            tls_server_name="ucla.global.remoterf.net",
        )

    def test_ca_fingerprint_is_computed_from_the_actual_ca_cert(self):
        fp = compute_ca_sha256(self.certs_dir / "ca.crt")
        self.assertRegex(fp, r"^([0-9A-F]{2}:){31}[0-9A-F]{2}$")

    def test_route_payload_includes_matching_ca_fingerprint(self):
        payload = build_route_payload(
            self.route,
            ca_crt_path=self.certs_dir / "ca.crt",
            server_crt_path=self.certs_dir / "server.crt",
        )
        self.assertEqual(payload["ca_sha256"], compute_ca_sha256(self.certs_dir / "ca.crt"))
        self.assertEqual(payload["grpc_endpoint"], "ucla.global.remoterf.net:61005")

    def test_route_never_publishes_the_lan_ip_san(self):
        payload = build_route_payload(
            self.route,
            ca_crt_path=self.certs_dir / "ca.crt",
            server_crt_path=self.certs_dir / "server.crt",
        )
        self.assertNotIn("203.0.113.10", str(payload))

    def test_mismatched_tls_server_name_raises_route_consistency_error(self):
        bad_route = RouteConfig(
            kind="tcp-relay",
            grpc_endpoint="ucla.global.remoterf.net:61005",
            certificate_endpoint="ucla.global.remoterf.net:61006",
            tls_server_name="not-the-configured-hostname.example",
        )
        with self.assertRaises(RouteConsistencyError):
            build_route_payload(
                bad_route,
                ca_crt_path=self.certs_dir / "ca.crt",
                server_crt_path=self.certs_dir / "server.crt",
            )


if __name__ == "__main__":
    unittest.main()
