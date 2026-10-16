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

import json
import subprocess
import sys
import unittest

from remoterf_device_core import manifest
from remoterf_device_core.digest import schema_digest


class ManifestTests(unittest.TestCase):
    def test_schemas_json_is_current(self):
        # A fresh process: building imports the drivers (and may stub pyadi).
        built = subprocess.run(
            [sys.executable, "-c", "import json; from remoterf_device_core import manifest; print(json.dumps(manifest.build()))"],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(json.loads(built.stdout), manifest.load(),
                         "run: python -m remoterf_device_core.manifest")

    def test_one_row_per_type_and_every_type_has_a_v1_hash(self):
        rows = manifest.load()
        self.assertEqual(len({r["device_type"] for r in rows}), len(rows))
        self.assertTrue(all(r["v1"].startswith("sha256:") for r in rows))
        self.assertIn(rows[0]["v1"], manifest.builtin_hashes())

    def test_schema_digest_is_the_idl_hash_rule(self):
        from remoterf_device_core.idl import DeviceSchema, idl_expose

        class Probe(DeviceSchema):
            device_type = "probe"
            driver_version = "0.0.1"

            @idl_expose(kind="get")
            def get_x(self):
                return 1

        idl = Probe().get_idl()
        body = {k: v for k, v in idl.items() if k != "schema_hash"}
        self.assertEqual(idl["schema_hash"], schema_digest(body))


if __name__ == "__main__":
    unittest.main()
