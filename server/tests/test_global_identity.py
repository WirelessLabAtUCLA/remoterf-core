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

import stat
import tempfile
import unittest
from pathlib import Path

from remoteRF_server.server.global_access import identity


class DeploymentIdentityTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_dir = Path(self._tmp.name) / "global"

    def test_init_identity_creates_private_key_with_owner_only_perms(self):
        priv_path = identity.init_identity(self.state_dir)
        mode = stat.S_IMODE(priv_path.stat().st_mode)
        self.assertEqual(mode, stat.S_IRUSR | stat.S_IWUSR)

    def test_init_identity_creates_public_key_and_unenrolled_state(self):
        identity.init_identity(self.state_dir)
        self.assertTrue(identity.public_key_path(self.state_dir).exists())
        state = identity.load_state(self.state_dir)
        self.assertFalse(state.enrolled)
        self.assertIsNone(state.deployment_id)

    def test_init_identity_refuses_to_overwrite_existing_identity(self):
        identity.init_identity(self.state_dir)
        priv_before = identity.private_key_path(self.state_dir).read_bytes()
        with self.assertRaises(identity.IdentityError):
            identity.init_identity(self.state_dir)
        self.assertEqual(identity.private_key_path(self.state_dir).read_bytes(), priv_before)

    def test_load_private_key_before_init_raises_clear_error(self):
        with self.assertRaises(identity.IdentityError):
            identity.load_private_key(self.state_dir)

    def test_public_key_pem_never_contains_private_key_material(self):
        identity.init_identity(self.state_dir)
        pub_pem = identity.public_key_pem(self.state_dir)
        priv_pem = identity.private_key_path(self.state_dir).read_text()
        self.assertIn("PUBLIC KEY", pub_pem)
        self.assertNotIn("PRIVATE KEY", pub_pem)
        self.assertNotEqual(pub_pem.strip(), priv_pem.strip())

    def test_public_key_b64_is_stable_and_matches_the_generated_key(self):
        identity.init_identity(self.state_dir)
        b64_first = identity.public_key_b64(self.state_dir)
        b64_second = identity.public_key_b64(self.state_dir)
        self.assertEqual(b64_first, b64_second)

    def test_save_and_load_state_round_trips(self):
        identity.init_identity(self.state_dir)
        state = identity.DeploymentState(
            deployment_id="dep-1",
            slug="ucla",
            display_name="UCLA WirelessLab",
            enrolled_at="2026-01-01T00:00:00Z",
            issuer="https://global.remoterf.net",
            api_base_url="https://global.remoterf.net",
        )
        identity.save_state(self.state_dir, state)
        reloaded = identity.load_state(self.state_dir)
        self.assertEqual(reloaded.deployment_id, "dep-1")
        self.assertTrue(reloaded.enrolled)

    def test_identity_exists_reflects_private_key_presence_only(self):
        self.assertFalse(identity.identity_exists(self.state_dir))
        identity.init_identity(self.state_dir)
        self.assertTrue(identity.identity_exists(self.state_dir))


if __name__ == "__main__":
    unittest.main()
