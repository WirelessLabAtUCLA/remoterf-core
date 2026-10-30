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

import hashlib
import json


def schema_digest(body: dict) -> str:
    """The one schema hash rule: sha256 of the canonical JSON body (no schema_hash in it)."""
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canon.encode('utf-8')).hexdigest()}"
