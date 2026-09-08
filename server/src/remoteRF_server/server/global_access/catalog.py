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

"""
Builds the public resource catalog snapshot: only explicitly-configured
exports, safe metadata only (no IPs, serials, filesystem paths, tokens).
Catalog metadata is discovery information, not authoritative reservation
state or enforcement. Gate C exposes no federated resource-access path.
"""

from __future__ import annotations

import hashlib
import json

from .config import GlobalConfig


def build_catalog_payload(cfg: GlobalConfig, *, known_device_ids) -> dict:
    known = {str(d) for d in known_device_ids}
    resources = []
    for export in cfg.exports:
        resources.append(
            {
                "local_resource_id": export.local_device_id,
                "display_name": export.display_name,
                "device_type": export.device_type,
                "visibility": export.visibility,
                "status": "online" if export.local_device_id in known else "offline",
                "policy_summary": {
                    "max_duration_minutes": export.reservation_policy.max_duration_minutes,
                    "max_active_reservations": export.reservation_policy.max_active_reservations,
                    "max_daily_minutes": export.reservation_policy.max_daily_minutes,
                    "allow_client_sample_upload": export.operation_policy.allow_client_sample_upload,
                },
            }
        )
    return {"resources": resources}


def canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def content_hash(payload: dict) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
