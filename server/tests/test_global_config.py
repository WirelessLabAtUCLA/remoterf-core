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

import copy
import unittest

from remoteRF_server.server.global_access.config import (
    GlobalConfigError,
    parse_global_config,
    validate_against_known_devices,
)

_BASE = {
    "global": {
        "enabled": True,
        "base_url": "https://global.remoterf.net",
        "issuer": "https://global.remoterf.net",
        "jwks_url": "https://global.remoterf.net/.well-known/jwks.json",
        "deployment_state_path": "~/.config/remoterf/global/deployment.json",
        "deployment_private_key_path": "~/.config/remoterf/global/deployment-private.pem",
        "heartbeat_seconds": 30,
        "offline_seconds": 90,
        "relay_ingress": {"trusted_peer_cidrs": ["10.77.0.1/32"]},
        "public_group": "global-public",
        "route": {
            "kind": "tcp-relay",
            "grpc_endpoint": "ucla.global.remoterf.net:61005",
            "certificate_endpoint": "ucla.global.remoterf.net:61006",
            "tls_server_name": "ucla.global.remoterf.net",
        },
        "exports": [
            {
                "local_device_id": "1",
                "display_name": "UCLA Pluto 1",
                "device_type": "ADALM-Pluto",
                "visibility": "public",
                "reservation_policy": {
                    "max_duration_minutes": 30,
                    "max_active_reservations": 1,
                    "max_daily_minutes": 120,
                },
                "operation_policy": {
                    "default": "deny",
                    "allow_operations": ["freq:GET", "freq:SET"],
                    "allow_client_sample_upload": False,
                },
            }
        ],
    }
}


def _cfg(**overrides):
    data = copy.deepcopy(_BASE)
    for path, value in overrides.items():
        keys = path.split(".")
        node = data["global"]
        for k in keys[:-1]:
            node = node[k]
        node[keys[-1]] = value
    return data


class GlobalConfigParsingTests(unittest.TestCase):
    def test_valid_config_parses(self):
        cfg = parse_global_config(_cfg())
        self.assertTrue(cfg.enabled)
        self.assertEqual(len(cfg.exports), 1)
        self.assertEqual(cfg.exports[0].local_device_id, "1")
        self.assertTrue(cfg.exports[0].operation_policy.allows("freq:GET"))
        self.assertFalse(cfg.exports[0].operation_policy.allows("tx:SET"))

    def test_missing_global_section_rejected(self):
        with self.assertRaises(GlobalConfigError):
            parse_global_config({})

    def test_unknown_top_level_key_rejected(self):
        data = _cfg()
        data["global"]["bogus_key"] = "x"
        with self.assertRaises(GlobalConfigError):
            parse_global_config(data)

    def test_http_base_url_rejected_by_default(self):
        data = _cfg()
        data["global"]["base_url"] = "http://global.remoterf.net"
        with self.assertRaises(GlobalConfigError):
            parse_global_config(data)

    def test_http_base_url_allowed_with_explicit_insecure_flag(self):
        data = _cfg()
        data["global"]["base_url"] = "http://127.0.0.1:8765"
        cfg = parse_global_config(data, allow_insecure_transport=True)
        self.assertEqual(cfg.base_url, "http://127.0.0.1:8765")

    def test_duplicate_local_device_id_rejected(self):
        data = _cfg()
        data["global"]["exports"].append(copy.deepcopy(data["global"]["exports"][0]))
        with self.assertRaises(GlobalConfigError):
            parse_global_config(data)

    def test_invalid_relay_cidr_rejected(self):
        data = _cfg()
        data["global"]["relay_ingress"]["trusted_peer_cidrs"] = ["not-a-cidr"]
        with self.assertRaises(GlobalConfigError):
            parse_global_config(data)

    def test_internal_wireguard_address_rejected_as_route_endpoint(self):
        data = _cfg()
        data["global"]["route"]["grpc_endpoint"] = "10.77.0.2:61005"
        with self.assertRaises(GlobalConfigError):
            parse_global_config(data)

    def test_loopback_address_rejected_as_route_endpoint(self):
        data = _cfg()
        data["global"]["route"]["grpc_endpoint"] = "127.0.0.1:61005"
        with self.assertRaises(GlobalConfigError):
            parse_global_config(data)

    def test_public_hostname_route_endpoint_accepted(self):
        cfg = parse_global_config(_cfg())
        self.assertEqual(cfg.route.grpc_endpoint, "ucla.global.remoterf.net:61005")

    def test_operation_policy_default_must_be_deny(self):
        data = _cfg()
        data["global"]["exports"][0]["operation_policy"]["default"] = "allow"
        with self.assertRaises(GlobalConfigError):
            parse_global_config(data)

    def test_unsupported_visibility_rejected(self):
        data = _cfg()
        data["global"]["exports"][0]["visibility"] = "unlisted"
        with self.assertRaises(GlobalConfigError):
            parse_global_config(data)

    def test_reservation_policy_daily_minutes_must_cover_single_duration(self):
        data = _cfg()
        data["global"]["exports"][0]["reservation_policy"]["max_daily_minutes"] = 10
        data["global"]["exports"][0]["reservation_policy"]["max_duration_minutes"] = 30
        with self.assertRaises(GlobalConfigError):
            parse_global_config(data)

    def test_offline_seconds_must_be_at_least_heartbeat_seconds(self):
        data = _cfg()
        data["global"]["heartbeat_seconds"] = 100
        data["global"]["offline_seconds"] = 30
        with self.assertRaises(GlobalConfigError):
            parse_global_config(data)

    def test_unsupported_route_kind_rejected(self):
        data = _cfg()
        data["global"]["route"]["kind"] = "direct-p2p"
        with self.assertRaises(GlobalConfigError):
            parse_global_config(data)


class ValidateAgainstKnownDevicesTests(unittest.TestCase):
    def test_known_device_produces_no_errors(self):
        cfg = parse_global_config(_cfg())
        errors = validate_against_known_devices(cfg, {"1", "2"})
        self.assertEqual(errors, [])

    def test_unknown_device_id_is_reported(self):
        cfg = parse_global_config(_cfg())
        errors = validate_against_known_devices(cfg, {"2", "3"})
        self.assertEqual(len(errors), 1)
        self.assertIn("1", errors[0])


if __name__ == "__main__":
    unittest.main()
