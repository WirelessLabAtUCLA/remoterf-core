from __future__ import annotations

import unittest

from remoteRF_server.server.global_access.ingress_policy import (
    is_trusted_relay_peer,
    parse_grpc_peer,
)


class GrpcPeerParsingTests(unittest.TestCase):
    def test_parses_ipv4_and_ipv6_peers(self):
        self.assertEqual(str(parse_grpc_peer("ipv4:10.77.0.1:54321")), "10.77.0.1")
        self.assertEqual(str(parse_grpc_peer("ipv6:[::1]:54321")), "::1")

    def test_unparseable_peer_returns_none(self):
        self.assertIsNone(parse_grpc_peer("unix:/tmp/socket"))
        self.assertIsNone(parse_grpc_peer(""))


class TrustedRelayPeerTests(unittest.TestCase):
    def test_only_configured_relay_peer_is_trusted(self):
        cidrs = ["10.77.0.1/32"]
        self.assertTrue(is_trusted_relay_peer("ipv4:10.77.0.1:5555", cidrs))
        self.assertFalse(is_trusted_relay_peer("ipv4:203.0.113.9:5555", cidrs))
        self.assertFalse(is_trusted_relay_peer("ipv4:192.168.1.50:5555", cidrs))
        self.assertFalse(is_trusted_relay_peer("ipv4:10.77.0.1:5555", []))
