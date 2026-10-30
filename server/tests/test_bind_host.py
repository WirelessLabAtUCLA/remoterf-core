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

import os
import socket
import unittest
from unittest.mock import patch

from remoteRF_server.server import grpc_server


class BindHostTests(unittest.TestCase):
    """
    RemoteRF Global v0 relies on REMOTERF_BIND_HOST taking precedence over
    LAN auto-discovery so the server can be told to listen on 0.0.0.0 (LAN +
    WireGuard interfaces) without any source change. These tests pin down
    that existing precedence so it can't silently regress.
    """

    def test_explicit_bind_host_env_var_wins_over_autodetect(self):
        with patch.dict(os.environ, {"REMOTERF_BIND_HOST": "0.0.0.0"}):
            self.assertEqual(grpc_server._get_bind_host(), "0.0.0.0")

    def test_explicit_bind_host_is_stripped_of_whitespace(self):
        with patch.dict(os.environ, {"REMOTERF_BIND_HOST": "  10.77.0.2  "}):
            self.assertEqual(grpc_server._get_bind_host(), "10.77.0.2")

    def test_blank_bind_host_env_var_falls_back_to_autodetect(self):
        fake_sockname = ("192.168.50.7", 0)
        with patch.dict(os.environ, {"REMOTERF_BIND_HOST": "   "}):
            with patch("socket.socket") as mock_socket_cls:
                mock_sock = mock_socket_cls.return_value.__enter__.return_value
                mock_sock.getsockname.return_value = fake_sockname
                self.assertEqual(grpc_server._get_bind_host(), "192.168.50.7")

    def test_unset_bind_host_falls_back_to_loopback_when_undetectable(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("REMOTERF_BIND_HOST", None)
            with patch("socket.socket") as mock_socket_cls:
                mock_sock = mock_socket_cls.return_value.__enter__.return_value
                mock_sock.connect.side_effect = OSError("network unreachable")
                self.assertEqual(grpc_server._get_bind_host(), "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
