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
Classifies a gRPC peer address against the configured trusted relay CIDRs
(REMOTERF_GLOBAL_RELAY_PEER_CIDRS / global.relay_ingress.trusted_peer_cidrs).

Only ever reads `context.peer()` — never a client-supplied header — and is
used for exactly one purpose: deciding whether ACC:login/ACC:create_user
must be refused because the connection arrived via the public relay path
(see grpc_server.py's GenericRPCServicer.Call). It is never used to grant
extra trust to anything.
"""

from __future__ import annotations

import ipaddress
from typing import Optional, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def parse_grpc_peer(peer: str) -> Optional[IPAddress]:
    if not peer:
        return None

    if peer.startswith("ipv4:"):
        host_port = peer[len("ipv4:"):]
        host = host_port.rsplit(":", 1)[0]
    elif peer.startswith("ipv6:"):
        host_port = peer[len("ipv6:"):]
        if host_port.startswith("["):
            end = host_port.find("]")
            if end == -1:
                return None
            host = host_port[1:end]
        else:
            host = host_port.rsplit(":", 1)[0]
    else:
        return None

    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def is_trusted_relay_peer(peer: str, trusted_cidrs) -> bool:
    addr = parse_grpc_peer(peer)
    if addr is None:
        return False
    for cidr in trusted_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if addr.version == network.version and addr in network:
            return True
    return False
