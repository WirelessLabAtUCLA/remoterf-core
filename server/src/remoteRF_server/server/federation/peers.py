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

"""FederationPeers: where a partner's FederationV2 listener is and the CA
pinned for it, so the HOME dials the partner itself instead of asking the
broker to forward.

A row arrives one of two ways: an admin adds it (`serverrf federation peers
add`), or the cluster agent takes it from the partner's own signed status
note, verified with the key pinned at join -- so Global relays the route but
can never substitute one. An admin row is never overwritten by the agent.
"""

from __future__ import annotations

import os
import re
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from cryptography import x509
from remoterf_federation_core import canonical_uuid

from .migrations import configure_connection, migrate_peers_usergroups_schema

MAX_CA_PEM_BYTES = 16384
_ENDPOINT = re.compile(r"^(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+):([1-9][0-9]{0,4})$")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
ROUTE_FIELDS = frozenset({"grpc_endpoint", "tls_server_name", "ca_pem"})


def validate_route(route: object) -> dict:
    """The route a lab advertises for itself, as the store keeps it."""
    if type(route) is not dict or set(route) != ROUTE_FIELDS:
        raise ValueError("route has the wrong fields")
    endpoint, name, ca_pem = route["grpc_endpoint"], route["tls_server_name"], route["ca_pem"]
    if type(endpoint) is not str or _ENDPOINT.match(endpoint) is None:
        raise ValueError("route endpoint must be host:port")
    if type(name) is not str or _HOSTNAME.match(name) is None:
        raise ValueError("route tls_server_name must be a hostname")
    if type(ca_pem) is not str or not 0 < len(ca_pem) <= MAX_CA_PEM_BYTES:
        raise ValueError("route ca_pem is missing or too large")
    try:
        x509.load_pem_x509_certificate(ca_pem.encode("utf-8"))
    except ValueError:
        raise ValueError("route ca_pem is not a PEM certificate") from None
    return {"grpc_endpoint": endpoint, "tls_server_name": name, "ca_pem": ca_pem}


def via(endpoint: str) -> str:
    """'relay' for a Global relay name, 'direct' for anything the admin gave."""
    from .. import global_onboarding

    host = endpoint.rsplit(":", 1)[0]
    return "relay" if host.endswith("." + global_onboarding.domain()) else "direct"


class PeerStore:
    def __init__(self, usergroups_path):
        self.path = Path(usergroups_path)
        self._ready = False

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        configure_connection(conn)
        if not self._ready:
            migrate_peers_usergroups_schema(conn)
            conn.commit()  # the migration's writes must not leave a transaction open
            self._ready = True
        return conn

    def get(self, deployment_id: str) -> dict | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM FederationPeers WHERE deployment_id=?", (canonical_uuid(deployment_id),)
            ).fetchone()
        return dict(row) if row is not None else None

    def list(self) -> list[dict]:
        with closing(self._connect()) as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM FederationPeers ORDER BY display_name")]

    def upsert(self, *, deployment_id: str, display_name: str, route: dict, source: str) -> bool:
        """Record a route; a cluster note never replaces what an admin set."""
        if source not in ("admin", "cluster"):
            raise ValueError("source must be admin or cluster")
        clean = validate_route(route)
        deployment_id = canonical_uuid(deployment_id)
        with closing(self._connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT source FROM FederationPeers WHERE deployment_id=?", (deployment_id,)
            ).fetchone()
            if row is not None and row["source"] == "admin" and source == "cluster":
                return False
            conn.execute(
                "INSERT INTO FederationPeers "
                "(deployment_id,display_name,endpoint,tls_server_name,ca_pem,via,source,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(deployment_id) DO UPDATE SET "
                "display_name=excluded.display_name, endpoint=excluded.endpoint, "
                "tls_server_name=excluded.tls_server_name, ca_pem=excluded.ca_pem, "
                "via=excluded.via, source=excluded.source, updated_at=excluded.updated_at",
                (
                    deployment_id, str(display_name or deployment_id)[:256], clean["grpc_endpoint"],
                    clean["tls_server_name"], clean["ca_pem"], via(clean["grpc_endpoint"]), source,
                    int(time.time()),
                ),
            )
        return True

    def remove(self, deployment_id: str) -> bool:
        with closing(self._connect()) as conn, conn:
            return conn.execute(
                "DELETE FROM FederationPeers WHERE deployment_id=?", (canonical_uuid(deployment_id),)
            ).rowcount > 0


def _relay_route(host: str) -> tuple[str, int] | None:
    """The relay route this deployment's own discovery document advertises:
    the public, SNI-routed port every client dials -- not the tunnel's
    backend port that global.env keeps, which only the VPS itself can reach."""
    import requests

    try:
        document = requests.get(
            f"https://{host}/.well-known/remoterf-deployment", timeout=5, allow_redirects=False
        ).json()
        for route in document.get("routes", []):
            if route.get("kind") == "relay" and route.get("host") and route.get("port"):
                return str(route["host"]), int(route["port"])
    except Exception:  # noqa: BLE001 - no document, no route this tick
        return None
    return None


def own_route() -> dict | None:
    """This lab's relay route, for its status note: the name and port clients
    dial, and the CA every client already pins."""
    from .. import global_onboarding

    host = global_onboarding.hostname()
    ca_path = Path(os.getenv("REMOTERF_CERT_DIR", global_onboarding.cfg_dir() / "certs")) / "ca.crt"
    try:
        ca_pem = ca_path.read_text("utf-8")
    except OSError:
        return None
    if not host:
        return None
    relay = _relay_route(host)
    if relay is None:
        return None
    try:
        return validate_route({"grpc_endpoint": f"{relay[0]}:{relay[1]}", "tls_server_name": relay[0], "ca_pem": ca_pem})
    except ValueError:
        return None
