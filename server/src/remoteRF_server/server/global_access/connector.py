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
Optional background connector: publishes route + catalog and sends
heartbeats to RemoteRF Global. One thread per GlobalConnector instance;
callers (grpc_server.ServerRuntime) are responsible for constructing at
most one instance per server process — see start_server_runtime().

Failure handling: any exception during a publish cycle is caught, logged as
a bounded warning (audit_event), and retried after an exponential backoff
(1s-60s, jittered, reset to 1s after the next success). A failing connector
never raises out of its thread and never blocks/crashes the rest of the
server.
"""

from __future__ import annotations

import random
import sys
import threading
import uuid
from pathlib import Path
from typing import Callable, Optional

from . import identity as identity_mod
from .api_client import GlobalApiClient, GlobalApiError
from .audit import audit_event
from .catalog import build_catalog_payload, content_hash
from .config import GlobalConfig
from .identity import PROTOCOL_VERSION
from .jwt_tools import sign_deployment_jwt
from .route import RouteConsistencyError, build_route_payload

MIN_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 60.0
CONNECTOR_VERSION = "1.0"


def _server_version() -> str:
    try:
        from importlib.metadata import version

        return version("remoteRF-server")
    except Exception:
        return "unknown"


class GlobalConnector:
    def __init__(
        self,
        *,
        cfg: GlobalConfig,
        state_dir: Path,
        cert_dir: Path,
        get_known_device_ids: Callable[[], set],
    ):
        self._cfg = cfg
        self._state_dir = Path(state_dir)
        self._cert_dir = Path(cert_dir)
        self._get_known_device_ids = get_known_device_ids
        self._client = GlobalApiClient(cfg.base_url)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._backoff = MIN_BACKOFF_SECONDS
        self._instance_id = str(uuid.uuid4())

    def start(self) -> None:
        if self._thread is not None:
            return
        state = identity_mod.load_state(self._state_dir)
        if not state.enrolled:
            raise RuntimeError(
                "deployment is not enrolled; run 'serverrf --global enroll' first"
            )
        self._thread = threading.Thread(
            target=self._run, name="remoterf-global-connector", daemon=True
        )
        self._thread.start()

    def stop(self, *, timeout: float = 2.0) -> None:
        self._stop_event.set()
        if (
            self._thread is not None
            and self._thread.is_alive()
            and self._thread is not threading.current_thread()
        ):
            self._thread.join(timeout=timeout)

    def publish_now(self) -> None:
        self._publish_once(force=True)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            ok = True
            try:
                self._publish_once(force=False)
            except Exception as exc:
                ok = False
                audit_event("connector_publish_failed", error=str(exc)[:200])

            if ok:
                self._backoff = MIN_BACKOFF_SECONDS
                wait_seconds = self._cfg.heartbeat_seconds
            else:
                wait_seconds = self._backoff
                self._backoff = min(MAX_BACKOFF_SECONDS, self._backoff * 2) + random.uniform(0, 1)

            if self._stop_event.wait(wait_seconds):
                break

    def _publish_once(self, *, force: bool) -> None:
        priv = identity_mod.load_private_key(self._state_dir)
        state = identity_mod.load_state(self._state_dir)
        if not state.enrolled:
            raise RuntimeError("deployment is not enrolled")

        audience = f"{self._cfg.base_url}/v1/deployment"

        def new_deployment_jwt() -> str:
            # Global consumes each connector JWT's JTI for replay protection,
            # so route, catalog, and heartbeat must not reuse one token.
            return sign_deployment_jwt(priv, deployment_id=state.deployment_id, audience=audience)

        try:
            route_payload = build_route_payload(
                self._cfg.route,
                ca_crt_path=self._cert_dir / "ca.crt",
                server_crt_path=self._cert_dir / "server.crt",
            )
        except RouteConsistencyError as exc:
            raise GlobalApiError(str(exc)) from exc

        self._client.publish_route(deployment_jwt=new_deployment_jwt(), route_payload=route_payload)

        known_ids = self._get_known_device_ids()
        catalog_payload = build_catalog_payload(self._cfg, known_device_ids=known_ids)
        new_hash = content_hash(catalog_payload)

        from .db import get_global_db

        db = get_global_db()
        version, old_hash = db.get_catalog_state()
        if force or new_hash != old_hash:
            if new_hash != old_hash:
                version += 1
            # The Global HTTP API names this field `catalog_version`; keeping
            # it explicit avoids FastAPI validation failures and makes stale
            # catalog sequencing observable at the wire boundary.
            payload_with_version = dict(catalog_payload, catalog_version=version)
            self._client.publish_catalog(
                deployment_jwt=new_deployment_jwt(), catalog_payload=payload_with_version
            )
            db.set_catalog_state(version=version, content_hash=new_hash)

        metadata = {
            "deployment_id": state.deployment_id,
            "protocol_version": PROTOCOL_VERSION,
            "server_version": _server_version(),
            "connector_version": CONNECTOR_VERSION,
            "catalog_version": version,
            "route_status": "ok",
            "instance_id": self._instance_id,
        }
        self._client.heartbeat(deployment_jwt=new_deployment_jwt(), metadata=metadata)
        audit_event("connector_heartbeat_ok", deployment_id=state.deployment_id, catalog_version=version)
