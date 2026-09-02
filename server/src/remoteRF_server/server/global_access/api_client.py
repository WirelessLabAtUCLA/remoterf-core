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
Typed HTTP client for the RemoteRF Global VPS API.

IMPORTANT: as of this writing, `remoterf-vps-global` implements only
`GET /` and `GET /health` — none of the endpoints below exist yet anywhere.
This module is the single, isolated place that assumes a contract for them
(POST /v1/deployment/enroll, /v1/deployment/heartbeat,
PUT /v1/deployment/route, PUT /v1/deployment/catalog,
GET /.well-known/jwks.json), documented in
docs/remoterf-global-server-v1.md. No other module in this codebase talks
HTTP to Global directly — this is where that assumption gets corrected once
the real API exists.

Never disables TLS verification (no verify=False anywhere) and never logs
request/response bodies or the Authorization header.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import requests

DEFAULT_TIMEOUT_SECONDS = 5.0


class GlobalApiError(RuntimeError):
    def __init__(self, message: str, *, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class EnrollResult:
    deployment_id: str
    slug: str
    issuer: str
    api_base_url: str
    supported_protocol_version: str


class GlobalApiClient:
    def __init__(self, base_url: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(self, method: str, path: str, *, json_body: dict, headers: Optional[dict] = None) -> dict:
        url = f"{self.base_url}{path}"
        try:
            resp = requests.request(
                method, url, json=json_body, timeout=self.timeout, headers=headers or {}
            )
        except requests.RequestException as exc:
            raise GlobalApiError(f"request to {path} failed: {exc}") from exc

        if resp.status_code >= 400:
            raise GlobalApiError(
                f"{method} {path} returned HTTP {resp.status_code}",
                status_code=resp.status_code,
            )
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError as exc:
            raise GlobalApiError(f"{method} {path} returned a non-JSON response") from exc

    def enroll(
        self,
        *,
        enrollment_token: str,
        slug: str,
        display_name: str,
        public_key_b64: str,
        protocol_version: str,
    ) -> EnrollResult:
        data = self._request(
            "POST",
            "/v1/deployment/enroll",
            json_body={
                "enrollment_token": enrollment_token,
                "slug": slug,
                "display_name": display_name,
                "public_key": public_key_b64,
                "protocol_version": protocol_version,
            },
        )
        if "deployment_id" not in data:
            raise GlobalApiError("enroll response missing 'deployment_id'")
        return EnrollResult(
            deployment_id=str(data["deployment_id"]),
            slug=str(data.get("slug", slug)),
            issuer=str(data.get("issuer", self.base_url)),
            api_base_url=str(data.get("api_base_url", self.base_url)),
            supported_protocol_version=str(data.get("supported_protocol_version", protocol_version)),
        )

    def heartbeat(self, *, deployment_jwt: str, metadata: dict) -> dict:
        return self._request(
            "POST",
            "/v1/deployment/heartbeat",
            json_body=metadata,
            headers={"Authorization": f"Bearer {deployment_jwt}"},
        )

    def publish_route(self, *, deployment_jwt: str, route_payload: dict) -> dict:
        return self._request(
            "PUT",
            "/v1/deployment/route",
            json_body=route_payload,
            headers={"Authorization": f"Bearer {deployment_jwt}"},
        )

    def publish_catalog(self, *, deployment_jwt: str, catalog_payload: dict) -> dict:
        return self._request(
            "PUT",
            "/v1/deployment/catalog",
            json_body=catalog_payload,
            headers={"Authorization": f"Bearer {deployment_jwt}"},
        )
