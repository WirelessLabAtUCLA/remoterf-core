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
Bounded, kid-keyed cache of RemoteRF Global's Ed25519 JWKS
(https://global.remoterf.net/.well-known/jwks.json), used to verify Global
user access assertions.

Trust/rotation model (see docs/remoterf-global-security.md):
  - only OKP/Ed25519 keys are ever accepted; any other kty is skipped.
  - keys are cached by kid for `ttl_seconds`; a normal request never
    refetches within the TTL.
  - an assertion whose kid isn't in the cache triggers exactly one forced
    refresh; if the kid is still unknown afterward, verification fails
    closed.
  - concurrent refreshes are collapsed onto a single in-flight HTTP request
    (a lock, not a queue) so many simultaneous unknown-kid assertions can't
    cause a thundering herd against Global.
  - if Global is unreachable but a previously-cached key is still fresh
    (within ttl_seconds), verification may proceed using it; an unknown key
    with no reachable JWKS endpoint fails closed.
"""

from __future__ import annotations

import base64
import threading
import time
from dataclasses import dataclass
from typing import Optional

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DEFAULT_TTL_SECONDS = 300
DEFAULT_HTTP_TIMEOUT = 5.0


class JWKSFetchError(RuntimeError):
    pass


@dataclass
class _CacheEntry:
    keys: dict  # kid -> Ed25519PublicKey
    fetched_at: float


class JWKSCache:
    def __init__(
        self,
        jwks_url: str,
        *,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        http_timeout: float = DEFAULT_HTTP_TIMEOUT,
    ):
        self._jwks_url = jwks_url
        self._ttl_seconds = ttl_seconds
        self._http_timeout = http_timeout
        self._lock = threading.Lock()
        self._entry: Optional[_CacheEntry] = None

    def _is_fresh(self, entry: Optional[_CacheEntry]) -> bool:
        return entry is not None and (time.monotonic() - entry.fetched_at) < self._ttl_seconds

    def _fetch_locked(self) -> _CacheEntry:
        resp = requests.get(self._jwks_url, timeout=self._http_timeout)
        resp.raise_for_status()
        body = resp.json()
        keys: dict = {}
        for jwk in body.get("keys", []):
            kid = jwk.get("kid")
            if not kid:
                continue
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                # Never accept symmetric keys or any algorithm besides
                # Ed25519/EdDSA, regardless of what the document claims.
                continue
            x = jwk.get("x")
            if not x:
                continue
            padded = x + "=" * (-len(x) % 4)
            try:
                raw = base64.urlsafe_b64decode(padded)
                keys[kid] = Ed25519PublicKey.from_public_bytes(raw)
            except Exception:
                continue
        return _CacheEntry(keys=keys, fetched_at=time.monotonic())

    def _refresh(self) -> None:
        with self._lock:
            # Another thread may have already refreshed while we waited.
            if self._is_fresh(self._entry):
                return
            try:
                self._entry = self._fetch_locked()
            except Exception as exc:
                if self._entry is None:
                    raise JWKSFetchError(str(exc)) from exc
                # Keep serving the stale cache; caller's freshness/kid
                # checks decide whether that's acceptable.

    def get_key(self, kid: str) -> Optional[Ed25519PublicKey]:
        entry = self._entry
        if self._is_fresh(entry) and kid in entry.keys:
            return entry.keys[kid]

        # Unknown kid (or fully expired cache): one forced refresh.
        try:
            self._refresh()
        except JWKSFetchError:
            # No cache at all and Global unreachable: fail closed.
            return None

        entry = self._entry
        if entry is None:
            return None
        return entry.keys.get(kid)
