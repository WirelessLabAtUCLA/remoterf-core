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
Durable per-deployment Ed25519 identity, separate from TLS certificates,
HostRF host tokens, Global user assertions, and local RemoteRF account
tokens.

Files (under the caller-supplied state dir, normally
``~/.config/remoterf/global/``):

  deployment-private.pem   0600, Ed25519 private key. NEVER printed/logged.
  deployment-public.pem    Ed25519 public key (safe to share/print).
  deployment.json          non-secret enrollment state (deployment_id, slug,
                            display_name, protocol_version, enrolled_at,
                            issuer, api_base_url).
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROTOCOL_VERSION = "1.0"

PRIVATE_KEY_FILENAME = "deployment-private.pem"
PUBLIC_KEY_FILENAME = "deployment-public.pem"
STATE_FILENAME = "deployment.json"


class IdentityError(RuntimeError):
    pass


@dataclass
class DeploymentState:
    deployment_id: Optional[str] = None
    slug: Optional[str] = None
    display_name: Optional[str] = None
    protocol_version: str = PROTOCOL_VERSION
    enrolled_at: Optional[str] = None
    issuer: Optional[str] = None
    api_base_url: Optional[str] = None

    @property
    def enrolled(self) -> bool:
        return bool(self.deployment_id)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "DeploymentState":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})


def private_key_path(state_dir: Path) -> Path:
    return Path(state_dir) / PRIVATE_KEY_FILENAME


def public_key_path(state_dir: Path) -> Path:
    return Path(state_dir) / PUBLIC_KEY_FILENAME


def state_path(state_dir: Path) -> Path:
    return Path(state_dir) / STATE_FILENAME


def identity_exists(state_dir: Path) -> bool:
    return private_key_path(state_dir).exists()


def init_identity(state_dir: Path, *, force: bool = False) -> Path:
    """
    Generate a new Ed25519 deployment keypair + empty (unenrolled)
    deployment.json. Refuses to overwrite an existing identity unless
    ``force`` is explicitly set (there is no CLI path that ever passes
    force=True — an operator must delete the files themselves first, so
    this is deliberately not exposed as a flag on ``serverrf global
    init-identity``).
    """
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)

    priv_path = private_key_path(state_dir)
    if priv_path.exists() and not force:
        raise IdentityError(
            f"deployment identity already exists at {priv_path}; refusing to "
            "overwrite. Remove it manually first if you really intend to "
            "generate a new identity (this changes your deployment's "
            "cryptographic identity — re-enrollment will be required)."
        )

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_pem)
    os.chmod(priv_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600

    public_key_path(state_dir).write_bytes(pub_pem)

    sp = state_path(state_dir)
    if not sp.exists():
        sp.write_text(json.dumps(DeploymentState().to_dict(), indent=2) + "\n", encoding="utf-8")

    return priv_path


def load_private_key(state_dir: Path) -> Ed25519PrivateKey:
    p = private_key_path(state_dir)
    if not p.exists():
        raise IdentityError(
            f"no deployment identity at {p}; run 'serverrf global init-identity' first"
        )
    data = p.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise IdentityError(f"{p} does not contain an Ed25519 private key")
    return key


def public_key_b64(state_dir: Path) -> str:
    """Raw 32-byte Ed25519 public key, base64url-encoded (no padding) —
    the form suitable for a JWK 'x' field / enrollment payload."""
    import base64

    priv = load_private_key(state_dir)
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def public_key_pem(state_dir: Path) -> str:
    p = public_key_path(state_dir)
    if not p.exists():
        raise IdentityError(f"no public key at {p}")
    return p.read_text(encoding="utf-8")


def load_state(state_dir: Path) -> DeploymentState:
    p = state_path(state_dir)
    if not p.exists():
        return DeploymentState()
    try:
        return DeploymentState.from_dict(json.loads(p.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, OSError) as exc:
        raise IdentityError(f"could not read deployment state {p}: {exc}") from exc


def save_state(state_dir: Path, state: DeploymentState) -> None:
    p = state_path(state_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state.to_dict(), indent=2) + "\n", encoding="utf-8")
