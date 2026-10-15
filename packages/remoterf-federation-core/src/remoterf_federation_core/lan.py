"""The lab login a Global account gets at each lab it joined by code.

The lab never sees the Global password. A client sends a lab `lan_secret`,
derived from the password and bound to that lab's deployment id, and the lab
stores only a PBKDF2 verifier of it -- the same format as any lab password,
so a lab checks it like one, online or with Global down. What a lab learns
is useless at Global (which checks the password itself) and at other labs
(their deployment ids differ).
"""

from __future__ import annotations

import hashlib
import os
import re

from .schemas import ValidationError, canonical_uuid

LAN_SALT_PREFIX = b"remoterf-lan-v1\0"
LAN_PBKDF2_ROUNDS = 210_000
# A verifier from Global sets the lab's KDF cost; bound it so a bad issuer
# cannot make every lab login burn CPU.
MAX_LAN_PBKDF2_ROUNDS = 2_000_000
LAN_USERNAME_RE = re.compile(r"[a-z0-9_.-]{3,64}")
_SALT_RE = re.compile(r"[0-9a-f]{32}")
_HASH_RE = re.compile(r"pbkdf2\$([0-9]{6,7})\$[0-9a-f]{64}")


def lan_secret(password: str, deployment_id: str, username: str) -> str:
    """What a client sends a linked lab instead of the password (64 hex chars)."""
    salt = LAN_SALT_PREFIX + canonical_uuid(deployment_id).encode() + b"\0" + username.lower().encode()
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32).hex()


def lan_verifier(secret: str) -> tuple[str, str]:
    """(salt, hash) a lab stores for `secret`, in its own password format."""
    salt = os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac("sha256", secret.encode(), bytes.fromhex(salt), LAN_PBKDF2_ROUNDS)
    return salt, f"pbkdf2${LAN_PBKDF2_ROUNDS}${digest.hex()}"


def validate_lan_credential(username: object, salt: object, hashed: object) -> dict:
    """The `username`/`lan_salt`/`lan_hash` an enroll may carry, checked together."""
    if type(username) is not str or not LAN_USERNAME_RE.fullmatch(username):
        raise ValidationError("invalid_enrollee")
    if type(salt) is not str or not _SALT_RE.fullmatch(salt):
        raise ValidationError("invalid_enrollee")
    match = _HASH_RE.fullmatch(hashed) if type(hashed) is str else None
    if match is None or not LAN_PBKDF2_ROUNDS <= int(match.group(1)) <= MAX_LAN_PBKDF2_ROUNDS:
        raise ValidationError("invalid_enrollee")
    return {"username": username, "lan_salt": salt, "lan_hash": hashed}


def held_keys(username: str, email: str) -> tuple[str, str]:
    """A lab account as Global sees it in that lab's status note ("held"):
    (name key, email key), 12 hex each. Unreadable, but a clash shows."""
    def key(kind: str, value: str) -> str:
        return hashlib.sha256(f"{kind}\0{value.strip().lower()}".encode()).hexdigest()[:12]

    return key("name", username), key("email", email)
