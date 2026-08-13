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

import os
import hashlib
import base64
import secrets
from dotenv import load_dotenv, find_dotenv

def generate_token(length=8) -> tuple[str, str, str]:
    random_bytes = secrets.token_bytes(length)  
    token = base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')  # Encode in base64 format
    salt = os.urandom(16).hex()  # 16 bytes of random salt
    hashed = hashlib.sha256(bytes.fromhex(salt) + token.encode()).hexdigest()  # Hash to sha256 standard
    return salt, hashed, token

def validate_token(salt, hash, token) -> bool:
    new_hashed = hashlib.sha256(bytes.fromhex(salt) + token.encode()).hexdigest()
    return new_hashed == hash

def hash_token(token: str) -> tuple[str, str]:
    salt = os.urandom(16).hex()
    hashed = hashlib.sha256(bytes.fromhex(salt) + token.encode()).hexdigest()
    return salt, hashed