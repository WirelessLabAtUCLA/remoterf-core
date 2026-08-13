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

# remoteRF_server/tools/gist_status.py

import json
import os
import time
import threading
import requests  

# Create public gist on your github. Keep note of the file name
# https://gist.github.com/ethange1/2a35e08a90bf88a70dfe7f42a55685ed

# The last one is the "GIST_ID" part of the URL, e.g. "2a35e08a90bf88a70dfe7f42a55685ed"

GIST_ID = "2a35e08a90bf88a70dfe7f42a55685ed"      

# Create the GITHUB_TOKEN (so your server can update it)
# GitHub → Settings
# Developer settings
# Personal access tokens → Fine-grained tokens
# Generate new token
# Set repository access to "Public Respositories"
# Permissions: enable Gists: Read and write
# Generate + copy the token (you only see it once)

# LIMIT OF 1 per minute ! BE MINDFUL OF RATE LIMITS! 

GH_TOKEN = ""

FILENAME = "ucla-wlab-remoterf-status.json"

# HOW TO PULL! https://gist.githubusercontent.com/ethange1/2a35e08a90bf88a70dfe7f42a55685ed/raw/ucla-wlab-remoterf-status.json

def build_status() -> dict:
    return {
        "updated_unix": int(time.time()),
    }

def push_gist(payload: dict) -> None:
    url = f"https://api.github.com/gists/{GIST_ID}"
    headers = {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
    }
    body = {
        "files": {
            FILENAME: {
                "content": json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n"
            }
        }
    }
    r = requests.patch(url, headers=headers, json=body, timeout=10)
    print(r.status_code, r.text)
    print("Retry-After:", r.headers.get("Retry-After"))
    print("X-RateLimit-Remaining:", r.headers.get("X-RateLimit-Remaining"))
    r.raise_for_status()

def status_publisher_loop(period_sec: int = 30) -> None:
    while True:
        try:
            push_gist(build_status())
        except Exception as e:
            print(f"[status] publish failed: {e}")
        time.sleep(period_sec)
        
status_publisher_loop(60)

# threading.Thread(target=status_publisher_loop, daemon=True).start()