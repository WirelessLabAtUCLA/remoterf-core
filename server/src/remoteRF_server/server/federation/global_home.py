"""A standing contract with the RemoteRF Global account home.

Students who register on Global (no lab code) join this lab with its
ordinary invite codes and reach its devices; that enrolment travels under a
contract between Global's account home and this lab. Global approved this
lab by hand, so the contract needs no second human: this lab proposes it on
the Global tick and the home accepts on its own. The cluster module's
contract machinery does the work; this file only names the party.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import requests
from remoterf_federation_core import validate_trusted_key_material

from .. import global_onboarding as g
from . import cluster

STATE_FILE = "global_home.json"
IDENTITY_PATH = "/.well-known/remoterf-identity"
IDENTITY_TTL = 86400
LABEL = "RemoteRF Global"


def _path() -> Path:
    return cluster._state_path().with_name(STATE_FILE)


def load() -> dict:
    try:
        return json.loads(_path().read_text())
    except (OSError, ValueError):
        return {}


def save(state: dict) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True))


def fetch_identity() -> dict:
    """Global's signing key, as the account home publishes it."""
    response = requests.get(g.broker_origin() + IDENTITY_PATH, timeout=10.0, allow_redirects=False)
    response.raise_for_status()
    return validate_trusted_key_material(response.json())


def contract_id() -> str | None:
    party = load().get("party") or {}
    return party.get("contract_id") if party.get("state") == "active" else None


def tick(notify=None) -> None:
    """One pass: pin Global's key, propose once, then advance until active."""
    notify = notify or (lambda text: None)
    if not g.participating() or g.state() != "active":
        return
    state = load()
    now = int(time.time())
    if not state.get("identity") or now - int(state.get("identity_at", 0)) > IDENTITY_TTL:
        state["identity"] = fetch_identity()
        state["identity_at"] = now
        save(state)
    home = state["identity"]
    cluster._pin(home, source="broker_candidate")  # Global vouches for its own home
    cluster._pin_self()
    party = state.setdefault("party", {"state": "created", "display_name": LABEL})
    if party.get("state") == "revoked":
        return  # ended on Global's side; an operator decides what happens next
    if not party.get("contract_id"):
        cluster._contract_with(party, home)
    directory = g.call("GET", "/v2/broker/contracts")["contracts"]
    # ponytail: no renewal when the contract runs out (CONTRACT_DAYS); clusters
    # share that ceiling, so one renewal pass can serve both.
    cluster._advance(party, home["deployment_id"], directory, label=LABEL, notify=notify, is_member=False)
    save(state)
