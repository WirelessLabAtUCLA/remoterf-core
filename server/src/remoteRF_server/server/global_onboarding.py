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

"""RemoteRF Global participation: consent, deployment request, relay, status.

Everything this module sends is one-way and signed by the deployment's own
Ed25519 identity.  Global is never authoritative for this deployment's trust,
contracts, accounts, or reservations, and never connects inward.

State lives in ``<config dir>/global.env``:

  GLOBAL_CONSENT    yes | no          answered once at first run
  GLOBAL_NAME       requested slug
  GLOBAL_EMAIL      contact address for a human admin
  GLOBAL_STATE      unregistered | requested | active | rejected
                    | suspended | left | expired | unknown
"""

from __future__ import annotations

import atexit
import contextvars
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$")

RELAY_KEY_FILENAME = "relay_ed25519"

CONSENT_TEXT = """\
Joining RemoteRF Global gives your lab a public address,
<name>.{domain}, so your users can reach it from anywhere
instead of only from your network. When they are on your network the
client still prefers the LAN, so nothing local gets slower.

It is also how labs work together. Once you and another deployment sign
an agreement, your users can reserve instruments there and theirs can
reserve yours, whether that lab is down the hall or on another
continent. Each partnership is arranged deliberately, one at a time,
with one exception: instruments a lab has opened to everyone on Global
reach your users as soon as you are in (`cluster remove` leaves such a
cluster). Joining Global shares none of your hardware on its own.

Once an hour it sends Global a short note: this deployment's name and
ID, version, uptime, how many accounts, what devices it has, how many
reservations are active, and your LAN address. Nothing else leaves your
server -- no credentials, no user or reservation details -- and the
connection only goes outward.

A RemoteRF admin reviews each new lab by hand, so there is a short wait
before your address goes live. You can join or leave whenever you like:

    serverrf global join
    serverrf global leave"""


# -----------------------------
# Locations and tiny env I/O
# -----------------------------

def domain() -> str:
    return os.getenv("REMOTERF_GLOBAL_DOMAIN", "global.remoterf.net")


def broker_origin() -> str:
    return os.getenv("REMOTERF_GLOBAL_ORIGIN", "https://" + domain()).rstrip("/")


def cfg_dir() -> Path:
    return Path(
        os.getenv(
            "REMOTERF_CONFIG_DIR",
            Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config")) / "remoterf",
        )
    )


def global_env_path() -> Path:
    return cfg_dir() / "global.env"


def identity_dir() -> Path:
    """The deployment's Ed25519 identity directory.

    Honours an explicit override, then the federation config already in use on
    a federated deployment, then the packaged default.
    """
    override = os.getenv("REMOTERF_FEDERATION_IDENTITY_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    config_path = os.getenv("REMOTERF_FEDERATION_CONFIG_PATH", "").strip()
    if config_path:
        try:
            import yaml

            value = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
            if type(value) is dict and type(value.get("identity_dir")) is str:
                return Path(value["identity_dir"]).expanduser()
        except Exception:
            pass
    share = Path(os.getenv("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return share / "remoterf" / "federation-v2" / "identity"


def read_env_kv(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def write_env_kv(path: Path, kv: Dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for k, v in kv.items():
        v = str(v)
        if any(c.isspace() for c in v) or any(c in v for c in ['"', "'"]):
            lines.append('{}="{}"'.format(k, v.replace('"', '\\"')))
        else:
            lines.append(f"{k}={v}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load() -> Dict[str, str]:
    return read_env_kv(global_env_path())


def update(**kv: str) -> Dict[str, str]:
    current = load()
    current.update({k: str(v) for k, v in kv.items()})
    write_env_kv(global_env_path(), current)
    return current


def state() -> str:
    return load().get("GLOBAL_STATE", "unregistered")


def participating() -> bool:
    return load().get("GLOBAL_CONSENT", "").lower() == "yes"


def hostname() -> Optional[str]:
    kv = load()
    name = kv.get("GLOBAL_FINAL_NAME") or kv.get("GLOBAL_NAME")
    return f"{name}.{domain()}" if name else None


def account_name(username: str) -> str:
    """A local account's full name: `alice@ucla` on Global, else just `alice`."""
    kv = load()
    name = kv.get("GLOBAL_FINAL_NAME") or kv.get("GLOBAL_NAME")
    return f"{username}@{name}" if name and state() == "active" else username


def invite(code_name: str, *, lan_only: bool = False) -> str:
    """What to hand a new user: the form `remoterf --register` accepts.

    On a live Global deployment that is `<public hostname>/<code>`, which the
    client resolves to this server from anywhere. A LAN-only group's code (or
    a deployment that is not on Global) is the bare code, entered after
    `remoterf -c -a <lan address>`.
    """
    if state() == "active" and not lan_only and hostname():
        return f"{hostname()}/{code_name}"
    return code_name


# -----------------------------
# Identity + relay key material
# -----------------------------

def ensure_identity() -> Path:
    """Ed25519 federation identity (idempotent) plus a relay transport key."""
    from .federation.identity import identity_exists, init_identity

    directory = identity_dir()
    if not identity_exists(directory):
        init_identity(directory)
    ensure_relay_key(directory)
    return directory


def relay_key_path(directory: Optional[Path] = None) -> Path:
    return (directory or identity_dir()) / RELAY_KEY_FILENAME


def ensure_relay_key(directory: Optional[Path] = None) -> Path:
    """Generate the restricted reverse-tunnel keypair if it is missing.

    Separate from the federation signing key on purpose: the transport key is
    handed to the relay host's authorized_keys, the signing key never leaves.
    """
    directory = Path(directory or identity_dir())
    directory.mkdir(parents=True, exist_ok=True)
    key = relay_key_path(directory)
    if not key.exists():
        subprocess.run(
            [
                "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                "remoterf-relay", "-f", str(key),
            ],
            check=True,
        )
        os.chmod(key, 0o600)
    return key


def relay_public_key(directory: Optional[Path] = None) -> str:
    return relay_key_path(directory).with_suffix(".pub").read_text(
        encoding="utf-8"
    ).strip()


# -----------------------------
# Name availability
# -----------------------------

def name_available(name: str, *, timeout: float = 5.0) -> Optional[bool]:
    """True/False, or None when Global could not be reached at all."""
    import requests

    try:
        response = requests.get(
            f"{broker_origin()}/v2/broker/deployments/names/{name}",
            timeout=timeout,
            allow_redirects=False,
        )
        response.raise_for_status()
        return response.json()["status"] == "available"
    except Exception:
        return None


# -----------------------------
# First-run consent
# -----------------------------

def _hint(text: str) -> None:
    """Secondary information: present, but not competing with the prompt."""
    from ..common.utils.ansi_codes import Sty, printf

    printf(text, Sty.GRAY)


def _warn(text: str) -> None:
    """A correction the operator has to act on."""
    from ..common.utils.ansi_codes import Sty, printf

    printf(text, Sty.WARNING)


def _ask(prompt: str) -> str:
    return input(prompt).strip()


def _confirm(question: str, *, default: bool | None = None):
    from ..common.utils.panel import confirm

    return confirm(question, default=default)


def _prompt_name() -> Optional[str]:
    while True:
        name = _ask("  Deployment name: ").lower()
        if not NAME_RE.match(name):
            _warn(
                "  Use 3-32 characters: lowercase letters, digits and dashes, "
                "starting and ending with a letter or digit."
            )
            continue
        available = name_available(name)
        if available is False:
            _warn(f"  {name} is already registered on RemoteRF Global. Choose another name:")
            continue
        if available is None:
            _hint("  Could not reach RemoteRF Global; the name will be re-checked when you join.")
        _hint(f"  You will appear as {name}.{domain()} once approved.")
        return name


def _prompt_display_name(default: str) -> str:
    """A human-readable lab name. It is what a RemoteRF admin sees when they
    review the request, and what your users see in the client."""
    name = _ask(f"  Display name [{default}]: ") or default
    return name[:200] if all(ord(c) >= 32 and ord(c) != 127 for c in name) else default


def _prompt_email() -> str:
    while True:
        email = _ask("  Contact email: ")
        if EMAIL_RE.match(email):
            return email
        _warn("  That does not look like an email address.")


def configure() -> bool:
    """Interactive deployment configuration; writes global.env on success."""
    name = _prompt_name()
    if name is None:
        return False
    display_name = _prompt_display_name(name)
    email = _prompt_email()
    update(
        GLOBAL_CONSENT="yes",
        GLOBAL_NAME=name,
        GLOBAL_DISPLAY_NAME=display_name,
        GLOBAL_EMAIL=email,
        GLOBAL_STATE="unregistered",
    )
    ensure_identity()
    return True


def submit_and_report() -> bool:
    """Send the request and tell the operator where it stands."""
    from ..common.utils.panel import marker, print_panel

    while True:
        try:
            submit_request()
        except GlobalError as exc:
            if exc.code == "name_taken":
                _warn(f"  {load().get('GLOBAL_NAME')} was just taken on RemoteRF Global.")
                name = _prompt_name()
                if name is None:
                    return False
                update(GLOBAL_NAME=name)
                continue
            _warn(f"  RemoteRF Global refused the request: {exc.code}")
            _hint("  This server keeps working on your network. Retry with "
                  "`serverrf global join`.")
            return False
        except Exception as exc:  # noqa: BLE001 - network/transport
            _warn(f"  Could not reach RemoteRF Global: {exc}")
            _hint("  This server keeps working on your network. Retry with "
                  "`serverrf global join`.")
            return False
        break

    kv = load()
    print()
    print_panel(
        "One more step",
        [
            f"{marker()} Requested as {kv.get('GLOBAL_NAME')}. Once a RemoteRF "
            f"admin approves, they email a code to {kv.get('GLOBAL_EMAIL')}. "
            "Redeeming it puts you live:",
            "",
            "    serverrf global verify <code>",
        ],
    )
    print()
    return True


def ensure_consent() -> bool:
    """Ask once, at first run, immediately after the Terms of Service.

    Returns False only when the operator aborted the prompt outright; a plain
    "no" is a complete, durable answer and the server starts normally.
    """
    if load().get("GLOBAL_CONSENT", "").lower() in {"yes", "no"}:
        return True
    if sys.stdin is None or not sys.stdin.isatty():
        # A service start (--headless under systemd) has no one to answer:
        # start outside Global and ask at the next start from a terminal.
        print("RemoteRF Global participation not asked (no terminal); `serverrf global join` joins.")
        return True
    from ..common.utils.panel import print_panel

    print()
    print_panel("RemoteRF Global participation", CONSENT_TEXT.format(domain=domain()))
    print()
    joined = _confirm("Join RemoteRF Global?")
    if joined is None:
        print("\n  RemoteRF Global participation is unanswered; leaving it unset.")
        return False
    if not joined:
        update(GLOBAL_CONSENT="no")
        return True
    if not configure():
        return False
    # Submitting here rather than leaving it to the background agent: the
    # operator just answered four questions and deserves an answer back.
    submit_and_report()
    return True


# -----------------------------
# Signed broker calls
# -----------------------------

BROKER_DEPLOYMENT_ID = os.getenv(
    "REMOTERF_GLOBAL_BROKER_ID", "9ec4601e-6b0b-4fed-9e8e-e16e3dd86431"
)
REQUEST_PATH = "/v2/broker/deployments/request"
VERIFY_PATH = "/v2/broker/deployments/verify"
ME_PATH = "/v2/broker/deployments/me"
LEAVE_PATH = "/v2/broker/deployments/leave"
REPORT_PATH = "/v2/broker/deployments/report"


class GlobalError(RuntimeError):
    """A refusal that came from Global, carrying its stable error code."""

    def __init__(self, code: str, message: str = ""):
        self.code = code
        super().__init__(message or code)


def _signing_material():
    """(private key, kid, deployment uuid-or-None) from the durable identity."""
    import hashlib

    from cryptography.hazmat.primitives import serialization

    from .federation.identity import load_private_key, load_state

    directory = ensure_identity()
    key = load_private_key(directory)
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    kid = hashlib.sha256(raw).hexdigest()[:32]
    return key, kid, load_state(directory).deployment_id


def _bearer(key, kid, deployment_id, *, method: str, path: str, body: bytes) -> str:
    import hashlib
    import time
    from uuid import uuid4

    import jwt
    from remoterf_federation_core import (
        BROKER_REQUEST_TYP,
        build_broker_request_claims,
    )

    now = int(time.time())
    claims = build_broker_request_claims(
        deployment_id=deployment_id,
        broker_deployment_id=BROKER_DEPLOYMENT_ID,
        method=method,
        path=path,
        body_sha256=hashlib.sha256(body).hexdigest(),
        issued_at=now,
        expires_at=now + 60,
        jti=str(uuid4()),
    )
    return jwt.encode(
        claims,
        key,
        algorithm="EdDSA",
        headers={"typ": BROKER_REQUEST_TYP, "kid": kid},
    )


def call(method: str, path: str, payload: Optional[dict] = None, *, timeout: float = 10.0):
    """One signed, one-way broker call. Raises GlobalError on a refusal."""
    import json
    from uuid import uuid4

    import requests

    key, kid, deployment_id = _signing_material()
    body = b"" if payload is None else json.dumps(payload).encode()
    if deployment_id is None:
        # Pre-approval there is no broker-issued identity yet; the request is
        # self-signed and Global binds this UUID to the key it carries.
        deployment_id = load().get("GLOBAL_DEPLOYMENT_ID") or str(uuid4())
        update(GLOBAL_DEPLOYMENT_ID=deployment_id)
    token = _bearer(key, kid, deployment_id, method=method, path=path, body=body)
    response = requests.request(
        method,
        broker_origin() + path,
        data=body if payload is not None else None,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept-Encoding": "identity",
        },
        timeout=timeout,
        allow_redirects=False,
    )
    if response.status_code >= 400:
        try:
            error = response.json()["error"]
        except Exception:  # noqa: BLE001
            raise GlobalError("http_" + str(response.status_code))
        raise GlobalError(error.get("code", "unknown"), error.get("message", ""))
    return response.json() if response.content else {}


def server_version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    for name in ("remoterf-server", "remoteRF-server", "remoterf_server"):
        try:
            return version(name)
        except PackageNotFoundError:
            continue
    return "unknown"


def lan_endpoint() -> Optional[str]:
    """host:port this Server answers on inside its own network."""
    env = read_env_kv(cfg_dir() / "server.env")
    port = env.get("GRPC_PORT", "12321")
    host = env.get("STATIC_IP") or env.get("SERVER_IP") or detected_lan_ip()
    return f"{host}:{port}" if host else None


# -----------------------------
# Where a call came from
# -----------------------------

# True while serving a call that arrived through the Global relay (or from a
# federation peer). LAN-only groups do not exist to such a call.
RELAYED = contextvars.ContextVar("remoterf_relayed", default=False)


def is_relayed(peer: str) -> bool:
    """Whether a gRPC peer string reached this Server through the relay.

    Relayed connections are opened by this machine's own ssh tunnel child, so
    they arrive from exactly the address the tunnel forwards to -- a source a
    client elsewhere on the LAN can never have. A client run on the Server box
    itself looks relayed too; that fails closed for LAN-only groups.
    """
    host = peer.split(":", 1)[1] if peer.startswith(("ipv4:", "ipv6:")) else peer
    host = host.rsplit(":", 1)[0].strip("[]")
    if host.startswith("::ffff:"):
        host = host[len("::ffff:"):]
    return host in {local_bind_host(), "127.0.0.1", "::1"}


def is_offsite(host: str) -> bool:
    """Whether a direct-path (Gate I) peer address lies outside this network.

    Such a peer is treated exactly like a relayed one. Loopback, link-local,
    RFC 1918 and the /24 of this machine's LAN address count as local; an
    IPv6 ULA does not, because VPN overlays hand those out too (fail closed).
    ponytail: /24 heuristic, refine with a real mask when a deployment needs it.
    """
    import ipaddress

    try:
        addr = ipaddress.ip_address(host.removeprefix("::ffff:"))
    except ValueError:
        return True
    if addr.is_loopback or addr.is_link_local:
        return False
    if addr.version == 6:
        return True
    if addr.is_private:
        return False
    try:
        return addr not in ipaddress.ip_network(
            f"{detected_lan_ip() or local_bind_host()}/24", strict=False
        )
    except ValueError:
        return True


def lan_only_hint(what: str) -> str:
    """The refusal a relayed caller sees for LAN-only material."""
    return (
        f"{what} only works from the lab network. Connect directly instead: "
        f"remoterf -c -a {lan_endpoint() or '<server LAN address>'}"
    )


def submit_request() -> dict:
    kv = load()
    payload = {
        "name": kv["GLOBAL_NAME"],
        "display_name": kv.get("GLOBAL_DISPLAY_NAME") or kv["GLOBAL_NAME"],
        "email": kv["GLOBAL_EMAIL"],
        "public_key": _public_key_b64(),
        "ssh_public_key": relay_public_key(),
        "lan_address": lan_endpoint(),
        "server_version": server_version(),
    }
    result = call("POST", REQUEST_PATH, payload)
    _apply_me(result)
    return result


def verify_contact(code: str) -> dict:
    """Prove the contact address with the code Global emailed to it."""
    result = call("POST", VERIFY_PATH, {"code": code})
    _apply_me(result)
    return result


def fetch_me() -> dict:
    try:
        result = call("GET", ME_PATH)
    except GlobalError as exc:
        # Global lost (or never had) this deployment: polling again cannot
        # fix it, only a re-join can. The identity is kept so the re-request
        # is keyed by the same issuer UUID.
        if exc.code == "unknown_deployment" and state() != "unknown":
            update(GLOBAL_STATE="unknown")
            _warn("  RemoteRF Global has no record of this deployment; "
                  "the relay stops. Run `serverrf global join` to re-register.")
        raise
    _apply_me(result)
    return result


def _public_key_b64() -> str:
    from .federation.identity import public_key_b64

    return public_key_b64(ensure_identity())


def _record_enrollment(deployment_id: str) -> None:
    """deployment.json is what the federation runtime binds to; it is written
    once, and a different id from Global is refused rather than adopted."""
    from datetime import datetime, timezone

    from .federation.identity import load_state, save_state

    directory = ensure_identity()
    state = load_state(directory)
    if state.deployment_id and state.deployment_id != deployment_id:
        raise GlobalError(
            "deployment_id_changed",
            f"Global answered with deployment {deployment_id}, but this "
            f"deployment is enrolled as {state.deployment_id}",
        )
    kv = load()
    state.deployment_id = deployment_id
    state.display_name = kv.get("GLOBAL_DISPLAY_NAME") or kv.get("GLOBAL_NAME")
    state.enrolled_at = state.enrolled_at or datetime.now(timezone.utc).isoformat()
    save_state(directory, state)


def _apply_me(result: dict) -> None:
    """Record what Global decided. The final name may differ from the request."""
    fields = {"GLOBAL_STATE": result["status"]}
    if result.get("deployment_id"):
        _record_enrollment(result["deployment_id"])
        fields["GLOBAL_DEPLOYMENT_ID"] = result["deployment_id"]
    if result.get("name"):
        fields["GLOBAL_FINAL_NAME"] = result["name"]
    if result.get("reason"):
        fields["GLOBAL_REASON"] = result["reason"]
    relay = result.get("relay")
    if relay:
        fields.update(
            GLOBAL_RELAY_HOSTNAME=relay["hostname"],
            GLOBAL_RELAY_TUNNEL_HOST=relay["tunnel_host"],
            GLOBAL_RELAY_TUNNEL_PORT=str(relay["tunnel_port"]),
            GLOBAL_RELAY_TUNNEL_USER=relay["tunnel_user"],
            GLOBAL_RELAY_HOST_KEY=relay["tunnel_host_key"],
            GLOBAL_RELAY_GRPC_PORT=str(relay["grpc_port"]),
            GLOBAL_RELAY_CERT_PORT=str(relay["cert_port"]),
        )
    update(**fields)


# -----------------------------
# The consented status report
# -----------------------------

# Exactly the fields the first-run consent text promises, plus cert_sha256 --
# public certificate material a client already sees when it connects, used by
# discovery to pin the deployment. Nothing may be added here without changing
# CONSENT_TEXT: test_report_payload_matches_the_consent_text enforces that.
STATUS_FIELDS = frozenset(
    {
        "server_version",
        "uptime_s",
        "users",
        "devices",
        "active_reservations",
        "lan_address",
        "cert_sha256",
    }
)

_STARTED_AT = None


def _uptime_seconds() -> int:
    import time

    global _STARTED_AT
    if _STARTED_AT is None:
        _STARTED_AT = time.monotonic()
    return int(time.monotonic() - _STARTED_AT)


def _db_dir() -> Path:
    return cfg_dir() / "db"


def _count(database: Path, sql: str, params=()) -> int:
    import sqlite3

    if not database.exists():
        return 0
    try:
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=2.0) as db:
            return int(db.execute(sql, params).fetchone()[0])
    except sqlite3.Error:
        return 0


def device_summary() -> list:
    """One entry per registered device: its type and whether it is connected.

    Types and counts only — never a device identifier, serial, or any data.
    """
    import yaml

    path = cfg_dir() / "devices.yml"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        devices = data.get("devices") or []
    except (OSError, yaml.YAMLError):
        return []
    try:
        from . import device_manager

        connected = set(device_manager.get_all_devices())
    except Exception:  # noqa: BLE001 - drivers are optional at report time
        connected = set()
    summary = []
    for item in devices:
        if type(item) is not dict or "device_id" not in item:
            continue
        summary.append(
            {
                "type": str(item.get("device_type") or "unknown").lower(),
                "online": int(item["device_id"]) in connected,
            }
        )
    return summary


def cert_sha256() -> Optional[str]:
    import hashlib

    path = Path(os.getenv("REMOTERF_CERT_DIR", cfg_dir() / "certs")) / "ca.crt"
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def status_payload() -> dict:
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    reservations = _db_dir() / "reservations.db"
    payload = {
        "server_version": server_version(),
        "uptime_s": _uptime_seconds(),
        "users": _count(reservations, "SELECT COUNT(*) FROM Accounts"),
        "devices": device_summary(),
        "active_reservations": _count(
            reservations,
            "SELECT COUNT(*) FROM Reservations WHERE start_time <= ? AND end_time > ?",
            (now, now),
        ),
        "lan_address": lan_endpoint(),
        "cert_sha256": cert_sha256(),
    }
    assert set(payload) == STATUS_FIELDS  # the consent text is the contract
    return payload


def send_liveness() -> None:
    from datetime import datetime, timezone

    call("POST", REPORT_PATH, {"kind": "liveness"})
    update(GLOBAL_LAST_SEEN_AT=datetime.now(timezone.utc).isoformat())


def send_status() -> None:
    from datetime import datetime, timezone

    call("POST", REPORT_PATH, {"kind": "status", "status": status_payload()})
    update(GLOBAL_LAST_REPORT_AT=datetime.now(timezone.utc).isoformat())


# -----------------------------
# Reverse tunnel (supervised child)
# -----------------------------

def local_ports() -> tuple[int, int]:
    env = read_env_kv(cfg_dir() / "server.env")
    return int(env.get("GRPC_PORT", 12321)), int(env.get("CERT_PORT", 12322))


def detected_lan_ip() -> Optional[str]:
    """The address the Server binds when REMOTERF_BIND_HOST is unset."""
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            return probe.getsockname()[0]
    except OSError:
        return None


def local_bind_host() -> str:
    """Where the tunnel should forward to on this machine.

    Mirrors the Server's own bind rule: REMOTERF_BIND_HOST when set (a
    wildcard bind is reachable on loopback), otherwise the detected LAN
    address -- the Server does not listen on 127.0.0.1 by default, so a
    forward aimed there would reach nothing.
    """
    configured = os.environ.get("REMOTERF_BIND_HOST", "").strip()
    if configured:
        return "127.0.0.1" if configured in {"0.0.0.0", "::", "*"} else configured
    return detected_lan_ip() or "127.0.0.1"


def known_hosts_path() -> Path:
    return identity_dir() / "relay_known_hosts"


def write_known_hosts() -> Optional[Path]:
    """Pin the relay host key. Without it the tunnel refuses to connect."""
    kv = load()
    host_key = kv.get("GLOBAL_RELAY_HOST_KEY", "").strip()
    host = kv.get("GLOBAL_RELAY_TUNNEL_HOST", "")
    port = kv.get("GLOBAL_RELAY_TUNNEL_PORT", "")
    if not (host_key and host and port):
        return None
    path = known_hosts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"[{host}]:{port} {host_key}\n", encoding="utf-8")
    return path


def tunnel_command() -> Optional[list]:
    kv = load()
    needed = (
        "GLOBAL_RELAY_TUNNEL_HOST",
        "GLOBAL_RELAY_TUNNEL_PORT",
        "GLOBAL_RELAY_TUNNEL_USER",
        "GLOBAL_RELAY_GRPC_PORT",
        "GLOBAL_RELAY_CERT_PORT",
    )
    if state() != "active" or any(not kv.get(key) for key in needed):
        return None
    known_hosts = write_known_hosts()
    if known_hosts is None:
        return None
    grpc_local, cert_local = local_ports()
    target = local_bind_host()
    return [
        "ssh", "-NT",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "IdentitiesOnly=yes",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-i", str(relay_key_path()),
        "-p", kv["GLOBAL_RELAY_TUNNEL_PORT"],
        "-R", f"127.0.0.1:{kv['GLOBAL_RELAY_GRPC_PORT']}:{target}:{grpc_local}",
        "-R", f"127.0.0.1:{kv['GLOBAL_RELAY_CERT_PORT']}:{target}:{cert_local}",
        f"{kv['GLOBAL_RELAY_TUNNEL_USER']}@{kv['GLOBAL_RELAY_TUNNEL_HOST']}",
    ]


class Tunnel:
    """The reverse tunnel as a supervised child, with exponential backoff.

    Replaces the per-host systemd unit: the tunnel starts only once Global has
    approved the deployment and there is a host key to pin, so a server that
    boots before the network can no longer crash-loop.
    """

    MIN_BACKOFF = 5.0
    MAX_BACKOFF = 300.0

    def __init__(self):
        self.process = None
        self.backoff = self.MIN_BACKOFF
        self.retry_at = 0.0

    def up(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None

    def supervise(self, now: float) -> None:
        command = tunnel_command()
        if command is None:
            self.stop()
            return
        if self.up():
            self.backoff = self.MIN_BACKOFF
            return
        if self.process is not None:
            self.process = None
            self.backoff = min(self.backoff * 2, self.MAX_BACKOFF)
        if now < self.retry_at:
            return
        self.retry_at = now + self.backoff
        self.process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


# -----------------------------
# Background agent
# -----------------------------

POLL_PENDING_SECONDS = 30  # approval shows up within a tick, not ten minutes
POLL_ACTIVE_SECONDS = 3600
LIVENESS_SECONDS = 300
STATUS_SECONDS = 3600
TICK_SECONDS = 60
POLL_BACKOFF_MAX_SECONDS = 900

# States the agent will never leave on its own: the operator or a Global admin
# has to act first, so the loop stops instead of retrying forever.
TERMINAL_STATES = {"left", "rejected", "expired", "unknown"}


def _tick(last: dict, tunnel=None) -> None:
    """One pass of the agent loop. Every step is best-effort and one-way."""
    import time

    now = time.monotonic()
    current = state()
    if current == "unregistered":
        submit_request()
        last["poll"] = now
        return
    interval = POLL_ACTIVE_SECONDS if current == "active" else POLL_PENDING_SECONDS
    if now - last.get("poll", -interval) >= interval:
        try:
            fetch_me()
        except Exception:
            # Stamp the poll so the next attempt waits out the backoff.
            backoff = min(2 * last.get("backoff", TICK_SECONDS), POLL_BACKOFF_MAX_SECONDS)
            last["backoff"] = backoff
            last["poll"] = now - interval + backoff
            raise
        last.pop("backoff", None)
        last["poll"] = now
    if tunnel is not None:
        tunnel.supervise(now)
    if current != "active":
        return
    for key, interval, send in (
        ("liveness", LIVENESS_SECONDS, send_liveness),
        ("status", STATUS_SECONDS, send_status),
    ):
        if now - last.get(key, -interval) >= interval:
            try:
                send()
            except GlobalError as exc:
                if exc.code == "unknown_deployment":
                    last.pop("poll", None)  # confirm with /me next tick, not in an hour
                raise
            last[key] = now
    _cluster_tick()


def _cluster_tick() -> None:
    """Drive pending clusters; a failure here never costs the liveness report."""
    import logging

    from .federation import cluster

    def notify(text: str) -> None:
        try:
            from ..common.utils.ansi_codes import Sty, printf

            printf(text, Sty.GRAY)
        except Exception:  # noqa: BLE001
            print(text)

    try:
        from .reservation import reservation_handler
    except Exception:  # noqa: BLE001
        reservation_handler = None
    try:
        cluster.tick(notify, home=reservation_handler)
    except Exception as exc:  # noqa: BLE001 - never let a cluster failure cost the liveness report
        logging.getLogger("remoteRF_server.global").warning("cluster tick failed: %s", exc)
    try:
        from .federation import global_home

        global_home.tick(notify)
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("remoteRF_server.global").warning("Global home tick failed: %s", exc)


def run_agent(stop=None, tunnel=None) -> None:
    """Poll Global, keep the relay up, and send the consented status report."""
    import logging
    import time

    logger = logging.getLogger("remoteRF_server.global")
    last: Dict[str, float] = {}
    tunnel = tunnel or Tunnel()
    while stop is None or not stop.is_set():
        try:
            if not participating() or state() in TERMINAL_STATES:
                tunnel.stop()
                return
            _tick(last, tunnel)
        except Exception as exc:  # noqa: BLE001 - never take the server down
            logger.warning(
                "global agent tick failed: %s (%s)",
                exc, getattr(exc, "code", type(exc).__name__),
            )
        if stop is not None:
            if stop.wait(TICK_SECONDS):
                tunnel.stop()
                return
        else:
            time.sleep(TICK_SECONDS)


def start_agent():
    """Start the agent in the background, or return None when not opted in."""
    import threading

    if not participating() or state() in TERMINAL_STATES:
        return None
    global _AGENT_TUNNEL
    stop = threading.Event()
    tunnel = _AGENT_TUNNEL = Tunnel()
    thread = threading.Thread(
        target=run_agent, args=(stop, tunnel), name="remoterf-global", daemon=True
    )
    thread.start()
    # A daemon thread just dies with the process; the ssh child it spawned
    # would not, and an orphaned tunnel keeps the relay ports for itself.
    global _AGENT_SHUTDOWN
    _AGENT_SHUTDOWN = (stop, tunnel)
    atexit.register(_shutdown, stop, tunnel)
    return stop


def _shutdown(stop, tunnel) -> None:
    stop.set()
    tunnel.stop()


def stop_agent() -> None:
    """For `restart`: exec skips atexit, and the orphan would keep the relay ports."""
    if _AGENT_SHUTDOWN is not None:
        _shutdown(*_AGENT_SHUTDOWN)


_AGENT_SHUTDOWN = None


# The running server's tunnel, for `status`. None outside a serving process.
_AGENT_TUNNEL = None


def tunnel_state() -> str:
    if not participating() or state() in TERMINAL_STATES:
        return "off"
    if tunnel_command() is None:
        return "not assigned"
    if _AGENT_TUNNEL is None:
        return "assigned"
    return "up" if _AGENT_TUNNEL.up() else "down"


# -----------------------------
# serverrf global <subcommand>
# -----------------------------

# What each state means to the operator reading it, rather than the bare word.
_STATE_SUMMARY = {
    "unregistered": "not requested yet",
    "unverified": "waiting for an approval code from a RemoteRF admin",
    "requested": "verified; a RemoteRF admin is assigning a name",
    "active": "live",
    "rejected": "not accepted",
    "suspended": "suspended by a RemoteRF admin",
    "left": "left RemoteRF Global",
    "expired": "request expired",
    "unknown": "RemoteRF Global has no record of this deployment -- run: serverrf global join",
}


def cmd_status(refresh: bool = True) -> int:
    from ..common.utils.panel import marker, print_panel

    kv = load()
    if not kv:
        print()
        print_panel(
            "RemoteRF Global",
            [f"{marker()} Not configured. Answered at first server start."],
        )
        print()
        return 0
    if not participating():
        print()
        print_panel(
            "RemoteRF Global",
            [
                f"{marker()} Not participating.",
                "",
                "    serverrf global join",
            ],
        )
        print()
        return 0

    # Ask Global rather than reporting a stale local answer: the operator runs
    # this precisely because they are waiting to hear about their request.
    unreachable = refused = None
    if refresh and state() not in TERMINAL_STATES:
        try:
            fetch_me()
        except GlobalError as exc:
            refused = exc.code
        except Exception as exc:  # noqa: BLE001 - offline is not an error here
            unreachable = str(exc)
        kv = load()

    current = kv.get("GLOBAL_STATE", "unregistered")
    rows = [
        f"{marker()} {current} -- {_STATE_SUMMARY.get(current, '')}".rstrip(" -"),
        "",
    ]
    fields = [
        ("name", kv.get("GLOBAL_NAME", "-")),
        ("display", kv.get("GLOBAL_DISPLAY_NAME", "-")),
        ("hostname", hostname() or "-"),
        ("email", kv.get("GLOBAL_EMAIL", "-")),
        ("tunnel", tunnel_state()),
        ("last report", kv.get("GLOBAL_LAST_REPORT_AT", "-")),
        ("last seen", kv.get("GLOBAL_LAST_SEEN_AT", "-")),
    ]
    if kv.get("GLOBAL_REASON"):
        fields.append(("reason", kv["GLOBAL_REASON"]))
    width = max(len(name) for name, _ in fields)
    rows += [f"{name:<{width}}  {value}" for name, value in fields]

    if current == "unverified":
        rows += ["", "    serverrf global verify <code>"]
    if refused:
        rows += ["", f"(refused by RemoteRF Global ({refused}))"]
    if unreachable:
        rows += ["", f"(could not reach RemoteRF Global just now: {unreachable})"]

    print()
    print_panel("RemoteRF Global", rows, literal=True)
    print()
    return 0


def cmd_join() -> int:
    if participating() and state() == "active":
        _warn(f"  Already live on RemoteRF Global as {hostname()}.")
        _hint("  To re-register under different details, run `global leave` first.")
        return 1
    if not configure():
        return 1
    return 0 if submit_and_report() else 1


def cmd_leave() -> int:
    if not participating():
        print("This server does not participate in RemoteRF Global.")
        return 0
    # Local state wins immediately: the relay and report stop whether or not
    # Global is reachable to acknowledge.
    update(GLOBAL_STATE="left")
    try:
        call("POST", LEAVE_PATH, {})
    except Exception as exc:  # noqa: BLE001
        print(f"note: could not notify RemoteRF Global ({exc}); stopped locally anyway.")
    print("Left RemoteRF Global. The relay and status report stop immediately.")
    return 0


def cmd_verify(code: str = "") -> int:
    from ..common.utils.panel import marker, print_panel

    if not participating():
        _warn("  This server does not participate in RemoteRF Global.")
        return 1
    code = (code or "").strip() or _ask("  Verification code: ")
    if not code:
        _warn("  A verification code is required.")
        return 1
    try:
        verify_contact(code)
    except GlobalError as exc:
        _warn(f"  {exc.code.replace('_', ' ')}.")
        if exc.code in {"verification_expired", "too_many_attempts"}:
            _hint("  Run `serverrf global join` to have a new code sent.")
        return 1
    except Exception as exc:  # noqa: BLE001
        _warn(f"  Could not reach RemoteRF Global: {exc}")
        return 1
    kv = load()
    print()
    print_panel(
        "Live" if state() == "active" else "Verified",
        [
            f"{marker()} {hostname()} is live."
            if state() == "active"
            else f"{marker()} {kv.get('GLOBAL_EMAIL')} confirmed.",
            "",
            "Your users can now register and connect from any network with "
            "an enrollment code:"
            if state() == "active"
            else "A RemoteRF admin will assign your final name shortly.",
            "",
            f"    {hostname()}/<code>"
            if state() == "active"
            else "    serverrf global status",
        ],
    )
    print()
    return 0


_COMMANDS = {"status": cmd_status, "join": cmd_join, "leave": cmd_leave}


def main(argv) -> int:
    if argv and argv[0] == "verify":
        # A code pasted from email may arrive wrapped across lines.
        return cmd_verify("".join(argv[1:]))
    if len(argv) != 1 or argv[0] not in _COMMANDS:
        print(
            "Usage: serverrf global status | join | verify <code> | leave",
            file=sys.stderr,
        )
        return 2
    return _COMMANDS[argv[0]]()
