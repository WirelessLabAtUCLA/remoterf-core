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

# src/remoteRF_host/host/host_tunnel_server.py

from __future__ import annotations

import sys
import threading
import queue
import time
import secrets
import traceback
import hashlib
import re
import uuid

from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Any, List, Set, Iterator

from concurrent.futures import Future
from concurrent import futures

import grpc

from ..common.utils.process_arg import map_arg  
from ..common.grpc import grpc_pb2 as generic_pb2  
from ..common.grpc import grpc_host_pb2_grpc as host_tunnel_pb2_grpc
from ..common.grpc import grpc_host_pb2 as host_tunnel_pb2

from .host_directory_store import (
    EnvStore,
    DeviceIdConflictError,
    now_ms,
    sanitize_env_key,
    csv_split,
    cfg_dir_from_file,
)

from .host_auth_token import is_host_token_valid, list_hosts

# =============================================================================
# Hardcoded logging mode (NO env vars)
#
# Pick ONE:
#   LOG_MODE = "OFF"   -> show nothing
#   LOG_MODE = "WARN"  -> show only WARN + ERROR
#   LOG_MODE = "ALL"   -> show everything (INFO + WARN + ERROR)
# =============================================================================

LOG_MODE = "OFF" 
_LOG_LOCK = threading.Lock()
HOST_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")  # adjust if you want

def _grpc_err_summary(e: grpc.RpcError) -> str:
    try:
        code = e.code()
        name = code.name if code else "UNKNOWN"
    except Exception:
        name = "UNKNOWN"
    try:
        details = e.details() or ""
    except Exception:
        details = ""
    return f"{name}: {details}".strip()

def _host_status(host_id: str) -> str:
    try:
        for hid, st in list_hosts():
            if hid == host_id:
                return (st or "").strip().lower()
    except Exception:
        pass
    return ""

def _auth_fail_code_and_details(host_id: str) -> tuple[str, str]:
    st = _host_status(host_id)
    if not st:
        return ("UNAUTHENTICATED", f"Unknown host_id={host_id!r}. Ask admin to provision a host token.")
    if st != "approved":
        return ("PERMISSION_DENIED", f"host_id={host_id!r} not approved (status={st!r}).")
    return ("UNAUTHENTICATED", f"Invalid host_token for host_id={host_id!r}.")

class HostIdConflictError(RuntimeError):
    def __init__(self, host_id: str, *, age_ms: int, replace_after_ms: int) -> None:
        super().__init__(
            f"host_id '{host_id}' already in use (last heartbeat {age_ms}ms ago). "
            f"Try again after {replace_after_ms}ms or fix the conflicting host config."
        )
        self.host_id = host_id
        self.age_ms = age_ms
        self.replace_after_ms = replace_after_ms

def _validate_host_id(raw: str) -> str:
    hid = (raw or "").strip()
    if not hid:
        raise ValueError("Missing host_id (set HOST_ID in host.env; do not auto-generate).")
    if hid == "unknown-host":
        raise ValueError("host_id cannot be 'unknown-host' (set HOST_ID in host.env).")
    if not HOST_ID_RE.fullmatch(hid):
        raise ValueError(
            "Invalid host_id. Allowed: 1..64 chars of [A-Za-z0-9_.-]. "
            f"Got: {hid!r}"
        )
    return hid

def _ts() -> str:
    t = time.time()
    sec = int(t)
    ms = int((t - sec) * 1000)
    lt = time.localtime(sec)
    return time.strftime("%H:%M:%S", lt) + f".{ms:03d}"

def _should_log(level: str) -> bool:
    lvl = (level or "").upper()
    mode = (LOG_MODE or "").upper()
    if mode == "OFF":
        return False
    if mode == "WARN":
        return lvl in ("WARN", "ERROR")
    if mode == "ALL":
        return lvl in ("INFO", "WARN", "ERROR")
    return lvl in ("WARN", "ERROR")

def _log(level: str, msg: str) -> None:
    if not _should_log(level):
        return
    tn = threading.current_thread().name
    with _LOG_LOCK:
        print(f"{_ts()} {level:<5} [{tn}] hostrf.host_tunnel_server: {msg}", file=sys.stderr, flush=True)

def info(msg: str) -> None:
    _log("INFO", msg)

def warn(msg: str) -> None:
    _log("WARN", msg)

def error(msg: str) -> None:
    _log("ERROR", msg)

def exception(msg: str) -> None:
    _log("ERROR", msg)
    traceback.print_exc(limit=80, file=sys.stderr)

# Helpers

def host_key(host_id: str) -> str:
    h = hashlib.sha256((host_id or "").encode("utf-8")).hexdigest()
    return h[:16]  # short stable key

def _safe_thread_tag(s: str) -> str:
    s = s or "peer"
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s)[:64]

def _copy_argument_map(dst_map: Any, src_map: Any) -> None:
    if src_map is None:
        return
    try:
        for k in src_map:
            dst_map[str(k)].CopyFrom(src_map[k])
    except Exception:
        for k, v in dict(src_map).items():
            dst_map[str(k)].CopyFrom(v)

# Types

@dataclass(frozen=True)
class DeviceRoute:
    host_id: str
    host_local_id: int


@dataclass
class HostStatus:
    host_id: str
    online: bool = False
    last_seen_ms: int = 0


@dataclass
class DeviceStatus:
    device_id: str
    host_id: str
    host_local_id: int
    online: bool = False
    last_seen_ms: int = 0

# Session

class HostSession:
    def __init__(self, host_id: str, *, peer: str = "<?>", session_uuid: str = "", outbound_max: int = 2048) -> None:
        self.host_id = host_id
        self.peer = peer
        self.session_uuid = (session_uuid or uuid.uuid4().hex[:10])

        self.out_q: "queue.Queue[Optional[host_tunnel_pb2.HostFrame]]" = queue.Queue(maxsize=int(outbound_max))
        self.inflight: Dict[str, Future] = {}
        self.inflight_lock = threading.Lock()
        self.last_heartbeat_ms = now_ms()
        self.alive = True
        self.outbound_max = int(outbound_max)

        info(
            f"[session] created host_id={self.host_id!r} sess={self.session_uuid} "
            f"peer={self.peer} outbound_max={self.outbound_max}"
        )

    def send(self, frame: host_tunnel_pb2.HostFrame, *, timeout: float = 2.0) -> bool:
        which = frame.WhichOneof("msg")
        if not self.alive:
            warn(f"[session] send refused (dead session) host_id={self.host_id!r} sess={self.session_uuid} type={which}")
            return False
        try:
            self.out_q.put(frame, timeout=timeout)
            info(f"[session] queued outbound host_id={self.host_id!r} sess={self.session_uuid} type={which}")
            return True
        except queue.Full:
            warn(
                f"[session] outbound queue FULL host_id={self.host_id!r} sess={self.session_uuid} "
                f"max={self.outbound_max} drop type={which}"
            )
            return False
        except Exception:
            exception(f"[session] send exception host_id={self.host_id!r} sess={self.session_uuid} type={which}")
            return False

    def close(self) -> None:
        if not self.alive:
            return
        info(f"[session] closing host_id={self.host_id!r} sess={self.session_uuid} peer={self.peer}")
        self.alive = False

        try:
            self.out_q.put_nowait(None)
        except Exception:
            exception(f"[session] close: failed to enqueue sentinel host_id={self.host_id!r} sess={self.session_uuid}")

        with self.inflight_lock:
            for rid, fut in list(self.inflight.items()):
                if not fut.done():
                    fut.set_exception(RuntimeError(f"Host '{self.host_id}' disconnected (req_id={rid})"))
            self.inflight.clear()

        info(f"[session] closed host_id={self.host_id!r} sess={self.session_uuid}")

# Registry

class HostTunnelRegistry:

    def __init__(self, *, active_cache_ttl_ms: int = 250, dir_cache_ttl_ms: int = 1000) -> None:
        self._lock = threading.RLock()

        # live sessions
        self._hosts: Dict[str, HostSession] = {}  # host_id -> session

        # directory state
        self._routes: Dict[str, DeviceRoute] = {}                      # device_id -> route(host_id, local_id)
        self._host_devices: Dict[str, Set[str]] = {}                   # host_id -> set(device_id)
        self._device_infos: Dict[str, host_tunnel_pb2.DeviceInfo] = {} # device_id -> DeviceInfo

        # status
        self._host_status: Dict[str, HostStatus] = {}
        self._device_status: Dict[str, DeviceStatus] = {}

        # IDL capability strings received via HostMeta.kv from each host.
        # Keyed by device_id (string gid).  Value is the compact caps string
        # emitted by the host's capabilities_string() helper, e.g.:
        #   "disable_dds:call0,filter:rw,hardwaregain_chan0:rw,..."
        self._host_device_caps: Dict[str, str] = {}
        # device_id -> the schema_hash the host reports for its driver (HostMeta.kv).
        self._host_device_schema: Dict[str, str] = {}

        # persistence
        cfg = cfg_dir_from_file(__file__)
        cfg.mkdir(parents=True, exist_ok=True)
        self._env_lists = EnvStore(cfg / "host_directory.env")
        self._env_meta = EnvStore(cfg / "host_directory_meta.env")

        # caches
        self._active_hosts_cache: Set[str] = set()
        self._active_hosts_cache_ts_ms: int = 0
        self._active_hosts_cache_ttl_ms: int = int(active_cache_ttl_ms)

        self._dir_cache: Dict[str, Tuple[str, Any, bool]] = {}
        self._dir_cache_ts_ms: int = 0
        self._dir_cache_ttl_ms: int = int(dir_cache_ttl_ms)

        info(f"[registry] init cfg_dir={cfg}")
        self._load_persisted()

    # caching helpers

    def _invalidate_caches_locked(self) -> None:
        self._active_hosts_cache_ts_ms = 0
        self._dir_cache_ts_ms = 0

    def _refresh_active_hosts_cache_locked(self, now: int) -> None:
        if self._active_hosts_cache_ts_ms and (now - self._active_hosts_cache_ts_ms) < self._active_hosts_cache_ttl_ms:
            return
        self._active_hosts_cache = {hid for hid, sess in self._hosts.items() if sess is not None and sess.alive}
        self._active_hosts_cache_ts_ms = now

    # persistence load

    def _load_persisted(self) -> None:
        kv_lists = self._env_lists.read_kv()
        kv_meta = self._env_meta.read_kv()

        known_hosts = csv_split(kv_lists.get("KNOWN_HOSTS", ""))
        known_devices = csv_split(kv_lists.get("KNOWN_DEVICES", ""))

        info(f"[registry] load persisted: known_hosts={len(known_hosts)} known_devices={len(known_devices)}")

        with self._lock:
            self._routes.clear()
            self._host_devices.clear()
            self._device_infos.clear()
            self._host_status.clear()
            self._device_status.clear()

            # seed hosts offline
            for hid in known_hosts:
                if hid:
                    self._host_status[hid] = HostStatus(host_id=hid, online=False, last_seen_ms=0)
                    self._host_devices.setdefault(hid, set())

            devices_from_host_lists: Set[str] = set()
            for k, v in kv_lists.items():
                if k.startswith("HOST_") and k.endswith("_DEVICES"):
                    devices_from_host_lists.update(csv_split(v))

            all_devices: List[str] = sorted(set(known_devices) | devices_from_host_lists)

            for device_id in all_devices:
                device_id = (device_id or "").strip()
                if not device_id:
                    continue

                # STRICT MODE: ignore any persisted non-numeric / non-canonical IDs
                if not device_id.isdigit() or device_id != str(int(device_id)):
                    warn(f"[registry] skipping persisted non-numeric/non-canonical device_id={device_id!r}")
                    continue

                dk = sanitize_env_key(device_id)

                host_id = (kv_meta.get(f"DEVICE_{dk}_HOST", "") or "").strip()
                local_id_s = (kv_meta.get(f"DEVICE_{dk}_LOCAL_ID", "") or "0").strip()
                try:
                    local_id = int(local_id_s)
                except Exception:
                    local_id = 0

                label = (kv_meta.get(f"DEVICE_{dk}_LABEL", "") or "").strip()
                serial = (kv_meta.get(f"DEVICE_{dk}_SERIAL", "") or "").strip()
                kind = (kv_meta.get(f"DEVICE_{dk}_KIND", "") or "").strip()

                if host_id:
                    if host_id not in self._host_status:
                        self._host_status[host_id] = HostStatus(host_id=host_id, online=False, last_seen_ms=0)
                    self._host_devices.setdefault(host_id, set()).add(device_id)
                    self._routes[device_id] = DeviceRoute(host_id=host_id, host_local_id=int(local_id))

                self._device_infos[device_id] = host_tunnel_pb2.DeviceInfo(
                    device_id=str(device_id),
                    local_id=int(local_id),
                    label=str(label),
                    serial=str(serial),
                    kind=str(kind),
                )

                self._device_status[device_id] = DeviceStatus(
                    device_id=str(device_id),
                    host_id=str(host_id),
                    host_local_id=int(local_id),
                    online=False,
                    last_seen_ms=0,
                )

            self._invalidate_caches_locked()

        info(
            f"[registry] persisted directory loaded: routes={len(self._routes)} "
            f"hosts={len(self._host_status)} devices={len(self._device_status)}"
        )

    # persistence write helpers

    def _persist_host_meta(self, host_id: str, *, host_name: str = "", platform: str = "", version: str = "") -> None:
        hk = host_key(host_id)
        self._env_meta.set_kv_if_absent(f"HOST_{hk}_ID", host_id)
        if host_name:
            self._env_meta.upsert_kv(f"HOST_{hk}_NAME", host_name)
        if platform:
            self._env_meta.upsert_kv(f"HOST_{hk}_PLATFORM", platform)
        if version:
            self._env_meta.upsert_kv(f"HOST_{hk}_VERSION", version)

    def persist_host_meta_from_hello(self, hello: Any) -> None:
        try:
            hid = str(getattr(hello, "host_id", "") or "").strip()
            ver = str(getattr(hello, "version", "") or "").strip()
            if hid:
                self._persist_host_meta(hid, version=ver)
                info(f"[registry] persisted host meta from hello: host_id={hid!r} version={ver!r}")
        except Exception:
            exception("[registry] persist_host_meta_from_hello failed")

    def _persist_host(self, host_id: str) -> None:
        self._env_lists.append_to_csv_list("KNOWN_HOSTS", host_id)
        info(f"[registry] persisted host list: host_id={host_id!r}")

    def _persist_device(self, host_id: str, device_id: str, local_id: int, device_info: Any) -> None:
        self._env_lists.append_to_csv_list("KNOWN_DEVICES", device_id)
        hk = host_key(host_id)
        self._env_meta.set_kv_if_absent(f"HOST_{hk}_ID", host_id)
        self._env_lists.append_to_csv_list(f"HOST_{hk}_DEVICES", device_id)

        dk = sanitize_env_key(device_id)
        self._env_meta.upsert_kv(f"DEVICE_{dk}_HOST", host_id)
        self._env_meta.upsert_kv(f"DEVICE_{dk}_LOCAL_ID", str(int(local_id)))

        label = str(getattr(device_info, "label", "") or "").strip()
        serial = str(getattr(device_info, "serial", "") or "").strip()
        kind = str(getattr(device_info, "kind", "") or "").strip()

        if label:
            self._env_meta.upsert_kv(f"DEVICE_{dk}_LABEL", label)
        if serial:
            self._env_meta.upsert_kv(f"DEVICE_{dk}_SERIAL", serial)
        if kind:
            self._env_meta.upsert_kv(f"DEVICE_{dk}_KIND", kind)

        info(
            f"[registry] persisted device: host_id={host_id!r} device_id={device_id!r} local_id={int(local_id)} "
            f"label={label!r} serial={serial!r} kind={kind!r}"
        )

    def _unpersist_device(self, host_id: str, device_id: str) -> None:
        self._env_lists.remove_from_csv_list("KNOWN_DEVICES", device_id)
        self._env_lists.remove_from_csv_list(f"HOST_{host_key(host_id)}_DEVICES", device_id)
        dk = sanitize_env_key(device_id)
        self._env_meta.remove_keys([f"DEVICE_{dk}_{f}" for f in ("HOST", "LOCAL_ID", "LABEL", "SERIAL", "KIND")])
        info(f"[registry] unpersisted device: host_id={host_id!r} device_id={device_id!r}")

    # directory/status mutators

    def register_host(self, host_id: str, session: HostSession, *, replace_if_stale_ms: int = 15_000) -> None:
        info(
            f"[registry] register_host: host_id={host_id!r} incoming_sess={session.session_uuid} "
            f"incoming_peer={session.peer}"
        )

        with self._lock:
            old = self._hosts.get(host_id)
            if old is not None and old.alive:
                age_ms = int(now_ms() - int(getattr(old, "last_heartbeat_ms", 0) or 0))

                if age_ms < replace_if_stale_ms:
                    warn(
                        f"[registry] HostIdConflict host_id={host_id!r} age_ms={age_ms} "
                        f"incoming_sess={session.session_uuid} incoming_peer={session.peer} "
                        f"existing_sess={getattr(old,'session_uuid','?')} existing_peer={getattr(old,'peer','?')}"
                    )
                    raise HostIdConflictError(host_id, age_ms=age_ms, replace_after_ms=replace_if_stale_ms)

                warn(
                    f"[registry] replacing STALE host_id={host_id!r} age_ms={age_ms} "
                    f"incoming_sess={session.session_uuid} incoming_peer={session.peer} "
                    f"existing_sess={getattr(old,'session_uuid','?')} existing_peer={getattr(old,'peer','?')}"
                )
                old.close()

            self._hosts[host_id] = session

            hs = self._host_status.get(host_id) or HostStatus(host_id=host_id)
            hs.online = True
            hs.last_seen_ms = now_ms()
            self._host_status[host_id] = hs

            self._host_devices.setdefault(host_id, set())
            self._persist_host(host_id)
            self._invalidate_caches_locked()

        info(f"[registry] register_host done: host_id={host_id!r} online=True incoming_sess={session.session_uuid}")

    def drop_host(self, host_id: str) -> None:
        info(f"[registry] drop_host: host_id={host_id!r}")
        with self._lock:
            sess = self._hosts.pop(host_id, None)
            if sess is not None:
                sess.close()

            hs = self._host_status.get(host_id) or HostStatus(host_id=host_id)
            hs.online = False
            hs.last_seen_ms = now_ms()
            self._host_status[host_id] = hs

            for did in self._host_devices.get(host_id, set()):
                ds = self._device_status.get(did)
                if ds is not None:
                    ds.online = False
                    ds.last_seen_ms = now_ms()

            self._invalidate_caches_locked()

        info(f"[registry] drop_host done: host_id={host_id!r} online=False")

    def drop_host_if_match(self, host_id: str, session: HostSession) -> bool:
        with self._lock:
            cur = self._hosts.get(host_id)
            if cur is not session:
                return False

            sess = self._hosts.pop(host_id, None)
            if sess is not None:
                sess.close()

            hs = self._host_status.get(host_id) or HostStatus(host_id=host_id)
            hs.online = False
            hs.last_seen_ms = now_ms()
            self._host_status[host_id] = hs

            for did in self._host_devices.get(host_id, set()):
                ds = self._device_status.get(did)
                if ds is not None:
                    ds.online = False
                    ds.last_seen_ms = now_ms()

            self._invalidate_caches_locked()

        info(f"[registry] drop_host_if_match done: host_id={host_id!r} online=False")
        return True

    def close_all_sessions(self) -> int:
        """End every live tunnel; each host reconnects and announces afresh."""
        with self._lock:
            sessions = [s for s in self._hosts.values() if s is not None and s.alive]
        for sess in sessions:
            sess.close()
        return len(sessions)

    def send_control(self, host_id: str, *, kind: str, device_id: str) -> bool:
        with self._lock:
            sess = self._hosts.get(host_id)
        if sess is None or not sess.alive:
            return False
        return sess.send(host_tunnel_pb2.HostFrame(
            control=host_tunnel_pb2.Control(kind=str(kind), device_id=str(device_id))
        ))

    def forget_host(self, host_id: str) -> Optional[List[str]]:
        """Remove a host and its devices from the directory, in memory and persisted.

        Returns the forgotten device ids, or None if the directory did not know the host.
        Raises RuntimeError while the host is connected: its next announce would add them back.
        """
        hk = host_key(host_id)
        with self._lock:
            sess = self._hosts.get(host_id)
            if sess is not None and sess.alive:
                raise RuntimeError(f"Host '{host_id}' is connected")

            known = host_id in self._host_status or host_id in self._host_devices
            dids = sorted(self._host_devices.get(host_id, set()))
            # Files first: if a write fails, memory still lists everything and a rerun retries it all.
            for did in dids:
                self._unpersist_device(host_id, did)
            self._env_lists.remove_from_csv_list("KNOWN_HOSTS", host_id)
            self._env_lists.remove_keys([f"HOST_{hk}_DEVICES"])
            self._env_meta.remove_keys([f"HOST_{hk}_{f}" for f in ("ID", "NAME", "PLATFORM", "VERSION")])

            for did in dids:
                self._routes.pop(did, None)
                self._device_infos.pop(did, None)
                self._device_status.pop(did, None)
                self._host_device_caps.pop(did, None)
                self._host_device_schema.pop(did, None)
            self._host_devices.pop(host_id, None)
            self._hosts.pop(host_id, None)
            self._host_status.pop(host_id, None)
            self._invalidate_caches_locked()

        info(f"[registry] forget_host done: host_id={host_id!r} known={known} devices={dids}")
        return dids if known else None

    def heartbeat(self, host_id: str, unix_ms: int = 0) -> None:
        now = int(unix_ms) or now_ms()
        with self._lock:
            hs = self._host_status.get(host_id) or HostStatus(host_id=host_id)
            hs.online = True
            hs.last_seen_ms = now
            self._host_status[host_id] = hs

            for did in self._host_devices.get(host_id, set()):
                ds = self._device_status.get(did)
                if ds is not None:
                    ds.online = True
                    ds.last_seen_ms = now

            self._invalidate_caches_locked()

        info(f"[registry] heartbeat: host_id={host_id!r} unix_ms={now}")

    # ── IDL capability cache ────────────────────────────────────────

    def store_host_device_caps(self, host_id: str, device_id: str, caps: str) -> None:
        """
        Store the IDL capability string for a host device.

        Called when the server receives HostMeta.kv["device.<gid>.caps"] in a
        MetaResponse.  The caps string is the compact attr:access list emitted
        by the host's capabilities_string() helper.
        """
        with self._lock:
            self._host_device_caps[str(device_id)] = str(caps)

    def store_host_device_schema_hash(self, host_id: str, device_id: str, schema_hash: str) -> None:
        with self._lock:
            self._host_device_schema[str(device_id)] = str(schema_hash)

    def get_host_device_schema_hash(self, device_id: str) -> str:
        with self._lock:
            return self._host_device_schema.get(str(device_id), "")

    def get_host_device_caps(self, device_id: str) -> str:
        """
        Return the IDL capability string for *device_id*, or "" if not yet received.
        """
        with self._lock:
            return self._host_device_caps.get(str(device_id), "")

    def announce_devices(self, host_id: str, devices: list, *, full_snapshot: bool = False) -> None:
        info(f"[registry] announce_devices: host_id={host_id!r} n={len(devices)}")

        # STRICT MODE:
        #   - device_id MUST be canonical decimal string for gid (e.g. "10")
        #   - reject "010", reject "pluto:...", reject duplicates in a single announce
        pairs: List[Tuple[Any, str]] = []
        seen: Set[str] = set()

        for d in devices:
            raw = str(getattr(d, "device_id", "") or "").strip()
            if not raw:
                continue

            if not raw.isdigit():
                raise ValueError(
                    f"Host device_id must be a numeric gid string (e.g. '10'). "
                    f"Got {raw!r} from host_id={host_id!r}."
                )

            canon = str(int(raw))
            if raw != canon:
                raise ValueError(
                    f"Host device_id must be canonical decimal with no leading zeros. "
                    f"Got {raw!r}; use {canon!r} (host_id={host_id!r})."
                )

            if canon in seen:
                raise ValueError(
                    f"Duplicate device_id {canon!r} in device announce from host_id={host_id!r}."
                )
            seen.add(canon)
            pairs.append((d, canon))

        # conflict check first (no partial apply)
        with self._lock:
            for _, device_id in pairs:
                existing = self._routes.get(device_id)
                if existing is not None and existing.host_id != host_id:
                    warn(
                        f"[registry] device_id conflict: device_id={device_id!r} "
                        f"existing_host={existing.host_id!r} new_host={host_id!r}"
                    )
                    raise DeviceIdConflictError(
                        device_id=device_id,
                        existing_host=existing.host_id,
                        new_host=host_id,
                    )

        now = now_ms()
        with self._lock:
            self._host_devices.setdefault(host_id, set())

            # Preserve old behavior: skip empty ids with warn (but strict checks already handled non-empty bad ones)
            for d in devices:
                device_id0 = str(getattr(d, "device_id", "") or "").strip()
                if not device_id0:
                    warn(f"[registry] announce_devices: skipping device with empty device_id host_id={host_id!r}")

            # A full snapshot drops this host's devices it no longer announces,
            # so a removed device stops listing online and frees its handle.
            if full_snapshot:
                for did in self._host_devices[host_id] - {device_id for _, device_id in pairs}:
                    self._routes.pop(did, None)
                    self._device_infos.pop(did, None)
                    self._device_status.pop(did, None)
                    self._host_devices[host_id].discard(did)
                    self._unpersist_device(host_id, did)

            for d, device_id in pairs:
                try:
                    local_id = int(getattr(d, "local_id", 0))
                except Exception:
                    local_id = 0

                label = str(getattr(d, "label", "") or "")
                serial = str(getattr(d, "serial", "") or "")
                kind = str(getattr(d, "kind", "") or "")

                info(
                    f"[registry] device: host_id={host_id!r} local_id={local_id} "
                    f"device_id={device_id!r} label={label!r} serial={serial!r} kind={kind!r}"
                )

                self._routes[device_id] = DeviceRoute(host_id=host_id, host_local_id=local_id)
                self._host_devices[host_id].add(device_id)

                ds = self._device_status.get(device_id) or DeviceStatus(
                    device_id=device_id,
                    host_id=host_id,
                    host_local_id=local_id,
                )
                ds.host_id = host_id
                ds.host_local_id = local_id
                ds.online = True
                ds.last_seen_ms = now
                self._device_status[device_id] = ds

                try:
                    tmp = host_tunnel_pb2.DeviceInfo()
                    tmp.CopyFrom(d)
                    # ensure stored info reflects canonical device_id key
                    tmp.device_id = str(device_id)
                    self._device_infos[device_id] = tmp
                except Exception:
                    self._device_infos[device_id] = host_tunnel_pb2.DeviceInfo(
                        device_id=str(device_id),
                        local_id=int(local_id),
                        label=label,
                        serial=serial,
                        kind=kind,
                    )

                self._persist_device(host_id, device_id, local_id, d)

            self._invalidate_caches_locked()

        info(f"[registry] announce_devices done: host_id={host_id!r} routes={len(self._routes)}")

    # FAST PATHS (use per-RPC)

    def is_host_device(self, device_id: str) -> bool:
        did = (device_id or "").strip()
        if not did:
            return False
        with self._lock:
            return did in self._routes

    def is_host_device_active(self, device_id: str) -> bool:
        did = (device_id or "").strip()
        if not did:
            return False
        now = now_ms()
        with self._lock:
            route = self._routes.get(did)
            if route is None:
                return False
            self._refresh_active_hosts_cache_locked(now)
            return route.host_id in self._active_hosts_cache

    def get_host_for_device(self, device_id: str) -> Optional[str]:
        did = (device_id or "").strip()
        if not did:
            return None
        with self._lock:
            r = self._routes.get(did)
            return r.host_id if r else None

    # UI/diagnostics snapshots

    def device_directory_cached(self, *, ttl_ms: Optional[int] = None) -> Dict[str, Tuple[str, Any, bool]]:
        now = now_ms()
        ttl = int(self._dir_cache_ttl_ms if ttl_ms is None else ttl_ms)

        with self._lock:
            if self._dir_cache_ts_ms and (now - self._dir_cache_ts_ms) < ttl:
                return dict(self._dir_cache)

            self._refresh_active_hosts_cache_locked(now)

            out: Dict[str, Tuple[str, Any, bool]] = {}
            for device_id, route in self._routes.items():
                info0 = self._device_infos.get(device_id)
                info_obj = info0
                if info0 is not None:
                    tmp = host_tunnel_pb2.DeviceInfo()
                    try:
                        tmp.CopyFrom(info0)
                        info_obj = tmp
                    except Exception:
                        info_obj = info0

                is_active = route.host_id in self._active_hosts_cache
                out[device_id] = (route.host_id, info_obj, is_active)

            self._dir_cache = out
            self._dir_cache_ts_ms = now
            return dict(out)

    # misc accessors

    def list_routes(self) -> Dict[str, Tuple[str, int]]:
        with self._lock:
            return {did: (r.host_id, r.host_local_id) for did, r in self._routes.items()}

    def list_hosts(self) -> Dict[str, HostStatus]:
        with self._lock:
            return dict(self._host_status)

    def list_devices(self) -> Dict[str, DeviceStatus]:
        with self._lock:
            return dict(self._device_status)

    # forwarding

    def _get_session_and_route(self, device_id: str) -> Tuple[HostSession, DeviceRoute]:
        with self._lock:
            route = self._routes.get(str(device_id))
            if route is None:
                raise KeyError(f"Unknown device_id={device_id}")

            sess = self._hosts.get(route.host_id)
            if sess is None or not sess.alive:
                raise RuntimeError(f"Host '{route.host_id}' not connected for device {device_id}")

            return sess, route

    def forward_request(
        self,
        *,
        device_id: str,
        request: "generic_pb2.GenericRPCRequest",
        timeout_sec: float,
        deadline_unix_ms: int = 0,
        cancel_on_timeout: bool = False,
    ) -> "generic_pb2.GenericRPCResponse":
        fn = str(getattr(request, "function_name", "") or "")
        info(f"[forward] device_id={device_id!r} fn={fn!r} timeout_sec={timeout_sec}")

        try:
            sess, route = self._get_session_and_route(str(device_id))
        except Exception as e:
            exception(f"[forward] route/session lookup failed device_id={device_id!r} err={e!r}")
            r = generic_pb2.GenericRPCResponse()
            r.results["Ok"].CopyFrom(map_arg(False))
            r.results["Error"].CopyFrom(map_arg(f"Route/session lookup failed: {e}"))
            return r

        req_id = secrets.token_hex(12)
        fut: Future = Future()

        with sess.inflight_lock:
            sess.inflight[req_id] = fut

        try:
            gid_u32 = int(str(device_id))  # strict mode: device_id is canonical gid string
        except Exception:
            gid_u32 = 0

        rpc_req = host_tunnel_pb2.RpcRequest(
            req_id=req_id,
            global_device_id=int(gid_u32),
            local_device_id=int(route.host_local_id),
            device_id=str(device_id),
            deadline_unix_ms=int(deadline_unix_ms or 0),
        )
        rpc_req.request.CopyFrom(request)

        frame = host_tunnel_pb2.HostFrame(rpc_request=rpc_req)

        info(f"[forward] -> host_id={sess.host_id!r} req_id={req_id} local_id={route.host_local_id}")

        if not sess.send(frame, timeout=2.0):
            with sess.inflight_lock:
                sess.inflight.pop(req_id, None)

            r = generic_pb2.GenericRPCResponse()
            r.results["Ok"].CopyFrom(map_arg(False))
            r.results["Error"].CopyFrom(map_arg(f"Host '{sess.host_id}' outbound queue full / not writable."))
            return r

        t0 = time.time()
        try:
            resp: host_tunnel_pb2.RpcResponse = fut.result(timeout=timeout_sec)
        except Exception as e:
            dt_ms = int((time.time() - t0) * 1000)
            warn(f"[forward] wait failed req_id={req_id} dt_ms={dt_ms} err={e!r}")

            if cancel_on_timeout:
                try:
                    ok = sess.send(host_tunnel_pb2.HostFrame(cancel=host_tunnel_pb2.Cancel(req_id=req_id)))
                    info(f"[forward] sent cancel req_id={req_id} ok={ok}")
                except Exception:
                    exception(f"[forward] failed sending cancel req_id={req_id}")

            with sess.inflight_lock:
                sess.inflight.pop(req_id, None)

            r = generic_pb2.GenericRPCResponse()
            r.results["Ok"].CopyFrom(map_arg(False))
            r.results["Error"].CopyFrom(map_arg(str(e)))
            return r

        with sess.inflight_lock:
            sess.inflight.pop(req_id, None)

        dt_ms = int((time.time() - t0) * 1000)
        info(f"[forward] <- resp req_id={req_id} ok={bool(resp.ok)} dt_ms={dt_ms} err={str(resp.error or '')!r}")

        if not resp.ok:
            r = generic_pb2.GenericRPCResponse()
            r.results["Ok"].CopyFrom(map_arg(False))
            r.results["Error"].CopyFrom(map_arg(resp.error or "Remote host error."))
            return r

        return resp.response

    def forward_request_by_host_device(
        self,
        *,
        host_id: str,
        device_id: str,
        request: "generic_pb2.GenericRPCRequest",
        timeout_sec: float,
        deadline_unix_ms: int = 0,
        cancel_on_timeout: bool = False,
    ) -> "generic_pb2.GenericRPCResponse":
        with self._lock:
            route = self._routes.get(str(device_id))
            if route is None:
                warn(f"[forward] unknown device_id={device_id!r}")
                r = generic_pb2.GenericRPCResponse()
                r.results["Ok"].CopyFrom(map_arg(False))
                r.results["Error"].CopyFrom(map_arg(f"Unknown device_id={device_id}"))
                return r

            if route.host_id != host_id:
                warn(f"[forward] device_id={device_id!r} not on host_id={host_id!r} (actual={route.host_id!r})")
                r = generic_pb2.GenericRPCResponse()
                r.results["Ok"].CopyFrom(map_arg(False))
                r.results["Error"].CopyFrom(map_arg(f"device_id={device_id} is not on host_id={host_id}"))
                return r

        return self.forward_request(
            device_id=device_id,
            request=request,
            timeout_sec=timeout_sec,
            deadline_unix_ms=deadline_unix_ms,
            cancel_on_timeout=cancel_on_timeout,
        )

# Convenience forwarders

def handle_host_device(
    registry: HostTunnelRegistry,
    *,
    host_id: str,
    device_id: str,
    function_name: str,
    args: Any,
    timeout_sec: float = 10.0,
) -> Dict[str, Any]:
    info(f"[handle_host_device] host_id={host_id!r} device_id={device_id!r} fn={function_name!r}")
    req = generic_pb2.GenericRPCRequest(function_name=str(function_name))
    _copy_argument_map(req.args, args)

    resp = registry.forward_request_by_host_device(
        host_id=host_id,
        device_id=device_id,
        request=req,
        timeout_sec=timeout_sec,
        cancel_on_timeout=True,
    )
    return dict(resp.results)

def handle_host_device_request(
    registry: HostTunnelRegistry,
    *,
    host_id: str,
    device_id: str,
    request: "generic_pb2.GenericRPCRequest",
    timeout_sec: float = 10.0,
) -> "generic_pb2.GenericRPCResponse":
    info(
        f"[handle_host_device_request] host_id={host_id!r} device_id={device_id!r} "
        f"fn={str(getattr(request,'function_name','') or '')!r}"
    )
    return registry.forward_request_by_host_device(
        host_id=host_id,
        device_id=device_id,
        request=request,
        timeout_sec=timeout_sec,
        cancel_on_timeout=True,
    )

# Servicer

class HostTunnelServicer(host_tunnel_pb2_grpc.HostTunnelServicer):
    def __init__(self, registry: HostTunnelRegistry) -> None:
        self.registry = registry

    def Connect(self, request_iterator: Iterator[host_tunnel_pb2.HostFrame], context):
        try:
            peer = context.peer()
        except Exception:
            peer = "unknown-peer"

        peer_tag = _safe_thread_tag(peer)
        stream_uuid = uuid.uuid4().hex[:10]
        info(f"[Connect] new stream peer={peer} stream_sess={stream_uuid}")

        host_id: Optional[str] = None
        session: Optional[HostSession] = None
        stop = threading.Event()
        fatal: Dict[str, str] = {}  # {"code": "...", "details": "..."}

        # IMPORTANT: only drop the host if THIS stream successfully registered it,
        # and only if the registry still points at THIS session.
        registered = False

        cleanup_lock = threading.Lock()
        cleanup_done = False

        def _cleanup(reason: str, *, detail: str = "") -> None:
            nonlocal cleanup_done
            with cleanup_lock:
                if cleanup_done:
                    return
                cleanup_done = True

            # stop pumps first
            try:
                stop.set()
            except Exception:
                pass

            hid = host_id or "?"
            det = (detail or "").strip()
            if det:
                warn(f"[host] offline host_id={hid!r} reason={reason} detail={det}")
            else:
                warn(f"[host] offline host_id={hid!r} reason={reason}")

            # If we never registered, do NOT drop: it could be a conflict with a real live host.
            try:
                if registered and host_id is not None and session is not None:
                    self.registry.drop_host_if_match(host_id, session)
            except Exception:
                pass

            # close session object (no-op if already closed)
            try:
                if session is not None:
                    session.close()
            except Exception:
                pass

        def _on_rpc_done():
            try:
                _cleanup("grpc-stream-done")
            except Exception:
                pass

        try:
            context.add_callback(_on_rpc_done)
        except Exception:
            pass

        def inbound_loop():
            nonlocal host_id, session, registered
            info(f"[inbound] start peer={peer} stream_sess={stream_uuid}")

            try:
                for frame in request_iterator:
                    which = frame.WhichOneof("msg")
                    if which is None:
                        warn(f"[inbound] frame with no msg peer={peer} stream_sess={stream_uuid}")
                        continue

                    info(f"[inbound] IN type={which} peer={peer} stream_sess={stream_uuid} host_id={host_id or '?'}")

                    if which == "hello":
                        # Guard: only accept one HELLO per stream.
                        if session is not None or host_id is not None:
                            warn(f"[inbound] duplicate HELLO ignored host_id={host_id!r} peer={peer} stream_sess={stream_uuid}")
                            continue

                        hello = frame.hello
                        raw_id = str(getattr(hello, "host_id", "") or "")
                        raw_tok = str(getattr(hello, "host_token", "") or "")  # NEW FIELD

                        try:
                            host_id = _validate_host_id(raw_id)
                        except ValueError as e:
                            error(f"[inbound] invalid hello.host_id peer={peer} stream_sess={stream_uuid} err={e}")
                            fatal["code"] = "INVALID_ARGUMENT"
                            fatal["details"] = str(e)
                            stop.set()
                            return

                        # Auth gate: MUST pass before we register the host_id.
                        if not is_host_token_valid(host_id, raw_tok, require_status="approved"):
                            code, details = _auth_fail_code_and_details(host_id)
                            error(
                                f"[inbound] auth failed host_id={host_id!r} peer={peer} stream_sess={stream_uuid} "
                                f"code={code} details={details}"
                            )
                            fatal["code"] = code
                            fatal["details"] = details
                            stop.set()
                            return

                        ver = str(getattr(hello, "version", "") or "")
                        info(f"[inbound] HELLO host_id={host_id!r} version={ver!r} peer={peer} stream_sess={stream_uuid}")

                        # ONE session per stream
                        session = HostSession(host_id, peer=peer, session_uuid=stream_uuid)

                        # ONE register per stream
                        try:
                            self.registry.register_host(host_id, session, replace_if_stale_ms=15_000)
                            registered = True
                        except HostIdConflictError as e:
                            error(f"[inbound] HostIdConflictError host_id={host_id!r} stream_sess={stream_uuid} err={e}")
                            fatal["code"] = "ALREADY_EXISTS"
                            fatal["details"] = str(e)
                            try:
                                session.close()
                            except Exception:
                                pass
                            stop.set()
                            return

                        self.registry.persist_host_meta_from_hello(hello)

                        # Ask host for metadata immediately on join
                        try:
                            mrid = secrets.token_hex(12)
                            ok = session.send(
                                host_tunnel_pb2.HostFrame(
                                    meta_request=host_tunnel_pb2.MetaRequest(
                                        req_id=mrid,
                                        include_platform=True,
                                        include_env=True,
                                        include_devices=True,
                                    )
                                )
                            )
                            info(
                                f"[inbound] sent MetaRequest req_id={mrid} ok={ok} "
                                f"host_id={host_id!r} stream_sess={stream_uuid}"
                            )
                        except Exception:
                            exception("[inbound] FAILED sending MetaRequest")

                        # heartbeat ack
                        try:
                            ok = session.send(
                                host_tunnel_pb2.HostFrame(
                                    heartbeat=host_tunnel_pb2.Heartbeat(unix_ms=now_ms())
                                )
                            )
                            info(
                                f"[inbound] sent heartbeat ack ok={ok} "
                                f"host_id={host_id!r} stream_sess={stream_uuid}"
                            )
                        except Exception:
                            exception("[inbound] FAILED sending heartbeat ack")

                    elif which == "device_announce":
                        if session is None or host_id is None:
                            warn(f"[inbound] device_announce before hello/session: ignoring peer={peer} stream_sess={stream_uuid}")
                            continue

                        ann = frame.device_announce
                        n = len(getattr(ann, "devices", []))
                        info(
                            f"[inbound] DEVICE_ANNOUNCE host_id={host_id!r} n={n} stream_sess={stream_uuid} "
                            f"unix_ms={int(getattr(ann,'unix_ms',0) or 0)} full_snapshot={bool(getattr(ann,'full_snapshot',False))}"
                        )

                        for d in list(ann.devices):
                            info(
                                f"[inbound]  device local_id={int(getattr(d,'local_id',0))} "
                                f"label={str(getattr(d,'label','') or '')!r} "
                                f"device_id={str(getattr(d,'device_id','') or '')!r} "
                                f"serial={str(getattr(d,'serial','') or '')!r} "
                                f"kind={str(getattr(d,'kind','') or '')!r}"
                            )

                        try:
                            self.registry.announce_devices(
                                host_id, list(ann.devices), full_snapshot=bool(ann.full_snapshot)
                            )
                            info(f"[inbound] registry announce applied host_id={host_id!r} stream_sess={stream_uuid}")
                        except ValueError as e:
                            error(
                                f"[inbound] INVALID_ARGUMENT device announce host_id={host_id!r} "
                                f"stream_sess={stream_uuid} err={e}"
                            )
                            fatal["code"] = "INVALID_ARGUMENT"
                            fatal["details"] = str(e)
                            stop.set()
                            return
                        except DeviceIdConflictError as e:
                            error(f"[inbound] DeviceIdConflictError host_id={host_id!r} stream_sess={stream_uuid} err={e}")
                            fatal["code"] = "ALREADY_EXISTS"
                            fatal["details"] = str(e)
                            stop.set()
                            return
                        except Exception:
                            exception(f"[inbound] announce_devices crashed host_id={host_id!r} stream_sess={stream_uuid}")

                        # heartbeat ack after announce
                        try:
                            ok = session.send(
                                host_tunnel_pb2.HostFrame(
                                    heartbeat=host_tunnel_pb2.Heartbeat(unix_ms=now_ms())
                                )
                            )
                            info(
                                f"[inbound] sent heartbeat ack after announce ok={ok} "
                                f"host_id={host_id!r} stream_sess={stream_uuid}"
                            )
                        except Exception:
                            exception("[inbound] FAILED sending heartbeat ack after announce")

                    elif which == "rpc_response":
                        if session is None:
                            warn(f"[inbound] rpc_response before session: ignoring peer={peer} stream_sess={stream_uuid}")
                            continue

                        resp = frame.rpc_response
                        rid = str(getattr(resp, "req_id", "") or "")
                        ok = bool(getattr(resp, "ok", False))
                        err_s = str(getattr(resp, "error", "") or "")
                        info(f"[inbound] RPC_RESPONSE req_id={rid} ok={ok} error={err_s!r} stream_sess={stream_uuid}")

                        with session.inflight_lock:
                            fut = session.inflight.get(rid)

                        if fut is not None and not fut.done():
                            fut.set_result(resp)
                            info(f"[inbound] delivered rpc_response to waiter req_id={rid} stream_sess={stream_uuid}")
                        else:
                            warn(f"[inbound] rpc_response has no inflight waiter req_id={rid} stream_sess={stream_uuid}")

                    elif which == "meta_response":
                        # NEW proto: MetaResponse.meta.devices + meta.kv (IDL caps)
                        if host_id is None or session is None:
                            warn(f"[inbound] meta_response before hello/session: ignoring peer={peer} stream_sess={stream_uuid}")
                            continue

                        mr = frame.meta_response
                        ok = bool(getattr(mr, "ok", False))
                        err_s = str(getattr(mr, "error", "") or "")
                        info(f"[inbound] META_RESPONSE ok={ok} error={err_s!r} stream_sess={stream_uuid}")

                        if ok:
                            try:
                                meta = getattr(mr, "meta", None)
                                devs = list(getattr(meta, "devices", []) or [])
                            except Exception:
                                devs = []

                            if devs:
                                info(f"[inbound] META_RESPONSE applying {len(devs)} devices to registry host_id={host_id!r}")
                                try:
                                    self.registry.announce_devices(host_id, devs)
                                    self.registry.heartbeat(host_id, now_ms())
                                except ValueError as e:
                                    error(f"[inbound] META_RESPONSE INVALID_ARGUMENT host_id={host_id!r} err={e}")
                                    fatal["code"] = "INVALID_ARGUMENT"
                                    fatal["details"] = str(e)
                                    stop.set()
                                    return
                                except DeviceIdConflictError as e:
                                    error(f"[inbound] META_RESPONSE DeviceIdConflictError host_id={host_id!r} err={e}")
                                    fatal["code"] = "ALREADY_EXISTS"
                                    fatal["details"] = str(e)
                                    stop.set()
                                    return
                                except Exception:
                                    exception("[inbound] META_RESPONSE announce_devices failed")
                            else:
                                info("[inbound] META_RESPONSE had no meta.devices (or empty)")

                            # Read per-device IDL capability strings from meta.kv.
                            # Keys: "device.<gid>.caps"  "device.<gid>.type"
                            # These are emitted by the host's tunnel_agent._collect_meta().
                            try:
                                kv = dict(getattr(meta, "kv", {}) or {})
                                for k, v in kv.items():
                                    # e.g. k="device.0.caps", v="disable_dds:call0,filter:rw,..."
                                    parts = k.split(".")
                                    if len(parts) == 3 and parts[0] == "device" and parts[2] == "caps":
                                        device_id = parts[1]
                                        self.registry.store_host_device_caps(host_id, device_id, str(v))
                                        info(
                                            f"[inbound] stored IDL caps device_id={device_id} "
                                            f"host_id={host_id!r} n_attrs={len(v.split(','))}"
                                        )
                                    elif len(parts) == 3 and parts[0] == "device" and parts[2] == "schema_hash":
                                        self.registry.store_host_device_schema_hash(host_id, parts[1], str(v))
                            except Exception:
                                exception("[inbound] META_RESPONSE failed reading meta.kv caps")

                    elif which == "heartbeat":
                        if session is not None and host_id is not None:
                            ms = int(getattr(frame.heartbeat, "unix_ms", 0) or 0) or now_ms()
                            session.last_heartbeat_ms = ms
                            self.registry.heartbeat(host_id, ms)
                            info(f"[inbound] HEARTBEAT host_id={host_id!r} unix_ms={ms} stream_sess={stream_uuid}")
                        else:
                            warn(
                                f"[inbound] heartbeat before hello/session: ignoring peer={peer} "
                                f"stream_sess={stream_uuid} host_id={(host_id or '?')!r}"
                            )

                    elif which == "cancel":
                        try:
                            rid = str(getattr(frame.cancel, "req_id", "") or "")
                            warn(f"[inbound] CANCEL received from host?? req_id={rid} peer={peer} stream_sess={stream_uuid}")
                        except Exception:
                            exception("[inbound] cancel frame parse failed")

                    else:
                        warn(f"[inbound] unknown frame type={which} peer={peer} stream_sess={stream_uuid}")

            except grpc.RpcError as e:
                warn(
                    f"[inbound] stream ended peer={peer} stream_sess={stream_uuid} "
                    f"host_id={host_id or '?'} grpc={_grpc_err_summary(e)}"
                )
            except Exception:
                exception(f"[inbound] loop crashed peer={peer} stream_sess={stream_uuid} host_id={host_id or '?'}")
            finally:
                info(f"[inbound] exiting peer={peer} stream_sess={stream_uuid} host_id={host_id or '?'}")
                _cleanup("inbound-exit")

        t = threading.Thread(target=inbound_loop, daemon=True, name=f"inbound_{peer_tag}")
        t.start()

        info(f"[Connect] outbound pump starting peer={peer} stream_sess={stream_uuid}")

        printed_waiting = False
        try:
            while not stop.is_set():
                if not context.is_active():
                    _cleanup("context-inactive")
                    break

                if fatal:
                    code = fatal.get("code", "")
                    details = fatal.get("details", "fatal")
                    error(f"[Connect] aborting stream peer={peer} stream_sess={stream_uuid} code={code} details={details}")
                    _cleanup(f"fatal:{code}", detail=details)

                    if code == "ALREADY_EXISTS":
                        context.abort(grpc.StatusCode.ALREADY_EXISTS, details)
                    if code == "INVALID_ARGUMENT":
                        context.abort(grpc.StatusCode.INVALID_ARGUMENT, details)
                    if code == "UNAUTHENTICATED":
                        context.abort(grpc.StatusCode.UNAUTHENTICATED, details)
                    if code == "PERMISSION_DENIED":
                        context.abort(grpc.StatusCode.PERMISSION_DENIED, details)

                    context.abort(grpc.StatusCode.UNKNOWN, details)

                if session is None:
                    if not printed_waiting:
                        info(f"[Connect] waiting for HELLO peer={peer} stream_sess={stream_uuid}")
                        printed_waiting = True
                    time.sleep(0.05)
                    continue

                try:
                    out = session.out_q.get(timeout=0.5)
                except queue.Empty:
                    continue
                except Exception:
                    exception(
                        f"[Connect] outbound queue get failed peer={peer} stream_sess={stream_uuid} "
                        f"host_id={host_id or '?'}"
                    )
                    continue

                if out is None:
                    info(f"[Connect] outbound sentinel -> end stream peer={peer} stream_sess={stream_uuid} host_id={host_id or '?'}")
                    _cleanup("outbound-sentinel")
                    break

                out_type = out.WhichOneof("msg")
                info(f"[Connect] OUT type={out_type} peer={peer} stream_sess={stream_uuid} host_id={host_id or '?'}")
                yield out

        except grpc.RpcError as e:
            warn(
                f"[Connect] outbound ended peer={peer} stream_sess={stream_uuid} "
                f"host_id={host_id or '?'} grpc={_grpc_err_summary(e)}"
            )
            _cleanup("outbound-grpc", detail=_grpc_err_summary(e))
        except GeneratorExit:
            _cleanup("generator-exit")
            raise
        finally:
            _cleanup("connect-finally")
            info(f"[Connect] stream ended peer={peer} stream_sess={stream_uuid} host_id={host_id or '?'}")

# Credentials + server start

def build_server_credentials(
    *,
    private_key_pem: bytes,
    certificate_chain_pem: bytes,
    client_ca_pem: Optional[bytes] = None,
    require_client_auth: bool = True,
) -> grpc.ServerCredentials:
    info(f"[creds] build_server_credentials client_ca={'yes' if bool(client_ca_pem) else 'no'} require_client_auth={require_client_auth}")
    if client_ca_pem:
        return grpc.ssl_server_credentials(
            ((private_key_pem, certificate_chain_pem,),),
            root_certificates=client_ca_pem,
            require_client_auth=require_client_auth,
        )
    return grpc.ssl_server_credentials(((private_key_pem, certificate_chain_pem),))


def start_host_tunnel_server(
    *,
    host: str,
    port: int,
    server_credentials: grpc.ServerCredentials,
    registry: Optional[HostTunnelRegistry] = None,
    max_workers: int = 32,
) -> Tuple[grpc.Server, threading.Thread, HostTunnelRegistry]:
    if registry is not None:
        reg = set_tunnel_registry(registry)
    else:
        reg = get_tunnel_registry(create=True)
        assert reg is not None

    options = [
        ("grpc.max_send_message_length", 100 * 1024 * 1024),
        ("grpc.max_receive_message_length", 100 * 1024 * 1024),
        ("grpc.keepalive_time_ms", 30_000),
        ("grpc.keepalive_timeout_ms", 10_000),
        ("grpc.http2.max_pings_without_data", 0),
        ("grpc.keepalive_permit_without_calls", 1),
    ]

    bind_addr = f"{host}:{int(port)}"
    info(f"[server] creating grpc.server max_workers={max_workers} bind={bind_addr}")

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=max_workers),
        options=options,
    )

    host_tunnel_pb2_grpc.add_HostTunnelServicer_to_server(HostTunnelServicer(reg), server)

    try:
        added = server.add_secure_port(bind_addr, server_credentials)
        info(f"[server] add_secure_port addr={bind_addr} -> {added}")
    except Exception:
        exception(f"[server] add_secure_port failed addr={bind_addr}")
        raise

    def run():
        try:
            info(f"[server] starting on {bind_addr}")
            server.start()
            info(f"[server] started on {bind_addr} (waiting for termination)")
            server.wait_for_termination()
            info("[server] wait_for_termination returned")
        except Exception:
            exception("[server] run() crashed")
            raise

    th = threading.Thread(target=run, daemon=True, name="host_tunnel_server")
    th.start()
    return server, th, reg

# Singleton registry (process-wide)

_TUNNEL_REGISTRY_LOCK = threading.Lock()
TUNNEL_REGISTRY: Optional["HostTunnelRegistry"] = None

def get_tunnel_registry(*, create: bool = True) -> Optional["HostTunnelRegistry"]:
    global TUNNEL_REGISTRY

    if TUNNEL_REGISTRY is not None:
        return TUNNEL_REGISTRY
    if not create:
        return None

    with _TUNNEL_REGISTRY_LOCK:
        if TUNNEL_REGISTRY is None:
            TUNNEL_REGISTRY = HostTunnelRegistry()
        return TUNNEL_REGISTRY

def set_tunnel_registry(reg: "HostTunnelRegistry") -> "HostTunnelRegistry":
    """Force the singleton to a specific instance."""
    global TUNNEL_REGISTRY
    with _TUNNEL_REGISTRY_LOCK:
        TUNNEL_REGISTRY = reg
    return reg