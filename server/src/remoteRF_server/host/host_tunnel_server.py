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
import os

from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Any, List, Set, Iterator

from concurrent.futures import Future
from concurrent import futures

import grpc

# Your existing GenericRPC schema compiled to python.
from ..common.grpc import grpc_pb2 as generic_pb2  # type: ignore

# Your existing map_arg helper that produces generic_pb2.Argument
from ..common.utils.process_arg import map_arg  # type: ignore

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

# =============================================================================
# Hardcoded logging mode (NO env vars)
#
# Pick ONE:
#   LOG_MODE = "OFF"   -> show nothing
#   LOG_MODE = "WARN"  -> show only WARN + ERROR
#   LOG_MODE = "ALL"   -> show everything (INFO + WARN + ERROR)
# =============================================================================

LOG_MODE = "OFF"  # <-- change this

_LOG_LOCK = threading.Lock()

HOST_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")  # adjust if you want

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
    # safe default if mis-set
    return lvl in ("WARN", "ERROR")

def _log(level: str, msg: str) -> None:
    if not _should_log(level):
        return
    tn = threading.current_thread().name
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

# =============================================================================
# Helpers
# =============================================================================

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

# =============================================================================
# Types
# =============================================================================

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

# =============================================================================
# Session
# =============================================================================

class HostSession:
    """
    Represents one connected host (one bidi stream).
    Owns:
      - outbound frame queue
      - inflight req_id -> Future
    """
    def __init__(self, host_id: str, *, outbound_max: int = 2048) -> None:
        self.host_id = host_id
        self.out_q: "queue.Queue[Optional[host_tunnel_pb2.HostFrame]]" = queue.Queue(maxsize=int(outbound_max))
        self.inflight: Dict[str, Future] = {}
        self.inflight_lock = threading.Lock()
        self.last_heartbeat_ms = now_ms()
        self.alive = True
        self.outbound_max = int(outbound_max)

        info(f"[session] created host_id={self.host_id!r} outbound_max={self.outbound_max}")

    def send(self, frame: host_tunnel_pb2.HostFrame, *, timeout: float = 2.0) -> bool:
        which = frame.WhichOneof("msg")
        if not self.alive:
            warn(f"[session] send refused (dead session) host_id={self.host_id!r} type={which}")
            return False
        try:
            self.out_q.put(frame, timeout=timeout)
            info(f"[session] queued outbound host_id={self.host_id!r} type={which}")
            return True
        except queue.Full:
            warn(f"[session] outbound queue FULL host_id={self.host_id!r} max={self.outbound_max} drop type={which}")
            return False
        except Exception:
            exception(f"[session] send exception host_id={self.host_id!r} type={which}")
            return False

    def close(self) -> None:
        if not self.alive:
            return
        info(f"[session] closing host_id={self.host_id!r}")
        self.alive = False

        try:
            self.out_q.put_nowait(None)
        except Exception:
            exception(f"[session] close: failed to enqueue sentinel host_id={self.host_id!r}")

        with self.inflight_lock:
            for rid, fut in list(self.inflight.items()):
                if not fut.done():
                    fut.set_exception(RuntimeError(f"Host '{self.host_id}' disconnected (req_id={rid})"))
            self.inflight.clear()

        info(f"[session] closed host_id={self.host_id!r}")

# =============================================================================
# Registry
# =============================================================================

class HostTunnelRegistry:
    """
    Persistent host/device directory + live sessions.

    Persists under <repo_root>/.config/:
      - host_directory.env        (append-only CSV lists)
      - host_directory_meta.env   (upsert metadata; never deletes keys)

    Enforces:
      - device_id is globally unique across hosts (rejects conflicting host announce)
    """

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

    # ---------------------------
    # caching helpers
    # ---------------------------

    def _invalidate_caches_locked(self) -> None:
        self._active_hosts_cache_ts_ms = 0
        self._dir_cache_ts_ms = 0

    def _refresh_active_hosts_cache_locked(self, now: int) -> None:
        if self._active_hosts_cache_ts_ms and (now - self._active_hosts_cache_ts_ms) < self._active_hosts_cache_ttl_ms:
            return
        self._active_hosts_cache = {hid for hid, sess in self._hosts.items() if sess is not None and sess.alive}
        self._active_hosts_cache_ts_ms = now

    # ---------------------------
    # persistence load
    # ---------------------------

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
                if not device_id:
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

        info(f"[registry] persisted directory loaded: routes={len(self._routes)} hosts={len(self._host_status)} devices={len(self._device_status)}")

    # ---------------------------
    # persistence write helpers
    # ---------------------------

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

    # ---------------------------
    # directory/status mutators
    # ---------------------------

    def register_host(
        self,
        host_id: str,
        session: HostSession,
        *,
        replace_if_stale_ms: int = 15_000,  # tweak: how long without heartbeat before we allow replacement
    ) -> None:
        info(f"[registry] register_host: host_id={host_id!r}")

        with self._lock:
            old = self._hosts.get(host_id)
            if old is not None and old.alive:
                age_ms = int(now_ms() - int(getattr(old, "last_heartbeat_ms", 0) or 0))
                if age_ms < replace_if_stale_ms:
                    # conflict: someone else is already using this host_id
                    raise HostIdConflictError(host_id, age_ms=age_ms, replace_after_ms=replace_if_stale_ms)

                # stale: allow replacement
                warn(f"[registry] register_host: replacing STALE session host_id={host_id!r} age_ms={age_ms}")
                old.close()

            self._hosts[host_id] = session

            hs = self._host_status.get(host_id) or HostStatus(host_id=host_id)
            hs.online = True
            hs.last_seen_ms = now_ms()
            self._host_status[host_id] = hs

            self._host_devices.setdefault(host_id, set())
            self._persist_host(host_id)
            self._invalidate_caches_locked()

        info(f"[registry] register_host done: host_id={host_id!r} online=True")

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

    def announce_devices(self, host_id: str, devices: list) -> None:
        info(f"[registry] announce_devices: host_id={host_id!r} n={len(devices)}")

        # conflict check first (no partial apply)
        with self._lock:
            for d in devices:
                device_id = str(getattr(d, "device_id", "")).strip()
                if not device_id:
                    continue
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

            for d in devices:
                device_id = str(getattr(d, "device_id", "")).strip()
                if not device_id:
                    warn(f"[registry] announce_devices: skipping device with empty device_id host_id={host_id!r}")
                    continue

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
                    self._device_infos[device_id] = tmp
                except Exception:
                    self._device_infos[device_id] = host_tunnel_pb2.DeviceInfo(
                        device_id=device_id,
                        local_id=int(local_id),
                        label=label,
                        serial=serial,
                        kind=kind,
                    )

                self._persist_device(host_id, device_id, local_id, d)

            self._invalidate_caches_locked()

        info(f"[registry] announce_devices done: host_id={host_id!r} routes={len(self._routes)}")

    # ---------------------------
    # FAST PATHS (use per-RPC)
    # ---------------------------

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

    # ---------------------------
    # UI/diagnostics snapshots
    # ---------------------------

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

    # ---------------------------
    # misc accessors
    # ---------------------------

    def list_routes(self) -> Dict[str, Tuple[str, int]]:
        with self._lock:
            return {did: (r.host_id, r.host_local_id) for did, r in self._routes.items()}

    def list_hosts(self) -> Dict[str, HostStatus]:
        with self._lock:
            return dict(self._host_status)

    def list_devices(self) -> Dict[str, DeviceStatus]:
        with self._lock:
            return dict(self._device_status)

    # ---------------------------
    # forwarding
    # ---------------------------

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

        rpc_req = host_tunnel_pb2.RpcRequest(
            req_id=req_id,
            device_id=str(device_id),
            local_device_id=int(route.host_local_id),
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

# =============================================================================
# Convenience forwarders
# =============================================================================

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

# =============================================================================
# Servicer
# =============================================================================

class HostTunnelServicer(host_tunnel_pb2_grpc.HostTunnelServicer):
    def __init__(self, registry: HostTunnelRegistry) -> None:
        self.registry = registry

    def Connect(self, request_iterator: Iterator[host_tunnel_pb2.HostFrame], context):
        try:
            peer = context.peer()
        except Exception:
            peer = "unknown-peer"

        peer_tag = _safe_thread_tag(peer)
        info(f"[Connect] new stream peer={peer}")

        host_id: Optional[str] = None
        session: Optional[HostSession] = None
        stop = threading.Event()
        fatal: Dict[str, str] = {}  # {"code": "...", "details": "..."}

        def inbound_loop():
            nonlocal host_id, session
            info(f"[inbound] start peer={peer}")

            try:
                for frame in request_iterator:
                    which = frame.WhichOneof("msg")
                    if which is None:
                        warn(f"[inbound] frame with no msg peer={peer}")
                        continue

                    info(f"[inbound] IN type={which} peer={peer} host_id={host_id or '?'}")

                    if which == "hello":
                        hello = frame.hello
                        raw = str(getattr(hello, "host_id", "") or "")
                        try:
                            host_id = _validate_host_id(raw)
                        except ValueError as e:
                            error(f"[inbound] invalid hello.host_id peer={peer} err={e}")
                            fatal["code"] = "INVALID_ARGUMENT"
                            fatal["details"] = str(e)
                            stop.set()
                            return

                        ver = str(getattr(hello, "version", "") or "")
                        info(f"[inbound] HELLO host_id={host_id!r} version={ver!r} peer={peer}")

                        session = HostSession(host_id)
                        try:
                            self.registry.register_host(host_id, session, replace_if_stale_ms=15_000)
                        except HostIdConflictError as e:
                            error(f"[inbound] HostIdConflictError host_id={host_id!r} err={e}")
                            fatal["code"] = "ALREADY_EXISTS"
                            fatal["details"] = str(e)
                            stop.set()
                            return
                        ver = str(getattr(hello, "version", "") or "")
                        info(f"[inbound] HELLO host_id={host_id!r} version={ver!r} peer={peer}")

                        session = HostSession(host_id)
                        self.registry.register_host(host_id, session)
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
                            info(f"[inbound] sent MetaRequest req_id={mrid} ok={ok} host_id={host_id!r}")
                        except Exception:
                            exception("[inbound] FAILED sending MetaRequest")

                        # heartbeat ack
                        try:
                            ok = session.send(host_tunnel_pb2.HostFrame(heartbeat=host_tunnel_pb2.Heartbeat(unix_ms=now_ms())))
                            info(f"[inbound] sent heartbeat ack ok={ok} host_id={host_id!r}")
                        except Exception:
                            exception("[inbound] FAILED sending heartbeat ack")

                    elif which == "device_announce":
                        if session is None or host_id is None:
                            warn(f"[inbound] device_announce before hello/session: ignoring peer={peer}")
                            continue

                        ann = frame.device_announce
                        n = len(getattr(ann, "devices", []))
                        info(
                            f"[inbound] DEVICE_ANNOUNCE host_id={host_id!r} n={n} "
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
                            self.registry.announce_devices(host_id, list(ann.devices))
                            info(f"[inbound] registry announce applied host_id={host_id!r}")
                        except DeviceIdConflictError as e:
                            error(f"[inbound] DeviceIdConflictError host_id={host_id!r} err={e}")
                            fatal["code"] = "ALREADY_EXISTS"
                            fatal["details"] = str(e)
                            stop.set()
                            return
                        except Exception:
                            exception(f"[inbound] announce_devices crashed host_id={host_id!r}")

                        # heartbeat ack after announce
                        try:
                            ok = session.send(host_tunnel_pb2.HostFrame(heartbeat=host_tunnel_pb2.Heartbeat(unix_ms=now_ms())))
                            info(f"[inbound] sent heartbeat ack after announce ok={ok} host_id={host_id!r}")
                        except Exception:
                            exception("[inbound] FAILED sending heartbeat ack after announce")

                    elif which == "rpc_response":
                        if session is None:
                            warn(f"[inbound] rpc_response before session: ignoring peer={peer}")
                            continue

                        resp = frame.rpc_response
                        rid = str(getattr(resp, "req_id", "") or "")
                        ok = bool(getattr(resp, "ok", False))
                        err_s = str(getattr(resp, "error", "") or "")
                        info(f"[inbound] RPC_RESPONSE req_id={rid} ok={ok} error={err_s!r}")

                        with session.inflight_lock:
                            fut = session.inflight.get(rid)

                        if fut is not None and not fut.done():
                            fut.set_result(resp)
                            info(f"[inbound] delivered rpc_response to waiter req_id={rid}")
                        else:
                            warn(f"[inbound] rpc_response has no inflight waiter req_id={rid}")

                    elif which == "meta_response":
                        try:
                            mr = frame.meta_response
                            ok = bool(getattr(mr, "ok", False))
                            err_s = str(getattr(mr, "error", "") or "")
                            info(f"[inbound] META_RESPONSE ok={ok} error={err_s!r}")
                            try:
                                info(f"[inbound] META_RESPONSE proto:\n{mr}")
                            except Exception:
                                pass
                        except Exception:
                            exception("[inbound] meta_response handling crashed")

                    elif which == "heartbeat":
                        if session is not None and host_id is not None:
                            ms = int(getattr(frame.heartbeat, "unix_ms", 0) or 0) or now_ms()
                            session.last_heartbeat_ms = ms
                            self.registry.heartbeat(host_id, ms)
                            info(f"[inbound] HEARTBEAT host_id={host_id!r} unix_ms={ms}")
                        else:
                            warn(f"[inbound] heartbeat before hello/session: ignoring peer={peer} host_id={(host_id or '?')!r}")

                    elif which == "cancel":
                        try:
                            rid = str(getattr(frame.cancel, "req_id", "") or "")
                            warn(f"[inbound] CANCEL received from host?? req_id={rid} peer={peer}")
                        except Exception:
                            exception("[inbound] cancel frame parse failed")

                    else:
                        warn(f"[inbound] unknown frame type={which} peer={peer}")

            except Exception:
                exception(f"[inbound] loop crashed peer={peer} host_id={host_id or '?'}")
            finally:
                info(f"[inbound] exiting peer={peer} host_id={host_id or '?'}")
                stop.set()
                if host_id is not None:
                    try:
                        self.registry.drop_host(host_id)
                    except Exception:
                        exception(f"[inbound] registry.drop_host failed host_id={host_id!r}")
                if session is not None:
                    try:
                        session.close()
                    except Exception:
                        exception(f"[inbound] session.close failed host_id={host_id!r}")

        t = threading.Thread(target=inbound_loop, daemon=True, name=f"inbound_{peer_tag}")
        t.start()

        info(f"[Connect] outbound pump starting peer={peer}")

        printed_waiting = False
        while not stop.is_set():
            if fatal:
                code = fatal.get("code", "")
                details = fatal.get("details", "fatal")
                error(f"[Connect] aborting stream peer={peer} code={code} details={details}")
                if code == "ALREADY_EXISTS":
                    context.abort(grpc.StatusCode.ALREADY_EXISTS, details)
                if code == "INVALID_ARGUMENT":
                    context.abort(grpc.StatusCode.INVALID_ARGUMENT, details)
                context.abort(grpc.StatusCode.UNKNOWN, details)

            if session is None:
                if not printed_waiting:
                    info(f"[Connect] waiting for HELLO peer={peer}")
                    printed_waiting = True
                time.sleep(0.05)
                continue

            try:
                out = session.out_q.get(timeout=0.5)
            except queue.Empty:
                continue
            except Exception:
                exception(f"[Connect] outbound queue get failed peer={peer} host_id={host_id or '?'}")
                continue

            if out is None:
                info(f"[Connect] outbound sentinel -> end stream peer={peer} host_id={host_id or '?'}")
                break

            out_type = out.WhichOneof("msg")
            info(f"[Connect] OUT type={out_type} peer={peer} host_id={host_id or '?'}")
            yield out

        info(f"[Connect] stream ended peer={peer} host_id={host_id or '?'}")

# =============================================================================
# Credentials + server start
# =============================================================================

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
    reg = registry or HostTunnelRegistry()

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