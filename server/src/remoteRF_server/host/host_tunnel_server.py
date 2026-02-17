# src/remoteRF_host/host/host_tunnel_server.py

from __future__ import annotations

import threading
import queue
import time
import secrets
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Any, List, Set, Iterator
from concurrent.futures import Future
from concurrent import futures
from pathlib import Path

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


def _copy_argument_map(dst_map: Any, src_map: Any) -> None:
    if src_map is None:
        return
    try:
        for k in src_map:
            dst_map[str(k)].CopyFrom(src_map[k])
    except Exception:
        for k, v in dict(src_map).items():
            dst_map[str(k)].CopyFrom(v)


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


class HostSession:
    """
    Represents one connected host (one bidi stream).
    Owns:
      - outbound frame queue
      - inflight req_id -> Future
    """
    def __init__(self, host_id: str, *, outbound_max: int = 2048) -> None:
        self.host_id = host_id
        self.out_q: "queue.Queue[Optional[host_tunnel_pb2.HostFrame]]" = queue.Queue(maxsize=outbound_max)
        self.inflight: Dict[str, Future] = {}
        self.inflight_lock = threading.Lock()
        self.last_heartbeat_ms = now_ms()
        self.alive = True

    def send(self, frame: host_tunnel_pb2.HostFrame, *, timeout: float = 2.0) -> bool:
        if not self.alive:
            return False
        try:
            self.out_q.put(frame, timeout=timeout)
            return True
        except queue.Full:
            return False

    def close(self) -> None:
        self.alive = False
        try:
            self.out_q.put_nowait(None)
        except Exception:
            pass

        with self.inflight_lock:
            for _, fut in list(self.inflight.items()):
                if not fut.done():
                    fut.set_exception(RuntimeError(f"Host '{self.host_id}' disconnected"))
            self.inflight.clear()

class HostTunnelRegistry:
    """
    Persistent host/device directory + live sessions.

    Persists under <repo_root>/.config/:
      - host_directory.env        (append-only CSV lists)
      - host_directory_meta.env   (upsert metadata; never deletes keys)

    Fast per-RPC routing helpers:
      - is_host_device(device_id) -> bool
      - is_host_device_active(device_id) -> bool (cached TTL)
      - get_host_for_device(device_id) -> Optional[str]

    UI/diagnostics:
      - device_directory_cached() -> {device_id: (host_id, device_info, is_active)} (cached TTL)

    Enforces:
      - device_id is globally unique across hosts (rejects conflicting host announce)
    """

    def __init__(self, *, active_cache_ttl_ms: int = 250, dir_cache_ttl_ms: int = 1000) -> None:
        self._lock = threading.RLock()

        # live sessions
        self._hosts: Dict[str, HostSession] = {}  # host_id -> session

        # persistent-ish directory state
        self._routes: Dict[str, DeviceRoute] = {}              # device_id -> route(host_id, local_id)
        self._host_devices: Dict[str, Set[str]] = {}           # host_id -> set(device_id)
        self._device_infos: Dict[str, host_tunnel_pb2.DeviceInfo] = {}  # device_id -> DeviceInfo

        # status (rebuilt + updated live)
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

        self._load_persisted()

    # ---------------------------
    # caching helpers
    # ---------------------------

    def _invalidate_caches_locked(self) -> None:
        # must be called under self._lock
        self._active_hosts_cache_ts_ms = 0
        self._dir_cache_ts_ms = 0

    def _refresh_active_hosts_cache_locked(self, now: int) -> None:
        # must be called under self._lock
        if self._active_hosts_cache_ts_ms and (now - self._active_hosts_cache_ts_ms) < self._active_hosts_cache_ttl_ms:
            return
        self._active_hosts_cache = {hid for hid, sess in self._hosts.items() if sess is not None and sess.alive}
        self._active_hosts_cache_ts_ms = now

    # ---------------------------
    # persistence load
    # ---------------------------

    def _load_persisted(self) -> None:
        """
        Rebuild directory state from repo_root/.config/*.env

        On boot, everything starts offline until hosts reconnect.
        This restores *directory + metadata* only (routes/devices/labels).
        """
        kv_lists = self._env_lists.read_kv()
        kv_meta = self._env_meta.read_kv()

        known_hosts = csv_split(kv_lists.get("KNOWN_HOSTS", ""))
        known_devices = csv_split(kv_lists.get("KNOWN_DEVICES", ""))

        # also accept hosts referenced by HOST_*_DEVICES keys even if KNOWN_HOSTS drifted
        hosts_from_keys: Set[str] = set()
        for k, v in kv_lists.items():
            if k.startswith("HOST_") and k.endswith("_DEVICES"):
                # We don't know the original host_id from the sanitized key reliably.
                # That's fine; we still load routes primarily from DEVICE_*_HOST in meta.
                # But we DO want to retain the device list; we’ll stitch it via meta host ids.
                # So: just collect devices from these keys.
                pass

        # Reset directory + status (do not touch live sessions)
        with self._lock:
            self._routes.clear()
            self._host_devices.clear()
            self._device_infos.clear()
            self._host_status.clear()
            self._device_status.clear()

            # seed known hosts as offline
            for hid in known_hosts:
                if hid:
                    self._host_status[hid] = HostStatus(host_id=hid, online=False, last_seen_ms=0)
                    self._host_devices.setdefault(hid, set())

            # collect devices that appear anywhere
            devices_from_host_lists: Set[str] = set()
            for k, v in kv_lists.items():
                if k.startswith("HOST_") and k.endswith("_DEVICES"):
                    devices_from_host_lists.update(csv_split(v))

            devices_from_meta: Set[str] = set()
            # any DEVICE_<X>_HOST implies a known device id (but we can’t reverse sanitize_env_key)
            # so we rely on KNOWN_DEVICES + HOST_*_DEVICES as primary device-id sources.
            # meta augments those devices; it can’t introduce new raw device ids safely.
            all_devices: List[str] = sorted(set(known_devices) | devices_from_host_lists)

            # build device entries offline
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
                    # ensure host exists
                    if host_id not in self._host_status:
                        self._host_status[host_id] = HostStatus(host_id=host_id, online=False, last_seen_ms=0)
                    self._host_devices.setdefault(host_id, set()).add(device_id)

                    # route exists even while offline
                    self._routes[device_id] = DeviceRoute(host_id=host_id, host_local_id=int(local_id))

                # keep info visible even when offline
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

    # ---------------------------
    # persistence write helpers
    # ---------------------------

    def _persist_host(self, host_id: str) -> None:
        self._env_lists.append_to_csv_list("KNOWN_HOSTS", host_id)

    def _persist_device(self, host_id: str, device_id: str, local_id: int, device_info: Any) -> None:
        self._env_lists.append_to_csv_list("KNOWN_DEVICES", device_id)
        self._env_lists.append_to_csv_list(f"HOST_{sanitize_env_key(host_id)}_DEVICES", device_id)

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

    # ---------------------------
    # directory/status mutators
    # ---------------------------

    def register_host(self, host_id: str, session: HostSession) -> None:
        with self._lock:
            old = self._hosts.get(host_id)
            if old is not None:
                old.close()

            self._hosts[host_id] = session

            hs = self._host_status.get(host_id) or HostStatus(host_id=host_id)
            hs.online = True
            hs.last_seen_ms = now_ms()
            self._host_status[host_id] = hs

            self._host_devices.setdefault(host_id, set())
            self._persist_host(host_id)
            self._invalidate_caches_locked()

    def drop_host(self, host_id: str) -> None:
        with self._lock:
            sess = self._hosts.pop(host_id, None)
            if sess is not None:
                sess.close()

            hs = self._host_status.get(host_id) or HostStatus(host_id=host_id)
            hs.online = False
            hs.last_seen_ms = now_ms()
            self._host_status[host_id] = hs

            # mark that host's devices offline (keep routes)
            for did in self._host_devices.get(host_id, set()):
                ds = self._device_status.get(did)
                if ds is not None:
                    ds.online = False
                    ds.last_seen_ms = now_ms()

            self._invalidate_caches_locked()

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

            # no need to invalidate full cache; active-cache TTL handles this
            # but host status flips can matter; be conservative:
            self._invalidate_caches_locked()

    def announce_devices(self, host_id: str, devices: list) -> None:
        """
        Enforce global uniqueness of device_id:
          - If any device_id is already owned by a different host -> raise DeviceIdConflictError.
        """
        # conflict check first (no partial apply)
        with self._lock:
            for d in devices:
                device_id = str(getattr(d, "device_id", "")).strip()
                if not device_id:
                    continue
                existing = self._routes.get(device_id)
                if existing is not None and existing.host_id != host_id:
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
                    continue

                # local_id is basically not used; keep for completeness
                try:
                    local_id = int(getattr(d, "local_id", 0))
                except Exception:
                    local_id = 0

                # route
                self._routes[device_id] = DeviceRoute(host_id=host_id, host_local_id=local_id)
                self._host_devices[host_id].add(device_id)

                # status
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

                # info (copy protobuf if possible)
                try:
                    tmp = host_tunnel_pb2.DeviceInfo()
                    tmp.CopyFrom(d)
                    self._device_infos[device_id] = tmp
                except Exception:
                    # fallback minimal
                    self._device_infos[device_id] = host_tunnel_pb2.DeviceInfo(
                        device_id=device_id,
                        local_id=int(local_id),
                        label=str(getattr(d, "label", "") or ""),
                        serial=str(getattr(d, "serial", "") or ""),
                        kind=str(getattr(d, "kind", "") or ""),
                    )

                self._persist_device(host_id, device_id, local_id, d)

            self._invalidate_caches_locked()

    # ---------------------------
    # FAST PATHS (use per-RPC)
    # ---------------------------

    def is_host_device(self, device_id: str) -> bool:
        """
        O(1): does the directory route this device_id to a host?
        (Host may be offline.)
        """
        did = (device_id or "").strip()
        if not did:
            return False
        with self._lock:
            return did in self._routes

    def is_host_device_active(self, device_id: str) -> bool:
        """
        O(1) route lookup + cached host-alive check (TTL).
        True iff device routes to a host AND that host's tunnel session is alive.
        """
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
        """
        Returns:
          { device_id: (host_id, device_info, is_active) }

        Cached rebuild at most once per ttl_ms.
        """
        now = now_ms()
        ttl = int(self._dir_cache_ttl_ms if ttl_ms is None else ttl_ms)

        with self._lock:
            if self._dir_cache_ts_ms and (now - self._dir_cache_ts_ms) < ttl:
                return dict(self._dir_cache)

            self._refresh_active_hosts_cache_locked(now)

            out: Dict[str, Tuple[str, Any, bool]] = {}
            for device_id, route in self._routes.items():
                info0 = self._device_infos.get(device_id)
                info = info0
                if info0 is not None:
                    tmp = host_tunnel_pb2.DeviceInfo()
                    try:
                        tmp.CopyFrom(info0)
                        info = tmp
                    except Exception:
                        info = info0

                is_active = route.host_id in self._active_hosts_cache
                out[device_id] = (route.host_id, info, is_active)

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
    # forwarding (unchanged)
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
        sess, route = self._get_session_and_route(str(device_id))

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

        if not sess.send(frame, timeout=2.0):
            with sess.inflight_lock:
                sess.inflight.pop(req_id, None)

            r = generic_pb2.GenericRPCResponse()
            r.results["Ok"].CopyFrom(map_arg(False))
            r.results["Error"].CopyFrom(map_arg(f"Host '{sess.host_id}' outbound queue full / not writable."))
            return r

        try:
            resp: host_tunnel_pb2.RpcResponse = fut.result(timeout=timeout_sec)
        except Exception as e:
            if cancel_on_timeout:
                try:
                    sess.send(host_tunnel_pb2.HostFrame(cancel=host_tunnel_pb2.Cancel(req_id=req_id)))
                except Exception:
                    pass

            with sess.inflight_lock:
                sess.inflight.pop(req_id, None)

            r = generic_pb2.GenericRPCResponse()
            r.results["Ok"].CopyFrom(map_arg(False))
            r.results["Error"].CopyFrom(map_arg(str(e)))
            return r

        with sess.inflight_lock:
            sess.inflight.pop(req_id, None)

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
                r = generic_pb2.GenericRPCResponse()
                r.results["Ok"].CopyFrom(map_arg(False))
                r.results["Error"].CopyFrom(map_arg(f"Unknown device_id={device_id}"))
                return r

            if route.host_id != host_id:
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

def handle_host_device(
    registry: HostTunnelRegistry,
    *,
    host_id: str,
    device_id: str,
    function_name: str,
    args: Any,
    timeout_sec: float = 10.0,
) -> Dict[str, Any]:
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
    return registry.forward_request_by_host_device(
        host_id=host_id,
        device_id=device_id,
        request=request,
        timeout_sec=timeout_sec,
        cancel_on_timeout=True,
    )


class HostTunnelServicer(host_tunnel_pb2_grpc.HostTunnelServicer):
    def __init__(self, registry: HostTunnelRegistry) -> None:
        self.registry = registry

    def Connect(self, request_iterator: Iterator[host_tunnel_pb2.HostFrame], context):
        host_id: Optional[str] = None
        session: Optional[HostSession] = None
        stop = threading.Event()
        fatal: Dict[str, str] = {}  # {"code": "...", "details": "..."}

        def inbound_loop():
            nonlocal host_id, session
            try:
                for frame in request_iterator:
                    which = frame.WhichOneof("msg")
                    if which is None:
                        continue

                    if which == "hello":
                        hello = frame.hello
                        host_id = str(hello.host_id).strip() or "unknown-host"
                        session = HostSession(host_id)
                        self.registry.register_host(host_id, session)

                        try:
                            session.send(
                                host_tunnel_pb2.HostFrame(
                                    heartbeat=host_tunnel_pb2.Heartbeat(unix_ms=now_ms())
                                )
                            )
                        except Exception:
                            pass

                    elif which == "device_announce":
                        if session is None or host_id is None:
                            continue
                        ann = frame.device_announce
                        try:
                            self.registry.announce_devices(host_id, list(ann.devices))
                        except DeviceIdConflictError as e:
                            fatal["code"] = "ALREADY_EXISTS"
                            fatal["details"] = str(e)
                            stop.set()
                            return

                        try:
                            session.send(
                                host_tunnel_pb2.HostFrame(
                                    heartbeat=host_tunnel_pb2.Heartbeat(unix_ms=now_ms())
                                )
                            )
                        except Exception:
                            pass

                    elif which == "rpc_response":
                        if session is None:
                            continue
                        resp = frame.rpc_response
                        rid = str(resp.req_id)

                        with session.inflight_lock:
                            fut = session.inflight.get(rid)

                        if fut is not None and not fut.done():
                            fut.set_result(resp)

                    elif which == "heartbeat":
                        if session is not None and host_id is not None:
                            session.last_heartbeat_ms = int(frame.heartbeat.unix_ms) or now_ms()
                            self.registry.heartbeat(host_id, int(frame.heartbeat.unix_ms) or 0)

                    elif which == "cancel":
                        pass

            except Exception:
                pass
            finally:
                stop.set()
                if host_id is not None:
                    self.registry.drop_host(host_id)
                if session is not None:
                    session.close()

        t = threading.Thread(target=inbound_loop, daemon=True)
        t.start()

        while not stop.is_set():
            if fatal:
                code = fatal.get("code", "")
                details = fatal.get("details", "fatal")
                if code == "ALREADY_EXISTS":
                    context.abort(grpc.StatusCode.ALREADY_EXISTS, details)
                context.abort(grpc.StatusCode.UNKNOWN, details)

            if session is None:
                time.sleep(0.05)
                continue

            try:
                out = session.out_q.get(timeout=0.5)
            except queue.Empty:
                continue

            if out is None:
                break
            yield out


def build_server_credentials(
    *,
    private_key_pem: bytes,
    certificate_chain_pem: bytes,
    client_ca_pem: Optional[bytes] = None,
    require_client_auth: bool = True,
) -> grpc.ServerCredentials:
    if client_ca_pem:
        return grpc.ssl_server_credentials(
            ((private_key_pem, certificate_chain_pem,),),
            root_certificates=client_ca_pem,
            require_client_auth=require_client_auth,
        )
    return grpc.ssl_server_credentials(((private_key_pem, certificate_chain_pem,),))


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

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=max_workers),
        options=options,
    )

    host_tunnel_pb2_grpc.add_HostTunnelServicer_to_server(HostTunnelServicer(reg), server)
    server.add_secure_port(f"{host}:{int(port)}", server_credentials)

    def run():
        server.start()
        server.wait_for_termination()

    th = threading.Thread(target=run, daemon=True)
    th.start()
    return server, th, reg
