# host_tunnel_server.py
#
# Updated to relay your *existing* GenericRPC payloads end-to-end:
#   - Tunnel RpcRequest carries remote_rf.GenericRPCRequest (function_name + map<string, Argument>)
#   - Tunnel RpcResponse carries remote_rf.GenericRPCResponse (map<string, Argument>)
#
# REQUIRED host_tunnel.proto changes (summary):
#   - DeviceInfo must include: string device_id
#   - RpcRequest must include: string device_id, uint32 local_device_id, remote_rf.GenericRPCRequest request
#   - RpcResponse must include: remote_rf.GenericRPCResponse response
#   - (Optional) keep legacy fields like global_device_id if you want, but this code does not require them.

import os
import re
import threading
import queue
import time
import secrets
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Any, List, Set, Iterator
from concurrent.futures import Future
from concurrent import futures

import grpc

# Your existing GenericRPC schema compiled to python.
# NOTE: adjust this import if your generated module name differs.
# This must contain: GenericRPCRequest, GenericRPCResponse, Argument
from ..common.grpc import grpc_pb2 as generic_pb2  # type: ignore

# Your existing map_arg helper that produces generic_pb2.Argument
# (same helper you use in PlutoServer)
from ..common.utils.process_arg import map_arg  # type: ignore

from . import host_tunnel_pb2, host_tunnel_pb2_grpc  # type: ignore


def _now_ms() -> int:
    return int(time.time() * 1000)


def _sanitize_env_key(s: str) -> str:
    # env keys: A-Z0-9_
    s = s.strip().upper()
    s = re.sub(r"[^A-Z0-9_]", "_", s)
    s = re.sub(r"_+", "_", s)
    return s[:120]  # avoid insane keys


def _copy_argument_map(dst_map: Any, src_map: Any) -> None:
    """
    Copy map<string, Argument> into another map<string, Argument>.
    Works for protobuf map containers or plain dicts.
    """
    if src_map is None:
        return
    try:
        for k in src_map:
            dst_map[str(k)].CopyFrom(src_map[k])
    except Exception:
        for k, v in dict(src_map).items():
            dst_map[str(k)].CopyFrom(v)


class _EnvAppendOnly:
    """
    "Append-only" in the sense that keys/lists only ever GROW.
    We rewrite the file to update list values (since .env has no true append operator),
    but we never remove values once present.
    """
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()

    def _read_lines(self) -> List[str]:
        if not os.path.exists(self.path):
            return []
        with open(self.path, "r", encoding="utf-8") as f:
            return f.read().splitlines()

    def _write_lines(self, lines: List[str]) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + ("\n" if lines else ""))

    def append_to_csv_list(self, key: str, value: str) -> None:
        key = _sanitize_env_key(key)
        value = value.strip()
        if not value:
            return

        with self._lock:
            lines = self._read_lines()
            idx = None
            cur = ""

            for i, ln in enumerate(lines):
                if ln.startswith(key + "="):
                    idx = i
                    cur = ln[len(key) + 1:].strip()
                    break

            existing = [x.strip() for x in cur.split(",") if x.strip()] if cur else []
            if value in existing:
                return

            existing.append(value)
            new_line = f"{key}=" + ",".join(existing)

            if idx is None:
                lines.append(new_line)
            else:
                lines[idx] = new_line

            self._write_lines(lines)

    def set_kv_if_absent(self, key: str, value: str) -> None:
        key = _sanitize_env_key(key)
        value = value.strip()
        if not value:
            return

        with self._lock:
            lines = self._read_lines()
            for ln in lines:
                if ln.startswith(key + "="):
                    return
            lines.append(f"{key}={value}")
            self._write_lines(lines)


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
        self.last_heartbeat_ms = _now_ms()
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

        # fail all inflight
        with self.inflight_lock:
            for _, fut in list(self.inflight.items()):
                if not fut.done():
                    fut.set_exception(RuntimeError(f"Host '{self.host_id}' disconnected"))
            self.inflight.clear()


class HostTunnelRegistry:
    """
    Owns:
      - sessions: host_id -> HostSession
      - routes: device_id -> DeviceRoute(host_id, local_id)
      - directory/status: known hosts/devices and online/last_seen
      - persistence into a local .env file (append-only growth)
    """
    def __init__(self, *, env_path: str = ".env.host_directory") -> None:
        self._lock = threading.RLock()

        self._hosts: Dict[str, HostSession] = {}
        self._routes: Dict[str, DeviceRoute] = {}  # device_id -> route

        self._host_status: Dict[str, HostStatus] = {}
        self._device_status: Dict[str, DeviceStatus] = {}

        self._host_devices: Dict[str, Set[str]] = {}  # host_id -> set(device_id)

        self._env = _EnvAppendOnly(env_path)

    # ---------- persistence ----------
    def _persist_host(self, host_id: str) -> None:
        self._env.append_to_csv_list("KNOWN_HOSTS", host_id)

    def _persist_device(self, host_id: str, device_id: str, local_id: int) -> None:
        self._env.append_to_csv_list("KNOWN_DEVICES", device_id)
        self._env.append_to_csv_list(f"HOST_{_sanitize_env_key(host_id)}_DEVICES", device_id)
        # set once (append-only semantics)
        self._env.set_kv_if_absent(f"DEVICE_{_sanitize_env_key(device_id)}_HOST", host_id)
        self._env.set_kv_if_absent(f"DEVICE_{_sanitize_env_key(device_id)}_LOCAL_ID", str(int(local_id)))

    # ---------- directory/status ----------
    def register_host(self, host_id: str, session: HostSession) -> None:
        with self._lock:
            old = self._hosts.get(host_id)
            if old is not None:
                old.close()

            self._hosts[host_id] = session

            hs = self._host_status.get(host_id) or HostStatus(host_id=host_id)
            hs.online = True
            hs.last_seen_ms = _now_ms()
            self._host_status[host_id] = hs

            self._persist_host(host_id)

    def drop_host(self, host_id: str) -> None:
        with self._lock:
            sess = self._hosts.pop(host_id, None)
            if sess is not None:
                sess.close()

            hs = self._host_status.get(host_id) or HostStatus(host_id=host_id)
            hs.online = False
            hs.last_seen_ms = _now_ms()
            self._host_status[host_id] = hs

            # Mark that host's devices offline but KEEP routes (so directory stays visible)
            for did in self._host_devices.get(host_id, set()):
                ds = self._device_status.get(did)
                if ds is not None:
                    ds.online = False
                    ds.last_seen_ms = _now_ms()

    def announce_devices(self, host_id: str, devices: list) -> None:
        """
        devices[*] must include:
          - d.device_id (string) globally unique & stable
          - d.local_id (int)
        """
        now = _now_ms()
        with self._lock:
            self._host_devices.setdefault(host_id, set())

            for d in devices:
                device_id = str(getattr(d, "device_id", "")).strip()
                local_id = int(getattr(d, "local_id", -1))

                if not device_id or local_id < 0:
                    continue

                # collision policy: if device_id already owned by another host, reject
                existing = self._routes.get(device_id)
                if existing is not None and existing.host_id != host_id:
                    # keep existing route; ignore conflicting claim
                    continue

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

                self._persist_device(host_id, device_id, local_id)

    def heartbeat(self, host_id: str, unix_ms: int = 0) -> None:
        now = int(unix_ms) or _now_ms()
        with self._lock:
            hs = self._host_status.get(host_id) or HostStatus(host_id=host_id)
            hs.online = True
            hs.last_seen_ms = now
            self._host_status[host_id] = hs

            # optional: also refresh device last_seen for devices on that host
            for did in self._host_devices.get(host_id, set()):
                ds = self._device_status.get(did)
                if ds is not None:
                    ds.online = True
                    ds.last_seen_ms = now

    def list_hosts(self) -> Dict[str, HostStatus]:
        with self._lock:
            return dict(self._host_status)

    def list_devices(self) -> Dict[str, DeviceStatus]:
        with self._lock:
            return dict(self._device_status)

    def list_routes(self) -> Dict[str, Tuple[str, int]]:
        with self._lock:
            return {did: (r.host_id, r.host_local_id) for did, r in self._routes.items()}

    # ---------- forwarding ----------
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
        """
        Forward a GenericRPCRequest to the host that owns device_id.
        Returns GenericRPCResponse (map<string, Argument> results).
        """
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
    args: Any,  # map<string, Argument>
    timeout_sec: float = 10.0,
) -> Dict[str, Any]:
    """
    Convenience wrapper that mirrors your existing local call style:
      (function_name, args_map) -> dict(map results)
    """
    req = generic_pb2.GenericRPCRequest(function_name=str(function_name))
    _copy_argument_map(req.args, args)

    resp = registry.forward_request_by_host_device(
        host_id=host_id,
        device_id=device_id,
        request=req,
        timeout_sec=timeout_sec,
        cancel_on_timeout=True,
    )

    # Keep your old return style: dict[str, Argument]
    return dict(resp.results)


def handle_host_device_request(
    registry: HostTunnelRegistry,
    *,
    host_id: str,
    device_id: str,
    request: "generic_pb2.GenericRPCRequest",
    timeout_sec: float = 10.0,
) -> "generic_pb2.GenericRPCResponse":
    """
    Fully seamless relay: pass in the client GenericRPCRequest and get back GenericRPCResponse.
    """
    return registry.forward_request_by_host_device(
        host_id=host_id,
        device_id=device_id,
        request=request,
        timeout_sec=timeout_sec,
        cancel_on_timeout=True,
    )


class HostTunnelServicer(host_tunnel_pb2_grpc.HostTunnelServicer):
    """
    Bidi stream:
      host -> server: hello, device_announce, rpc_response, heartbeat, cancel(optional)
      server -> host: rpc_request, cancel(optional)
    """
    def __init__(self, registry: HostTunnelRegistry) -> None:
        self.registry = registry

    def Connect(self, request_iterator: Iterator[host_tunnel_pb2.HostFrame], context):
        host_id: Optional[str] = None
        session: Optional[HostSession] = None
        stop = threading.Event()

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

                        # optional: immediate ack/heartbeat back to host
                        try:
                            session.send(host_tunnel_pb2.HostFrame(heartbeat=host_tunnel_pb2.Heartbeat(unix_ms=_now_ms())))
                        except Exception:
                            pass

                    elif which == "device_announce":
                        if session is None or host_id is None:
                            continue
                        ann = frame.device_announce
                        self.registry.announce_devices(host_id, list(ann.devices))

                        # optional ack
                        try:
                            session.send(host_tunnel_pb2.HostFrame(heartbeat=host_tunnel_pb2.Heartbeat(unix_ms=_now_ms())))
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
                            session.last_heartbeat_ms = int(frame.heartbeat.unix_ms) or _now_ms()
                            self.registry.heartbeat(host_id, int(frame.heartbeat.unix_ms) or 0)

                    elif which == "cancel":
                        # Host-initiated cancel (rare). If you support host cancelling, handle it here.
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

        # outbound loop: yield frames from session queue
        while not stop.is_set():
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
    """
    If you pass client_ca_pem, this enforces mTLS for hosts.
    If you do not pass client_ca_pem, it will still be TLS server-auth only.
    """
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
    """
    Start the host tunnel gRPC server on (host, port) in a daemon thread.

    Returns: (grpc_server, thread, registry)

    Store the registry globally and use:
      - registry.list_hosts(), registry.list_devices()
      - handle_host_device_request(...) for seamless relay
    """
    reg = registry or HostTunnelRegistry()

    options = [
        ('grpc.max_send_message_length', 100 * 1024 * 1024),
        ('grpc.max_receive_message_length', 100 * 1024 * 1024),
        ('grpc.keepalive_time_ms', 30_000),
        ('grpc.keepalive_timeout_ms', 10_000),
        ('grpc.http2.max_pings_without_data', 0),
        ('grpc.keepalive_permit_without_calls', 1),
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
