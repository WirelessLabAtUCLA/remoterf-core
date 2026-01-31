import threading
import queue
import time
import secrets
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Any
from concurrent.futures import Future

import grpc

# You already have these in your project:
# - grpc_pb2 (contains Arg, GenericRPCResponse map types, etc.)
# - map_arg/unmap_arg helpers
from ..common.grpc import grpc_pb2, map_arg  # type: ignore

# These are generated from host_tunnel.proto (you must compile it)
from . import host_tunnel_pb2, host_tunnel_pb2_grpc  # type: ignore


def _now_ms() -> int:
    return int(time.time() * 1000)


def _pack_args_map(args_map: Any) -> Dict[str, bytes]:
    """
    Convert your existing protobuf map<string, Arg> into map<string, bytes>
    where bytes is Arg.SerializeToString().
    """
    out: Dict[str, bytes] = {}
    if args_map is None:
        return out
    try:
        # protobuf map container is iterable like a dict
        for k in args_map:
            v = args_map[k]
            out[str(k)] = v.SerializeToString()
    except Exception:
        # If args_map is already a python dict[str, Arg]
        for k, v in dict(args_map).items():
            out[str(k)] = v.SerializeToString()
    return out


def _unpack_args_map_bytes(m: Dict[str, bytes]) -> Dict[str, Any]:
    """
    Convert map<string, bytes> where bytes is serialized Arg back into dict[str, Arg].
    """
    out: Dict[str, Any] = {}
    for k, b in m.items():
        a = grpc_pb2.Arg()
        a.ParseFromString(b)
        out[str(k)] = a
    return out


@dataclass
class DeviceRoute:
    host_id: str
    host_local_id: int


class HostSession:
    """
    Represents one connected host (one bidi stream).
    Owns:
      - outbound frame queue
      - inflight req_id -> Future
      - device local/global mappings (optional)
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
        # unblock writer loop
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
    Thread-safe registry:
      - host_id -> HostSession
      - global_device_id -> DeviceRoute(host_id, local_id)
    """
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._hosts: Dict[str, HostSession] = {}
        self._routes: Dict[int, DeviceRoute] = {}
        self._next_global_device_id = 0

    def register_host(self, host_id: str, session: HostSession) -> None:
        with self._lock:
            old = self._hosts.get(host_id)
            if old is not None:
                old.close()
            self._hosts[host_id] = session

    def drop_host(self, host_id: str) -> None:
        with self._lock:
            sess = self._hosts.pop(host_id, None)
            if sess is not None:
                sess.close()

            # remove device routes owned by this host
            to_del = [gid for gid, r in self._routes.items() if r.host_id == host_id]
            for gid in to_del:
                del self._routes[gid]

    def announce_devices(self, host_id: str, devices: list) -> Dict[int, int]:
        """
        Assign global IDs for the announced host-local devices.
        Returns mapping: {global_device_id: host_local_id}
        """
        with self._lock:
            mapping: Dict[int, int] = {}
            for d in devices:
                local_id = int(d.local_id)
                gid = self._next_global_device_id
                self._next_global_device_id += 1
                self._routes[gid] = DeviceRoute(host_id=host_id, host_local_id=local_id)
                mapping[gid] = local_id
            return mapping

    def list_routes(self) -> Dict[int, Tuple[str, int]]:
        with self._lock:
            return {gid: (r.host_id, r.host_local_id) for gid, r in self._routes.items()}

    def _get_session_and_route(self, global_device_id: int) -> Tuple[HostSession, DeviceRoute]:
        with self._lock:
            route = self._routes.get(int(global_device_id))
            if route is None:
                raise KeyError(f"Unknown global_device_id={global_device_id}")

            sess = self._hosts.get(route.host_id)
            if sess is None or not sess.alive:
                raise RuntimeError(f"Host '{route.host_id}' not connected for device {global_device_id}")

            return sess, route

    def forward_rpc(
        self,
        *,
        global_device_id: int,
        function_name: str,
        args_map: Any,
        timeout_sec: float,
        deadline_unix_ms: int = 0,
        cancel_on_timeout: bool = False,
    ) -> Dict[str, Any]:
        """
        Forward a device-scoped RPC to the correct host.
        Returns dict[str, Arg] (your existing response map style).

        - timeout_sec bounds the wait for response
        - cancel_on_timeout optionally sends Cancel(req_id) when we give up
        """
        sess, route = self._get_session_and_route(int(global_device_id))

        req_id = secrets.token_hex(12)
        fut: Future = Future()

        with sess.inflight_lock:
            sess.inflight[req_id] = fut

        frame = host_tunnel_pb2.HostFrame(
            rpc_request=host_tunnel_pb2.RpcRequest(
                req_id=req_id,
                global_device_id=int(global_device_id),
                local_device_id=int(route.host_local_id),
                function_name=str(function_name),
                args=_pack_args_map(args_map),
                deadline_unix_ms=int(deadline_unix_ms or 0),
            )
        )

        if not sess.send(frame, timeout=2.0):
            with sess.inflight_lock:
                sess.inflight.pop(req_id, None)
            return {
                "Ok": map_arg(False),
                "Error": map_arg(f"Host '{sess.host_id}' outbound queue full / not writable."),
            }

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
            return {"Ok": map_arg(False), "Error": map_arg(str(e))}

        # cleanup inflight
        with sess.inflight_lock:
            sess.inflight.pop(req_id, None)

        if not resp.ok:
            return {"Ok": map_arg(False), "Error": map_arg(resp.error or "Remote host error.")}

        return _unpack_args_map_bytes(resp.results)


class HostTunnelServicer(host_tunnel_pb2_grpc.HostTunnelServicer):
    """
    Bidi stream:
      host -> server: hello, device_announce, rpc_response, heartbeat, cancel(optional)
      server -> host: rpc_request, cancel(optional), (optionally ack frames)
    """
    def __init__(self, registry: HostTunnelRegistry) -> None:
        self.registry = registry

    def Connect(self, request_iterator, context):
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
                        mapping = self.registry.announce_devices(host_id, list(ann.devices))

                        # optional: you can send an "ack" via heartbeat or add a new proto message if you want.
                        # For now, just send a heartbeat (or no-op).
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
                        if session is not None:
                            session.last_heartbeat_ms = int(frame.heartbeat.unix_ms) or _now_ms()

                    elif which == "cancel":
                        # Host-initiated cancel (rare). If you support host cancelling, handle it here.
                        # Typically server is the one that cancels.
                        pass

            except Exception:
                # stream ended or error
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

    You can store the registry globally and use registry.forward_rpc(...) from your RPC layer.
    """
    reg = registry or HostTunnelRegistry()

    options = [
        ('grpc.max_send_message_length', 100 * 1024 * 1024),
        ('grpc.max_receive_message_length', 100 * 1024 * 1024),

        # keepalive defaults suitable for long-lived streams (tune later)
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
