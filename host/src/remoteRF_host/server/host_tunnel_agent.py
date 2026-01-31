# host_tunnel_agent.py
#
# Host-side agent:
#   - Maintains a long-lived gRPC bidi stream to the main server (HOST_PORT).
#   - Announces devices on connect.
#   - Receives forwarded RPC calls and executes them locally (rpc_manager.run_rpc).
#   - Replies with RpcResponse.
#
# Start it in its own process on the remote host that has the SDRs.

import os
import time
import threading
import queue
import traceback
import secrets
from dataclasses import dataclass
from typing import Dict, Any, Optional, Iterable, List

import grpc

from ..common.grpc import grpc_pb2  # your existing Arg message
from ..common.utils import map_arg  # used for Ok/Error style if you want

from .rpc_manager import rpc_manager  # host-local rpc execution
from .device_manager import get_all_devices_str  # host-local discovery (adjust as needed)

from . import host_tunnel_pb2, host_tunnel_pb2_grpc  # generated from host_tunnel.proto


def _now_ms() -> int:
    return int(time.time() * 1000)


def _pack_args_map(args_bytes_map: Dict[str, bytes]) -> Dict[str, Any]:
    """
    Convert map<string, bytes> -> dict[str, Arg]
    """
    out: Dict[str, Any] = {}
    for k, b in args_bytes_map.items():
        a = grpc_pb2.Arg()
        a.ParseFromString(b)
        out[str(k)] = a
    return out


def _unpack_results_map(results_map: Dict[str, Any]) -> Dict[str, bytes]:
    """
    Convert dict[str, Arg] -> map<string, bytes>
    """
    out: Dict[str, bytes] = {}
    if results_map is None:
        return out
    for k, v in results_map.items():
        # v should already be an Arg; if you ever store python primitives, you must map_arg() first.
        if hasattr(v, "SerializeToString"):
            out[str(k)] = v.SerializeToString()
        else:
            out[str(k)] = map_arg(v).SerializeToString()
    return out


@dataclass
class AgentConfig:
    server_host: str
    server_port: int
    host_id: str
    version: str = "host-agent/0.1"

    # TLS paths (recommended)
    ca_pem_path: Optional[str] = None           # CA cert that signed the server cert
    client_cert_pem_path: Optional[str] = None  # client cert (mTLS)
    client_key_pem_path: Optional[str] = None   # client private key (mTLS)

    # behavior
    heartbeat_interval_sec: float = 10.0
    reconnect_min_delay_sec: float = 1.0
    reconnect_max_delay_sec: float = 30.0
    outbound_max: int = 2048


class HostTunnelAgent:
    def __init__(self, cfg: AgentConfig) -> None:
        self.cfg = cfg
        self._stop = threading.Event()

        self._out_q: "queue.Queue[Optional[host_tunnel_pb2.HostFrame]]" = queue.Queue(maxsize=cfg.outbound_max)

        # best-effort cancel map: req_id -> threading.Event
        self._cancel_flags: Dict[str, threading.Event] = {}
        self._cancel_lock = threading.Lock()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._out_q.put_nowait(None)
        except Exception:
            pass

    def _enqueue(self, frame: host_tunnel_pb2.HostFrame, *, timeout: float = 2.0) -> bool:
        try:
            self._out_q.put(frame, timeout=timeout)
            return True
        except queue.Full:
            return False

    def _device_announce_frame(self) -> host_tunnel_pb2.HostFrame:
        """
        Translate your host-local device inventory into DeviceAnnounce.
        Replace this with a richer discovery if needed.
        """
        devs = get_all_devices_str()  # dict[int, str]
        infos: List[host_tunnel_pb2.DeviceInfo] = []
        for local_id in sorted(devs.keys()):
            infos.append(host_tunnel_pb2.DeviceInfo(local_id=int(local_id), label=str(devs[local_id])))
        return host_tunnel_pb2.HostFrame(
            device_announce=host_tunnel_pb2.DeviceAnnounce(devices=infos)
        )

    def _hello_frame(self) -> host_tunnel_pb2.HostFrame:
        return host_tunnel_pb2.HostFrame(
            hello=host_tunnel_pb2.HostHello(host_id=self.cfg.host_id, version=self.cfg.version)
        )

    def _heartbeat_frame(self) -> host_tunnel_pb2.HostFrame:
        return host_tunnel_pb2.HostFrame(
            heartbeat=host_tunnel_pb2.Heartbeat(unix_ms=_now_ms())
        )

    def _make_channel(self) -> grpc.Channel:
        target = f"{self.cfg.server_host}:{int(self.cfg.server_port)}"

        # If no TLS material provided, you can use an insecure channel for early bring-up.
        # Strongly recommend TLS/mTLS for anything real.
        if not self.cfg.ca_pem_path:
            return grpc.insecure_channel(target)

        ca_pem = open(self.cfg.ca_pem_path, "rb").read()

        if self.cfg.client_cert_pem_path and self.cfg.client_key_pem_path:
            cert_pem = open(self.cfg.client_cert_pem_path, "rb").read()
            key_pem = open(self.cfg.client_key_pem_path, "rb").read()
            creds = grpc.ssl_channel_credentials(
                root_certificates=ca_pem,
                private_key=key_pem,
                certificate_chain=cert_pem,
            )
        else:
            creds = grpc.ssl_channel_credentials(root_certificates=ca_pem)

        opts = [
            ("grpc.max_send_message_length", 100 * 1024 * 1024),
            ("grpc.max_receive_message_length", 100 * 1024 * 1024),
            ("grpc.keepalive_time_ms", 30_000),
            ("grpc.keepalive_timeout_ms", 10_000),
            ("grpc.http2.max_pings_without_data", 0),
            ("grpc.keepalive_permit_without_calls", 1),
        ]
        return grpc.secure_channel(target, creds, options=opts)

    def _register_cancel(self, req_id: str) -> threading.Event:
        ev = threading.Event()
        with self._cancel_lock:
            self._cancel_flags[req_id] = ev
        return ev

    def _consume_cancel(self, req_id: str) -> None:
        with self._cancel_lock:
            self._cancel_flags.pop(req_id, None)

    def _set_cancel(self, req_id: str) -> None:
        with self._cancel_lock:
            ev = self._cancel_flags.get(req_id)
        if ev is not None:
            ev.set()

    def _handle_rpc_request(self, req: host_tunnel_pb2.RpcRequest) -> None:
        """
        Execute host-local RPC and respond.
        Runs in a worker thread so stream reader stays responsive.
        """
        req_id = str(req.req_id)
        cancel_ev = self._register_cancel(req_id)

        try:
            # Deserialize args bytes -> Arg
            args_py = _pack_args_map(req.args)

            # OPTIONAL:
            # You can inject routing info into args so your device_manager can pick correct local device:
            # e.g. args_py["__local_device_id"] = map_arg(int(req.local_device_id))
            #
            # But only do this if your host rpc layer expects it.
            #
            # If your host already selects device by token/reservation, you might not need local_device_id.
            # For typical "device op" calls, you *will* want local device id wired in somewhere.

            # Execute. If you want cancellation to work mid-call, you must thread cancellation into your
            # rpc_manager / device ops (not shown here).
            results = rpc_manager.run_rpc(function_name=req.function_name, args=args_py)

            # If canceled after completion, still reply (server can ignore if timed out).
            resp = host_tunnel_pb2.HostFrame(
                rpc_response=host_tunnel_pb2.RpcResponse(
                    req_id=req_id,
                    ok=True,
                    results=_unpack_results_map(results),
                    error="",
                )
            )
            self._enqueue(resp)

        except Exception as e:
            tb = traceback.format_exc(limit=10)
            resp = host_tunnel_pb2.HostFrame(
                rpc_response=host_tunnel_pb2.RpcResponse(
                    req_id=req_id,
                    ok=False,
                    results={},
                    error=f"{e}\n{tb}",
                )
            )
            self._enqueue(resp)

        finally:
            self._consume_cancel(req_id)

    def _outbound_generator(self) -> Iterable[host_tunnel_pb2.HostFrame]:
        """
        Yield outbound frames from the queue until stopped.
        """
        while not self._stop.is_set():
            try:
                item = self._out_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                return
            yield item

    def run_forever(self) -> None:
        """
        Main reconnect loop.
        """
        delay = self.cfg.reconnect_min_delay_sec

        while not self._stop.is_set():
            try:
                channel = self._make_channel()
                stub = host_tunnel_pb2_grpc.HostTunnelStub(channel)

                # Prime outbound with hello + device announce
                self._enqueue(self._hello_frame())
                self._enqueue(self._device_announce_frame())

                # Heartbeat thread
                hb_stop = threading.Event()

                def hb_loop():
                    while not hb_stop.is_set() and not self._stop.is_set():
                        self._enqueue(self._heartbeat_frame())
                        time.sleep(self.cfg.heartbeat_interval_sec)

                hb_thread = threading.Thread(target=hb_loop, daemon=True)
                hb_thread.start()

                # Start bidi stream
                stream = stub.Connect(self._outbound_generator())

                # Reset backoff after successful connect
                delay = self.cfg.reconnect_min_delay_sec

                # Read loop (blocking) — handle server->host frames
                for frame in stream:
                    which = frame.WhichOneof("msg")
                    if which == "rpc_request":
                        req = frame.rpc_request
                        # run RPC in a worker thread so we can continue reading stream
                        threading.Thread(target=self._handle_rpc_request, args=(req,), daemon=True).start()

                    elif which == "cancel":
                        self._set_cancel(frame.cancel.req_id)

                    elif which == "heartbeat":
                        # server heartbeat; ignore or log
                        pass

                # If we exit read loop, stream ended
                hb_stop.set()

            except grpc.RpcError:
                # stream broke; reconnect
                pass
            except Exception:
                # unexpected error; reconnect
                pass

            # backoff
            if self._stop.is_set():
                break
            time.sleep(delay)
            delay = min(delay * 1.7, self.cfg.reconnect_max_delay_sec)


# -------------------------
# Convenience entrypoint
# -------------------------

def start_host_tunnel_agent_thread(cfg: AgentConfig) -> Tuple[HostTunnelAgent, threading.Thread]:
    agent = HostTunnelAgent(cfg)
    th = threading.Thread(target=agent.run_forever, daemon=True)
    th.start()
    return agent, th


if __name__ == "__main__":
    # Example env wiring (adjust to your deployment)
    server_host = os.getenv("MAIN_SERVER_HOST", "127.0.0.1")
    server_port = int(os.getenv("HOST_PORT", "61007"))
    host_id = os.getenv("HOST_ID", f"host-{secrets.token_hex(4)}")

    cfg = AgentConfig(
        server_host=server_host,
        server_port=server_port,
        host_id=host_id,
        version=os.getenv("HOST_VERSION", "host-agent/dev"),
        ca_pem_path=os.getenv("CA_PEM_PATH"),                 # optional
        client_cert_pem_path=os.getenv("CLIENT_CERT_PATH"),   # optional
        client_key_pem_path=os.getenv("CLIENT_KEY_PATH"),     # optional
    )

    agent = HostTunnelAgent(cfg)
    try:
        agent.run_forever()
    except KeyboardInterrupt:
        agent.stop()
