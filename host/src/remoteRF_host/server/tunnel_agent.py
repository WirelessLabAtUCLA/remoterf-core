# host_tunnel_agent.py
#
# Host-side agent (UPDATED):
#   - Reads HOST_ID + per-device unique IDs from a local .env file
#   - Connects to main server via HostTunnel bidi stream
#   - Sends HostHello(host_id=...) and DeviceAnnounce(devices=[... device_id ...])
#   - Receives RpcRequest(request=remote_rf.GenericRPCRequest) and executes locally
#   - Replies with RpcResponse(response=remote_rf.GenericRPCResponse)
#
# Expected .env format (example):
#   HOST_ID=host-ucla-lab-01
#   HOST_MASTER_TOKEN=***REMOVED***
#   DEVICE_0_ID=pluto-10447392da11001009001500f02af8a678
#   DEVICE_1_ID=pluto-10447392da110010f9ff1500612ff8ecb0
#   # optional alternative mapping:
#   # DEVICE_MAP=0:pluto-aaa,1:pluto-bbb
#
# Notes:
#   - This agent will OVERRIDE args['a'] (token) to a host-local master token with _force and local_id,
#     so your existing PlutoServer/device_manager token gating on the host can remain unchanged.
#     (Main server still enforces reservations/tokens; host just executes.)
#
# Proto assumptions:
#   - grpc_host.proto (package remoterf) imports grpc.proto (package remote_rf)
#   - DeviceInfo includes: string device_id
#   - RpcRequest includes: remote_rf.GenericRPCRequest request
#   - RpcResponse includes: remote_rf.GenericRPCResponse response

import os
import re
import time
import threading
import queue
import traceback
import secrets
from dataclasses import dataclass
from typing import Dict, Any, Optional, Iterable, List, Tuple

import grpc

from ..common.grpc import *

# IMPORTANT: use the *same* grpc_pb2 module that the generated host_pb2 imported,
# so protobuf message classes match exactly.
try:
    generic_pb2 = host_pb2.grpc__pb2  # type: ignore  # generated alias inside pb2
except Exception:
    import grpc_pb2 as generic_pb2  # type: ignore

# Host-local RPC execution
from .rpc_manager import rpc_manager  # type: ignore

# Optional: host-local discovery labels (safe if absent)
try:
    from .device_manager import get_all_devices_str  # type: ignore
except Exception:
    get_all_devices_str = None


def _now_ms() -> int:
    return int(time.time() * 1000)


# -------------------------
# .env parsing (no deps)
# -------------------------

_ENV_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def _strip_quotes(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
        return v[1:-1]
    return v


def load_env_file(path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not path or not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8") as f:
        for raw in f.read().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = _ENV_LINE.match(line)
            if not m:
                continue
            k = m.group(1).strip()
            v = _strip_quotes(m.group(2))
            out[k] = v
    return out


def _parse_device_ids_from_env(env: Dict[str, str]) -> Dict[int, str]:
    """
    Supports:
      DEVICE_<n>_ID=...
      DEVICE_MAP=0:id0,1:id1,...
    Returns {local_id: device_id}
    """
    mapping: Dict[int, str] = {}

    # DEVICE_MAP first (explicit)
    dm = env.get("DEVICE_MAP", "").strip()
    if dm:
        parts = [p.strip() for p in dm.split(",") if p.strip()]
        for p in parts:
            if ":" not in p:
                continue
            a, b = p.split(":", 1)
            try:
                lid = int(a.strip())
            except Exception:
                continue
            did = b.strip()
            if did:
                mapping[lid] = did

    # DEVICE_<n>_ID overrides/adds
    for k, v in env.items():
        m = re.match(r"^DEVICE_(\d+)_ID$", k.strip().upper())
        if not m:
            continue
        try:
            lid = int(m.group(1))
        except Exception:
            continue
        did = v.strip()
        if did:
            mapping[lid] = did

    return mapping


# -------------------------
# Argument coercion helpers
# -------------------------

def _argument_bool(x: bool) -> Any:
    a = generic_pb2.Argument()
    a.bool_value = bool(x)
    return a


def _argument_string(s: str) -> Any:
    a = generic_pb2.Argument()
    a.string_value = str(s)
    return a


def _coerce_argument(v: Any) -> Any:
    """
    Ensure v becomes a generic_pb2.Argument, even if it came from another module instance.
    """
    if v is None:
        return _argument_string("None")

    # Already correct type
    if isinstance(v, generic_pb2.Argument):
        return v

    # Another protobuf message with same wire format
    if hasattr(v, "SerializeToString"):
        try:
            a = generic_pb2.Argument()
            a.ParseFromString(v.SerializeToString())
            return a
        except Exception:
            pass

    # Primitive fallback (covers your Ok/Error cases)
    if isinstance(v, bool):
        return _argument_bool(v)
    if isinstance(v, (int,)):
        a = generic_pb2.Argument()
        a.int64_value = int(v)
        return a
    if isinstance(v, (float,)):
        a = generic_pb2.Argument()
        a.float_value = float(v)
        return a

    return _argument_string(str(v))


def _coerce_argument_map(m: Any) -> Dict[str, Any]:
    """
    Convert a protobuf map or dict-like of {str: Argument} into a plain dict
    with coerced Argument values.
    """
    out: Dict[str, Any] = {}
    if m is None:
        return out
    try:
        for k in m:
            out[str(k)] = _coerce_argument(m[k])
    except Exception:
        for k, v in dict(m).items():
            out[str(k)] = _coerce_argument(v)
    return out


# -------------------------
# Agent config + agent
# -------------------------

@dataclass
class AgentConfig:
    server_host: str
    server_port: int

    # .env file path on the host
    env_path: str = ".env"

    # TLS paths (recommended)
    ca_pem_path: Optional[str] = None           # CA cert that signed the server cert
    client_cert_pem_path: Optional[str] = None  # client cert (mTLS)
    client_key_pem_path: Optional[str] = None   # client private key (mTLS)

    # behavior
    heartbeat_interval_sec: float = 10.0
    reconnect_min_delay_sec: float = 1.0
    reconnect_max_delay_sec: float = 30.0
    outbound_max: int = 2048

    # optional: override version string
    version: str = "host-agent/0.2"


class HostTunnelAgent:
    def __init__(self, cfg: AgentConfig) -> None:
        self.cfg = cfg
        self._stop = threading.Event()
        self._out_q: "queue.Queue[Optional[host_pb2.HostFrame]]" = queue.Queue(maxsize=cfg.outbound_max)

        # best-effort cancel map: req_id -> threading.Event
        self._cancel_flags: Dict[str, threading.Event] = {}
        self._cancel_lock = threading.Lock()

        # loaded from .env per connect
        self._host_id: str = ""
        self._master_token: str = "***REMOVED***"
        self._device_ids: Dict[int, str] = {}  # local_id -> device_id

    def stop(self) -> None:
        self._stop.set()
        try:
            self._out_q.put_nowait(None)
        except Exception:
            pass

    def _enqueue(self, frame: host_pb2.HostFrame, *, timeout: float = 2.0) -> bool:
        try:
            self._out_q.put(frame, timeout=timeout)
            return True
        except queue.Full:
            return False

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

    # -------- env wiring --------

    def _reload_from_env(self) -> None:
        env = load_env_file(self.cfg.env_path)

        host_id = env.get("HOST_ID", "").strip()
        if not host_id:
            # deterministic fallback if missing (still works, but you said hard-coded)
            host_id = os.getenv("HOST_ID", "").strip() or f"host-{secrets.token_hex(4)}"
        self._host_id = host_id

        mt = env.get("HOST_MASTER_TOKEN", "").strip() or env.get("MASTER_TOKEN", "").strip()
        if mt:
            self._master_token = mt

        self._device_ids = _parse_device_ids_from_env(env)

    # -------- frames --------

    def _hello_frame(self) -> host_pb2.HostFrame:
        return host_pb2.HostFrame(
            hello=host_pb2.HostHello(host_id=self._host_id, version=self.cfg.version)
        )

    def _heartbeat_frame(self) -> host_pb2.HostFrame:
        return host_pb2.HostFrame(
            heartbeat=host_pb2.Heartbeat(unix_ms=_now_ms())
        )

    def _device_announce_frame(self) -> host_pb2.HostFrame:
        """
        Announces devices using device IDs from .env.
        Label comes from device_manager.get_all_devices_str() if available; else a simple default.
        """
        labels: Dict[int, str] = {}
        if callable(get_all_devices_str):
            try:
                labels = dict(get_all_devices_str())  # type: ignore
            except Exception:
                labels = {}

        infos: List[host_pb2.DeviceInfo] = []
        for local_id in sorted(self._device_ids.keys()):
            device_id = self._device_ids[local_id].strip()
            if not device_id:
                continue
            label = labels.get(local_id, f"Device {local_id}")
            infos.append(
                host_pb2.DeviceInfo(
                    local_id=int(local_id),
                    label=str(label),
                    device_id=str(device_id),
                )
            )

        return host_pb2.HostFrame(
            device_announce=host_pb2.DeviceAnnounce(devices=infos, unix_ms=_now_ms(), full_snapshot=True)
        )

    # -------- grpc channel --------

    def _make_channel(self) -> grpc.Channel:
        target = f"{self.cfg.server_host}:{int(self.cfg.server_port)}"

        # Insecure for early bring-up
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

    # -------- rpc execution --------

    def _override_token_for_local_device(self, args_map: Any, local_device_id: int) -> None:
        """
        Replace args_map['a'] with a host-local "force" token so existing host PlutoServer/device_manager
        can select the intended local device without relying on main-server reservation tokens.
        """
        try:
            forced = f"{self._master_token}_{int(local_device_id)}_force"
            args_map["a"].CopyFrom(_argument_string(forced))
        except Exception:
            # If args_map isn't writable / not a protobuf map, ignore
            pass

    def _handle_rpc_request(self, req: host_pb2.RpcRequest) -> None:
        """
        Execute host-local RPC and respond.
        Runs in a worker thread so stream reader stays responsive.
        """
        req_id = str(req.req_id)
        _ = self._register_cancel(req_id)

        try:
            # NEW: request is already a GenericRPCRequest (function_name + args: map<string, Argument>)
            greq = req.request

            # Make a mutable args dict/map
            # Prefer using the protobuf map container directly if possible.
            args_map = greq.args

            # Inject/override token for local device selection
            self._override_token_for_local_device(args_map, int(req.local_device_id))

            # Execute locally (rpc_manager should accept map<string, Argument>)
            results_any = rpc_manager.run_rpc(function_name=greq.function_name, args=args_map)

            # Coerce to a GenericRPCResponse
            gresp = generic_pb2.GenericRPCResponse()
            results = _coerce_argument_map(results_any)
            for k, v in results.items():
                gresp.results[str(k)].CopyFrom(v)

            out = host_pb2.HostFrame(
                rpc_response=host_pb2.RpcResponse(
                    req_id=req_id,
                    ok=True,
                    error="",
                    response=gresp,
                )
            )
            self._enqueue(out)

        except Exception as e:
            tb = traceback.format_exc(limit=10)
            gresp = generic_pb2.GenericRPCResponse()
            gresp.results["Ok"].CopyFrom(_argument_bool(False))
            gresp.results["Error"].CopyFrom(_argument_string(f"{e}\n{tb}"))

            out = host_pb2.HostFrame(
                rpc_response=host_pb2.RpcResponse(
                    req_id=req_id,
                    ok=False,
                    error=f"{e}",
                    response=gresp,
                )
            )
            self._enqueue(out)

        finally:
            self._consume_cancel(req_id)

    # -------- outbound stream --------

    def _outbound_generator(self) -> Iterable[host_pb2.HostFrame]:
        while not self._stop.is_set():
            try:
                item = self._out_q.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                return
            yield item

    # -------- main loop --------

    def run_forever(self) -> None:
        delay = self.cfg.reconnect_min_delay_sec

        while not self._stop.is_set():
            try:
                # reload ID + device IDs on each connect attempt
                self._reload_from_env()

                channel = self._make_channel()
                stub = host_pb2_grpc.HostTunnelStub(channel)

                # Prime outbound
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

                for frame in stream:
                    which = frame.WhichOneof("msg")
                    if which == "rpc_request":
                        threading.Thread(
                            target=self._handle_rpc_request,
                            args=(frame.rpc_request,),
                            daemon=True,
                        ).start()

                    elif which == "cancel":
                        self._set_cancel(frame.cancel.req_id)

                    elif which == "heartbeat":
                        pass

                    elif which == "device_announce":
                        # server shouldn't send this; ignore
                        pass

                hb_stop.set()

            except grpc.RpcError:
                pass
            except Exception:
                pass

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
    # Environment overrides (optional)
    server_host = os.getenv("MAIN_SERVER_HOST", "127.0.0.1")
    server_port = int(os.getenv("HOST_PORT", "61007"))
    env_path = os.getenv("HOST_ENV_PATH", ".env")

    cfg = AgentConfig(
        server_host=server_host,
        server_port=server_port,
        env_path=env_path,
        version=os.getenv("HOST_VERSION", "host-agent/dev"),
        ca_pem_path=os.getenv("CA_PEM_PATH"),
        client_cert_pem_path=os.getenv("CLIENT_CERT_PATH"),
        client_key_pem_path=os.getenv("CLIENT_KEY_PATH"),
    )

    agent = HostTunnelAgent(cfg)
    try:
        agent.run_forever()
    except KeyboardInterrupt:
        agent.stop()
