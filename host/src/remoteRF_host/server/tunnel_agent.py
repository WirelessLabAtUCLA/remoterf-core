# tunnel_agent.py
#
# Host-side agent (repo-local config):
#   Reads config from:
#     <repo>/config/remoteRF_host/net.env     (REMOTERF_ADDR, REMOTERF_CA_CERT, optional mTLS)
#     <repo>/config/remoteRF_host/host.env    (HOST_ID, optional HOST_MASTER_TOKEN)
#     <repo>/config/remoteRF_host/devices.env (DEVICE_<n>_ID or DEVICE_MAP)
#
#   Connects to main server via HostTunnel bidi stream, announces devices, executes RPC locally.

from __future__ import annotations

import os
import re
import time
import threading
import queue
import traceback
import secrets
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Any, Optional, Iterable, List, Tuple

import grpc

from ..common.grpc import grpc_host_pb2 as host_pb2
from ..common.grpc import grpc_host_pb2_grpc as host_pb2_grpc

import sys
from typing import NoReturn

def _die_config(net_env: Path, msg: str, *, code: int = 2) -> NoReturn:
    print(f"ERROR: {msg}", file=sys.stderr)
    print(f"Config file: {net_env}", file=sys.stderr)
    print("Fix:", file=sys.stderr)
    print("  hostrf -c -a <host:port>", file=sys.stderr)
    print("  hostrf -c -a --show", file=sys.stderr)
    raise SystemExit(code)

try:
    generic_pb2 = host_pb2.grpc__pb2  # generated alias inside grpc_host_pb2.py
except Exception:
    from ..common.grpc import grpc_pb2 as generic_pb2  # fallback

from .rpc_manager import rpc_manager  # type: ignore

try:
    from .device_manager import get_all_devices_str  # type: ignore
except Exception:
    get_all_devices_str = None


def _now_ms() -> int:
    return int(time.time() * 1000)


# -------------------------
# repo-local config paths
# -------------------------

def _repo_root() -> Path:
    """
    Try to find the repo root by locating the 'src' directory in parents and returning its parent.
    Fallback: go up 3 levels (works for src/remoteRF_host/server/host_tunnel_agent.py).
    """
    p = Path(__file__).resolve()
    for parent in p.parents:
        if parent.name == "src":
            return parent.parent
    return p.parents[3]

def _cfg_dir() -> Path:
    return _repo_root() / ".config"

def _net_env_path() -> Path:
    return _cfg_dir() / "net.env"

def _host_env_path() -> Path:
    return _cfg_dir() / "host.env"

def _devices_env_path() -> Path:
    return _cfg_dir() / "devices.env"


def _resolve_path(base_env_path: Path, p: str) -> str:
    """
    If p is relative, resolve it relative to the directory containing base_env_path.
    """
    if not p:
        return ""
    pp = Path(p).expanduser()
    if pp.is_absolute():
        return str(pp)
    return str((base_env_path.parent / pp).resolve())


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
# Argument helpers
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
    if v is None:
        return _argument_string("None")

    if isinstance(v, generic_pb2.Argument):
        return v

    if hasattr(v, "SerializeToString"):
        try:
            a = generic_pb2.Argument()
            a.ParseFromString(v.SerializeToString())
            return a
        except Exception:
            pass

    if isinstance(v, bool):
        return _argument_bool(v)
    if isinstance(v, int):
        a = generic_pb2.Argument()
        a.int64_value = int(v)
        return a
    if isinstance(v, float):
        a = generic_pb2.Argument()
        a.float_value = float(v)
        return a

    return _argument_string(str(v))

def _coerce_argument_map(m: Any) -> Dict[str, Any]:
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
    # derived from net.env (REMOTERF_ADDR)
    server_host: str
    server_port: int

    # repo-local envs
    net_env_path: str
    host_env_path: str
    devices_env_path: str

    # TLS paths (derived from net.env)
    ca_pem_path: Optional[str] = None
    client_cert_pem_path: Optional[str] = None
    client_key_pem_path: Optional[str] = None

    heartbeat_interval_sec: float = 10.0
    reconnect_min_delay_sec: float = 1.0
    reconnect_max_delay_sec: float = 30.0
    outbound_max: int = 2048

    version: str = "host-agent/0.2"


class HostTunnelAgent:
    def __init__(self, cfg: AgentConfig) -> None:
        self.cfg = cfg
        self._stop = threading.Event()
        self._out_q: "queue.Queue[Optional[host_pb2.HostFrame]]" = queue.Queue(maxsize=cfg.outbound_max)

        self._cancel_flags: Dict[str, threading.Event] = {}
        self._cancel_lock = threading.Lock()

        self._host_id: str = ""
        self._master_token: str = "***REMOVED***"
        self._device_ids: Dict[int, str] = {}

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

    # -------- host inventory (host.env + devices.env) --------

    def _reload_from_env(self) -> None:
        host_env = load_env_file(self.cfg.host_env_path)
        dev_env = load_env_file(self.cfg.devices_env_path)

        # HOST_ID
        host_id = host_env.get("HOST_ID", "").strip()
        if not host_id:
            host_id = os.getenv("HOST_ID", "").strip() or f"host-{secrets.token_hex(4)}"
        self._host_id = host_id

        # HOST_MASTER_TOKEN (optional)
        mt = (host_env.get("HOST_MASTER_TOKEN", "").strip()
              or host_env.get("MASTER_TOKEN", "").strip()
              or os.getenv("HOST_MASTER_TOKEN", "").strip()
              or os.getenv("MASTER_TOKEN", "").strip())
        if mt:
            self._master_token = mt

        # devices
        merged = dict(dev_env)
        # allow device map living in host.env too (optional)
        for k, v in host_env.items():
            if k not in merged:
                merged[k] = v
        self._device_ids = _parse_device_ids_from_env(merged)

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
            device_announce=host_pb2.DeviceAnnounce(
                devices=infos,
                unix_ms=_now_ms(),
                full_snapshot=True,
            )
        )

    # -------- channel --------

    def _make_channel(self) -> grpc.Channel:
        addr = f"{self.cfg.server_host}:{int(self.cfg.server_port)}"

        options = [
            ('grpc.max_send_message_length', 100 * 1024 * 1024),
            ('grpc.max_receive_message_length', 100 * 1024 * 1024),
            ('grpc.keepalive_time_ms', 30_000),
            ('grpc.keepalive_timeout_ms', 10_000),
            ('grpc.http2.max_pings_without_data', 0),
            ('grpc.keepalive_permit_without_calls', 1),
        ]

        if not self.cfg.ca_pem_path:
            return grpc.insecure_channel(addr, options=options)

        ca_path = Path(self.cfg.ca_pem_path).expanduser().resolve()
        with ca_path.open("rb") as f:
            trusted_certs = f.read()

        if self.cfg.client_cert_pem_path and self.cfg.client_key_pem_path:
            cert_path = Path(self.cfg.client_cert_pem_path).expanduser().resolve()
            key_path = Path(self.cfg.client_key_pem_path).expanduser().resolve()
            with cert_path.open("rb") as f:
                client_cert = f.read()
            with key_path.open("rb") as f:
                client_key = f.read()

            credentials = grpc.ssl_channel_credentials(
                root_certificates=trusted_certs,
                private_key=client_key,
                certificate_chain=client_cert,
            )
        else:
            credentials = grpc.ssl_channel_credentials(root_certificates=trusted_certs)

        return grpc.secure_channel(addr, credentials, options=options)

    # -------- rpc execution --------

    def _override_token_for_local_device(self, args_map: Any, local_device_id: int) -> None:
        try:
            forced = f"{self._master_token}_{int(local_device_id)}_force"
            args_map["a"].CopyFrom(_argument_string(forced))
        except Exception:
            pass

    def _handle_rpc_request(self, req: host_pb2.RpcRequest) -> None:
        req_id = str(req.req_id)
        _ = self._register_cancel(req_id)

        try:
            greq = req.request
            args_map = greq.args

            self._override_token_for_local_device(args_map, int(req.local_device_id))

            results_any = rpc_manager.run_rpc(function_name=greq.function_name, args=args_map)

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
                    error=str(e),
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
                self._reload_from_env()

                channel = self._make_channel()
                stub = host_pb2_grpc.HostTunnelStub(channel)

                self._enqueue(self._hello_frame())
                self._enqueue(self._device_announce_frame())

                hb_stop = threading.Event()

                def hb_loop():
                    while not hb_stop.is_set() and not self._stop.is_set():
                        self._enqueue(self._heartbeat_frame())
                        time.sleep(self.cfg.heartbeat_interval_sec)

                threading.Thread(target=hb_loop, daemon=True).start()

                stream = stub.Connect(self._outbound_generator())
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

                hb_stop.set()

            except grpc.RpcError:
                pass
            except Exception:
                pass

            if self._stop.is_set():
                break

            time.sleep(delay)
            delay = min(delay * 1.7, self.cfg.reconnect_max_delay_sec)


def start_host_tunnel_agent_thread(cfg: AgentConfig) -> Tuple[HostTunnelAgent, threading.Thread]:
    agent = HostTunnelAgent(cfg)
    th = threading.Thread(target=agent.run_forever, daemon=True)
    th.start()
    return agent, th


def _parse_addr(addr: str) -> Tuple[str, int]:
    a = (addr or "").strip()
    if not a or ":" not in a:
        raise ValueError("REMOTERF_ADDR must be like 'host:port'")
    host, port_s = a.rsplit(":", 1)
    return host.strip(), int(port_s.strip())


def main() -> None:
    # repo-local env paths (written by hostrf CLI)
    net_env = _net_env_path()
    host_env = _host_env_path()
    dev_env = _devices_env_path()

    net_kv = load_env_file(str(net_env))
    addr = (net_kv.get("REMOTERF_ADDR", "").strip() or os.getenv("REMOTERF_ADDR", "").strip())
    if not addr:
        _die_config(net_env, "REMOTERF_ADDR is not set.")

    try:
        server_host, server_port = _parse_addr(addr)
    except Exception as e:
        _die_config(net_env, f"Invalid REMOTERF_ADDR={addr!r} ({e}).")

    server_host, server_port = _parse_addr(addr)

    # cert paths resolve relative to net.env directory
    ca_path = _resolve_path(net_env, net_kv.get("REMOTERF_CA_CERT", "").strip())
    client_cert = _resolve_path(net_env, net_kv.get("REMOTERF_CLIENT_CERT", "").strip())
    client_key = _resolve_path(net_env, net_kv.get("REMOTERF_CLIENT_KEY", "").strip())

    cfg = AgentConfig(
        server_host=server_host,
        server_port=server_port,
        net_env_path=str(net_env),
        host_env_path=str(host_env),
        devices_env_path=str(dev_env),
        version=os.getenv("HOST_VERSION", "host-agent/dev"),
        ca_pem_path=ca_path or None,
        client_cert_pem_path=client_cert or None,
        client_key_pem_path=client_key or None,
    )

    agent = HostTunnelAgent(cfg)
    try:
        agent.run_forever()
    except KeyboardInterrupt:
        agent.stop()