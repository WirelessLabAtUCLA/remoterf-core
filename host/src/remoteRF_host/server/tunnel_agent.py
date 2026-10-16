#!/usr/bin/env python3
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

# tunnel_agent.py
#
# Host-side agent:
#   Reads host config from:
#     ~/.config/remoterf/host/net.env        (REMOTERF_ADDR, REMOTERF_CA_CERT, optional mTLS)
#     ~/.config/remoterf/host/host.env       (HOST_ID, HOST_TOKEN, optional HOST_MASTER_TOKEN)
#     ~/.config/remoterf/host/devices.yml    (or devices.yaml)
#
# Connects to main server via HostTunnel bidi stream, announces devices, executes RPC locally.
#
# Canonical identity:
#   - gid is the ONLY global device identity.
#   - We announce DeviceInfo.device_id = "<gid>" (decimal string)
#   - We also set DeviceInfo.local_id = gid
#
# NO log levels / env config:
#   INFO/WARN/ERROR always print to stderr.

from __future__ import annotations

import os
import re
import hashlib
import time
import queue
import grpc
import random
import threading
import traceback

from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Any, Optional, Iterable, List, Tuple, NoReturn

from ..common.utils import device_name_key, get_devices_config_path, get_host_config_dir
from ..common.utils.host_logging import error, exception, info, status, warn
from ..common.grpc import grpc_host_pb2 as host_pb2
from ..common.grpc import grpc_host_pb2_grpc as host_pb2_grpc
from ..config.cert_fetcher import normalize_sha256, pin_ca

BANNER_CREDIT = "Created by the Wireless Lab at UCLA"


# -------------------------
# Fatal config helpers
# -------------------------

def _die_config(net_env: Path, msg: str, *, code: int = 2) -> NoReturn:
    error(f"Config error: {msg}", component="hostrf.tunnel_agent")
    error(f"Config file: {net_env}", component="hostrf.tunnel_agent")
    error("Fix:", component="hostrf.tunnel_agent")
    error("  hostrf --config --addr <host:port>", component="hostrf.tunnel_agent")
    error("  hostrf --config --show", component="hostrf.tunnel_agent")
    raise SystemExit(code)


def _die_host_config(host_env: Path, msg: str, *, code: int = 2) -> NoReturn:
    error(f"Host config error: {msg}", component="hostrf.tunnel_agent")
    error(f"Config file: {host_env}", component="hostrf.tunnel_agent")
    error("Fix:", component="hostrf.tunnel_agent")
    error(f"  Edit {host_env} and set a unique HOST_ID, e.g.", component="hostrf.tunnel_agent")
    error("    HOST_ID=my-host-1", component="hostrf.tunnel_agent")
    error("    HOST_TOKEN=my-host-token", component="hostrf.tunnel_agent")
    error("  Ensure only one agent uses a given HOST_ID at a time.", component="hostrf.tunnel_agent")
    raise SystemExit(code)


def _die_devices_config(dev_yaml: Path, msg: str, *, code: int = 2) -> NoReturn:
    error(f"Devices config error: {msg}", component="hostrf.tunnel_agent")
    error(f"Config file: {dev_yaml}", component="hostrf.tunnel_agent")
    error("Fix:", component="hostrf.tunnel_agent")
    error("  Ensure devices.yml/devices.yaml contains a top-level 'devices:' list.", component="hostrf.tunnel_agent")
    error("  Ensure each device_id (gid) is unique across ALL hosts.", component="hostrf.tunnel_agent")
    error("  Example:", component="hostrf.tunnel_agent")
    error("    devices:", component="hostrf.tunnel_agent")
    error("      - device_id: 10", component="hostrf.tunnel_agent")
    error("        device_type: adalm_pluto", component="hostrf.tunnel_agent")
    error("        name: pluto-10", component="hostrf.tunnel_agent")
    error("        init:", component="hostrf.tunnel_agent")
    error("          serial: 104473b...", component="hostrf.tunnel_agent")
    raise SystemExit(code)


# -------------------------
# Generic Argument message import
# -------------------------

try:
    generic_pb2 = host_pb2.grpc__pb2
except Exception:
    from ..common.grpc import grpc_pb2 as generic_pb2


# -------------------------
# Project imports (host-side)
# -------------------------

from .rpc_manager import rpc_manager  # type: ignore

try:
    from .device_manager import end_reservation, get_configured_devices, get_device_schema, reload_devices  # type: ignore
except Exception:
    end_reservation = None
    get_configured_devices = None
    get_device_schema = None
    reload_devices = None


# -------------------------
# Misc helpers
# -------------------------

def _now_ms() -> int:
    return int(time.time() * 1000)


def _device_count_label(count: int) -> str:
    return f"{count} device" if count == 1 else f"{count} devices"


def _single_line(text: str, *, max_len: int = 120) -> str:
    flat = " ".join(str(text or "").split())
    if len(flat) <= max_len:
        return flat
    return flat[: max_len - 3] + "..."


def _grpc_reason(code: Optional[grpc.StatusCode], details: str) -> str:
    name = getattr(code, "name", None) or str(code or "UNKNOWN")
    detail = _single_line(details)
    if detail:
        return f"{name}: {detail}"
    return name


# -------------------------
# Host config paths
# -------------------------

def _cfg_dir() -> Path:
    return get_host_config_dir()


def _net_env_path() -> Path:
    return _cfg_dir() / "net.env"


def _host_env_path() -> Path:
    return _cfg_dir() / "host.env"


def _devices_yaml_path() -> Path:
    return get_devices_config_path(create=True)


def _resolve_path(base_env_path: Path, p: str) -> str:
    if not p:
        return ""
    pp = Path(p).expanduser()
    if pp.is_absolute():
        return str(pp)
    return str((base_env_path.parent / pp).resolve())


# -------------------------
# .env parsing (for net.env / host.env only)
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
    server_host: str
    server_port: int

    net_env_path: str
    host_env_path: str
    devices_yaml_path: str

    ca_pem_path: Optional[str] = None
    ca_sha256: str = ""
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
        self._master_token: str = "Master"

        self._devices: Dict[int, Dict[str, str]] = {}

        self._host_token: str = ""

    def stop(self) -> None:
        info("Stop requested.")
        self._stop.set()
        try:
            self._out_q.put_nowait(None)
        except Exception:
            exception("Failed to enqueue stop sentinel.", component="hostrf.tunnel_agent")

    def _enqueue(self, frame: host_pb2.HostFrame, *, timeout: float = 2.0) -> bool:
        try:
            which = frame.WhichOneof("msg")
            self._out_q.put(frame, timeout=timeout)
            info(f"Enqueued outbound frame type={which}", component="hostrf.tunnel_agent")
            return True
        except queue.Full:
            which = frame.WhichOneof("msg")
            warn(
                f"Outbound queue full (max={self.cfg.outbound_max}). Dropping frame type={which}",
                component="hostrf.tunnel_agent",
            )
            return False
        except Exception:
            exception("Outbound enqueue failed.", component="hostrf.tunnel_agent")
            return False

    # -------------------------
    # Reconnect hygiene
    # -------------------------

    def _drain_outbound_queue(self) -> None:
        drained = 0
        while True:
            try:
                x = self._out_q.get_nowait()
                if x is None:
                    continue
                drained += 1
            except queue.Empty:
                break
            except Exception:
                exception("Failed draining outbound queue.", component="hostrf.tunnel_agent")
                break
        if drained:
            warn(
                f"Drained {drained} stale outbound frame(s) before starting a new stream.",
                component="hostrf.tunnel_agent",
            )

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

    def _schema_for_gid(self, gid: int):
        if not callable(get_device_schema):
            return None
        try:
            return get_device_schema(gid)  # type: ignore[misc]
        except Exception:
            exception(f"get_device_schema({gid}) failed.", component="hostrf.tunnel_agent")
            return None

    # -------- inventory --------

    def _reload_from_env(self) -> None:
        host_env = load_env_file(self.cfg.host_env_path)

        host_id = host_env.get("HOST_ID", "").strip() or os.getenv("HOST_ID", "").strip()
        if not host_id:
            _die_host_config(Path(self.cfg.host_env_path), "HOST_ID is not set (server requires a stable, explicit host id).")
        self._host_id = host_id

        tok = host_env.get("HOST_TOKEN", "").strip() or os.getenv("HOST_TOKEN", "").strip()
        if not tok:
            _die_host_config(Path(self.cfg.host_env_path), "HOST_TOKEN is not set.")
        self._host_token = tok

        mt = (
            host_env.get("HOST_MASTER_TOKEN", "").strip()
            or host_env.get("MASTER_TOKEN", "").strip()
            or os.getenv("HOST_MASTER_TOKEN", "").strip()
            or os.getenv("MASTER_TOKEN", "").strip()
        )
        token_state = "default"
        if mt:
            self._master_token = mt
            token_state = "set"

        try:
            if callable(reload_devices):
                reload_devices()  # type: ignore[misc]
            if callable(get_configured_devices):
                self._devices = dict(get_configured_devices())  # type: ignore[misc]
            else:
                self._devices = {}
        except Exception as e:
            _die_devices_config(Path(self.cfg.devices_yaml_path), f"Failed to load schema-backed inventory: {e}")

        if not self._devices:
            info(
                f"No devices found in {self.cfg.devices_yaml_path}; announcing zero devices.",
                component="hostrf.tunnel_agent",
            )

        info(
            f"Inventory reloaded: host_id={self._host_id} devices={len(self._devices)} "
            f"master_token={token_state} host_env={self.cfg.host_env_path} devices_yaml={self.cfg.devices_yaml_path}",
            component="hostrf.tunnel_agent",
        )

    # -------- frames --------

    def _hello_frame(self) -> host_pb2.HostFrame:
        hello = host_pb2.HostHello(host_id=self._host_id, version=self.cfg.version)

        if hasattr(hello, "host_token"):
            hello.host_token = self._host_token

        return host_pb2.HostFrame(hello=hello)

    def _heartbeat_frame(self) -> host_pb2.HostFrame:
        return host_pb2.HostFrame(
            heartbeat=host_pb2.Heartbeat(unix_ms=_now_ms())
        )

    def _device_announce_frame(self) -> host_pb2.HostFrame:
        infos: List[host_pb2.DeviceInfo] = []
        for gid in sorted(self._devices.keys()):
            d = self._devices[gid]
            label = (str(d.get("label", "")).strip() or f"Device {gid}")
            dtype = str(d.get("kind") or d.get("type") or "").lower()

            schema = self._schema_for_gid(gid)
            if schema is not None and hasattr(schema, "list_exposed"):
                exposed = schema.list_exposed()
                n_ops = (
                    len(exposed.get("getters", []))
                    + len(exposed.get("setters", []))
                    + len(exposed.get("calls", []))
                )
                info(
                    f"Device gid={gid} type={dtype!r}: "
                    f"schema exposes {n_ops} operation(s).",
                    component="hostrf.tunnel_agent",
                )

            infos.append(
                host_pb2.DeviceInfo(
                    local_id=int(gid),
                    label=str(label),
                    device_id=str(int(gid)),
                    serial=str(d.get("serial", "")),
                    kind=str(d.get("kind", "")),
                    # Server 1.2.0 resolves <handle>@lab from this; newer Servers key the label themselves.
                    handle=device_name_key(label),
                )
            )

        info(f"Prepared DeviceAnnounce with {len(infos)} device(s).", component="hostrf.tunnel_agent")
        return host_pb2.HostFrame(
            device_announce=host_pb2.DeviceAnnounce(
                devices=infos,
                unix_ms=_now_ms(),
                full_snapshot=True,
            )
        )

    # -------- meta --------

    def _new_meta_message(self):
        for name in ("HostMeta", "Meta", "MetaPayload"):
            cls = getattr(host_pb2, name, None)
            if cls is not None:
                try:
                    return cls()
                except Exception:
                    continue
        return None

    def _collect_meta(self, req: host_pb2.MetaRequest):
        meta = self._new_meta_message()
        if meta is None:
            warn(
                "MetaRequest received but no compatible meta message type found in host_pb2.",
                component="hostrf.tunnel_agent",
            )
            return None

        def _set(field: str, value: Any) -> None:
            try:
                setattr(meta, field, value)
            except Exception:
                pass

        def _set_kv(key: str, value: str) -> None:
            try:
                meta.kv[key] = value
            except Exception:
                pass

        _set("host_id", self._host_id)
        _set("unix_ms", _now_ms())
        _set("version", self.cfg.version)

        if self._devices:
            for gid in sorted(self._devices.keys()):
                d = self._devices[gid]
                dtype = str(d.get("kind") or d.get("type") or "").lower()
                if dtype:
                    _set_kv(f"device.{gid}.type", dtype)

                schema = self._schema_for_gid(gid)
                if schema is None or not hasattr(schema, "get_capabilities_string"):
                    continue

                caps = schema.get_capabilities_string()

                schema_type = str(getattr(schema, "device_type", "") or dtype)
                driver_version = str(getattr(schema, "driver_version", "") or "")
                schema_hash = ""
                if hasattr(schema, "get_idl_hash"):
                    try:
                        schema_hash = str(schema.get_idl_hash() or "")
                    except Exception:
                        exception(f"Failed computing schema hash for gid={gid}", component="hostrf.tunnel_agent")

                _set_kv(f"device.{gid}.type", schema_type)
                if caps:
                    _set_kv(f"device.{gid}.caps", caps)
                if driver_version:
                    _set_kv(f"device.{gid}.driver_version", driver_version)
                if schema_hash:
                    _set_kv(f"device.{gid}.schema_hash", schema_hash)
                info(
                    f"IDL meta for gid={gid} type={dtype}: "
                    f"{len(caps.split(',')) if caps else 0} attribute(s)",
                    component="hostrf.tunnel_agent",
                )

        return meta

    def _handle_meta_request(self, req: host_pb2.MetaRequest) -> None:
        req_id = str(req.req_id)
        cancel_ev = self._register_cancel(req_id)
        try:
            info(f"MetaRequest req_id={req_id}", component="hostrf.tunnel_agent")

            if cancel_ev.is_set():
                warn(f"MetaRequest req_id={req_id} canceled before handling.", component="hostrf.tunnel_agent")
                return

            self._reload_from_env()
            meta = self._collect_meta(req)

            resp = host_pb2.MetaResponse(req_id=req_id, ok=True, error="")
            if meta is not None and hasattr(resp, "meta"):
                try:
                    resp.meta.CopyFrom(meta)
                except Exception:
                    exception(
                        "Failed to attach meta payload; sending ok response without meta.",
                        component="hostrf.tunnel_agent",
                    )

            frame = host_pb2.HostFrame(meta_response=resp)
            self._enqueue(frame)

        except Exception:
            exception(f"MetaRequest req_id={req_id} failed.", component="hostrf.tunnel_agent")
            frame = host_pb2.HostFrame(
                meta_response=host_pb2.MetaResponse(
                    req_id=req_id,
                    ok=False,
                    error="MetaRequest handler exception (see host logs).",
                )
            )
            self._enqueue(frame)
        finally:
            self._consume_cancel(req_id)

    # -------- channel --------

    def _make_channel(self) -> grpc.Channel:
        addr = f"{self.cfg.server_host}:{int(self.cfg.server_port)}"

        options = [
            ("grpc.max_send_message_length", 100 * 1024 * 1024),
            ("grpc.max_receive_message_length", 100 * 1024 * 1024),
            ("grpc.keepalive_time_ms", 30_000),
            ("grpc.keepalive_timeout_ms", 10_000),
            ("grpc.http2.max_pings_without_data", 0),
            ("grpc.keepalive_permit_without_calls", 1),
        ]

        if not self.cfg.ca_pem_path:
            raise FileNotFoundError("No CA cert configured: the host only connects over TLS.")

        ca_path = Path(self.cfg.ca_pem_path).expanduser().resolve()
        if not ca_path.exists():
            raise FileNotFoundError(f"CA cert not found: {ca_path}")

        with ca_path.open("rb") as f:
            trusted_certs = f.read()
        if hashlib.sha256(trusted_certs).hexdigest() != self.cfg.ca_sha256:
            _die_config(Path(self.cfg.net_env_path), f"{ca_path} no longer matches the pinned REMOTERF_CA_SHA256.")

        mtls = False
        if self.cfg.client_cert_pem_path and self.cfg.client_key_pem_path:
            cert_path = Path(self.cfg.client_cert_pem_path).expanduser().resolve()
            key_path = Path(self.cfg.client_key_pem_path).expanduser().resolve()
            if not cert_path.exists():
                raise FileNotFoundError(f"Client cert not found: {cert_path}")
            if not key_path.exists():
                raise FileNotFoundError(f"Client key not found: {key_path}")

            with cert_path.open("rb") as f:
                client_cert = f.read()
            with key_path.open("rb") as f:
                client_key = f.read()

            credentials = grpc.ssl_channel_credentials(
                root_certificates=trusted_certs,
                private_key=client_key,
                certificate_chain=client_cert,
            )
            mtls = True
        else:
            credentials = grpc.ssl_channel_credentials(root_certificates=trusted_certs)

        info(
            f"Opening TLS channel to {addr} (CA={ca_path}, mTLS={'yes' if mtls else 'no'})",
            component="hostrf.tunnel_agent",
        )
        return grpc.secure_channel(addr, credentials, options=options)

    # -------- control --------

    def _handle_control(self, ctl) -> None:
        kind = str(getattr(ctl, "kind", "") or "")
        if kind != "reservation_end":
            warn(f"Ignoring control frame kind={kind!r}", component="hostrf.tunnel_agent")
            return
        try:
            gid = int(str(ctl.device_id))
        except ValueError:
            warn(f"reservation_end for a bad device_id={ctl.device_id!r}", component="hostrf.tunnel_agent")
            return
        if gid not in self._devices or not callable(end_reservation):
            warn(f"reservation_end for unknown gid={gid}", component="hostrf.tunnel_agent")
            return
        end_reservation(gid)
        status(f"Reservation ended on device {gid}: sessions closed, device reset.", component="hostrf")

    # -------- rpc execution --------

    def _override_token_for_gid(self, args_map: Any, gid_s: str) -> None:
        try:
            forced = f"{self._master_token}_{gid_s}_force"
            args_map["a"].CopyFrom(_argument_string(forced))
        except Exception:
            exception(f"Failed to override token for gid={gid_s!r}", component="hostrf.tunnel_agent")

    def _resolve_request_gid(self, req: host_pb2.RpcRequest) -> Tuple[str, int]:
        gid_s = (getattr(req, "device_id", "") or "").strip()
        if gid_s:
            if not gid_s.isdigit():
                raise ValueError(f"Invalid gid device_id={gid_s!r} (expected decimal string).")
            gid_i = int(gid_s)
            if str(gid_i) != gid_s:
                raise ValueError(f"Non-canonical gid string {gid_s!r} (expected {gid_i}).")
            if gid_i not in self._devices:
                raise ValueError(f"Unknown gid={gid_s!r} for this host.")
            return gid_s, gid_i

        gid_i = int(getattr(req, "local_device_id", 0))
        if gid_i not in self._devices:
            raise ValueError(f"Unknown local_device_id/gid={gid_i} for this host.")
        return str(gid_i), gid_i

    def _handle_rpc_request(self, req: host_pb2.RpcRequest) -> None:
        req_id = str(req.req_id)
        _ = self._register_cancel(req_id)

        t0 = time.time()
        try:
            greq = req.request
            args_map = greq.args

            gid_s, gid_i = self._resolve_request_gid(req)

            info(
                f"RpcRequest req_id={req_id} gid={gid_i} fn={str(greq.function_name)}",
                component="hostrf.tunnel_agent",
            )

            # self._override_token_for_gid(args_map, gid_s)

            try:
                args_map["gid"].CopyFrom(_argument_string(gid_s))
            except Exception:
                pass
            try:
                args_map["device_id"].CopyFrom(_coerce_argument(gid_i))
            except Exception:
                pass

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

            dt_ms = int((time.time() - t0) * 1000.0)
            info(f"RpcResponse req_id={req_id} ok=true dt_ms={dt_ms}", component="hostrf.tunnel_agent")

        except Exception:
            exception(f"RpcRequest req_id={req_id} FAILED", component="hostrf.tunnel_agent")
            tb = traceback.format_exc(limit=20)

            gresp = generic_pb2.GenericRPCResponse()
            gresp.results["Ok"].CopyFrom(_argument_bool(False))
            gresp.results["Error"].CopyFrom(_argument_string(tb))

            out = host_pb2.HostFrame(
                rpc_response=host_pb2.RpcResponse(
                    req_id=req_id,
                    ok=False,
                    error="RpcRequest handler exception (see host logs).",
                    response=gresp,
                )
            )
            self._enqueue(out)

        finally:
            self._consume_cancel(req_id)

    # -------- outbound stream --------

    def _outbound_generator(self, *, initial: List[host_pb2.HostFrame]) -> Iterable[host_pb2.HostFrame]:
        info("Outbound generator started.", component="hostrf.tunnel_agent")

        for f in initial:
            which = f.WhichOneof("msg")
            info(f"Outbound initial -> type={which}", component="hostrf.tunnel_agent")
            yield f

        while not self._stop.is_set():
            try:
                item = self._out_q.get(timeout=0.5)
            except queue.Empty:
                continue
            except Exception:
                exception("Outbound queue get failed.", component="hostrf.tunnel_agent")
                continue

            if item is None:
                info("Outbound generator got stop sentinel; exiting.", component="hostrf.tunnel_agent")
                return

            which = item.WhichOneof("msg")
            info(f"Outbound -> type={which}", component="hostrf.tunnel_agent")
            yield item

        info("Outbound generator exiting due to stop flag.", component="hostrf.tunnel_agent")

    # -------- main loop --------

    def run_forever(self) -> None:
        delay = self.cfg.reconnect_min_delay_sec
        attempt = 0
        status_started = False

        info(
            f"HostTunnelAgent starting: target={self.cfg.server_host}:{int(self.cfg.server_port)} version={self.cfg.version}",
            component="hostrf.tunnel_agent",
        )
        info(BANNER_CREDIT, component="hostrf.tunnel_agent")
        info("Press Ctrl+C to stop.", component="hostrf.tunnel_agent")

        try:
            while not self._stop.is_set():
                hb_stop: Optional[threading.Event] = None
                channel: Optional[grpc.Channel] = None
                addr = f"{self.cfg.server_host}:{int(self.cfg.server_port)}"
                retry_reason = ""
                stream_established = False
                attempt += 1

                try:
                    self._reload_from_env()
                    self._drain_outbound_queue()

                    tls = "yes" if self.cfg.ca_pem_path else "no"
                    info(f"Connect attempt #{attempt} to {addr} (tls={tls})", component="hostrf.tunnel_agent")

                    if attempt == 1:
                        status(
                            f"Starting host '{self._host_id}' -> {addr} ({_device_count_label(len(self._devices))}).",
                            component="hostrf",
                        )
                        status_started = True

                    channel = self._make_channel()
                    stub = host_pb2_grpc.HostTunnelStub(channel)

                    initial = [self._hello_frame(), self._device_announce_frame()]

                    stream = stub.Connect(self._outbound_generator(initial=initial))
                    delay = self.cfg.reconnect_min_delay_sec
                    stream_established = True
                    status(
                        f"Connected to {addr} as '{self._host_id}' ({_device_count_label(len(self._devices))}).",
                        component="hostrf",
                    )
                    info("HostTunnel stream established. Waiting for server frames...", component="hostrf.tunnel_agent")

                    hb_stop = threading.Event()

                    def hb_loop() -> None:
                        try:
                            info(
                                f"Heartbeat loop started (interval={self.cfg.heartbeat_interval_sec:.1f}s).",
                                component="hostrf.tunnel_agent",
                            )
                            while not hb_stop.is_set() and not self._stop.is_set():
                                self._enqueue(self._heartbeat_frame())
                                time.sleep(self.cfg.heartbeat_interval_sec)
                        except Exception:
                            exception("Heartbeat loop crashed.", component="hostrf.tunnel_agent")
                        finally:
                            info("Heartbeat loop exiting.", component="hostrf.tunnel_agent")

                    threading.Thread(target=hb_loop, daemon=True, name="hb_loop").start()

                    for frame in stream:
                        which = frame.WhichOneof("msg")
                        if which == "rpc_request":
                            threading.Thread(
                                target=self._handle_rpc_request,
                                args=(frame.rpc_request,),
                                daemon=True,
                                name=f"rpc_{frame.rpc_request.req_id}",
                            ).start()
                        elif which == "meta_request":
                            threading.Thread(
                                target=self._handle_meta_request,
                                args=(frame.meta_request,),
                                daemon=True,
                                name=f"meta_{frame.meta_request.req_id}",
                            ).start()
                        elif which == "control":
                            # In order: the next holder's frames queue behind it.
                            self._handle_control(frame.control)
                        elif which == "cancel":
                            rid = str(frame.cancel.req_id)
                            warn(f"Cancel req_id={rid}", component="hostrf.tunnel_agent")
                            self._set_cancel(rid)
                        elif which == "heartbeat":
                            pass
                        else:
                            warn(f"Received unknown frame type={which}", component="hostrf.tunnel_agent")

                    retry_reason = "server closed the stream"

                except grpc.RpcError as e:
                    code = None
                    details = ""
                    try:
                        code = e.code()
                    except Exception:
                        code = None
                    try:
                        details = e.details() or ""
                    except Exception:
                        details = ""

                    if code in (grpc.StatusCode.ALREADY_EXISTS, grpc.StatusCode.INVALID_ARGUMENT):
                        dlow = (details or "").lower()
                        if "device" in dlow and "conflict" in dlow:
                            _die_devices_config(
                                Path(self.cfg.devices_yaml_path),
                                f"Server rejected device inventory: {details or code}",
                            )
                        _die_host_config(Path(self.cfg.host_env_path), f"Server rejected this host: {details or code}")

                    retry_reason = _grpc_reason(code, details)
                    if code not in (
                        grpc.StatusCode.UNAVAILABLE,
                        grpc.StatusCode.CANCELLED,
                        grpc.StatusCode.DEADLINE_EXCEEDED,
                    ):
                        warn(f"gRPC error: code={code} details={details}", component="hostrf.tunnel_agent")

                except Exception:
                    exception("Unexpected error in run loop.", component="hostrf.tunnel_agent")
                    retry_reason = "unexpected local error"

                finally:
                    if hb_stop is not None:
                        hb_stop.set()
                    if stream_established:
                        try:
                            from .dynamic_v2_bridge import close_all_bridge_sessions

                            closed = close_all_bridge_sessions()
                            if closed:
                                info(
                                    f"Closed {closed} Dynamic v2 host session(s) after tunnel loss.",
                                    component="hostrf.tunnel_agent",
                                )
                            # A reservation_end may be lost with the tunnel.
                            if callable(end_reservation):
                                for gid in list(self._devices):
                                    end_reservation(gid)
                        except Exception:
                            exception(
                                "Dynamic v2 tunnel-loss cleanup failed.",
                                component="hostrf.tunnel_agent",
                            )
                    if channel is not None:
                        try:
                            channel.close()
                        except Exception:
                            warn("Channel close failed during reconnect cleanup.", component="hostrf.tunnel_agent")

                if self._stop.is_set():
                    break

                sleep_s = delay + random.uniform(0.0, min(0.5, delay * 0.2))
                if stream_established:
                    status(
                        f"Connection to {addr} lost ({retry_reason or 'disconnected'}). Retrying in {sleep_s:.1f}s.",
                        component="hostrf",
                    )
                else:
                    status(
                        f"Unable to connect to {addr} ({retry_reason or 'connection failed'}). Retrying in {sleep_s:.1f}s.",
                        component="hostrf",
                    )
                time.sleep(sleep_s)
                delay = min(delay * 1.7, self.cfg.reconnect_max_delay_sec)
        finally:
            info("HostTunnelAgent exiting.", component="hostrf.tunnel_agent")
            if status_started:
                status("Stopped.", component="hostrf")


# -------------------------
# Thread helper
# -------------------------

def start_host_tunnel_agent_thread(cfg: AgentConfig) -> Tuple[HostTunnelAgent, threading.Thread]:
    agent = HostTunnelAgent(cfg)
    th = threading.Thread(target=agent.run_forever, daemon=True, name="host_tunnel_agent")
    th.start()
    return agent, th


# -------------------------
# Config parsing
# -------------------------

def _parse_addr(addr: str) -> Tuple[str, int]:
    a = (addr or "").strip()
    if not a or ":" not in a:
        raise ValueError("REMOTERF_ADDR must be like 'host:port'")
    host, port_s = a.rsplit(":", 1)
    return host.strip(), int(port_s.strip())


# -------------------------
# Main
# -------------------------

def main() -> None:
    info("tunnel_agent main() starting.", component="hostrf.tunnel_agent")

    net_env = _net_env_path()
    host_env = _host_env_path()
    devices_yaml = _devices_yaml_path()

    net_kv = load_env_file(str(net_env))
    addr = (net_kv.get("REMOTERF_ADDR", "").strip() or os.getenv("REMOTERF_ADDR", "").strip())
    if not addr:
        _die_config(net_env, "REMOTERF_ADDR is not set.")

    try:
        server_host, server_port = _parse_addr(addr)
    except Exception as e:
        _die_config(net_env, f"Invalid REMOTERF_ADDR={addr!r} ({e}).")

    ca_path = _resolve_path(net_env, net_kv.get("REMOTERF_CA_CERT", "").strip())
    if not ca_path or not Path(ca_path).is_file():
        _die_config(net_env, "No CA cert (REMOTERF_CA_CERT): the host only connects over TLS.")
    ca_pin = normalize_sha256(net_kv.get("REMOTERF_CA_SHA256", ""))
    ca_digest = hashlib.sha256(Path(ca_path).read_bytes()).hexdigest()
    if not ca_pin:
        # Hosts set up before 1.3: pin the CA they already trust.
        warn(f"Pinning the current CA (sha256 {ca_digest}); check it against `hosts token` on the lab.",
             component="hostrf.tunnel_agent")
        pin_ca(net_env, ca_digest)
        ca_pin = ca_digest
    if ca_digest != ca_pin:
        _die_config(net_env, f"{ca_path} does not match the pinned REMOTERF_CA_SHA256.")
    client_cert = _resolve_path(net_env, net_kv.get("REMOTERF_CLIENT_CERT", "").strip())
    client_key = _resolve_path(net_env, net_kv.get("REMOTERF_CLIENT_KEY", "").strip())

    cfg = AgentConfig(
        server_host=server_host,
        server_port=server_port,
        net_env_path=str(net_env),
        host_env_path=str(host_env),
        devices_yaml_path=str(devices_yaml),
        version=os.getenv("HOST_VERSION", "host-agent/dev"),
        ca_pem_path=ca_path,
        ca_sha256=ca_pin,
        client_cert_pem_path=client_cert or None,
        client_key_pem_path=client_key or None,
    )

    info(
        f"Config loaded: addr={cfg.server_host}:{int(cfg.server_port)} tls={'yes' if cfg.ca_pem_path else 'no'}",
        component="hostrf.tunnel_agent",
    )
    info(
        f"Paths: net_env={cfg.net_env_path} host_env={cfg.host_env_path} devices_yaml={cfg.devices_yaml_path}",
        component="hostrf.tunnel_agent",
    )

    agent = HostTunnelAgent(cfg)
    try:
        agent.run_forever()
    except KeyboardInterrupt:
        status("Stopping...", component="hostrf")
        agent.stop()
    except Exception:
        exception("Fatal error in main().", component="hostrf.tunnel_agent")
        raise


if __name__ == "__main__":
    main()
