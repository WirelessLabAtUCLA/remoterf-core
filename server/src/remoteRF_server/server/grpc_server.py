
from __future__ import annotations
import threading
import socket
import os
import io
import sys
import time
from dataclasses import dataclass, field

from typing import Tuple 

# os.system('clear')

from concurrent import futures
from datetime import datetime

# Remove warnings
# import os
# os.environ.setdefault("GRPC_VERBOSITY", "ERROR")
# os.environ.setdefault("GRPC_TRACE", "")

from pathlib import Path
import os
import re
import time
from typing import Any

import grpc

import traceback
import contextlib

from ..common.grpc import *
from .reservation import reservation_handler
from .rpc_manager import rpc_manager
from .dynamic_v2 import (
    DynamicControlV2Servicer,
    SampleDataV1Servicer,
    session_manager,
)
from .host_dynamic_v2 import host_session_proxy
from .acc_perms import perms
from ..common.utils import *
from .device_manager import close_local_devices, get_all_devices, get_all_devices_str
from .user_group_cli import make_user_group_local, edit_user_group_local, list_user_groups_local, remove_user_group_local, make_enrollment_codes_local, remove_enrollment_code_local, list_enrollment_codes_local, export_user_groups_csv_local, export_enrollment_codes_csv_local
from .user_group_handler import user_group_handler, start_usergroup_cleanup_loop

from ..host import host_tunnel_server as hts
from ..host.host_tunnel_server import HostTunnelRegistry, HostTunnelServicer
from ..common.grpc import grpc_host_pb2_grpc as host_tunnel_pb2_grpc
from ..common.grpc import grpc_host_pb2 as host_tunnel_pb2

from pathlib import Path
from prompt_toolkit import PromptSession
from prompt_toolkit.output import DummyOutput

from ..tools.gist_status import start_status_publisher
from .cert_provider import start_cert_provider, stop_cert_provider

from pathlib import Path

def _xdg_config_home() -> Path:
    return Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config"))

def _cfg_dir() -> Path:
    # same convention as your serverrf CLI
    return Path(os.getenv("REMOTERF_CONFIG_DIR", _xdg_config_home() / "remoterf"))

def _server_env_path() -> Path:
    return _cfg_dir() / "server.env"

def _read_env_kv(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out

def _get_port(name: str, *, default: int | None = None) -> int:
    # precedence: real env var > server.env > default
    v = os.getenv(name)
    if v is None:
        kv = _read_env_kv(_server_env_path())
        v = kv.get(name)

    if v is None or str(v).strip() == "":
        if default is None:
            raise SystemExit(f"Missing {name}. Set it via serverrf --config or environment.")
        return int(default)

    try:
        n = int(str(v).strip())
    except Exception:
        raise SystemExit(f"Invalid {name} (expected int): {v!r}")

    if n <= 0 or n > 65535:
        raise SystemExit(f"{name} out of range (1..65535): {n}")
    return n

try:
    session = PromptSession()
except Exception as exc:
    if type(exc).__name__ != "NoConsoleScreenBufferError":
        raise
    # Importing the server in a headless process (tests, services, containers)
    # may not provide a real console screen buffer. The interactive serve path
    # still gets the normal output whenever one is available.
    session = PromptSession(output=DummyOutput())
BANNER_CREDIT = "Created at UCLA by E. Ge and I. Roberts."

from dotenv import load_dotenv, find_dotenv
dotenv_path = find_dotenv('.env.server')
load_dotenv(dotenv_path)

def _get_bind_host() -> str:
    configured = (os.getenv("REMOTERF_BIND_HOST") or "").strip()
    if configured:
        return configured

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as detector:
            detector.connect(("8.8.8.8", 80))
            return detector.getsockname()[0]
    except OSError:
        return "127.0.0.1"


local_ip = _get_bind_host()
# local_port = os.getenv('GRPC_PORT')
local_port = str(_get_port("GRPC_PORT"))    
cert_port = str(_get_port("CERT_PORT"))   

# keep dotenv for *other* settings if you want, but ports come from server.env
dotenv_path = find_dotenv('.env.server')
load_dotenv(dotenv_path)

# print(f"Local IP: {local_ip}")
# print(f"Local Port: {local_port}")

# Implement the GenericRPC service
class GenericRPCServicer(grpc_pb2_grpc.GenericRPCServicer):
    def Call(self, request, context):
        
        # Remote Admin
        # function_name_args = request.function_name.split(':')
        # if function_name_args[0] == "RemoteAdmin":
        #     ok, err, caller = verify_remote_admin(request.args)
        #     if not ok:
        #         # You can also: context.abort(grpc.StatusCode.PERMISSION_DENIED, err)
        #         return grpc_pb2.GenericRPCResponse(results={
        #             "Ok": map_arg(False),
        #             "Error": map_arg(err),
        #         })

        #     return grpc_pb2.GenericRPCResponse(
        #         results=remote_admin_call(function_name=function_name_args[1], args=request.args)
        #     )
            
        # Normal RPC
        response = rpc_manager.run_rpc(function_name=request.function_name, args=request.args)
        return grpc_pb2.GenericRPCResponse(results=response)
    

@dataclass
class ServerRuntime:
    grpc_server: Any
    cert_server: Any
    stop_event: threading.Event
    update_thread: threading.Thread | None
    bind_host: str
    grpc_port: int
    cert_port: int
    _stop_lock: threading.Lock = field(default_factory=threading.Lock)
    _stopped: bool = False

    def wait(self) -> None:
        while not self.stop_event.wait(0.5):
            pass

    def stop(self, *, grace_sec: float = 1.0) -> None:
        with self._stop_lock:
            if self._stopped:
                return
            self._stopped = True
            self.stop_event.set()

        termination = self.grpc_server.stop(max(0.0, float(grace_sec)))
        try:
            termination.wait(timeout=max(1.0, float(grace_sec) + 2.0))
        finally:
            session_manager.close_all()
            host_session_proxy.close_all()
            close_local_devices()
            if self.cert_server is not None:
                stop_cert_provider(self.cert_server)
            if (
                self.update_thread is not None
                and self.update_thread.is_alive()
                and self.update_thread is not threading.current_thread()
            ):
                self.update_thread.join(timeout=2.0)


def _load_server_credentials(cert_dir: Path):
    cert_key = cert_dir / "server.key"
    cert_crt = cert_dir / "server.crt"
    missing = [
        str(path)
        for path in (cert_key, cert_crt)
        if not path.exists()
    ]
    if missing:
        raise FileNotFoundError(
            "Missing TLS file(s):\n  " + "\n  ".join(missing)
        )
    private_key = cert_key.read_bytes()
    certificate_chain = cert_crt.read_bytes()
    return grpc.ssl_server_credentials(
        ((private_key, certificate_chain),)
    )


def _print_tls_credentials_error(cert_dir: Path, error: Exception) -> None:
    messages = (
        "TLS certs/keys not found or unreadable.",
        f"Expected in: {cert_dir}",
        f"Fix: run serverrf --gen-certs {local_ip} --force",
        "Or set REMOTERF_CERT_DIR to your cert folder.",
        f"Details: {error}",
    )
    for message in messages:
        printf(message, Sty.MAGENTA)


def start_server_runtime(
    *,
    bind_host: str | None = None,
    grpc_port: int | None = None,
    certificate_port: int | None = None,
    cert_dir: Path | None = None,
    include_host_tunnel: bool = True,
    run_reservation_updates: bool = True,
    publish_status: bool = True,
) -> ServerRuntime:
    bind_host = str(bind_host or local_ip)
    grpc_port = int(local_port if grpc_port is None else grpc_port)
    certificate_port = int(
        cert_port if certificate_port is None else certificate_port
    )
    if cert_dir is None:
        xdg_config = Path(
            os.getenv("XDG_CONFIG_HOME", Path.home() / ".config")
        )
        cert_dir = Path(
            os.getenv(
                "REMOTERF_CERT_DIR",
                xdg_config / "remoterf" / "certs",
            )
        )
    cert_dir = Path(cert_dir)

    options = [
        ('grpc.max_send_message_length', 100 * 1024 * 1024),
        ('grpc.max_receive_message_length', 100 * 1024 * 1024)
    ]

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=100), options=options)
    grpc_pb2_grpc.add_GenericRPCServicer_to_server(GenericRPCServicer(), server)
    grpc_pb2_grpc.add_DynamicControlV2Servicer_to_server(
        DynamicControlV2Servicer(), server
    )
    grpc_pb2_grpc.add_SampleDataV1Servicer_to_server(
        SampleDataV1Servicer(), server
    )

    try:
        server_credentials = _load_server_credentials(cert_dir)
    except Exception as e:
        _print_tls_credentials_error(cert_dir, e)
        raise SystemExit(2)

    if include_host_tunnel:
        reg = hts.get_tunnel_registry()
        if reg is None:
            raise RuntimeError("host tunnel registry is unavailable")
        hts.TUNNEL_REGISTRY = reg
        host_tunnel_pb2_grpc.add_HostTunnelServicer_to_server(
            HostTunnelServicer(reg),
            server,
        )

    bound_grpc_port = server.add_secure_port(
        f"{bind_host}:{grpc_port}",
        server_credentials,
    )
    if bound_grpc_port == 0:
        raise RuntimeError(
            f"could not bind secure gRPC server to {bind_host}:{grpc_port}"
        )

    cert_server = None
    stop_event = threading.Event()
    update_thread = None
    try:
        cert_server, _cert_thread = start_cert_provider(
            host=bind_host,
            port=certificate_port,
            ca_path=cert_dir / "ca.crt",
        )
        reservation_handler.update_devices()
        server.start()
        if run_reservation_updates:
            update_thread = threading.Thread(
                target=update_devices,
                args=(stop_event,),
                name="remoterf-reservation-updates",
                daemon=True,
            )
            update_thread.start()
            start_usergroup_cleanup_loop(interval_sec=60)
        if publish_status:
            start_status_publisher()
    except Exception:
        stop_event.set()
        server.stop(0)
        session_manager.close_all()
        host_session_proxy.close_all()
        if cert_server is not None:
            stop_cert_provider(cert_server)
        raise

    return ServerRuntime(
        grpc_server=server,
        cert_server=cert_server,
        stop_event=stop_event,
        update_thread=update_thread,
        bind_host=bind_host,
        grpc_port=int(bound_grpc_port),
        cert_port=int(cert_server.server_address[1]),
    )


def update_devices(stop_event: threading.Event) -> None:
    while not stop_event.wait(1.0):
        try:
            reservation_handler.update_devices()
        except Exception as exc:
            print(
                f"Warning: reservation update failed: {exc}",
                file=sys.stderr,
            )


def serve() -> None:
    runtime = start_server_runtime()
    try:
        runtime.wait()
    except KeyboardInterrupt:
        pass
    finally:
        runtime.stop()

start_time = datetime.now()

def welcome():
    printf(f"Server running nominally.", Sty.BOLD)
    printf(BANNER_CREDIT, Sty.GRAY)
    printf(f"Local IP: ", Sty.DEFAULT, f"{local_ip}", Sty.ITALIC, f" | Port: ", Sty.DEFAULT, f"{local_port}", Sty.ITALIC)
    # printf(f"   -> Started at ", Sty.DEFAULT, f"{start_time}", Sty.DEFAULT)
    printf("Input ", Sty.DEFAULT, "'help'", Sty.BOLD," for help menu.", Sty.DEFAULT)

def clear():
    os.system('clear')
    welcome()
    
def set_acc():
    while True:
        username = session.prompt("Enter username to manage (c to cancel): ")
        if username == 'exit' or username == 'c' or username == 'e':
            return
        perm = perms.get_perms(username)
        if perm == []:
            printf(f"User: {username} does not exist.", Sty.RED)
        else:
            break
    
    print(f"User: {username} : <{perm[0][0]}>")
    printf(f"'s'", Sty.MAGENTA, " - Set perm details", Sty.DEFAULT)
    printf(f"'D'", Sty.MAGENTA, " - Delete user", Sty.DEFAULT)
    printf(f"'r'", Sty.MAGENTA, " - Manage reservations", Sty.DEFAULT)
    printf(f"'c'", Sty.MAGENTA, " - Cancel", Sty.DEFAULT)
    
    inpu = session.prompt(stylize("Enter command: ", Sty.DEFAULT))
    if inpu == 's':
        inpu2 = session.prompt(stylize("Setting perms: ", Sty.DEFAULT, " (U{User}/P{PowerUser}/A{Admin}) ", Sty.GRAY, ": ", Sty.DEFAULT))
        if inpu2 == 'U':
            perms.set_user(username)
            printf("Set to User. ", Sty.GREEN)
            
        elif inpu2 == 'P':
            printf("Setting PowerUser perms. ", Sty.BOLD, "Input 'c' to cancel anytime.", Sty.DEFAULT)
            
            while True: # Allowed Devices
                device_ids = session.prompt(stylize("Enter device ids allowed ", Sty.DEFAULT, 'int,int,int,...', Sty.GRAY, ": ", Sty.DEFAULT))
                if device_ids == 'c':
                    return
                try:
                    device_list = [int(x) for x in device_ids.split(',')]
                    if session.prompt(stylize(f"Confirm that this is the correct list of devices: {device_list} ", Sty.DEFAULT, "(y/n)", Sty.GRAY, ": ", Sty.DEFAULT)) == 'y':   
                        break
                except ValueError:
                    printf("Invalid input. Try Again.", Sty.RED)
                    
            while True: # Max Reservations
                max_res = session.prompt(stylize("Enter max reservations allowed ", Sty.DEFAULT, 'int', Sty.GRAY, ": ", Sty.DEFAULT))
                if max_res == 'c':
                    return
                try:
                    max_res = int(max_res)
                    if session.prompt(stylize(f"Confirm that this is the correct number of max reservations: {max_res} ", Sty.DEFAULT, "(y/n)", Sty.GRAY, ": ", Sty.DEFAULT)) == 'y':
                        break
                except ValueError:
                    printf("Invalid input. Try Again.", Sty.RED)
                    
            while True: # Max Reservation Time
                max_res_time = session.prompt(stylize("Enter max length of a single reservation ", Sty.DEFAULT, 'int [seconds]', Sty.GRAY, ": ", Sty.DEFAULT))
                if max_res_time == 'c':
                    return
                try:
                    max_res_time = int(max_res_time)
                    if session.prompt(stylize(f"Confirm that this is the correct max reservation time in SECONDS: {max_res_time} ", Sty.DEFAULT, "(y/n)", Sty.GRAY, ": ", Sty.DEFAULT)) == 'y':
                        break
                except ValueError:
                    printf("Invalid input. Try Again.", Sty.RED)
            
            perms.set_poweruser(username, devices_allowed=device_list, max_reservations=max_res, max_reservation_time_sec=max_res_time)
        elif inpu2 == 'A':
            perms.set_admin(username)
        else:
            printf("Invalid input. Skipping.", Sty.RED)
        
    elif inpu == 'D':
        if input(f"Are you sure you want to delete user: {username}? (Y/N): ") == 'Y':
            printf(f"Deleting user: {username}", Sty.MAGENTA)
            reservation_handler.remove_user(username=username)
        else:
            printf("Delete canceled", Sty.GRAY)
    elif inpu == 'r':
        print("Managing reservations:")
        while True:
            inpu = session.prompt(stylize("Enter command: ", Sty.DEFAULT, "'a' to add, 'c' to cancel, 'e' to exit (anytime), 'v' to view. : ", Sty.GRAY))
            if inpu == 'e':
                break
            elif inpu == 'a':
                while True:
                    device_id = session.prompt(stylize("Enter device id: ", Sty.DEFAULT))
                    if device_id == 'c' or device_id == 'e':
                        break
                    try:
                        device_id = int(device_id)
                        if device_id not in get_all_devices():
                            printf("Invalid device id.", Sty.GRAY)
                            continue
                        start_time = session.prompt(stylize("Enter start time: ", Sty.DEFAULT, "YYYY-MM-DD HH:MM:SS -> ", Sty.GRAY))
                        end_time = session.prompt(stylize("Enter end time: ", Sty.DEFAULT, "YYYY-MM-DD HH:MM:SS -> ", Sty.GRAY))
                        token = reservation_handler.reserve_device(username=username, device_id=device_id, start_time=datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S'), end_time=datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S'), is_server=True)
                        api = unmap_arg(token['Token'])
                        printf("Reservation added. TOKEN -> ", Sty.GREEN, f"{api}", Sty.MAGENTA)
                        break
                    except ValueError:
                        printf("Invalid input. Try Again.", Sty.GRAY)
            elif inpu == 'v':
                reservations = reservation_handler.grab_all_reservations_server()
                for key, reservation in reservations.items():
                    if reservation[0] == username:
                        print(f"ID: {key}, User: {reservation[0]}, Device: {reservation[1]}, Start: {reservation[2]}, End: {reservation[3]}")
                if reservations == {}:
                    printf("No reservations found.", Sty.GRAY)
            elif inpu == 'c':
                while True:
                    try:
                        inpu2 = session.prompt(stylize("Enter reservation id to cancel: ", Sty.DEFAULT))
                        if inpu2 == 'c' or inpu2 == 'e':
                            break
                        reservation_handler.remove_reservation(res_id=int(inpu2))
                        reservation_handler.update_devices()
                        printf(f"Reservation {inpu2} removed.", Sty.GREEN)
                        break
                    except Exception as e:
                        printf(f"Error: {e}", Sty.GRAY)
        
    elif inpu == 'c':
        print("Canceled. Exiting ...")

def get_devices():
    data = get_all_devices_str()
    
    printf("Devices:", Sty.BOLD)
    for key, value in data.items():
        printf(f"Device ID:", Sty.DEFAULT, f' {key}', Sty.MAGENTA, f" Device Name: ", Sty.DEFAULT, f"{(value)}", Sty.GRAY)

def _fmt_ms_ago(ms: int) -> str:
    if not ms:
        return "-"
    now = int(time.time() * 1000)
    dt = max(0, now - int(ms))
    if dt < 1000:
        return f"{dt}ms"
    if dt < 60_000:
        return f"{dt/1000:.1f}s"
    return f"{dt/60_000:.1f}m"

def _cmd_hosts_status() -> None:
    reg = hts.get_tunnel_registry()
    assert reg is not None
    
    # print("\n[hosts status] registry debug")
    # print(f"  hts module: {hts.__name__}")
    # reg = hts.get_tunnel_registry(create=False)
    # print(f"  registry id: {id(reg) if reg else None}\n")

    hosts = reg.list_hosts()     # host_id -> HostStatus
    devices = reg.list_devices() # device_id -> DeviceStatus

    # Build host -> device list
    by_host: dict[str, list[str]] = {}
    for did, ds in devices.items():
        by_host.setdefault(ds.host_id or "-", []).append(did)

    printf("Hosts:", Sty.BOLD)
    if not hosts:
        printf("  (none)", Sty.GRAY)
        return

    for hid, hs in sorted(hosts.items(), key=lambda kv: kv[0]):
        dlist = sorted(by_host.get(hid, []))
        printf(
            "  ", Sty.DEFAULT,
            f"{hid}", Sty.MAGENTA,
            "  online=", Sty.DEFAULT, f"{hs.online}", Sty.GRAY if hs.online else Sty.GRAY,
            "  last_seen=", Sty.DEFAULT, f"{_fmt_ms_ago(hs.last_seen_ms)} ago", Sty.GRAY,
            "  devices=", Sty.DEFAULT, f"{len(dlist)}", Sty.GRAY
        )
        for did in dlist:
            ds = devices.get(did)
            if ds is None:
                continue
            printf(
                "     - ", Sty.DEFAULT,
                f"{did}", Sty.MAGENTA,
                "  local_id=", Sty.DEFAULT, f"{ds.host_local_id}", Sty.GRAY,
                "  online=", Sty.DEFAULT, f"{ds.online}", Sty.GRAY if ds.online else Sty.GRAY,
                "  last_seen=", Sty.DEFAULT, f"{_fmt_ms_ago(ds.last_seen_ms)} ago", Sty.GRAY
            )

def _cmd_devices_status() -> None:
    reg = hts.get_tunnel_registry()
    assert reg is not None

    devices = reg.list_devices()
    printf("Devices (live):", Sty.BOLD)
    if not devices:
        printf("  (none)", Sty.GRAY)
        return

    for did, ds in sorted(devices.items(), key=lambda kv: kv[0]):
        printf(
            "  ", Sty.DEFAULT,
            f"{did}", Sty.MAGENTA,
            "  host=", Sty.DEFAULT, f"{ds.host_id or '-'}", Sty.GRAY,
            "  local_id=", Sty.DEFAULT, f"{ds.host_local_id}", Sty.GRAY,
            "  online=", Sty.DEFAULT, f"{ds.online}", Sty.GREEN if ds.online else Sty.RED,
            "  last_seen=", Sty.DEFAULT, f"{_fmt_ms_ago(ds.last_seen_ms)} ago", Sty.BLUE
        )
        
from typing import Iterable
import contextlib

def _repo_root_guess() -> Path:
    """
    Best-effort: find <repo>/src/... and return <repo>.
    Fallback: walk up a few levels from this file.
    """
    p = Path(__file__).resolve()
    for parent in p.parents:
        if parent.name == "src":
            return parent.parent
    # fallback
    return p.parents[3] if len(p.parents) >= 4 else p.parent

# Optional: if you later add "kick" support (see section 2)
HOST_TUNNEL_EPOCH = 0

def _read_env_kv_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out

def _env_values_as_paths(env_path: Path) -> list[Path]:
    """
    Parse an env file and treat values that look like filesystem paths as candidate dirs.
    Relative paths are resolved relative to the env file's directory.
    """
    kv = _read_env_kv_file(env_path)
    base = env_path.parent
    out: list[Path] = []

    for _, v in kv.items():
        if not v:
            continue
        # heuristics: looks like a path
        if ("/" not in v) and ("\\" not in v) and (not v.startswith(".")) and (not v.startswith("~")):
            continue

        p = Path(v).expanduser()
        if not p.is_absolute():
            p = (base / p).resolve()
        out.append(p)

    return out

def _host_state_dirs() -> list[Path]:
    """
    Aggressive candidate list:
      - user config (~/.config/remoterf or REMOTERF_CONFIG_DIR)
      - repo/.config
      - repo/config  (+ common subdirs)
      - src/remoteRF_server/config
      - plus env overrides + paths referenced by .env.host_directory (if present)
    """
    repo = _repo_root_guess()

    cands: list[Path] = [
        _cfg_dir(),
        repo / ".config",
        repo / "config",
        repo / "config" / "remoteRF_server",
        repo / "config" / "remoteRF_host",
        repo / "src" / "remoteRF_server" / "config",
        (Path(__file__).resolve().parent.parent / "config"),
    ]

    # Environment overrides (add any you might plausibly use)
    for k in (
        "REMOTERF_HOSTDIR_DIR",
        "REMOTERF_HOST_DIRECTORY_DIR",
        "REMOTERF_HOST_DIR",
        "HOST_DIRECTORY_DIR",
        "HOST_DIRECTORY_PATH",
        "REMOTERF_STATE_DIR",
    ):
        v = os.getenv(k)
        if v:
            cands.append(Path(v).expanduser())

    # If you have a .env.host_directory file, harvest any path-like values from it
    env_host_dir = repo / "src" / "remoteRF_server" / "config" / ".env.host_directory"
    if env_host_dir.exists():
        cands.extend(_env_values_as_paths(env_host_dir))

    # de-dupe + keep only dirs (or dirs that could exist)
    out: list[Path] = []
    seen: set[str] = set()
    for d in cands:
        try:
            rp = str(d.expanduser().resolve())
        except Exception:
            rp = str(d)
        if rp not in seen:
            seen.add(rp)
            out.append(d)
    return out

def _host_state_files() -> list[Path]:
    """
    Broader scan than just host_directory.env:
    We only match filenames that clearly look like host/tunnel/registry state.
    """
    patterns = [
        "host_directory*.env",
        "host_directory*.json",
        "host_directory*.db",
        "host_directory*.sqlite*",
        "host_directory*.pkl",
        "host_tunnel*.env",
        "host_tunnel*.json",
        "tunnel_registry*.env",
        "tunnel_registry*.json",
        "*host*registry*.json",
        "*host*registry*.db",
        "*host*registry*.sqlite*",
        "*host*state*.json",
        "*host*state*.db",
        "*host*state*.sqlite*",
    ]

    files: list[Path] = []
    for d in _host_state_dirs():
        try:
            if not d.exists() or not d.is_dir():
                continue
        except Exception:
            continue

        for pat in patterns:
            try:
                files.extend(sorted(d.glob(pat)))
            except Exception:
                pass

    # de-dupe
    out: list[Path] = []
    seen: set[str] = set()
    for p in files:
        try:
            rp = str(p.resolve())
        except Exception:
            rp = str(p)
        if rp not in seen:
            seen.add(rp)
            out.append(p)
    return out

def _deep_clear_state(obj: Any) -> list[str]:
    """
    Best-effort: clear dict/list/set fields on an object, recursively,
    but only for fields that look like state (host/device/route/session/cache/store/etc).
    """
    cleared: list[str] = []
    seen: set[int] = set()

    state_name = re.compile(r"(host|device|route|session|dir|store|cache|meta|seen|status)", re.I)

    def walk(x: Any, prefix: str) -> None:
        oid = id(x)
        if oid in seen:
            return
        seen.add(oid)

        # containers
        if isinstance(x, dict):
            x.clear()
            cleared.append(prefix)
            return
        if isinstance(x, list):
            x.clear()
            cleared.append(prefix)
            return
        if isinstance(x, set):
            x.clear()
            cleared.append(prefix)
            return

        # objects with __dict__
        d = getattr(x, "__dict__", None)
        if not isinstance(d, dict):
            return

        for k, v in list(d.items()):
            # never touch locks/threads/etc
            if k in ("_lock", "lock", "_thread", "thread", "_executor", "executor"):
                continue
            if not state_name.search(k):
                continue

            if isinstance(v, (dict, list, set)):
                try:
                    v.clear()
                    cleared.append(f"{prefix}.{k}")
                except Exception:
                    pass
            else:
                # recurse into nested state objects (EnvStore, etc.)
                walk(v, f"{prefix}.{k}")

    walk(obj, obj.__class__.__name__)
    return cleared

def _try_clear_registry_in_memory(reg: object) -> list[str]:
    """
    Stronger in-memory clear:
      - calls obvious reset/clear methods if present
      - clears common containers
      - recursively clears state-like fields (even if names differ)
    """
    cleared: list[str] = []

    lock = getattr(reg, "_lock", None)
    acquired = False
    try:
        if lock is not None and hasattr(lock, "acquire") and hasattr(lock, "release"):
            lock.acquire()
            acquired = True

        # Prefer explicit APIs if you have them
        for meth in (
            "clear",
            "reset",
            "wipe",
            "wipe_all",
            "wipe_state",
            "clear_state",
            "reset_state",
            "prune",
            "gc",
        ):
            fn = getattr(reg, meth, None)
            if callable(fn):
                try:
                    fn()
                    cleared.append(f"{meth}()")
                except Exception:
                    pass

        # Clear obvious containers by direct attribute scan
        for attr, v in list(getattr(reg, "__dict__", {}).items()):
            if isinstance(v, (dict, list, set)):
                try:
                    v.clear()
                    cleared.append(attr)
                except Exception:
                    pass

        # Recursive targeted clear (for EnvStore etc.)
        cleared.extend(_deep_clear_state(reg))

    finally:
        if acquired:
            try:
                lock.release()
            except Exception:
                pass

    # de-dupe
    out: list[str] = []
    seen: set[str] = set()
    for x in cleared:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def _cmd_hosts_wipe(*, yes: bool = False) -> None:
    if not yes:
        try:
            resp = session.prompt(stylize("Type 'wipe-hosts' to confirm wiping host state: ", Sty.RED))
        except KeyboardInterrupt:
            printf("Cancelled.", Sty.GRAY)
            return
        if (resp or "").strip().lower() != "wipe-hosts":
            printf("Wipe aborted.", Sty.GRAY)
            return

    # 1) delete persisted files (if any)
    files = [p for p in _host_state_files() if p.exists()]
    if not files:
        printf("No persisted host directory files found (searched common dirs/patterns).", Sty.YELLOW)
    else:
        for p in files:
            try:
                p.unlink()
                printf("Deleted: ", Sty.DEFAULT, f"{p}", Sty.MAGENTA)
            except Exception as e:
                printf("ERROR deleting: ", Sty.RED, f"{p} -> {e}", Sty.DEFAULT)
                return

    # 2) clear in-memory registry (THIS is what drives `hosts status`)
    reg = hts.get_tunnel_registry()
    if reg is None:
        printf("Host tunnel registry not initialized; only persisted wipe attempted.", Sty.GRAY)
    else:
        cleared = _try_clear_registry_in_memory(reg)
        if cleared:
            printf("Cleared in-memory registry state:", Sty.GREEN)
            # keep output short-ish
            for item in cleared[:20]:
                printf("  - ", Sty.DEFAULT, item, Sty.GRAY)
            if len(cleared) > 20:
                printf("  ...", Sty.GRAY)
        else:
            printf("WARNING: in-memory wipe could not confirm any cleared fields.", Sty.YELLOW)
            printf("If `hosts status` still shows data, it is almost certainly being repopulated by live connections.", Sty.YELLOW)

    printf("Host wipe complete.", Sty.GREEN)

# def help():
#     printf("/------- HELP -------/", Sty.BOLD)
#     printf("'exit'          ", Sty.MAGENTA, " - Stop server.", Sty.DEFAULT)
#     printf("'help'          ", Sty.MAGENTA, " - Help.", Sty.DEFAULT)
#     printf("'clear'         ", Sty.MAGENTA, " - Clear terminal screen.", Sty.DEFAULT)
#     printf("'show a'         ", Sty.MAGENTA, " - Print all accounts", Sty.DEFAULT)
#     printf("'show d'         ", Sty.MAGENTA, " - Print all devices", Sty.DEFAULT)
#     # printf("'view p'        ", Sty.MAGENTA, " - Print all perms", Sty.DEFAULT) # Deprecated
#     printf("'show r'         ", Sty.MAGENTA, " - Print all reservations", Sty.DEFAULT)
#     printf("'rm aa'         ", Sty.MAGENTA, " - Remove all accounts", Sty.DEFAULT)
#     # printf("'rm a'          ", Sty.MAGENTA, " - Remove one account", Sty.DEFAULT)
#     printf("'rm ar'         ", Sty.MAGENTA, " - Remove all reservations", Sty.DEFAULT)
#     printf("'rm db'         ", Sty.MAGENTA, " - Remove all database entries", Sty.DEFAULT)
#     printf("'setacc'        ", Sty.MAGENTA, " - Set account details (and deletion)", Sty.DEFAULT)
    
#     printf("'mk group'      ", Sty.MAGENTA, " - Make a user group", Sty.DEFAULT)
#     printf("'rm group'      ", Sty.MAGENTA, " - Remove a user group", Sty.DEFAULT)
#     printf("'edit group'    ", Sty.MAGENTA, " - Edit a user group", Sty.DEFAULT)
#     printf("'show g'        ", Sty.MAGENTA, " - View all user groups", Sty.DEFAULT)
    
#     printf("'mk codes'      ", Sty.MAGENTA, " - Make enrollment codes", Sty.DEFAULT)
#     printf("'show c'        ", Sty.MAGENTA, " - View all enrollment codes", Sty.DEFAULT)
#     printf("'rm codes'      ", Sty.MAGENTA, " - Remove enrollment code", Sty.DEFAULT)
    
# def server_input(inpu:str) -> bool:
#     if inpu == "h" or inpu == "help":
#         help()
#     elif inpu == 'show r':
#         reservation_handler.print_all_reservations()
#     elif inpu == 'show a':
#         reservation_handler.print_all_accounts()
#     elif inpu == 'show p':
#         perms.print_perms()
#     elif inpu == 'show d':
#         get_devices()
#     elif inpu == 'clear':
#         clear()
#     elif inpu == 'rm aa':
#         reservation_handler.remove_all_users()
#     elif inpu == 'rm ar':
#         reservation_handler.remove_all_reservations()
#     elif inpu == 'rm db':
#         reservation_handler.rm_db()
#     elif inpu == 'setacc':
#         set_acc()
#     elif inpu in ('mk group', 'mk g'):
#         make_user_group_local(session)
#     elif inpu in ('rm group', 'rm g'):
#         remove_user_group_local(session)
#     elif inpu in ('edit group', 'edit g'):
#         edit_user_group_local(session)
#     elif inpu in ('show g', 'show groups'):
#         list_user_groups_local(session)
#     elif inpu in ('mk codes', 'mk code', 'mk c'):
#         make_enrollment_codes_local(session)
#     elif inpu == 'show c':
#         list_enrollment_codes_local(session)
#     elif inpu in ('rm code', 'rm c', 'rm codes'):
#         remove_enrollment_code_local(session)
#     elif inpu in ('exit', 'quit'):
#         return False
#     else:
#         print(f"Invalid command: {inpu}")
#     return True

from typing import Callable

def _norm_cmd(s: str) -> str:
    return " ".join((s or "").strip().split()).lower()

def _cmd_status() -> None:
    try:
        uptime = datetime.now() - start_time
        printf("Status:", Sty.BOLD)
        printf("  Started: ", Sty.DEFAULT, f"{start_time}", Sty.BLUE)
        printf("  Uptime : ", Sty.DEFAULT, f"{str(uptime).split('.')[0]}", Sty.BLUE)
        printf("  Bind   : ", Sty.DEFAULT, f"{local_ip}:{local_port}", Sty.MAGENTA)
        printf("  Cert   : ", Sty.DEFAULT, f"{local_ip}:{cert_port}", Sty.MAGENTA)
    except Exception:
        printf("Status unavailable.", Sty.RED)

def help() -> None:
    printf("RemoteRF Server Shell", Sty.BOLD)
    printf("Type ", Sty.DEFAULT, "help", Sty.MAGENTA, " to see commands. Type ", Sty.DEFAULT, "quit", Sty.MAGENTA, " to exit.", Sty.DEFAULT)
    print()

    printf("Server:", Sty.BOLD)
    printf("  help, h                  ", Sty.MAGENTA, "- Show this help", Sty.DEFAULT)
    printf("  clear                    ", Sty.MAGENTA, "- Clear the screen", Sty.DEFAULT)
    printf("  status                   ", Sty.MAGENTA, "- Show server status (uptime/bind)", Sty.DEFAULT)
    printf("  quit / exit              ", Sty.MAGENTA, "- Exit the shell", Sty.DEFAULT)
    print()

    printf("Users:", Sty.BOLD)
    printf("  users list               ", Sty.MAGENTA, "- List accounts", Sty.DEFAULT)
    printf("  users manage             ", Sty.MAGENTA, "- Manage a user (perms / delete / reservations)", Sty.DEFAULT)
    printf("  users purge              ", Sty.MAGENTA, "- Remove ALL users", Sty.DEFAULT)
    print()

    printf("Devices:", Sty.BOLD)
    printf("  devices list             ", Sty.MAGENTA, "- List devices", Sty.DEFAULT)
    printf("  devices status          ", Sty.MAGENTA, "- Live device online/last_seen/route", Sty.DEFAULT)
    print()

    printf("Reservations:", Sty.BOLD)
    printf("  reservations list        ", Sty.MAGENTA, "- List reservations", Sty.DEFAULT)
    printf("  reservations purge       ", Sty.MAGENTA, "- Remove ALL reservations", Sty.DEFAULT)
    print()

    printf("Groups:", Sty.BOLD)
    printf("  groups list              ", Sty.MAGENTA, "- List user groups", Sty.DEFAULT)
    printf("  groups create            ", Sty.MAGENTA, "- Create a user group (interactive)", Sty.DEFAULT)
    printf("  groups edit              ", Sty.MAGENTA, "- Edit a user group (interactive)", Sty.DEFAULT)
    printf("  groups delete            ", Sty.MAGENTA, "- Delete a user group (interactive)", Sty.DEFAULT)
    printf("  groups csv               ", Sty.MAGENTA, "- Export ALL user groups as CSV to Downloads", Sty.DEFAULT)
    print()

    printf("Enrollment Codes:", Sty.BOLD)
    printf("  codes list               ", Sty.MAGENTA, "- List enrollment codes", Sty.DEFAULT)
    printf("  codes create             ", Sty.MAGENTA, "- Create enrollment codes (interactive)", Sty.DEFAULT)
    printf("  codes delete             ", Sty.MAGENTA, "- Delete an enrollment code (interactive)", Sty.DEFAULT)
    printf("  codes csv                ", Sty.MAGENTA, "- Export ALL enrollment codes as CSV to Downloads", Sty.DEFAULT)
    print()
    
    printf("Host Tunnel (live):", Sty.BOLD)
    printf("  hosts status            ", Sty.MAGENTA, "- Live host online/last_seen/devices", Sty.DEFAULT)
    printf("  hosts wipe              ", Sty.MAGENTA, "- Wipe persisted host directory state (and clear in-memory)", Sty.DEFAULT)

    printf("Database:", Sty.BOLD)
    printf("  db purge                 ", Sty.MAGENTA, "- Remove all database entries", Sty.DEFAULT)
    print()

def server_input(inpu: str) -> bool:
    cmd = _norm_cmd(inpu)
    if not cmd:
        return True

    def _stay(fn: Callable[[], None]) -> bool:
        fn()
        return True

    DISPATCH: dict[str, Callable[[], bool]] = {
        # ---- server ----
        "help": lambda: _stay(help),
        "h": lambda: _stay(help),
        "?": lambda: _stay(help),

        "clear": lambda: _stay(clear),
        "cls": lambda: _stay(clear),

        "status": lambda: _stay(_cmd_status),
        "server status": lambda: _stay(_cmd_status),

        "quit": lambda: False,
        "exit": lambda: False,
        "q": lambda: False,

        # ---- users ----
        "users list": lambda: _stay(reservation_handler.print_all_accounts),
        "u list": lambda: _stay(reservation_handler.print_all_accounts),
        "accounts list": lambda: _stay(reservation_handler.print_all_accounts),

        "users manage": lambda: _stay(set_acc),
        "users manage": lambda: _stay(set_acc),
        "setacc": lambda: _stay(set_acc),  # old

        "users purge": lambda: _stay(reservation_handler.remove_all_users),
        "rm aa": lambda: _stay(reservation_handler.remove_all_users),  # old

        # perms (kept; optional to advertise)
        "users perms": lambda: _stay(perms.print_perms),
        "show p": lambda: _stay(perms.print_perms),  # old

        # ---- devices ----
        "devices list": lambda: _stay(get_devices),
        "show d": lambda: _stay(get_devices),  # old

        # ---- reservations ----
        "reservations list": lambda: _stay(reservation_handler.print_all_reservations),
        "show r": lambda: _stay(reservation_handler.print_all_reservations),  # old

        "reservations purge": lambda: _stay(reservation_handler.remove_all_reservations),
        "rm ar": lambda: _stay(reservation_handler.remove_all_reservations),  # old

        # ---- db ----
        "db purge": lambda: _stay(reservation_handler.rm_db),
        "rm db": lambda: _stay(reservation_handler.rm_db),  # old

        # ---- groups ----
        "groups create": lambda: _stay(lambda: make_user_group_local(session)),
        "mk group": lambda: _stay(lambda: make_user_group_local(session)),  # old
        "mk g": lambda: _stay(lambda: make_user_group_local(session)),      # old

        "groups delete": lambda: _stay(lambda: remove_user_group_local(session)),
        "rm group": lambda: _stay(lambda: remove_user_group_local(session)),  # old
        "rm g": lambda: _stay(lambda: remove_user_group_local(session)),      # old

        "groups edit": lambda: _stay(lambda: edit_user_group_local(session)),
        "edit group": lambda: _stay(lambda: edit_user_group_local(session)),  # old
        "edit g": lambda: _stay(lambda: edit_user_group_local(session)),      # old

        "groups list": lambda: _stay(lambda: list_user_groups_local(session)),
        "show g": lambda: _stay(lambda: list_user_groups_local(session)),      # old
        "show groups": lambda: _stay(lambda: list_user_groups_local(session)), # old
        "groups csv": lambda: _stay(export_user_groups_csv_local),

        # ---- enrollment codes ----
        "codes create": lambda: _stay(lambda: make_enrollment_codes_local(session)),
        "mk codes": lambda: _stay(lambda: make_enrollment_codes_local(session)),  # old
        "mk code": lambda: _stay(lambda: make_enrollment_codes_local(session)),   # old
        "mk c": lambda: _stay(lambda: make_enrollment_codes_local(session)),      # old

        "codes list": lambda: _stay(lambda: list_enrollment_codes_local(session)),
        "show c": lambda: _stay(lambda: list_enrollment_codes_local(session)),    # old

        "codes delete": lambda: _stay(lambda: remove_enrollment_code_local(session)),
        "rm codes": lambda: _stay(lambda: remove_enrollment_code_local(session)), # old
        "rm code": lambda: _stay(lambda: remove_enrollment_code_local(session)),  # old
        "rm c": lambda: _stay(lambda: remove_enrollment_code_local(session)),     # old
        
        # ---- host tunnel ----
        "hosts status": lambda: _stay(_cmd_hosts_status),
        "host status": lambda: _stay(_cmd_hosts_status),

        "devices status": lambda: _stay(_cmd_devices_status),
        "tunnel devices": lambda: _stay(_cmd_devices_status),
        
        "codes csv": lambda: _stay(export_enrollment_codes_csv_local),
    }

    fn = DISPATCH.get(cmd)
    if fn is None:
        # allow: "hosts wipe" and "hosts wipe -y"
        if cmd.startswith("hosts wipe"):
            yes = ("-y" in cmd.split()) or ("--yes" in cmd.split())
            _cmd_hosts_wipe(yes=yes)
            return True

        printf("Unknown command: ", Sty.RED, f"{inpu}", Sty.DEFAULT)
        printf("Type ", Sty.DEFAULT, "help", Sty.MAGENTA, " to see commands.", Sty.DEFAULT)
        return True

    return fn()

def main() -> int:
    runtime = start_server_runtime()
    welcome()
    try:
        while server_input(
            session.prompt(stylize("server@remoterf: ", Sty.BOLD))
        ):
            pass
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        runtime.stop()
    return 0


def headless_main() -> int:
    runtime = start_server_runtime()
    welcome()
    try:
        runtime.wait()
    except KeyboardInterrupt:
        pass
    finally:
        runtime.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(headless_main())
