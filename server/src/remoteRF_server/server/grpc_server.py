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


from __future__ import annotations
import threading
import logging
import socket
import os
import sys
import time
from dataclasses import dataclass, field

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

logger = logging.getLogger("remoteRF_server.grpc")

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
from .device_manager import close_local_devices, reload_devices, get_registered_devices, get_all_devices_str, handle_report
from .user_group_cli import make_user_group_local, edit_user_group_local, list_user_groups_local, remove_user_group_local, make_enrollment_codes_local, remove_enrollment_code_local, list_enrollment_codes_local, export_user_groups_csv_local, export_enrollment_codes_csv_local
from .user_group_handler import start_usergroup_cleanup_loop
from .global_onboarding import start_agent

from ..host import host_tunnel_server as hts
from ..host.host_tunnel_server import HostTunnelServicer
from ..common.grpc import grpc_host_pb2_grpc as host_tunnel_pb2_grpc

from pathlib import Path
from prompt_toolkit import PromptSession
from prompt_toolkit.output import DummyOutput

from ..tools.gist_status import start_status_publisher
from .cert_provider import start_cert_provider, stop_cert_provider
try:
    from . import direct_path
except Exception as _exc:  # noqa: BLE001 - an optimization: without it every call still goes over the relay
    direct_path = None
    _DIRECT_PATH_ERROR = f"{type(_exc).__name__}: {_exc}"

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
BANNER_CREDIT = "Created by the Wireless Lab at UCLA"

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

        # Normal RPC. Everything below reads RELAYED instead of the peer:
        # LAN-only groups do not exist to a call that came through the relay.
        from .global_onboarding import RELAYED, is_relayed

        token = RELAYED.set(is_relayed(context.peer()))
        try:
            response = rpc_manager.run_rpc(function_name=request.function_name, args=request.args)
        finally:
            RELAYED.reset(token)
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
    writer_lock: Any = None
    federation_permissions: Any = None
    federation_devices: Any = None
    control_server: Any = None
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
            if direct_path is not None:
                direct_path.shutdown()
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
            if self.control_server is not None:
                self.control_server.stop()
                self.control_server = None
            if self.writer_lock is not None:
                self.writer_lock.close()
                self.writer_lock = None
            close_permissions = getattr(self.federation_permissions, "close", None)
            if close_permissions is not None:
                close_permissions()
            if self.federation_devices is not None:
                self.federation_devices.close()


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
    federation_executor: Any = None,
    home_federation_enroller: Any = None,
    home_federation_permissions: Any = None,
) -> ServerRuntime:
    bind_host = str(bind_host or local_ip)
    grpc_port = int(local_port if grpc_port is None else grpc_port)
    certificate_port = int(
        cert_port if certificate_port is None else certificate_port
    )
    from remoteRF_server.common.utils.db_location import get_db_dir
    from .federation.legacy_state import acquire_runtime_writer_lock

    writer_lock = acquire_runtime_writer_lock(get_db_dir())
    from .federation.runtime import federation_enabled

    home_federation_devices = None

    try:
        if federation_enabled():
            supplied = (
                federation_executor,
                home_federation_enroller,
                home_federation_permissions,
            )
            if any(value is not None for value in supplied):
                if not all(value is not None for value in supplied):
                    raise RuntimeError("Refusing partial federation activation")
            else:
                from .federation.runtime import build_configured_server_federation

                configured = build_configured_server_federation(reservation_handler)
                federation_executor = configured.executor
                home_federation_enroller = configured.enroller
                home_federation_permissions = configured.permissions
                home_federation_devices = configured.devices
    except Exception:
        logger.error("federation_readiness_failure component=server_composition")
        writer_lock.close()
        raise
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
    if direct_path is not None:
        direct_path.CERT_DIR = cert_dir
        direct_path.BIND_HOST = bind_host
        direct_path.UDP_PORT = int(os.getenv("REMOTERF_DIRECT_UDP_PORT", grpc_port) or 0)

    options = [
        ('grpc.max_send_message_length', 100 * 1024 * 1024),
        ('grpc.max_receive_message_length', 100 * 1024 * 1024),
        # Clients ping every 20 s while a call is open, to notice a dead
        # network; a long device call that sends no data must not be struck
        # for it (gRPC's default allowance is one ping per 5 minutes).
        ('grpc.http2.min_ping_interval_without_data_ms', 10_000),
    ]

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=100), options=options)
    reservation_handler.federation_enroller = home_federation_enroller
    reservation_handler.federation_permissions = home_federation_permissions
    reservation_handler.federation_devices = home_federation_devices
    from .deployment.capabilities import register_capabilities
    from .federation.destination import register_grpc_federation
    register_capabilities(server)
    register_grpc_federation(server, federation_executor)
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
        writer_lock.close()
        _print_tls_credentials_error(cert_dir, e)
        raise SystemExit(2)

    from . import remote_admin_ssh

    remote_admin_ssh.register(server)
    if include_host_tunnel:
        reg = hts.get_tunnel_registry()
        if reg is None:
            writer_lock.close()
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
        writer_lock.close()
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
        # The one place local hardware is opened: importing device_manager does not.
        # The startup check runs before server.start(): no call reaches a
        # Pluto it is power-cycling.
        def open_devices(on_device):
            reload_devices(on_device=on_device)
            reservation_handler.update_devices()

        from . import startup_check

        startup_check.run(open_devices)
        server.start()
        if direct_path is not None:
            direct_path.start_listener()
        else:
            print(f"Warning: direct path off, every call goes over the relay ({_DIRECT_PATH_ERROR}). "
                  "Usually conda replaced pip's cryptography; fix: pip install --force-reinstall remoterf-server")
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
    except BaseException:  # Ctrl-C during the startup check too: close_local_devices powers Plutos down
        stop_event.set()
        server.stop(0)
        session_manager.close_all()
        host_session_proxy.close_all()
        close_local_devices()
        if cert_server is not None:
            stop_cert_provider(cert_server)
        close_permissions = getattr(home_federation_permissions, "close", None)
        if close_permissions is not None:
            close_permissions()
        if home_federation_devices is not None:
            home_federation_devices.close()
        writer_lock.close()
        raise

    from .control import ControlServer

    control_server = ControlServer(control_handler)
    try:
        control_server.start()
    except OSError as exc:
        logger.warning("control socket unavailable: %s", exc)
        control_server = None
    global _runtime
    _runtime = ServerRuntime(
        grpc_server=server,
        cert_server=cert_server,
        stop_event=stop_event,
        update_thread=update_thread,
        bind_host=bind_host,
        grpc_port=int(bound_grpc_port),
        cert_port=int(cert_server.server_address[1]),
        writer_lock=writer_lock,
        federation_permissions=home_federation_permissions,
        federation_devices=home_federation_devices,
        control_server=control_server,
    )
    return _runtime


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
    from ..common.utils.panel import marker, print_panel
    from . import console

    rows = [
        f"{marker()} Server running nominally.",
        BANNER_CREDIT,
        "",
        f"bind    {local_ip}:{local_port}",
    ]
    try:
        from . import global_onboarding as g

        lan = g.lan_endpoint()
        if lan and lan != f"{local_ip}:{local_port}":
            rows.append(f"lan     {lan}")
        if g.participating() and g.state() == "active" and g.hostname():
            rows.append(f"global  {g.hostname()}")
    except Exception:  # noqa: BLE001 - the banner never fails on Global state
        pass
    rows += ["", "Input 'help' for help menu."]
    if console.attached():
        rows.append("Ctrl-C leaves this console (server keeps running); quit stops it.")
    # Breathing room after first-run setup and driver bookkeeping.
    print()
    print_panel("RemoteRF Server", rows, literal=True)
    print()

def ask(text, *, secret: bool = False) -> str:
    """Every prompt inside a console command: the console's own prompt, or the
    caller's terminal when the command came over the control socket."""
    from . import control

    if control.bridged():
        from prompt_toolkit.formatted_text import fragment_list_to_text, to_formatted_text

        return control.ask(fragment_list_to_text(to_formatted_text(text)), secret=secret)
    return session.prompt(text, is_password=secret)


def clear():
    os.system('clear')
    welcome()
    
def set_acc():
    while True:
        username = ask("Enter username to manage (c to cancel): ")
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
    
    inpu = ask(stylize("Enter command: ", Sty.DEFAULT))
    if inpu == 's':
        inpu2 = ask(stylize("Setting perms: ", Sty.DEFAULT, " (U{User}/P{PowerUser}/A{Admin}) ", Sty.GRAY, ": ", Sty.DEFAULT))
        if inpu2 == 'U':
            perms.set_user(username)
            printf("Set to User. ", Sty.GREEN)
            
        elif inpu2 == 'P':
            printf("Setting PowerUser perms. ", Sty.BOLD, "Input 'c' to cancel anytime.", Sty.DEFAULT)
            
            while True: # Allowed Devices
                device_ids = ask(stylize("Enter device ids allowed ", Sty.DEFAULT, 'int,int,int,...', Sty.GRAY, ": ", Sty.DEFAULT))
                if device_ids == 'c':
                    return
                try:
                    device_list = [int(x) for x in device_ids.split(',')]
                    if ask(stylize(f"Confirm that this is the correct list of devices: {device_list} ", Sty.DEFAULT, "(y/n)", Sty.GRAY, ": ", Sty.DEFAULT)) == 'y':   
                        break
                except ValueError:
                    printf("Invalid input. Try Again.", Sty.RED)
                    
            while True: # Max Reservations
                max_res = ask(stylize("Enter max reservations allowed ", Sty.DEFAULT, 'int', Sty.GRAY, ": ", Sty.DEFAULT))
                if max_res == 'c':
                    return
                try:
                    max_res = int(max_res)
                    if ask(stylize(f"Confirm that this is the correct number of max reservations: {max_res} ", Sty.DEFAULT, "(y/n)", Sty.GRAY, ": ", Sty.DEFAULT)) == 'y':
                        break
                except ValueError:
                    printf("Invalid input. Try Again.", Sty.RED)
                    
            while True: # Max Reservation Time
                max_res_time = ask(stylize("Enter max length of a single reservation ", Sty.DEFAULT, 'int [seconds]', Sty.GRAY, ": ", Sty.DEFAULT))
                if max_res_time == 'c':
                    return
                try:
                    max_res_time = int(max_res_time)
                    if ask(stylize(f"Confirm that this is the correct max reservation time in SECONDS: {max_res_time} ", Sty.DEFAULT, "(y/n)", Sty.GRAY, ": ", Sty.DEFAULT)) == 'y':
                        break
                except ValueError:
                    printf("Invalid input. Try Again.", Sty.RED)
            
            perms.set_poweruser(username, devices_allowed=device_list, max_reservations=max_res, max_reservation_time_sec=max_res_time)
        elif inpu2 == 'A':
            perms.set_admin(username)
        else:
            printf("Invalid input. Skipping.", Sty.RED)
        
    elif inpu == 'D':
        if ask(f"Are you sure you want to delete user: {username}? (Y/N): ") == 'Y':
            printf(f"Deleting user: {username}", Sty.MAGENTA)
            reservation_handler.remove_user(username=username)
        else:
            printf("Delete canceled", Sty.GRAY)
    elif inpu == 'r':
        print("Managing reservations:")
        while True:
            inpu = ask(stylize("Enter command: ", Sty.DEFAULT, "'a' to add, 'c' to cancel, 'e' to exit (anytime), 'v' to view. : ", Sty.GRAY))
            if inpu == 'e':
                break
            elif inpu == 'a':
                while True:
                    device_id = ask(stylize("Enter device id: ", Sty.DEFAULT))
                    if device_id == 'c' or device_id == 'e':
                        break
                    try:
                        device_id = int(device_id)
                        if device_id not in get_registered_devices():
                            printf("Invalid device id.", Sty.GRAY)
                            continue
                        start_time = ask(stylize("Enter start time: ", Sty.DEFAULT, "YYYY-MM-DD HH:MM:SS -> ", Sty.GRAY))
                        end_time = ask(stylize("Enter end time: ", Sty.DEFAULT, "YYYY-MM-DD HH:MM:SS -> ", Sty.GRAY))
                        token = reservation_handler.reserve_device(username=username, device_id=device_id, start_time=datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S'), end_time=datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S'), is_server=True)
                        if 'Token' not in token:
                            printf(unmap_arg(token['ace']), Sty.GRAY)
                            continue
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
                        inpu2 = ask(stylize("Enter reservation id to cancel: ", Sty.DEFAULT))
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
    from ..common.utils.panel import print_table

    reg = hts.get_tunnel_registry(create=False)
    live = reg.list_devices() if reg is not None else {}
    rows = []
    devices = get_all_devices_str()
    handles = handle_report()
    for key, value in sorted(devices.items()):
        ds = live.get(str(key))
        rows.append({
            "device_id": key,
            "name": value,
            "handle": handles.get(key, "-"),
            "host": f"{ds.host_id} #{ds.host_local_id}" if ds else "local",
            "last_seen": f"{_fmt_ms_ago(ds.last_seen_ms)} ago" if ds and ds.last_seen_ms else "-",
        })
    print_table("Devices", rows, ["device_id", "name", "handle", "host", "last_seen"], empty="No devices configured.")

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
    from ..common.utils.panel import print_table

    reg = hts.get_tunnel_registry()
    assert reg is not None
    hosts = reg.list_hosts()     # host_id -> HostStatus
    devices = reg.list_devices() # device_id -> DeviceStatus
    by_host: dict[str, int] = {}
    for ds in devices.values():
        by_host[ds.host_id or "-"] = by_host.get(ds.host_id or "-", 0) + 1
    rows = [
        {
            "host_id": hid,
            "online": hs.online,
            "last_seen": f"{_fmt_ms_ago(hs.last_seen_ms)} ago",
            "devices": by_host.get(hid, 0),
        }
        for hid, hs in sorted(hosts.items(), key=lambda kv: kv[0])
    ]
    print_table("Hosts (live)", rows, ["host_id", "online", "last_seen", "devices"])


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
            resp = ask(stylize("Type 'wipe-hosts' to confirm wiping host state: ", Sty.RED))
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
    # Only the command words are case-insensitive (commands.normalize); the
    # arguments -- verification codes, tokens, passwords -- must survive intact.
    words = (s or "").strip().split()
    if words and words[0].lower() == "serverrf":
        words = words[1:]
    return " ".join(words)

def _cmd_detach() -> None:
    from . import console

    if console.attached():
        printf("Server keeps running. ", Sty.GRAY, "serverrf -s", Sty.MAGENTA, " to come back.", Sty.GRAY)
        console.detach()
    else:
        printf("Not in the console; the server runs in this terminal. Use quit to stop it.", Sty.GRAY)


def _cmd_status() -> None:
    from ..common.utils.panel import marker, print_panel
    from . import global_onboarding as g

    try:
        uptime = str(datetime.now() - start_time).split(".")[0]
        fields = [
            ("started", str(start_time).split(".")[0]),
            ("uptime", uptime),
            ("bind", f"{local_ip}:{local_port}"),
            ("cert", f"{local_ip}:{cert_port}"),
            ("devices", str(len(get_all_devices_str()))),
        ]
        kv = g.load()
        if g.participating():
            state = kv.get("GLOBAL_STATE", "unregistered")
            fields += [
                ("", ""),
                ("global", f"{state} -- {g._STATE_SUMMARY.get(state, '')}".rstrip(" -")),
                ("hostname", g.hostname() or "-"),
                ("tunnel", g.tunnel_state()),
                ("last report", (kv.get("GLOBAL_LAST_REPORT_AT") or "-").split(".")[0]),
                ("last seen", (kv.get("GLOBAL_LAST_SEEN_AT") or "-").split(".")[0]),
            ]
        else:
            fields += [("", ""), ("global", "not participating (serverrf global join)")]
        width = max(len(name) for name, _ in fields)
        rows = [f"{marker()} Server running since {fields[0][1]}", ""]
        rows += [f"{name:<{width}}  {value}" if name else "" for name, value in fields]
        print()
        print_panel("Server status", rows, literal=True)
        print()
    except Exception as exc:  # noqa: BLE001
        printf(f"Status unavailable: {exc}", Sty.RED)

# Canonical spellings only; the aliases in DISPATCH are deliberately unlisted.
def help() -> None:
    from .commands import cmd_help

    cmd_help([])


_runtime: ServerRuntime | None = None
_exit_action: str | None = None   # "quit" | "restart", set when asked from another thread

# Spellings the console accepted before the shared command table.
_OLD_ALIASES = {
    "server status": "status", "u list": "users list", "accounts list": "users list",
    "setacc": "users manage", "rm aa": "users purge", "show p": "users perms",
    "show d": "devices list", "show r": "reservations list", "rm ar": "reservations purge",
    "rm db": "db purge", "mk group": "groups create", "mk g": "groups create",
    "rm group": "groups remove", "rm g": "groups remove", "edit group": "groups edit",
    "edit g": "groups edit", "show g": "groups list", "show groups": "groups list",
    "mk codes": "codes create", "mk code": "codes create", "mk c": "codes create",
    "show c": "codes list", "rm codes": "codes remove", "rm code": "codes remove",
    "rm c": "codes remove", "host status": "hosts status", "tunnel devices": "devices list",
}


def _console_argv(inpu: str) -> list[str]:
    import shlex

    cmd = _norm_cmd(inpu)
    for old, new in _OLD_ALIASES.items():
        if cmd.lower() == old or cmd.lower().startswith(old + " "):
            cmd = new + cmd[len(old):]
            break
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


def server_input(inpu: str) -> bool:
    """One console line. False when the server should stop."""
    from .commands import RestartRequested, StopRequested, dispatch

    argv = _console_argv(inpu)
    if not argv:
        return True
    global _exit_action
    try:
        dispatch(argv, in_daemon=True)
    except StopRequested:
        _exit_action = "quit"
        return False
    except RestartRequested:
        _exit_action = "restart"
        return False
    except Exception:
        # A broken command must never take the server down with it.
        import traceback

        traceback.print_exc()
        printf("That command failed; the server is still running.", Sty.WARNING)
    return True


def control_handler(argv: list[str]) -> int:
    """A command sent by `serverrf …` from a shell; runs here, in the server."""
    from .commands import RestartRequested, StopRequested, dispatch

    try:
        return dispatch(argv, in_daemon=True)
    except StopRequested:
        _request_exit("quit")
    except RestartRequested:
        _request_exit("restart")
    except Exception as exc:
        print(f"That command failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


def _request_exit(action: str) -> None:
    """Make the main loop finish as if `quit`/`restart` had been typed."""
    global _exit_action
    _exit_action = action
    app = getattr(session, "app", None)
    loop = getattr(app, "loop", None)
    if app is not None and app.is_running and loop is not None:
        loop.call_soon_threadsafe(lambda: app.exit(result=action))
    elif _runtime is not None:
        # Headless: wake the main thread's wait(); it runs the full stop there
        # (a thread spawned here would be a daemon and die with the process).
        _runtime.stop_event.set()


def _reexec() -> None:
    """Restart in place: same pid's tmux window, same argv, fresh process."""
    from . import global_onboarding as g

    g.stop_agent()
    if sys.stdin.isatty():
        os.system("stty sane")
    os.execv(sys.executable, [sys.executable, "-m", "remoteRF_server.serverrf_cli", *sys.argv[1:]])


# The shared command table calls these by name (commands.py).
def cmd_status(argv): _cmd_status()
def cmd_detach(argv): _cmd_detach()
def cmd_clear(argv): clear()
def cmd_hosts_status(argv): _cmd_hosts_status()
def cmd_hosts_wipe(argv): _cmd_hosts_wipe(yes=("-y" in argv or "--yes" in argv))
def cmd_users_list(argv): reservation_handler.print_all_accounts()
def cmd_users_manage(argv): set_acc()
def cmd_users_perms(argv): perms.print_perms()
def cmd_users_purge(argv): reservation_handler.remove_all_users()
def cmd_reservations_list(argv): reservation_handler.print_all_reservations()


def cmd_users_prune_proxies(argv):
    """Dry run unless -y: proxies whose home left, half-deleted ones, and with
    --stale DAYS those unseen that long with nothing booked."""
    import sqlite3
    from contextlib import closing

    from ..common.utils.panel import print_table
    from .federation import cluster
    from .federation.principals import orphan_proxies
    from .user_group_handler import user_group_handler

    stale = None
    if "--stale" in argv:
        try:
            stale = int(argv[argv.index("--stale") + 1])
        except (IndexError, ValueError):
            printf("Usage: users prune-proxies [--stale DAYS] [-y]", Sty.RED)
            return 2
    orphans = orphan_proxies(reservation_handler.filepath, user_group_handler.filepath, stale_days=stale)
    rows = [{"username": o["username"] or "(no account)", "home": cluster.peer_name(o["issuer"]) if o["issuer"] else "?",
             "last_active": datetime.fromtimestamp(o["last_active"]).strftime("%Y-%m-%d") if o["last_active"] else "",
             "reservations": o["reservations"], "reason": o["reason"]} for o in orphans]
    print_table("Orphaned federated proxies", rows, ["username", "home", "last_active", "reservations", "reason"],
                empty="No orphaned proxies.")
    if not orphans:
        return 0
    if any(o["reason"] == "stale" for o in orphans):
        printf("A 'stale' visitor may still be real: removing one ends their access here until "
               "their home deployment enrols them again.", Sty.YELLOW)
    if not ("-y" in argv or "--yes" in argv):
        printf(f"{len(orphans)} orphaned proxies. Nothing removed; run `users prune-proxies"
               f"{f' --stale {stale}' if stale is not None else ''} -y` to remove them.", Sty.GRAY)
        return 0
    for o in orphans:
        if o["username"]:
            reservation_handler.remove_user(username=o["username"])
        else:
            with closing(sqlite3.connect(user_group_handler.filepath, timeout=10.0)) as conn, conn:
                conn.execute("DELETE FROM FederatedPrincipals WHERE id=?", (o["principal_id"],))
            cluster.forget_account(o["local_account_id"])
    printf(f"Removed {len(orphans)} orphaned proxies.", Sty.GRAY)
    return 0
def cmd_reservations_purge(argv): reservation_handler.remove_all_reservations()
def cmd_db_purge(argv): reservation_handler.rm_db()
def cmd_stats_purge(argv):
    from . import reservation

    if not ("-y" in argv or "--yes" in argv):
        try:
            resp = ask(stylize("Type 'purge-stats' to confirm deleting the activity log: ", Sty.RED))
        except KeyboardInterrupt:
            printf("Cancelled.", Sty.GRAY)
            return
        if (resp or "").strip().lower() != "purge-stats":
            printf("Purge aborted.", Sty.GRAY)
            return
    with reservation.log_lock:
        try:
            reservation.LOG_PATH.unlink()
        except FileNotFoundError:
            printf("No activity log to purge.", Sty.GRAY)
            return
    printf(f"Purged activity log: {reservation.LOG_PATH}", Sty.GRAY)
def cmd_devices_list(argv): get_devices()


def cmd_diag(argv):
    from . import diag

    flags = {a.lower() for a in argv}
    unknown = flags - {"--force", "-f", "--copy", "-c"}
    if unknown:
        printf(f"Unknown option {sorted(unknown)[0]}. Usage: diag [--force] [--copy]", Sty.RED)
        return 2
    return diag.run(force=bool(flags & {"--force", "-f"}), copy=bool(flags & {"--copy", "-c"}),
                    ask=ask)


def cmd_reload_devices(argv):
    from . import device_manager

    device_manager.reload_devices()


def cmd_stop(argv):
    from .commands import StopRequested

    raise StopRequested()


def cmd_restart(argv):
    from .commands import RestartRequested

    raise RestartRequested()


def main() -> int:
    from . import console

    runtime = start_server_runtime()
    start_agent()  # after the devices are open: its first status report lists them
    welcome()
    try:
        while True:
            try:
                if not server_input(session.prompt(stylize("serverrf> ", Sty.BOLD))):
                    break
            except (EOFError, KeyboardInterrupt):
                if not console.attached():
                    break
                # In the console, Ctrl-C leaves; only `quit` stops the server.
                printf("Server keeps running. Type ", Sty.GRAY, "quit", Sty.MAGENTA,
                       " to stop it; ", Sty.GRAY, "serverrf -s", Sty.MAGENTA, " to come back.", Sty.GRAY)
                console.detach()
    finally:
        runtime.stop()
    if _exit_action == "restart":
        _reexec()
    printf("Stopped the RemoteRF server background process.", Sty.GRAY)
    return 0


def headless_main() -> int:
    runtime = start_server_runtime()
    start_agent()  # after the devices are open: its first status report lists them
    welcome()
    try:
        runtime.wait()
    except KeyboardInterrupt:
        pass
    finally:
        runtime.stop()
    if _exit_action == "restart":
        _reexec()
    printf("Stopped the RemoteRF server background process.", Sty.GRAY)
    return 0


if __name__ == "__main__":
    raise SystemExit(headless_main())
