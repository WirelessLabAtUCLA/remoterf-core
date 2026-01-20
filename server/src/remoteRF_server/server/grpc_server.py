import threading
import socket
import os
import io
import sys
import time

from typing import Tuple 

os.system('clear')

from concurrent import futures
from datetime import datetime

import grpc

import traceback
import contextlib

from ..common.grpc import *
from .reservation import reservation_handler
from .rpc_manager import rpc_manager
from .acc_perms import perms
from ..common.utils import *
from .device_manager import get_all_devices, get_all_devices_str

from pathlib import Path
from prompt_toolkit import PromptSession

session = PromptSession()

from dotenv import load_dotenv, find_dotenv
dotenv_path = find_dotenv('.env.server')
load_dotenv(dotenv_path)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))

local_ip = s.getsockname()[0] # grab the local ip
local_port = os.getenv('GRPC_PORT')

print(f"Local IP: {local_ip}")
print(f"Local Port: {local_port}")

# Implement the GenericRPC service
class GenericRPCServicer(grpc_pb2_grpc.GenericRPCServicer):
    def Call(self, request, context):
        
        # Remote Admin
        function_name_args = request.function_name.split(':')
        if function_name_args[0] == "RemoteAdmin":
            ok, err, caller = verify_remote_admin(request.args)
            if not ok:
                # You can also: context.abort(grpc.StatusCode.PERMISSION_DENIED, err)
                return grpc_pb2.GenericRPCResponse(results={
                    "Ok": map_arg(False),
                    "Error": map_arg(err),
                })

            return grpc_pb2.GenericRPCResponse(
                results=remote_admin_call(function_name=function_name_args[1], args=request.args)
            )
            
        # Normal RPC
        response = rpc_manager.run_rpc(function_name=request.function_name, args=request.args)
        return grpc_pb2.GenericRPCResponse(results=response)
    

# Function to start the server
def serve():
    
    options = [
        ('grpc.max_send_message_length', 100 * 1024 * 1024),
        ('grpc.max_receive_message_length', 100 * 1024 * 1024)
    ]
    
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=100), options=options)
    grpc_pb2_grpc.add_GenericRPCServicer_to_server(GenericRPCServicer(), server)

    # For generating server credentials for secure connections
    
    # Rasp
    #* Server credentials generation: Add server ip to this line
    #* openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt -subj "/CN=192.168.1.169" -addext "subjectAltName=IP:192.168.1.169"
    
    #ubuntu VM
    # openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt -subj "/CN=192.168.64.5" -addext "subjectAltName=IP:192.168.64.5"
    
    #router
    # openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt -subj "/CN=128.97.88.21" -addext "subjectAltName=IP:128.97.88.21"

    #magikarp
    # openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt -subj "/CN=192.168.1.109" -addext "subjectAltName=IP:192.168.1.109"
    
    #wlab
    # openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt -subj "/CN=164.67.195.207" -addext "subjectAltName=IP:164.67.195.207"

    # Read key and certificate
    
    cert_key = Path(__file__).resolve().parent.parent/'certs'/'server.key'
    cert_crt = Path(__file__).resolve().parent.parent/'certs'/'server.crt'
    
    with cert_key.open('rb') as f:
        private_key = f.read()
    with cert_crt.open('rb') as f:
        certificate_chain = f.read()

    # Create server credentials
    server_credentials = grpc.ssl_server_credentials(
        ((private_key, certificate_chain,),))
    
    from .cert_provider import start_cert_provider
    cert_server, cert_thread = start_cert_provider(host=local_ip, port=int(os.getenv("CERT_PORT", "61006")))

    # Add secure port
    server.add_secure_port(f'{local_ip}:{local_port}', server_credentials)
    server.start()
    server.wait_for_termination()
    
def update_devices():
    while True:
        reservation_handler.update_devices()
        time.sleep(60)

threading.Thread(target=serve, daemon=True).start()
threading.Thread(target=update_devices, daemon=True).start()

start_time = datetime.now()

def welcome():
    printf(f"Server running nominally.", Sty.BOLD)
    printf(f"   -> Started at ", Sty.DEFAULT, f"{start_time}", Sty.BLUE)
    printf("Input ", Sty.DEFAULT, "'help'", Sty.GREEN," for help menu.", Sty.DEFAULT)

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

def help():
    printf("/------- HELP -------/", Sty.BOLD)
    printf("'exit'", Sty.MAGENTA, " - Stop server.", Sty.DEFAULT)
    printf("'help'", Sty.MAGENTA, " - Help.", Sty.DEFAULT)
    printf("'clear'", Sty.MAGENTA, " - Clear terminal screen.", Sty.DEFAULT)
    printf("'printa'", Sty.MAGENTA, " - Print all accounts", Sty.DEFAULT)
    printf("'printd'", Sty.MAGENTA, " - Print all devices", Sty.DEFAULT)
    printf("'printp'", Sty.MAGENTA, " - Print all perms", Sty.DEFAULT)
    printf("'printr'", Sty.MAGENTA, " - Print all reservations", Sty.DEFAULT)
    printf("'rm aa'", Sty.MAGENTA, " - Remove all accounts", Sty.DEFAULT)
    printf("'rm a'", Sty.MAGENTA, " - Remove one account", Sty.DEFAULT)
    printf("'rm ar'", Sty.MAGENTA, " - Remove all reservations", Sty.DEFAULT)
    printf("'rm db'", Sty.MAGENTA, " - Remove all database entries", Sty.DEFAULT)
    printf("'setacc'", Sty.MAGENTA, " - Set account details", Sty.DEFAULT)

def server_input(inpu:str) -> bool:
    if inpu == "h" or inpu == "help":
        help()
    elif inpu == 'printr':
        reservation_handler.print_all_reservations()
    elif inpu == 'printa':
        reservation_handler.print_all_accounts()
    elif inpu == 'printp':
        perms.print_perms()
    elif inpu == 'printd':
        get_devices()
    elif inpu == 'clear':
        clear()
    elif inpu == 'rm aa':
        reservation_handler.remove_all_users()
    elif inpu == 'rm ar':
        reservation_handler.remove_all_reservations()
    elif inpu == 'rm db':
        reservation_handler.rm_db()
    elif inpu == 'setacc':
        set_acc()
    elif inpu == 'exit' or inpu == 'quit':
        return False
    else:
        print(f"Invalid command: {inpu}")
    return True
        
welcome()

def main():
    while server_input(session.prompt(stylize('server@remote_rf: ', Sty.BLUE))):
        # print("New")
        pass

if __name__ == '__main__':
    main()
    
# region Remote Admin
    
from typing import List, Optional

def remove_all_users_remote() -> str:
    """
    Removes all user accounts from the system and returns a message about the operation.
    """
    reservation_handler.remove_all_users()
    return "All user accounts have been removed successfully."


def remove_user_remote(username: str) -> str:
    """
    Removes a single user account from the system and returns a message about the operation.
    """
    reservation_handler.remove_user(username=username)
    return f"User '{username}' has been removed successfully."


def remove_all_reservations_remote() -> str:
    """
    Removes all reservations from the system and returns a message about the operation.
    """
    reservation_handler.remove_all_reservations()
    return "All reservations have been removed successfully."

def set_account_remote(
    username: str,
    permission: str,
    device_list: Optional[List[int]] = None,
    max_reservations: Optional[int] = None,
    max_reservation_time_sec: Optional[int] = None
) -> str:
    """
    Sets user permission. Valid permission strings: 
    'U' (User), 'P' (PowerUser), 'A' (Admin).
    For 'P' (PowerUser), device_list, max_reservations, and max_reservation_time_sec
    must be provided.

    Returns a string describing the outcome of setting the account.
    """
    messages = []

    current_perm = perms.get_perms(username)
    if not current_perm:
        messages.append(f"User '{username}' does not exist. Creating a new entry.")

    if permission == 'U':
        perms.set_user(username)
        messages.append(f"User '{username}' set to User level.")
    elif permission == 'P':
        if device_list is None or max_reservations is None or max_reservation_time_sec is None:
            raise ValueError("For PowerUser, device_list, max_reservations, and "
                             "max_reservation_time_sec must all be provided.")
        perms.set_poweruser(
            username,
            devices_allowed=device_list,
            max_reservations=max_reservations,
            max_reservation_time_sec=max_reservation_time_sec
        )
        messages.append(f"User '{username}' set to PowerUser level with devices: "
                        f"{device_list}, max_reservations: {max_reservations}, "
                        f"max_reservation_time_sec: {max_reservation_time_sec}")
    elif permission == 'A':
        perms.set_admin(username)
        messages.append(f"User '{username}' set to Admin level.")
    else:
        messages.append("Invalid permission input. Use 'U', 'P', or 'A'.")

    return "\n".join(messages)

import io
import contextlib

def print_all_reservations_remote() -> str:
    """
    Returns information about all reservations (instead of printing it).

    Tries (in order):
      1) reservation_handler.grab_all_reservations_server() if available
      2) capture stdout from reservation_handler.print_all_reservations()
    """
    # Preferred path: structured data
    if hasattr(reservation_handler, "grab_all_reservations_server"):
        reservations = reservation_handler.grab_all_reservations_server()
        if not reservations:
            return "No reservations found."

        lines = ["All reservations:"]
        # reservations: {res_id(int): (username, device_id, start_time, end_time)}
        for res_id in sorted(reservations.keys()):
            res = reservations[res_id]
            try:
                username, device_id, start_time, end_time = res
            except Exception:
                # fallback if structure differs
                lines.append(f"ID: {res_id} -> {res}")
                continue
            lines.append(
                f"ID: {res_id}, User: {username}, Device: {device_id}, Start: {start_time}, End: {end_time}"
            )
        return "\n".join(lines)

    # Fallback: capture whatever the existing print function emits
    if hasattr(reservation_handler, "print_all_reservations"):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            reservation_handler.print_all_reservations()
        out = buf.getvalue().strip()
        return out if out else "No reservations found."

    return "No reservation listing method found on reservation_handler."

def print_all_accounts_remote() -> str:
    """
    Returns information about all user accounts (instead of printing it).

    Tries (in order):
      1) reservation_handler.get_all_accounts() if you implemented it
      2) capture stdout from reservation_handler.print_all_accounts()
    """
    if hasattr(reservation_handler, "get_all_accounts"):
        accounts = reservation_handler.get_all_accounts()
        if not accounts:
            return "No user accounts found."
        return "\n".join(["All user accounts:"] + [str(a) for a in accounts])

    if hasattr(reservation_handler, "print_all_accounts"):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            reservation_handler.print_all_accounts()
        out = buf.getvalue().strip()
        return out if out else "No user accounts found."

    return "No account listing method found on reservation_handler."

def print_all_perms_remote() -> str:
    """
    Returns permission information for all users (instead of printing it).

    Tries (in order):
      1) capture stdout from perms.print_perms()
      2) fall back to a minimal message if no print method exists
    """
    if hasattr(perms, "print_perms"):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            perms.print_perms()
        out = buf.getvalue().strip()
        return out if out else "No permissions found."
    return "No permission listing method found on perms."


def print_all_devices_remote() -> str:
    """
    Returns device information (instead of printing it).

    Uses get_all_devices_str() (preferred structured source) and formats it.
    Falls back to the server's get_devices() printing path if needed.
    """
    try:
        data = get_all_devices_str()
        if not data:
            return "No devices found."

        lines = ["All devices:"]
        # data: {device_id: device_name_or_desc}
        for dev_id in sorted(data.keys()):
            lines.append(f"Device ID: {dev_id} Device Name: {data[dev_id]}")
        return "\n".join(lines)
    except Exception:
        # Fallback: capture whatever get_devices() prints
        if "get_devices" in globals() and callable(get_devices):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                get_devices()
            out = buf.getvalue().strip()
            return out if out else "No devices found."
        return "Failed to retrieve devices."

def _safe_unmap(v):
    try:
        return unmap_arg(v)
    except Exception:
        return v

def _safe_map(v):
    try:
        return map_arg(v)
    except Exception:
        return v
    
def verify_remote_admin(args: map) -> Tuple[bool, str, str]:
    """
    Returns: (ok, error_message, username)
    """
    try:
        raw_args = dict(args) if args is not None else {}
    except Exception:
        raw_args = {}

    # Use auth_un/auth_pw to avoid colliding with "username" (target) args
    if "auth_un" not in raw_args or "auth_pw" not in raw_args:
        return False, "Missing admin credentials (auth_un/auth_pw).", ""

    username = _safe_unmap(raw_args.get("auth_un"))
    password = _safe_unmap(raw_args.get("auth_pw"))

    if not username or not password:
        return False, "Missing admin credentials (auth_un/auth_pw).", ""

    # 1) Validate username/password against Accounts DB
    login_res = reservation_handler.login_user(str(username), str(password))
    if not isinstance(login_res, dict) or ("UC" not in login_res):
        return False, "Invalid login credentials.", str(username)

    # 2) Validate perms DB says this user is Admin
    try:
        rows = perms.get_perms(str(username))
    except Exception:
        return False, "Failed to read permissions database.", str(username)

    if not rows:
        return False, "Permissions not found. Access denied.", str(username)

    # Your get_perms UNION returns one row if you enforce exclusivity; be safe anyway:
    is_admin = any((r and len(r) > 0 and r[0] == "Admin") for r in rows)
    if not is_admin:
        return False, f"User '{username}' is not an Admin.", str(username)

    return True, "", str(username)
    
def remote_admin_call(function_name: str, args: map) -> map:
    # Normalize protobuf map containers to a plain dict and unmap values
    try:
        raw_args = dict(args) if args is not None else {}
    except Exception:
        raw_args = {}

    args_py = {str(k): _safe_unmap(v) for k, v in raw_args.items()}

    def get_arg(name, *, required=False, default=None, aliases=()):
        if name in args_py:
            return args_py[name]
        for a in aliases:
            if a in args_py:
                return args_py[a]
        if required:
            raise KeyError(f"Missing required arg '{name}'")
        return default

    # Normalize function name
    fn = (function_name or "").strip()
    if fn.endswith("_remote"):
        fn = fn[:-7]
    fn_key = fn.lower()

    try:
        # ---- remove_all_users ----
        if fn_key in ("remove_all_users", "remove_all_accounts", "rm_all_users", "rm_aa"):
            msg = remove_all_users_remote()
            return {"Ok": _safe_map(True), "Result": _safe_map(msg)}

        # ---- remove_user ----
        if fn_key in ("remove_user", "rm_user", "rm_a"):
            username = get_arg("username", required=True, aliases=("user", "u"))
            msg = remove_user_remote(str(username))
            return {"Ok": _safe_map(True), "Result": _safe_map(msg)}

        # ---- remove_all_reservations ----
        if fn_key in ("remove_all_reservations", "rm_all_reservations", "rm_ar"):
            msg = remove_all_reservations_remote()
            return {"Ok": _safe_map(True), "Result": _safe_map(msg)}

        # ---- set_account ----
        if fn_key in ("set_account", "set_acc", "set_user_perm", "setperm"):
            username = get_arg("username", required=True, aliases=("user", "u"))
            permission = get_arg("permission", required=True, aliases=("perm", "p"))

            device_list = get_arg(
                "device_list",
                default=None,
                aliases=("devices", "devices_allowed", "device_ids"),
            )
            if isinstance(device_list, str):
                device_list = [int(x) for x in device_list.split(",") if x.strip() != ""]
            elif device_list is not None:
                device_list = [int(x) for x in list(device_list)]

            max_reservations = get_arg(
                "max_reservations",
                default=None,
                aliases=("max_res", "maxRes"),
            )
            if max_reservations is not None:
                max_reservations = int(max_reservations)

            max_reservation_time_sec = get_arg(
                "max_reservation_time_sec",
                default=None,
                aliases=("max_time", "max_res_time_sec", "maxResTimeSec"),
            )
            if max_reservation_time_sec is not None:
                max_reservation_time_sec = int(max_reservation_time_sec)

            msg = set_account_remote(
                username=str(username),
                permission=str(permission),
                device_list=device_list,
                max_reservations=max_reservations,
                max_reservation_time_sec=max_reservation_time_sec,
            )
            return {"Ok": _safe_map(True), "Result": _safe_map(msg)}

        # ---- print_all_accounts ----
        if fn_key in ("print_all_accounts", "print_accounts", "printa"):
            msg = print_all_accounts_remote()
            return {"Ok": _safe_map(True), "Result": _safe_map(msg)}

        # ---- print_all_reservations ----
        if fn_key in ("print_all_reservations", "print_reservations", "printr"):
            msg = print_all_reservations_remote()
            return {"Ok": _safe_map(True), "Result": _safe_map(msg)}

        # ---- print_all_perms ----
        if fn_key in ("print_all_perms", "print_perms", "printp"):
            msg = print_all_perms_remote()
            return {"Ok": _safe_map(True), "Result": _safe_map(msg)}

        # ---- print_all_devices ----
        if fn_key in ("print_all_devices", "print_devices", "printd"):
            msg = print_all_devices_remote()
            return {"Ok": _safe_map(True), "Result": _safe_map(msg)}

        # ---- unknown ----
        supported = [
            "remove_all_users",
            "remove_user (username)",
            "remove_all_reservations",
            "set_account (username, permission, ...)",
            "print_all_accounts",
            "print_all_reservations",
            "print_all_perms",
            "print_all_devices",
        ]
        return {
            "Ok": _safe_map(False),
            "Error": _safe_map(f"Unknown RemoteAdmin function '{fn}'. Supported: {supported}"),
        }

    except Exception as e:
        tb = traceback.format_exc(limit=5)
        return {
            "Ok": _safe_map(False),
            "Error": _safe_map(str(e)),
            "Traceback": _safe_map(tb),
        }


# endregion
