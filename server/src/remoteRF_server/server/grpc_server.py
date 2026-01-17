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
    
# region Remote Admin Calls
    
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


def print_all_accounts_remote() -> str:
    """
    Returns information about all user accounts (instead of printing it).
    """
    # If reservation_handler.print_all_accounts() normally prints directly,
    # you'll need a way to retrieve that same data. For example, if there's
    # a hypothetical function get_all_accounts() returning a list/dict of user info:
    accounts = reservation_handler.get_all_accounts()  # or any equivalent method
    if not accounts:
        return "No user accounts found."

    # Build a multiline string describing each account
    result_lines = ["All user accounts:"]
    for acc in accounts:
        # Customize formatting as desired; for example:
        result_lines.append(str(acc))

    return "\n".join(result_lines)
