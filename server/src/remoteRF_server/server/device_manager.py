import adi
# import uhd
# from hackrf import *
from ..common.utils import *
import subprocess

import time
import gc

#* Device manager *
'''
Responsible for starting and managing queues for devices.
'''

# TODO: Implement multiple device support
#region PlutoSDR

def connect_pluto(*, ip='', usb=''):
    try:
        if ip == '':
            device = adi.Pluto(f'usb:{usb}')
            print(f"Connected to Pluto usb:{usb}")
        else:
            device = adi.Pluto(f'ip:{ip}')
            print(f"Connected to Pluto ip:{ip}")
        return device
    except Exception as e:
        print(f"Pluto {ip}: {e}")
        return None

import subprocess
import re

def get_usb_port_from_serial(serial):
    try:
        # Run iio_info -s and get the output
        output = subprocess.check_output(["iio_info", "-s"]).decode("utf-8")
    except Exception as e:
        print(f"Error running iio_info: {e}")
        return None

    # Regex to find the USB port associated with the given serial number
    pattern = re.compile(rf"\d+:.*serial={serial}\s+\[usb:(\S+)\]")

    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            return match.group(1)  # Return the USB port

    print(f"No device found with serial {serial}")
    return None

# def connect_hackrf(device_index):
#     try:
#         device = HackRF(device_index=device_index)
#         print(f"Connected to HackRF {device_index}")
#         return device
#     except Exception as e:
#         print(f"HackRF {device_index}: {e}")
#         return None
    
# def connect_usrp2901():
#     usrp = uhd.usrp.MultiUSRP()
#     print(f"Connected to USRP 2901")
#     return usrp
    
class temp:
    pass

device_serialization = {
    0: '10447392da11001009001500f02af8a678',
    1: '10447392da110010f9ff1500612ff8ecb0',
    2: '104473b04a06000ffbff3900f5de83267e',
    3: '10447376de0b00130b00200023119a89c6',
    4: '1044732a98110002faff1500f92ae517bf'
}

devices = { # device, salt, hash
    
    # iio_info -s
    # ^ find usb serial ports
    
    0: (connect_pluto(usb=get_usb_port_from_serial(device_serialization[0])),'',''),
    1: (connect_pluto(usb=get_usb_port_from_serial(device_serialization[1])),'',''),
    2: (connect_pluto(usb=get_usb_port_from_serial(device_serialization[2])),'',''),
    3: (connect_pluto(usb=get_usb_port_from_serial(device_serialization[3])),'',''),
    4: (connect_pluto(usb=get_usb_port_from_serial(device_serialization[4])),'',''),
    
    # 0: (connect_pluto(usb='1.8.5'),'',''),
    # 1: (connect_pluto(usb='1.18.5'),'',''),
    # 2: (connect_pluto(usb='1.8.5'),'',''),
    # 1: (connect_pluto(usb='1.8.5'),'',''),
    
    # hackrf
    # 10: (connect_hackrf(0),'',''),
    
    # 20: (connect_usrp2901(),'',''),
    
}

devices_info = {    # device, info
    0: "Pluto SDR (loopback)",
    1: "Pluto SDR (loopback)",
    2: "Pluto SDR (OTA)",
    3: "Pluto SDR (OTA)",
    4: "Pluto SDR (OTA)"
}

master_token = '***REMOVED***123'

transmitter = subprocess.Popen(['python3', 'transmitter.py'])
transmitter.terminate()

def start_transmitter():
    global transmitter
    transmitter = subprocess.Popen(['python3', 'transmitter.py'])
    
def terminate_transmitter():
    global transmitter
    transmitter.terminate()
    
def get_transmitter_state():
    global transmitter
    return transmitter.poll() == None

def get_device(device_id):
    return devices[device_id]

def get_all_devices() -> dict:
    return {k: v for k, v in devices.items() if v is not None}

def get_all_devices_str() -> dict:
    return devices_info

def get_device(*, api_token):
    
    # Check for master token
    
    if api_token == master_token:
        # Check for the first empty device
        for key, value in devices.items():
            if value[1] == '' and value[2] == '':
                return value[0]
            
        return None
    
    for key, value in devices.items():
        if validate_token(value[1], value[2], api_token):
            return value[0]
    return None
    
def set_device(device_id, salt, hash):
    devices[device_id] = (devices[device_id][0], salt, hash)
    
def set_pluto(ip='192.168.2.1'):
    # try:
    #     global device_pluto
    #     del device_pluto
    #     device_pluto = adi.Pluto(f'ip:{ip}')
    # except Exception as e:
    #     print(f"PlutoError: {e}")
    # NO IMPLEMENTATION SHOUlD BE GIVEN, AS THIS IS FOR DEVICE SETUP. Keeping it just to support common Pluto code
    pass