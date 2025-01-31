import adi
# import uhd
# from hackrf import *
from ..common.utils import *

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

devices = { # device, salt, hash
    
    # iio_info -s
    # ^ find usb serial ports
    0: (connect_pluto(usb='1.6.5'),'',''),
    # 1: (connect_pluto(usb='1.8.5'),'',''),
    # 2: (connect_pluto(usb='1.10.5'),'',''),
    # 1: (connect_pluto(usb='1.8.5'),'',''),
    
    # hackrf
    # 10: (connect_hackrf(0),'',''),
    
    # 20: (connect_usrp2901(),'',''),
    
}

devices_info = {    # device, info
    0: "PlutoSDR",
    1: "PlutoSDR",
    2: "PlutoSDR",
}

def get_device(device_id):
    return devices[device_id]

def get_all_devices() -> dict:
    return {k: v for k, v in devices.items() if v is not None}

def get_all_devices_str() -> dict:
    return devices_info

def get_device(*, api_token):
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