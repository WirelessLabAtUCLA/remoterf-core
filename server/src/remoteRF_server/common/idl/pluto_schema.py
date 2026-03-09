from . import *  #todo: change import to package later

import subprocess
import re
import adi

# ========================= PLUTO Connection Logic ========================= 

def connect_pluto(*, serial: str):
    serial = (serial or "").strip()
    if not serial:
        print("A Pluto serial must be provided")
        return None

    try:
        out = subprocess.check_output(
            ["iio_info", "-s"],
            text=True,
            stderr=subprocess.STDOUT
        )

        usb = None
        for line in out.splitlines():
            if (f"serial={serial}" in line) or (f"hw_serial={serial}" in line):
                m = re.search(r"\[usb:([^\]]+)\]", line)
                if m:
                    usb = m.group(1).strip()
                    break

        if not usb:
            print(f"No device found with serial {serial}")
            return None

        dev = adi.Pluto(f"usb:{usb}")
        print(f"Connected to Pluto serial={serial} via usb:{usb}")
        return dev

    except Exception as e:
        print(f"Failed to connect to Pluto serial={serial}: {e}")
        return None

# ========================= PLUTO Schema ========================= 

class PlutoSchema(DeviceSchema):
    
    device_type = "pluto" 
    driver_version = "0.0.1"
    
    @staticmethod
    def make_device(**kwargs):
        serial = kwargs.get("serial")
        return connect_pluto(serial=serial)
    
    #region ad9364
    
    @property
    @idl_expose(access="get")
    def filter(self):
        return self.device.filter
    
    @filter.setter
    @idl_expose(access="set")
    def filter(self, value):
        self.device.filter = value 
        
    @property
    @idl_expose(access="get")
    def loopback(self):
        return self.device.loopback
    
    @loopback.setter
    @idl_expose(access="set")
    def loopback(self, value):
        self.device.loopback = value
        
    @property
    @idl_expose(access="get")
    def gain_control_mode_chan0(self):
        return self.device.gain_control_mode_chan0
    
    @gain_control_mode_chan0.setter
    @idl_expose(access="set")
    def gain_control_mode_chan0(self, value):
        self.device.gain_control_mode_chan0 = value
        
    @property
    @idl_expose(access="get")
    def rx_hardwaregain_chan0(self):
        return self.device.rx_hardwaregain_chan0
    
    @rx_hardwaregain_chan0.setter
    @idl_expose(access="set")
    def rx_hardwaregain_chan0(self, value):
        self.device.rx_hardwaregain_chan0 = value
        
    @property
    @idl_expose(access="get")
    def tx_hardwaregain_chan0(self):
        return self.device.tx_hardwaregain_chan0
    
    @tx_hardwaregain_chan0.setter
    @idl_expose(access="set")
    def tx_hardwaregain_chan0(self, value):
        self.device.tx_hardwaregain_chan0 = value
    
    @property
    @idl_expose(access="get")
    def rx_rf_bandwidth(self):
        return self.device.rx_rf_bandwidth
    
    @rx_rf_bandwidth.setter
    @idl_expose(access="set")
    def rx_rf_bandwidth(self, value):
        self.device.rx_rf_bandwidth = value
        
    @property
    @idl_expose(access="get")
    def tx_rf_bandwidth(self):
        return self.device.tx_rf_bandwidth
    
    @tx_rf_bandwidth.setter
    @idl_expose(access="set")
    def tx_rf_bandwidth(self, value):
        self.device.tx_rf_bandwidth = value
        
    @property
    @idl_expose(access="get")
    def sample_rate(self):
        return self.device.sample_rate
    
    @sample_rate.setter
    @idl_expose(access="set")
    def sample_rate(self, value):
        self.device.sample_rate = value
    
    @property
    @idl_expose(access="get")
    def rx_lo(self):
        return self.device.rx_lo
    
    @rx_lo.setter
    @idl_expose(access="set")
    def rx_lo(self, value):
        self.device.rx_lo = value
    
    @property
    @idl_expose(access="get")
    def tx_lo(self):
        return self.device.tx_lo
    
    @tx_lo.setter
    @idl_expose(access="set")
    def tx_lo(self, value):
        self.device.tx_lo = value
    
    @property
    @idl_expose(access="get")
    def tx_cyclic_buffer(self):
        return self.device.tx_cyclic_buffer
    
    @tx_cyclic_buffer.setter
    @idl_expose(access="set")
    def tx_cyclic_buffer(self, value):
        self.device.tx_cyclic_buffer = value
        
        
    # region RX define
    
    @property
    @idl_expose(access="get")
    def rx(self):
        return self.device.rx()
    
    @property
    @idl_expose(access="get")
    def rx_buffer_size(self):
        return self.device.rx_buffer_size
    
    @rx_buffer_size.setter
    @idl_expose(access="set")
    def rx_buffer_size(self, value):
        self.device.rx_buffer_size = value
    
    @idl_expose
    def rx_destroy_buffer(self):
        self.device.rx_destroy_buffer()
        
    @property
    @idl_expose(access="get")
    def tx(self):
        return self.device.tx
    
    @tx.setter
    @idl_expose(access="set")
    def tx(self, value):
        self.device.tx = value
        
    @idl_expose
    def tx_destroy_buffer(self):
        self.device.tx_destroy_buffer()