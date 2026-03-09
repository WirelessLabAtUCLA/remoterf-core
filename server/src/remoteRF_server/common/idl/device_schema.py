# remoteRF_server/common/idl/schema_template.py

# Include any necessary device imports, etc!

# todo: 'throws error' if stuff isn't implemented, etc.
# todo: have device_manifest live in .config, etc. (not in codebase)

from . import * 

# todo: would import the decorators from remoteRF_server ... -> which allows any admin script to run with the platform!
# todo: you would run a 'baking the driver' (so it populates onto the .config or something with the proper version, etc. so the server knows!)

class DeviceSchema:
    
    device_type = "template" # MUST match device_type in the device manifest!
    driver_version = "0.0.1"
    
    # Returns instance of the device (ie: a class, etc!)
    # Used by the server to actually 'connect' to the hardware devices!
    # Define the proper args in the device Manifest -> pipes to this factory method to populate device list!
    # todo: kwargs are EXACTLY the 'init' section of the device manifest!
    @staticmethod
    def make_device(**kwargs):
        # Implement whatever logic you need to connect to the device (or init parameters, like BW, etc.)
        raise NotImplementedError
    
    # Called by the server on init!
    def __init__(self, device_instance):
        self.device = device_instance
    
    @idl_expose # Decorators for each 'exposed' method/property!
    def schema_info(self) -> float:
        return f"{self.device_type} v{self.driver_version}"
    
    # Example exposed method:
    @idl_expose # Decorators for each 'exposed' method/property!
    def some_method(self, arg1: float, arg2: float) -> float:
        return self.device.some_method(arg1, arg2) # EXAMPLE
        # raise NotImplementedError