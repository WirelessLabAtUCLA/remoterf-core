# rpc_manager.py

from ..drivers.adalm_pluto.pluto_remote_server import PlutoServer
# from .reservation import reservation_handler
from ..common.utils import *

import sys

class RpcManager:
    def __init__(self):
        self.debug = False
    
    def run_rpc(self, *, function_name, args) -> map:
            
        function_name_args = function_name.split(':')
        
        print(f"RPC: {function_name}, ARGS: {args}")
        
        # try:
        if function_name_args[0] == "Pluto":
            # if 'a' in args:
            return PlutoServer.handle_call(function_name=function_name, args=args)
            # else:
            #     return {'a': map_arg('No token provided')}
        
        # HOSTS don't have db !
        # elif function_name_args[0] == "ACC":
        #     return reservation_handler.handle_call(function_name=function_name_args[1], args=args)
        
        if function_name == "echo":
            return args        
    
    def toggle_debug(self):
        self.debug = not self.debug
        
rpc_manager = RpcManager()