# from ..drivers.adalm_pluto.pluto_remote_server import PlutoServer
# from .reservation import reservation_handler
# from ..common.utils import *
# from .device_manager import acquire_device, VirtualDevice
# from ..host import host_tunnel_server as hts  

# import sys

# class RpcManager:
#     def __init__(self):
#         self.debug = False
    
#     def run_rpc(self, *, function_name, args) -> map:
            
#         function_name_args = function_name.split(':')
        
#         # print(f"RPC: {function_name}, ARGS: {args}")
#         # try:
#         if function_name_args[0] == "Pluto":
#             if 'a' not in args:
#                 return {'a': map_arg('No token provided')}

#             api_token = unmap_arg(args['a'])

#             # Resolve once + serialize per-device I/O (local OR host)
#             with acquire_device(api_token) as (gid, dev):
#                 # Build payload for the *next stage* (local driver OR host agent)
#                 fwd_args = dict(args)
#                 fwd_args.pop('a', None)                 # remove external API token
#                 fwd_args['g'] = map_arg(int(gid))       # or map_arg(str(gid)) if your map_arg expects str

#                 if isinstance(dev, VirtualDevice):
#                     # Host pipeline
#                     return hts.forward_request(
#                         host_id=dev.host_id,
#                         device_id=dev.device_id,
#                         function_name=function_name,
#                         args=fwd_args,
#                     )
                 
#                 return {'a': map_arg('No token provided')}
#         elif function_name_args[0] == "HackRF":
#             pass
#         elif function_name_args[0] == "ACC":
#             return reservation_handler.handle_call(function_name=function_name_args[1], args=args)
        
#         if function_name == "echo":
#             return args        
    
#     def toggle_debug(self):
#         self.debug = not self.debug

from ..drivers.adalm_pluto.pluto_remote_server import PlutoServer
from .reservation import reservation_handler
from ..common.utils import *
from .device_manager import acquire_device, VirtualDevice
from ..host import host_tunnel_server as hts

class RpcManager:
    def __init__(self):
        self.debug = False

    def run_rpc(self, *, function_name, args) -> map:
        fn_type = function_name.split(':', 1)[0]
        
        print(f"RPC: {function_name}, ARGS: {args}")

        if fn_type == "Pluto":
            if 'a' not in args:
                return {'a': map_arg('No token provided')}

            api_token = unmap_arg(args['a'])

            try:
                with acquire_device(api_token) as (gid, dev):

                    if isinstance(dev, VirtualDevice):  
                        fwd_args = dict(args)
                        fwd_args.pop('a', None)            # remove external API token
                        fwd_args['g'] = map_arg(int(gid))  # or map_arg(str(gid)) if your mapper wants strings
                        
                        return hts.handle_host_device(
                            hts.get_tunnel_registry(create=False),
                            host_id=dev.host_id,
                            device_id=dev.device_id,     
                            function_name=function_name,
                            args=fwd_args,
                            timeout_sec=10.0,
                        )

                    return PlutoServer.handle_call(function_name=function_name, args=args)

            except Exception as e:
                return {'a': map_arg(str(e))}

        if fn_type == "ACC":
            return reservation_handler.handle_call(function_name=function_name.split(':', 1)[1], args=args)

        if function_name == "echo":
            return args

        return {'a': map_arg(f'Unknown RPC: {function_name}')}
        
rpc_manager = RpcManager()