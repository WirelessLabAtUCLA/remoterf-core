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

from .reservation import reservation_handler
from ..common.utils import *
from .device_manager import acquire_device, VirtualDevice
from ..host import host_tunnel_server as hts

class RpcManager:
    def __init__(self):
        self.debug = False

    def run_rpc(self, *, function_name, args) -> map:
        fn_type = function_name.split(':', 1)[0]

        if fn_type == "Pluto":
            if 'a' not in args:
                return {'a': map_arg('No token provided')}

            api_token = unmap_arg(args['a'])

            try:
                with acquire_device(api_token) as (gid, dev):

                    if isinstance(dev, VirtualDevice):
                        fwd_args = dict(args)
                        fwd_args.pop('a', None)
                        fwd_args['g'] = map_arg(int(gid))
                        return hts.handle_host_device(
                            hts.get_tunnel_registry(create=False),
                            host_id=dev.host_id,
                            device_id=dev.device_id,
                            function_name=function_name,
                            args=fwd_args,
                            timeout_sec=10.0,
                        )

                    # Schema-based local dispatch.
                    # Wire format: "Pluto:{prop}:{verb}"  verb = GET | SET | CALL0 | CALL1
                    parts = function_name.split(':')
                    prop = parts[1]
                    verb = parts[2] if len(parts) > 2 else ""

                    if verb == "GET":
                        result = dev.dispatch(f"get_{prop}", {})
                        return {prop: map_arg(result)}

                    elif verb == "SET":
                        value = unmap_arg(args[prop])
                        dev.dispatch(f"set_{prop}", {"value": value})
                        return {}

                    elif verb == "CALL0":
                        result = dev.dispatch(f"call_{prop}", {})
                        return {prop: map_arg(result)} if result is not None else {prop: map_arg('None')}

                    elif verb == "CALL1":
                        if 'arg1' not in args:
                            raise ValueError("CALL1 requires 'arg1' in args")
                        value = unmap_arg(args['arg1'])
                        result = dev.dispatch(f"call_{prop}", {"value": value})
                        return {prop: map_arg(result)} if result is not None else {prop: map_arg('None')}

                    else:
                        raise ValueError(f"Unknown verb {verb!r} in {function_name!r}")

            except Exception as e:
                return {'a': map_arg(str(e))}

        # Future: IDL control-plane endpoints (schema discovery, generic invoke)
        # if fn_type == "IDL":
        #     return self._handle_idl(function_name.split(':', 1)[1], args)

        if fn_type == "ACC":
            return reservation_handler.handle_call(function_name=function_name.split(':', 1)[1], args=args)

        if function_name == "echo":
            return args

        return {'a': map_arg(f'Unknown RPC: {function_name}')}

rpc_manager = RpcManager()