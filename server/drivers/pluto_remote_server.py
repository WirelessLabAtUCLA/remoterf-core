# from ....client import * 
from ..server.device_manager import set_pluto, get_device as device_pluto
from ..common.utils.process_arg import unmap_arg, map_arg
# from ...common.grpc import grpc_pb2
        
class PlutoServer: # server
    
    @staticmethod
    def handle_call(*, function_name, args):
        try:
            function_name_args = function_name.split(':')
            function_name = function_name_args[1]
            function_type = function_name_args[2]
            if function_name == "ip":
                set_pluto(ip=args[function_name].string_value.split(":")[1])
            elif function_type == "GET":
                return PlutoServer.get(function_name=function_name, token=unmap_arg(args['a']))
            elif function_type == "SET":
                PlutoServer.set(function_name=function_name, value=args[function_name], token=unmap_arg(args['a']))
            # else:
                # return PlutoServer.other(function_name=function_name, args=args)
        except Exception as e:
            # print(f"UE: Pluto_server ln:23: {e}")
            return {function_name:map_arg('None'), "Error":map_arg(f'{e}')}
            
    @staticmethod
    def get(*, function_name, token):
        try:
            device = device_pluto(api_token=token)
            if device == None:
                return {function_name:map_arg('None'), "UE":map_arg("API Token Invalid")}
            attr = getattr(device, function_name)
            if callable(attr):
                return {function_name:map_arg(attr())}
            else:
                return {function_name:map_arg(attr)}
        except Exception as e:
            
            # print(f"UE: Pluto_server ln:35: {e}")
            return {function_name:map_arg('None'), "UE":map_arg(f'{e}')}
    
    @staticmethod
    def set(*, function_name, value, token):
        try:
            device = device_pluto(api_token=token)
            if device == None:
                return {function_name:map_arg('None'), "UE":map_arg("API Token Invalid")}
            setattr(device, function_name, unmap_arg(value))
            return {}
        except Exception as e:
            # print(f"UE: Pluto_server ln:44: {e}")
            return {function_name:map_arg('None'), "UE":map_arg(f'{e}')}