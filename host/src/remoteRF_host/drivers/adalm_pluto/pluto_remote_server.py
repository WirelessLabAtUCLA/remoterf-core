# from ....client import * 
from ...server.device_manager import get_device
from ...common.utils.process_arg import unmap_arg, map_arg
# from ...common.grpc import grpc_pb2
        
class PlutoServer: # server
    
    @staticmethod
    def handle_call(*, function_name, args):
        try:
            # print(f'fn {function_name}')
            
            function_name_args = function_name.split(':')
            function_name = function_name_args[1]
            function_type = function_name_args[2]
            if function_name == "ip":
                # set_pluto(ip=args[function_name].string_value.split(":")[1])
                pass
            elif function_type == "GET":
                return PlutoServer.get(function_name=function_name, token=unmap_arg(args['a']))
            elif function_type == "SET":
                PlutoServer.set(function_name=function_name, value=args[function_name], token=unmap_arg(args['a']))
                
            elif function_type in ("CALL0", "CALL1"):
                # One function to handle both zero-arg and one-arg calls
                # print(f'CALL: {function_name}, ARGS: {args}')
                
                # print(f'CALL: {function_name}, ARGS: {args}')
                
                return PlutoServer.call_func(
                    function_name=function_name,
                    function_type=function_type,
                    args=args,
                    token=unmap_arg(args['a'])
                )
            else:
                # You can decide how to handle unknown function types
                raise ValueError(f"Unknown function_type: {function_type}. Is that a function you can call?")
                
            # else:
                # return PlutoServer.other(function_name=function_name, args=args)
        except Exception as e:
            # print(f"UE: Pluto_server ln:23: {e}")
            return {function_name:map_arg('None'), "Error":map_arg(f'{e}')}
        
    @staticmethod
    def call_func(*, function_name, function_type, args, token):
        """
        Calls a device method with either 0 or 1 argument.
        function_type can be CALL0 or CALL1.
        """
        device = get_device(id=token)
        if device is None:
            return {function_name: map_arg('None'), "UE": map_arg("API Token Invalid")}

        method = getattr(device, function_name)
        if not callable(method):
            raise ValueError(f"Device attribute '{function_name}' is not callable.")

        # if PlutoServer.DEBUG:
        
        # print(f"[DEBUG] call_func: calling {function_name} on {device} with type={function_type}")
        
        # print(f"raw values: {args['arg1']}")
        
        if function_type == "CALL0":
            # Zero-argument function call
            result = method()
        elif function_type == "CALL1":
            # Single-argument function call
            if 'arg1' not in args:
                raise ValueError("Client Package: CALL1 type requires 'arg1' in args.")
            python_arg = unmap_arg(args['arg1'])
            # if PlutoServer.DEBUG:
            #     print(f"[DEBUG] call_func: unmap_arg(args['arg1']) => {python_arg}")
            # print(f"Pluto.{method} \n unmapped arg: {python_arg}")
            # print(f"unmapped values: {python_arg}")
            # print(f"{function_name} is called on {device}")
            result = method(python_arg)
        else:
            raise ValueError(f"Unsupported call type: {function_type} (arg length not supported)")

        # If the function returns something, map it back
        if result is not None:
            return {function_name: map_arg(result)}
        else:
            # If there's no return value, return some placeholder
            return {function_name: map_arg('None')}
            
    @staticmethod
    def get(*, function_name, token):
        try:
            device = get_device(api_token=token)
            if device == None:
                return {function_name:map_arg('None'), "UE":map_arg("API Token Invalid")}
            if not hasattr(device, function_name):
                return {function_name:map_arg('None'), "UE":map_arg(f'{function_name} is not a gettable value.')}
            
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
            device = get_device(api_token=token)
            if device == None:
                return {function_name:map_arg('None'), "UE":map_arg("API Token Invalid")}
            if not hasattr(device, function_name):
                return {function_name:map_arg('None'), "UE":map_arg(f'{function_name} is not a settable value.')}
            
            setattr(device, function_name, unmap_arg(value))
            return {}
        except Exception as e:
            # print(f"UE: Pluto_server ln:44: {e}")
            return {function_name:map_arg('None'), "UE":map_arg(f'{e}')}