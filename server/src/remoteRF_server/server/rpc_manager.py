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
from ..common.grpc import grpc_pb2 as generic_pb2
from .device_manager import acquire_device, VirtualDevice, get_device_schema, find_device_id_by_name, get_device_by_id, resolve_gid_for_token
from ..host import host_tunnel_server as hts


def _normalize_device_rpc_type(value: str) -> str:
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum())


class RpcManager:
    def __init__(self):
        self.debug = False

    def run_rpc(self, *, function_name, args) -> map:
        fn_type = function_name.split(':', 1)[0]

        if fn_type == "IDL":
            return self._handle_idl(function_name.split(':', 1)[1], args)

        if fn_type == "ACC":
            return reservation_handler.handle_call(function_name=function_name.split(':', 1)[1], args=args)

        if function_name == "echo":
            return args

        if self._looks_like_device_rpc(function_name):
            return self._handle_device_rpc(function_name=function_name, args=args)

        return {'a': map_arg(f'Unknown RPC: {function_name}')}

    # ── IDL control-plane ────────────────────────────────────────────

    def _looks_like_device_rpc(self, function_name: str) -> bool:
        parts = function_name.split(':', 2)
        return len(parts) == 3 and all(parts)

    def _handle_device_rpc(self, *, function_name: str, args: dict) -> dict:
        if 'a' not in args:
            return {'a': map_arg('No token provided')}

        api_token = unmap_arg(args['a'])

        try:
            with acquire_device(api_token) as (gid, dev):
                self._validate_device_rpc_type(function_name=function_name, gid=gid, dev=dev)

                if self._should_use_builtin_ip_fallback(function_name=function_name, gid=gid, dev=dev):
                    return {"ip": map_arg(self._builtin_ip_fallback(gid=gid, dev=dev))}

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

                return self._dispatch_local_schema(function_name=function_name, args=args, dev=dev)

        except Exception as e:
            return {'a': map_arg(str(e))}

    def _validate_device_rpc_type(self, *, function_name: str, gid: int, dev: object) -> None:
        requested_type = function_name.split(':', 1)[0]
        actual_type = self._resolve_device_type(gid=gid, dev=dev)

        if not actual_type:
            return

        if _normalize_device_rpc_type(requested_type) != _normalize_device_rpc_type(actual_type):
            raise ValueError(
                f"RPC device type {requested_type!r} does not match reserved device type {actual_type!r}"
            )

    def _should_use_builtin_ip_fallback(self, *, function_name: str, gid: int, dev: object) -> bool:
        _, prop, verb = function_name.split(':', 2)
        if prop != "ip" or verb != "CALL0":
            return False

        schema = dev if hasattr(dev, "list_exposed") else get_device_schema(gid)
        if schema is None or not hasattr(schema, "list_exposed"):
            return True

        calls = schema.list_exposed().get("calls", [])
        return "call_ip" not in calls

    def _builtin_ip_fallback(self, *, gid: int, dev: object) -> str:
        actual_type = self._resolve_device_type(gid=gid, dev=dev) or "device"
        return f"{actual_type}:{int(gid)}"

    def _resolve_device_type(self, *, gid: int, dev: object) -> str:
        for candidate in (getattr(dev, "device_type", None), getattr(dev, "kind", None)):
            if candidate:
                return str(candidate)

        schema = get_device_schema(gid)
        if schema is None:
            return ""
        return str(getattr(schema, "device_type", "") or "")

    def _dispatch_local_schema(self, *, function_name: str, args: dict, dev: object) -> dict:
        _, prop, verb = function_name.split(':', 2)

        if verb == "GET":
            result = dev.dispatch(f"get_{prop}", {})
            return {prop: map_arg(result)}

        if verb == "SET":
            value = unmap_arg(args[prop])
            dev.dispatch(f"set_{prop}", {"value": value})
            return {}

        if verb == "CALL0":
            result = dev.dispatch(f"call_{prop}", {})
            return {prop: map_arg(result)} if result is not None else {prop: map_arg('None')}

        if verb == "CALL1":
            if 'arg1' not in args:
                raise ValueError("CALL1 requires 'arg1' in args")
            value = unmap_arg(args['arg1'])
            result = dev.dispatch(f"call_{prop}", {"value": value})
            return {prop: map_arg(result)} if result is not None else {prop: map_arg('None')}

        raise ValueError(f"Unknown verb {verb!r} in {function_name!r}")

    def _resolve_idl_target(self, args: dict) -> tuple[int | None, str | None]:
        if 'token' in args:
            api_token = str(unmap_arg(args['token']))
            gid = resolve_gid_for_token(api_token)
            if gid is None:
                return None, 'No schema available for this token (invalid token or device offline)'
            return gid, None

        if 'device_id' in args:
            try:
                return int(unmap_arg(args['device_id'])), None
            except (ValueError, TypeError):
                return None, 'device_id must be an integer'

        if 'device_name' in args:
            name = str(unmap_arg(args['device_name']))
            gid = find_device_id_by_name(name)
            if gid is None:
                return None, f'No device found with name {name!r}'
            return gid, None

        return None, 'IDL:get_drivers requires token, device_id, or device_name'

    def _fetch_host_idl(self, *, gid: int, dev: VirtualDevice, args: dict) -> dict:
        registry = hts.get_tunnel_registry(create=False)
        if registry is None:
            return {'error': map_arg('Host tunnel registry unavailable')}

        req = generic_pb2.GenericRPCRequest(function_name="IDL:get_drivers")
        for key, value in dict(args).items():
            if str(key) == "token":
                continue
            req.args[str(key)].CopyFrom(value)
        req.args["device_id"].CopyFrom(map_arg(int(gid)))
        req.args["g"].CopyFrom(map_arg(int(gid)))

        try:
            resp = hts.handle_host_device_request(
                registry,
                host_id=dev.host_id,
                device_id=dev.device_id,
                request=req,
                timeout_sec=10.0,
            )
        except Exception as e:
            return {'error': map_arg(str(e))}

        results = dict(resp.results)
        if 'error' in results:
            return results

        err = results.get('Error')
        if err is not None:
            return {'error': map_arg(str(unmap_arg(err)))}

        ok = results.get('Ok')
        if ok is not None:
            try:
                if not bool(unmap_arg(ok)):
                    return {'error': map_arg('Host schema fetch failed')}
            except Exception:
                return {'error': map_arg('Host schema fetch failed')}

        return results

    def _handle_idl(self, sub: str, args: dict) -> dict:
        """
        IDL:get_drivers  →  schema + driver metadata for a device.

        Args (one required):
            device_id   int     gid of the device
            device_name str     human-readable name (case-insensitive match)

        Returns:
            schema          str   full IDL as compact JSON  (parse with json.loads)
            driver_version  str   e.g. "0.0.1"
            schema_hash     str   e.g. "sha256:abcdef..."
            device_type     str   e.g. "pluto"
        """
        if sub == "get_drivers":
            gid, err = self._resolve_idl_target(args)
            if err is not None or gid is None:
                return {'error': map_arg(err or 'Unable to resolve device')}

            resolved = get_device_by_id(gid)
            dev = resolved[0] if resolved is not None else None

            if isinstance(dev, VirtualDevice):
                return self._fetch_host_idl(gid=gid, dev=dev, args=args)

            schema = get_device_schema(gid)
            if schema is None:
                return {'error': map_arg(f'No schema available for device {gid} (offline)')}

            return {
                'schema':         map_arg(schema.get_idl_json()),
                'driver_version': map_arg(schema.driver_version),
                'schema_hash':    map_arg(schema.get_idl_hash()),
                'device_type':    map_arg(schema.device_type),
            }

        return {'error': map_arg(f'Unknown IDL call: {sub!r}')}

rpc_manager = RpcManager()
