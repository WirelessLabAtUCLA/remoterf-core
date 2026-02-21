from ...common.utils.process_arg import unmap_arg, map_arg
from ...server.device_manager import get_device  # host device_manager.get_device(id=gid)

class PlutoServer:
    @staticmethod
    def _resolve_gid(args):
        for key in ("g", "gid"):
            if key in args:
                try:
                    return int(unmap_arg(args[key]))
                except Exception:
                    return None
        return None

    @staticmethod
    def _resolve_device(args):
        gid = PlutoServer._resolve_gid(args)
        if gid is None:
            return None, "Missing device id (expected args['g'] or args['gid'])."
        dev = get_device(id=gid)
        if dev is None:
            return None, f"Unknown/Disconnected device gid={gid} on this host."
        return dev, None

    @staticmethod
    def _safe_map(x):
        a = map_arg(x if x is not None else "None")
        # If map_arg produced an empty Argument(), unmap_arg will explode later.
        try:
            if not a.ListFields():
                a = map_arg(str(x))
        except Exception:
            pass
        return a

    @staticmethod
    def handle_call(*, function_name, args):
        try:
            parts = function_name.split(':')
            fn = parts[1]
            ftype = parts[2]

            device, err = PlutoServer._resolve_device(args)
            if device is None:
                return {fn: map_arg("None"), "UE": map_arg(err)}

            if fn == "ip":
                # host-side: either no-op OR set local ip if you still support it.
                # IMPORTANT: return fn key so client doesn't unmap a missing result.
                return {fn: map_arg("None")}

            if ftype == "GET":
                return PlutoServer.get(function_name=fn, device=device)

            if ftype == "SET":
                PlutoServer.set(function_name=fn, value=args[fn], device=device)
                # IMPORTANT: return fn key (don't return {})
                return {fn: map_arg("None")}

            if ftype in ("CALL0", "CALL1"):
                return PlutoServer.call_func(
                    function_name=fn,
                    function_type=ftype,
                    args=args,
                    device=device
                )

            raise ValueError(f"Unknown function_type: {ftype}")

        except Exception as e:
            # Ensure the requested key exists even on error
            try:
                fn = function_name.split(':')[1]
            except Exception:
                fn = "Result"
            return {fn: map_arg("None"), "Error": map_arg(str(e))}

    @staticmethod
    def call_func(*, function_name, function_type, args, device):
        method = getattr(device, function_name, None)
        if not callable(method):
            raise ValueError(f"Device attribute '{function_name}' is not callable.")

        if function_type == "CALL0":
            result = method()
        elif function_type == "CALL1":
            if 'arg1' not in args:
                raise ValueError("CALL1 requires 'arg1' in args.")
            python_arg = unmap_arg(args['arg1'])
            result = method(python_arg)
        else:
            raise ValueError(f"Unsupported call type: {function_type}")

        return {function_name: PlutoServer._safe_map(result)}

    @staticmethod
    def get(*, function_name, device):
        if not hasattr(device, function_name):
            return {function_name: map_arg("None"), "UE": map_arg(f"{function_name} is not a gettable value.")}

        attr = getattr(device, function_name)
        val = attr() if callable(attr) else attr
        return {function_name: PlutoServer._safe_map(val)}

    @staticmethod
    def set(*, function_name, value, device):
        if not hasattr(device, function_name):
            return {function_name: map_arg("None"), "UE": map_arg(f"{function_name} is not a settable value.")}

        setattr(device, function_name, unmap_arg(value))
        # caller returns {fn: "None"} so client won't unmap missing key
        return {}