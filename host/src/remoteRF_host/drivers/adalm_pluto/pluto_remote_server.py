# pluto_remote_server.py
#
# RPC handler for the ADALM-Pluto SDR.
#
# Every incoming call is validated against PLUTO_IDL before the device is
# touched.  This replaces the previous bare-getattr/setattr approach and
# creates a strict, auditable contract between the protocol layer and the
# hardware — mirroring how the server loops through device definitions when
# routing RPCs.
#
# Call routing (function_name format):  "Pluto:<attr>:<ftype>"
#   ftype ∈ { GET, SET, CALL0, CALL1 }

from __future__ import annotations

from ...common.utils.process_arg import unmap_arg, map_arg
from ...server.device_manager import get_device
from .pluto_idl import PLUTO_IDL, is_valid_call, valid_ftypes_for


class PlutoServer:

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

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
            return None, f"Unknown/disconnected device gid={gid} on this host."
        return dev, None

    @staticmethod
    def _safe_map(x):
        a = map_arg(x if x is not None else "None")
        try:
            if not a.ListFields():
                a = map_arg(str(x))
        except Exception:
            pass
        return a

    @staticmethod
    def _idl_error(fn: str, ftype: str):
        """Build an error result for an IDL-rejected call."""
        entry = PLUTO_IDL.get(fn)
        if entry is None:
            msg = f"'{fn}' is not a recognised Pluto attribute."
        else:
            allowed = valid_ftypes_for(fn, PLUTO_IDL)
            msg = (
                f"'{fn}' does not support {ftype}. "
                f"Allowed operation(s): {', '.join(sorted(allowed)) or 'none'}."
            )
        return {fn: map_arg("None"), "IDL_Error": map_arg(msg)}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    @staticmethod
    def handle_call(*, function_name, args):
        """
        Dispatch a single RPC call.

        Steps
        -----
        1. Parse   function_name → (attr, ftype)
        2. Resolve gid → device object
        3. Validate  (attr, ftype) against PLUTO_IDL          ← IDL gate
        4. Execute  GET / SET / CALL0 / CALL1
        """
        try:
            parts = function_name.split(":")
            fn    = parts[1]
            ftype = parts[2]

            # ---- resolve device ----
            device, err = PlutoServer._resolve_device(args)
            if device is None:
                return {fn: map_arg("None"), "UE": map_arg(err)}

            # ---- IDL gate: loop through IDL to validate before touching hardware ----
            if not is_valid_call(fn, ftype, PLUTO_IDL):
                return PlutoServer._idl_error(fn, ftype)

            # ---- dispatch ----
            if ftype == "GET":
                return PlutoServer._get(fn, device)

            if ftype == "SET":
                PlutoServer._set(fn, args[fn], device)
                return {fn: map_arg("None")}

            if ftype in ("CALL0", "CALL1"):
                return PlutoServer._call(fn, ftype, args, device)

            # Should be unreachable given IDL gate above
            return {fn: map_arg("None"), "UE": map_arg(f"Unknown ftype: {ftype}")}

        except Exception as e:
            try:
                fn = function_name.split(":")[1]
            except Exception:
                fn = "Result"
            return {fn: map_arg("None"), "Error": map_arg(str(e))}

    # ------------------------------------------------------------------
    # Operation implementations
    # ------------------------------------------------------------------

    @staticmethod
    def _get(fn: str, device):
        # "repr" is synthesised — it is not a pyadi-iio attribute.
        if fn == "repr":
            return {fn: PlutoServer._safe_map(repr(device))}

        if not hasattr(device, fn):
            return {fn: map_arg("None"), "UE": map_arg(f"'{fn}' not found on device.")}
        attr = getattr(device, fn)
        val  = attr() if callable(attr) else attr
        return {fn: PlutoServer._safe_map(val)}

    @staticmethod
    def _set(fn: str, value, device):
        if not hasattr(device, fn):
            return  # caller already returns {fn: "None"}
        setattr(device, fn, unmap_arg(value))

    @staticmethod
    def _call(fn: str, ftype: str, args, device):
        method = getattr(device, fn, None)

        if ftype == "CALL0":
            if not callable(method):
                # Property accessed via CALL0 (e.g. "ip" is a pyadi-iio property,
                # but the server sends Pluto:ip:CALL0).  Return its value directly.
                if method is not None:
                    return {fn: PlutoServer._safe_map(method)}
                raise ValueError(f"Device attribute '{fn}' not found or not callable.")
            result = method()

        else:  # CALL1
            if not callable(method):
                raise ValueError(f"Device attribute '{fn}' is not callable.")
            if "arg1" not in args:
                raise ValueError("CALL1 requires 'arg1' in args.")
            result = method(unmap_arg(args["arg1"]))

        return {fn: PlutoServer._safe_map(result)}
