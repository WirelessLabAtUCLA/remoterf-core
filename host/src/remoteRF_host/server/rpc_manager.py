# rpc_manager.py
#
# Routes incoming RPC calls to the correct device-type handler.
#
# The device-type prefix in function_name (e.g. "Pluto") is matched against
# the DEVICE_IDL_REGISTRY so routing is driven by the IDL, not hard-coded
# strings.  Adding a new driver only requires registering it in the IDL
# registry and adding the import + handler map below.

from __future__ import annotations

from ..drivers.adalm_pluto.pluto_remote_server import PlutoServer
from ..drivers.adalm_pluto.pluto_idl import DEVICE_IDL_REGISTRY
from ..common.utils import map_arg


# ---------------------------------------------------------------------------
# Handler registry  —  device_type (lowercase) → callable handler
#
# Each handler must accept:   handler(function_name=..., args=...)
# and return a result dict compatible with GenericRPCResponse.
# ---------------------------------------------------------------------------

_HANDLERS = {
    "pluto": PlutoServer.handle_call,
}

# Build a case-insensitive prefix map from IDL registry so the router stays
# in sync with whatever device types are actually registered.
_PREFIX_MAP: dict[str, str] = {
    dtype.lower(): dtype.capitalize()
    for dtype in DEVICE_IDL_REGISTRY
}


class RpcManager:
    def __init__(self):
        self.debug = False

    def run_rpc(self, *, function_name, args) -> dict:
        """
        Route *function_name* to the matching device-type handler.

        function_name format:  "<DeviceType>:<attr>:<ftype>"
        e.g.                   "Pluto:tx_lo:GET"
        """
        parts = (function_name or "").split(":", 2)
        if len(parts) < 3:
            if function_name == "echo":
                return args
            return {"Error": map_arg(f"Malformed function_name: {function_name!r}")}

        prefix = parts[0].lower()

        handler = _HANDLERS.get(prefix)
        if handler is not None:
            return handler(function_name=function_name, args=args)

        if function_name == "echo":
            return args

        return {"Error": map_arg(f"No handler registered for device type '{parts[0]}'.")}

    def toggle_debug(self):
        self.debug = not self.debug


rpc_manager = RpcManager()
