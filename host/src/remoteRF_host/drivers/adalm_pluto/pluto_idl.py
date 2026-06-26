# pluto_idl.py
#
# Interface Description Language (IDL) for the ADALM-Pluto SDR.
#
# Each entry:
#   attr_name -> {
#       "access": "r" | "w" | "rw" | "call0" | "call1" | "calln",
#       "type":   Python type name for the return / property value,
#       "arg_type": (call1 only) Python type name for the single argument,
#       "desc":   human-readable description,
#   }
#
# "access" maps directly to the RPC function-type suffix used in the protocol:
#   "r"     -> GET only
#   "w"     -> SET only
#   "rw"    -> GET + SET
#   "call0" -> CALL0 (no argument)
#   "call1" -> CALL1 (one argument)
#   "calln" -> CALLN (named arguments)
#
# This table is the single source of truth that PlutoServer uses to validate
# every incoming RPC before touching the device.  The tunnel agent also loops
# through it to build per-device capability strings in HostMeta.kv.
#
# Keep in sync with the server's pluto_schema.py.  Protocol-level attribute
# names must match exactly (e.g. "hardwaregain_chan0", not "rx_hardwaregain_chan0").

from __future__ import annotations
from typing import Dict, Any, Set

# ---------------------------------------------------------------------------
# Pluto IDL table
# ---------------------------------------------------------------------------

PLUTO_IDL: Dict[str, Dict[str, Any]] = {
    # ---- LO / frequency ----
    "tx_lo": {
        "access": "rw",
        "type": "int",
        "desc": "TX local-oscillator frequency (Hz)",
    },
    "rx_lo": {
        "access": "rw",
        "type": "int",
        "desc": "RX local-oscillator frequency (Hz)",
    },
    # ---- sample rate / bandwidth ----
    "sample_rate": {
        "access": "rw",
        "type": "int",
        "desc": "ADC/DAC sample rate (samples/s)",
    },
    "rx_rf_bandwidth": {
        "access": "rw",
        "type": "int",
        "desc": "RX analog filter bandwidth (Hz)",
    },
    "tx_rf_bandwidth": {
        "access": "rw",
        "type": "int",
        "desc": "TX analog filter bandwidth (Hz)",
    },
    # ---- gain ----
    "gain_control_mode_chan0": {
        "access": "rw",
        "type": "str",
        "desc": "RX gain-control mode: manual | slow_attack | fast_attack | hybrid",
    },
    "hardwaregain_chan0": {
        "access": "rw",
        "type": "float",
        "desc": "RX hardware gain (dB, settable in manual mode). "
                "pyadi-iio attribute: hardwaregain_chan0",
    },
    "tx_hardwaregain_chan0": {
        "access": "rw",
        "type": "float",
        "desc": "TX hardware attenuation (dB, negative value)",
    },
    # ---- buffers / cyclic ----
    "tx_cyclic_buffer": {
        "access": "rw",
        "type": "bool",
        "desc": "Enable TX cyclic (repeating) buffer mode",
    },
    "rx_buffer_size": {
        "access": "rw",
        "type": "int",
        "desc": "Number of complex samples per RX capture buffer",
    },
    # ---- misc ----
    "loopback": {
        "access": "rw",
        "type": "int",
        "desc": "Internal loopback: 0=off, 1=digital, 2=RF",
    },
    "filter": {
        "access": "rw",
        "type": "str",
        "desc": "FIR filter coefficient file path or CSV string",
    },
    # ---- FPGA filter flags ----
    "rx_dec8_filter_en": {
        "access": "rw",
        "type": "bool",
        "desc": "Enable decimate-by-8 FPGA filter on RX path",
    },
    "tx_int8_filter_en": {
        "access": "rw",
        "type": "bool",
        "desc": "Enable interpolate-by-8 FPGA filter on TX path",
    },
    # ---- device info (read-only via CALL0, returns URI/IP string) ----
    # NOTE: Server sends Pluto:ip:CALL0 — returns device.uri or device.ip.
    #       PlutoServer._call handles the non-callable property case gracefully.
    "ip": {
        "access": "call0",
        "type": "str",
        "desc": "Return the device URI / IP address string (connection identifier)",
    },
    "repr": {
        "access": "r",
        "type": "str",
        "desc": "Return repr() of the underlying device object",
    },
    # ---- data methods ----
    "rx": {
        "access": "call0",
        "type": "complex_array",
        "desc": "Capture a block of IQ samples (returns complex numpy array)",
    },
    "tx": {
        "access": "call1",
        "type": "None",
        "arg_type": "complex_array",
        "desc": "Transmit a block of IQ samples (arg: complex numpy array)",
    },
    "rx_destroy_buffer": {
        "access": "call0",
        "type": "None",
        "desc": "Release the RX IIO buffer",
    },
    "tx_destroy_buffer": {
        "access": "call0",
        "type": "None",
        "desc": "Release the TX IIO buffer",
    },
    "disable_dds": {
        "access": "call0",
        "type": "None",
        "desc": "Disable the internal DDS tone generator",
    },
}


# ---------------------------------------------------------------------------
# Helper: which RPC function-type suffixes are valid for a given IDL access
# ---------------------------------------------------------------------------

_ACCESS_TO_VALID_FTYPES: Dict[str, Set[str]] = {
    "r":     {"GET"},
    "w":     {"SET"},
    "rw":    {"GET", "SET"},
    "call0": {"CALL0"},
    "call1": {"CALL1"},
    "calln": {"CALLN"},
}


def valid_ftypes_for(attr: str, idl: Dict[str, Dict[str, Any]]) -> Set[str]:
    """Return the set of valid RPC function-type suffixes for *attr* in *idl*."""
    entry = idl.get(attr)
    if entry is None:
        return set()
    return _ACCESS_TO_VALID_FTYPES.get(entry["access"], set())


def is_valid_call(attr: str, ftype: str, idl: Dict[str, Dict[str, Any]]) -> bool:
    """Return True if calling *attr* with function-type *ftype* is legal per *idl*."""
    return ftype in valid_ftypes_for(attr, idl)


def capabilities_string(idl: Dict[str, Dict[str, Any]]) -> str:
    """
    Compact, machine-readable capability string for one device type.

    Format: comma-separated  attr:access  pairs, sorted by attribute name.
    Example: "disable_dds:call0,filter:rw,hardwaregain_chan0:rw,..."
    """
    return ",".join(
        f"{attr}:{info['access']}"
        for attr, info in sorted(idl.items())
    )


# ---------------------------------------------------------------------------
# Global registry: device-type string -> IDL table
# (add new device types here as more drivers are implemented)
# ---------------------------------------------------------------------------

DEVICE_IDL_REGISTRY: Dict[str, Dict[str, Dict[str, Any]]] = {
    "adalm_pluto": PLUTO_IDL,
}


def idl_for_device_type(device_type: str) -> Dict[str, Dict[str, Any]]:
    """Return the IDL table for *device_type*, or an empty dict if unknown."""
    return DEVICE_IDL_REGISTRY.get((device_type or "").strip().lower(), {})
