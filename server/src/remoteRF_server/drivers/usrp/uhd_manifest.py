"""Pinned UHD 4.10/B200 coverage manifest used by Dynamic IDL v2.

The manifest is intentionally independent of an installed UHD module.  A
target machine can enrich/verify it with ``tools/introspect_uhd.py``; runtime
dispatch still delegates argument coercion and hardware-specific failures to
the pinned native binding.
"""
from __future__ import annotations

import re
from typing import Iterable

from ...common.idl.v2 import build_schema, method, object_type, overload, parameter

TARGET_UHD_VERSION = "4.10.0.0"
TARGET_API_FAMILY = "uhd-python"


def canonical_uhd_version(value: object) -> str:
    """Return the upstream UHD version without distro/build metadata."""
    text = str(value or "").strip()
    if text.lower().startswith("uhd "):
        text = text[4:].strip()
    match = re.match(
        r"^(\d+)\.(\d+)\.(\d+)(?:\.(\d+|main|head))?",
        text,
        flags=re.IGNORECASE,
    )
    if match is None:
        return text.partition("-")[0].strip()
    major, minor, patch, build = match.groups()
    if build is None or build.lower() in {"main", "head"}:
        build = "0"
    return ".".join((major, minor, patch, build))


def is_supported_uhd_version(
    value: object,
    required: str = TARGET_UHD_VERSION,
) -> bool:
    return canonical_uhd_version(value) == canonical_uhd_version(required)


MULTIUSRP_METHODS = (
    # General/device/introspection
    "get_pp_string", "get_mboard_name", "get_num_mboards", "get_tree",
    "get_radio_control", "get_mb_controller", "get_usrp_rx_info",
    "get_usrp_tx_info", "get_rx_num_channels", "get_tx_num_channels",
    "get_rx_radio_channel", "get_tx_radio_channel",
    # Master clock
    "set_master_clock_rate", "get_master_clock_rate", "get_master_clock_rate_range",
    # Time and timed commands
    "get_time_now", "get_time_last_pps", "set_time_now", "set_time_next_pps",
    "set_time_unknown_pps", "get_time_synchronized", "set_command_time",
    "clear_command_time", "issue_stream_cmd",
    # Clock/time/sync sources
    "set_clock_source", "get_clock_source", "get_clock_sources",
    "set_time_source", "get_time_source", "get_time_sources",
    "set_sync_source", "get_sync_source", "get_sync_sources",
    "set_clock_source_out", "set_time_source_out",
    # Motherboard sensors
    "get_mboard_sensor_names", "get_mboard_sensor",
    # RX subdevice/rate
    "set_rx_subdev_spec", "get_rx_subdev_spec", "get_rx_subdev_name",
    "set_rx_rate", "get_rx_rate", "get_rx_rates", "set_rx_spp",
    # RX tuning/LO
    "set_rx_freq", "get_rx_freq", "get_rx_freq_range", "get_fe_rx_freq_range",
    "get_rx_lo_names", "set_rx_lo_source", "get_rx_lo_source",
    "get_rx_lo_sources", "set_rx_lo_export_enabled", "get_rx_lo_export_enabled",
    "set_rx_lo_freq", "get_rx_lo_freq", "get_rx_lo_freq_range",
    # RX gain/power
    "set_rx_gain", "get_rx_gain", "get_rx_gain_range", "get_rx_gain_names",
    "set_normalized_rx_gain", "get_normalized_rx_gain", "set_rx_agc",
    "set_rx_gain_profile", "get_rx_gain_profile", "get_rx_gain_profile_names",
    "has_rx_power_reference", "set_rx_power_reference", "get_rx_power_reference",
    "get_rx_power_range",
    # RX antenna/bandwidth/sensors/corrections
    "set_rx_antenna", "get_rx_antenna", "get_rx_antennas", "set_rx_bandwidth",
    "get_rx_bandwidth", "get_rx_bandwidth_range", "get_rx_sensor_names",
    "get_rx_sensor", "set_rx_dc_offset", "set_rx_iq_balance", "get_rx_dboard_iface",
    # TX subdevice/rate
    "set_tx_subdev_spec", "get_tx_subdev_spec", "get_tx_subdev_name",
    "set_tx_rate", "get_tx_rate", "get_tx_rates",
    # TX tuning/LO
    "set_tx_freq", "get_tx_freq", "get_tx_freq_range", "get_fe_tx_freq_range",
    "get_tx_lo_names", "set_tx_lo_source", "get_tx_lo_source",
    "get_tx_lo_sources", "set_tx_lo_export_enabled", "get_tx_lo_export_enabled",
    "set_tx_lo_freq", "get_tx_lo_freq", "get_tx_lo_freq_range",
    # TX gain/power
    "set_tx_gain", "get_tx_gain", "get_tx_gain_range", "get_tx_gain_names",
    "set_normalized_tx_gain", "get_normalized_tx_gain", "set_tx_gain_profile",
    "get_tx_gain_profile", "get_tx_gain_profile_names", "has_tx_power_reference",
    "set_tx_power_reference", "get_tx_power_reference", "get_tx_power_range",
    # TX antenna/bandwidth/sensors/corrections
    "set_tx_antenna", "get_tx_antenna", "get_tx_antennas", "set_tx_bandwidth",
    "get_tx_bandwidth", "get_tx_bandwidth_range", "get_tx_sensor_names",
    "get_tx_sensor", "set_tx_dc_offset", "set_tx_iq_balance", "get_tx_dboard_iface",
    # Streaming/GPIO/filters/registers
    "get_rx_stream", "get_tx_stream", "get_gpio_banks", "set_gpio_attr",
    "get_gpio_attr", "get_gpio_srcs", "get_gpio_src", "set_gpio_src",
    "get_gpio_src_banks",
    "get_rx_filter_names", "get_rx_filter", "set_rx_filter",
    "get_tx_filter_names", "get_tx_filter", "set_tx_filter",
    "set_user_register", "get_user_settings_iface",
    # Python convenience wrapper
    "recv_num_samps", "send_waveform",
)

OPTIONAL_METHODS = {
    "get_radio_control", "get_mb_controller", "get_rx_radio_channel",
    "get_tx_radio_channel", "set_rx_spp", "get_gpio_srcs", "get_gpio_src",
    "set_gpio_src", "get_gpio_src_banks",
}

HANDLE_RETURN_METHODS = {
    "get_tree": "uhd.property_tree",
    "get_radio_control": "uhd.usrp.radio_control",
    "get_mb_controller": "uhd.usrp.mboard_controller",
    "get_rx_dboard_iface": "uhd.usrp.dboard_iface",
    "get_tx_dboard_iface": "uhd.usrp.dboard_iface",
    "get_user_settings_iface": "uhd.usrp.user_settings_iface",
    "get_rx_stream": "uhd.usrp.RXStreamer",
    "get_tx_stream": "uhd.usrp.TXStreamer",
}

HANDLE_METHOD_RETURN_TYPES = {
    ("uhd.property_tree", "subtree"): "uhd.property_tree",
    ("uhd.property_tree", "access_bool"): "uhd.property.bool",
    ("uhd.property_tree", "access_int"): "uhd.property.int",
    ("uhd.property_tree", "access_double"): "uhd.property.double",
    ("uhd.property_tree", "access_str"): "uhd.property.str",
    ("uhd.property_tree", "access_device_addr"): "uhd.property.device_addr",
    ("uhd.property_tree", "access_dboard_iface"): "uhd.property.dboard_iface",
    ("uhd.property.dboard_iface", "get"): "uhd.usrp.dboard_iface",
    ("uhd.property.dboard_iface", "get_desired"): "uhd.usrp.dboard_iface",
}

USRP2901_UNSUPPORTED_HANDLE_TYPES = {
    "uhd.usrp.radio_control",
    "uhd.usrp.mboard_controller",
    "uhd.usrp.dboard_iface",
    "uhd.usrp.user_settings_iface",
}


def _optional(name: str, wire_type: str, default) -> dict:
    return parameter(name, wire_type, required=False, default=default)


_ALL_INDEXES = (1 << 64) - 1


def _positional(name: str, wire_type: str) -> dict:
    return parameter(name, wire_type, kind="positional_only")


def _signatures() -> dict[str, list[dict]]:
    chan = _optional("chan", "int", 0)
    mboard = _optional("mboard", "int", 0)
    return {
        "get_pp_string": [overload("default", returns="str")],
        "get_num_mboards": [overload("default", returns="int")],
        "get_mboard_name": [overload("default", [mboard], returns="str")],
        "get_rx_num_channels": [overload("default", returns="int")],
        "get_tx_num_channels": [overload("default", returns="int")],
        "set_master_clock_rate": [
            overload("rate", [parameter("rate", "float")], returns="None"),
            overload("rate_mboard", [parameter("rate", "float"), mboard], returns="None"),
        ],
        "get_master_clock_rate": [overload("default", [mboard], returns="float")],
        "get_time_now": [overload("default", [mboard], returns="uhd.types.TimeSpec")],
        "get_time_last_pps": [overload("default", [mboard], returns="uhd.types.TimeSpec")],
        "set_time_now": [
            overload("default", [parameter("time_spec", "uhd.types.TimeSpec"), mboard], returns="None")
        ],
        "set_time_next_pps": [
            overload("default", [parameter("time_spec", "uhd.types.TimeSpec"), mboard], returns="None")
        ],
        "set_time_unknown_pps": [
            overload("default", [parameter("time_spec", "uhd.types.TimeSpec")], returns="None")
        ],
        "set_clock_source": [
            overload("default", [parameter("source", "str"), mboard], returns="None")
        ],
        "set_time_source": [
            overload("default", [parameter("source", "str"), mboard], returns="None")
        ],
        "get_clock_source": [overload("default", [mboard], returns="str")],
        "get_time_source": [overload("default", [mboard], returns="str")],
        "get_clock_sources": [overload("default", [mboard], returns="list[str]")],
        "get_time_sources": [overload("default", [mboard], returns="list[str]")],
        "set_rx_rate": [
            overload("default", [parameter("rate", "float"), chan], returns="None")
        ],
        "get_rx_rate": [overload("default", [chan], returns="float")],
        "set_tx_rate": [
            overload("default", [parameter("rate", "float"), chan], returns="None")
        ],
        "get_tx_rate": [overload("default", [chan], returns="float")],
        "set_rx_freq": [
            overload(
                "default",
                [parameter("tune_request", "float|uhd.types.TuneRequest"), chan],
                returns="uhd.types.TuneResult",
            )
        ],
        "set_tx_freq": [
            overload(
                "default",
                [parameter("tune_request", "float|uhd.types.TuneRequest"), chan],
                returns="uhd.types.TuneResult",
            )
        ],
        "get_rx_freq": [overload("default", [chan], returns="float")],
        "get_tx_freq": [overload("default", [chan], returns="float")],
        "set_rx_gain": [
            overload("gain_chan", [parameter("gain", "float"), chan], returns="None"),
            overload(
                "gain_name_chan",
                [parameter("gain", "float"), parameter("name", "str"), chan],
                returns="None",
            ),
        ],
        "set_tx_gain": [
            overload("gain_chan", [parameter("gain", "float"), chan], returns="None"),
            overload(
                "gain_name_chan",
                [parameter("gain", "float"), parameter("name", "str"), chan],
                returns="None",
            ),
        ],
        "get_rx_gain": [
            overload("chan", [chan], returns="float"),
            overload("name_chan", [parameter("name", "str"), chan], returns="float"),
        ],
        "get_tx_gain": [
            overload("chan", [chan], returns="float"),
            overload("name_chan", [parameter("name", "str"), chan], returns="float"),
        ],
        "get_rx_stream": [
            overload("default", [parameter("stream_args", "uhd.usrp.StreamArgs")], returns="uhd.usrp.RXStreamer")
        ],
        "get_tx_stream": [
            overload("default", [parameter("stream_args", "uhd.usrp.StreamArgs")], returns="uhd.usrp.TXStreamer")
        ],
        "recv_num_samps": [
            overload(
                "default",
                [
                    parameter("num_samps", "int"),
                    parameter("freq", "float"),
                    parameter("rate", "float"),
                    parameter("channels", "list[int]"),
                    _optional("gain", "float", 10),
                ],
                returns="ndarray",
            )
        ],
        "send_waveform": [
            overload(
                "default",
                [
                    parameter("waveform_proto", "ndarray"),
                    parameter("duration", "float"),
                    parameter("freq", "float"),
                    parameter("rate", "float"),
                    parameter("channels", "list[int]"),
                    _optional("gain", "float", 10),
                ],
                returns="None",
            )
        ],
    }


def _control_signatures() -> dict[str, list[dict]]:
    chan = _optional("chan", "int", 0)
    mboard = _optional("mboard", "int", 0)
    all_chan = _optional("chan", "int", _ALL_INDEXES)
    all_mboards = _optional("mboard", "int", _ALL_INDEXES)
    return {
        "get_tree": [overload("default", returns="uhd.property_tree")],
        "get_radio_control": [
            overload("default", [chan], returns="uhd.usrp.radio_control")
        ],
        "get_mb_controller": [
            overload("default", [mboard], returns="uhd.usrp.mboard_controller")
        ],
        "get_usrp_rx_info": [
            overload("default", [chan], returns="dict[str,str]")
        ],
        "get_usrp_tx_info": [
            overload("default", [chan], returns="dict[str,str]")
        ],
        "get_rx_radio_channel": [overload("default", [chan], returns="int")],
        "get_tx_radio_channel": [overload("default", [chan], returns="int")],
        "set_master_clock_rate": [
            overload(
                "default",
                [parameter("rate", "float"), all_mboards],
                returns="None",
            )
        ],
        "get_master_clock_rate_range": [
            overload(
                "default",
                [all_mboards],
                returns="uhd.types.MetaRange",
            )
        ],
        "set_time_now": [
            overload(
                "default",
                [parameter("time_spec", "uhd.types.TimeSpec"), all_mboards],
                returns="None",
            )
        ],
        "set_time_next_pps": [
            overload(
                "default",
                [parameter("time_spec", "uhd.types.TimeSpec"), all_mboards],
                returns="None",
            )
        ],
        "set_time_unknown_pps": [
            overload(
                "default",
                [_positional("time_spec", "uhd.types.TimeSpec")],
                returns="None",
            )
        ],
        "get_time_synchronized": [overload("default", returns="bool")],
        "set_command_time": [
            overload(
                "default",
                [parameter("time_spec", "uhd.types.TimeSpec"), all_mboards],
                returns="None",
            )
        ],
        "clear_command_time": [
            overload("default", [all_mboards], returns="None")
        ],
        "issue_stream_cmd": [
            overload(
                "default",
                [parameter("rate", "uhd.types.StreamCMD"), all_chan],
                returns="None",
            )
        ],
        "set_clock_source": [
            overload(
                "default",
                [parameter("source", "str"), all_mboards],
                returns="None",
            )
        ],
        "set_time_source": [
            overload(
                "default",
                [parameter("source", "str"), all_mboards],
                returns="None",
            )
        ],
        "get_clock_source": [
            overload("default", [_positional("mboard", "int")], returns="str")
        ],
        "get_time_source": [
            overload("default", [_positional("mboard", "int")], returns="str")
        ],
        "get_clock_sources": [
            overload(
                "default",
                [_positional("mboard", "int")],
                returns="list[str]",
            )
        ],
        "get_time_sources": [
            overload(
                "default",
                [_positional("mboard", "int")],
                returns="list[str]",
            )
        ],
        "set_sync_source": [
            overload(
                "clock_time",
                [
                    parameter("clock_source", "str"),
                    parameter("time_source", "str"),
                    all_mboards,
                ],
                returns="None",
            ),
            overload(
                "device_addr",
                [
                    parameter("sync_source", "uhd.types.DeviceAddr"),
                    all_mboards,
                ],
                returns="None",
            ),
        ],
        "get_sync_source": [
            overload(
                "default",
                [_positional("mboard", "int")],
                returns="uhd.types.DeviceAddr",
            )
        ],
        "get_sync_sources": [
            overload(
                "default",
                [_positional("mboard", "int")],
                returns="list[uhd.types.DeviceAddr]",
            )
        ],
        "set_clock_source_out": [
            overload(
                "default",
                [parameter("enb", "bool"), all_mboards],
                returns="None",
            )
        ],
        "set_time_source_out": [
            overload(
                "default",
                [parameter("enb", "bool"), all_mboards],
                returns="None",
            )
        ],
        "get_mboard_sensor_names": [
            overload("default", [mboard], returns="list[str]")
        ],
        "get_mboard_sensor": [
            overload(
                "default",
                [parameter("name", "str"), mboard],
                returns="uhd.types.SensorValue",
            )
        ],
    }


def _rx_signatures() -> dict[str, list[dict]]:
    chan = _optional("chan", "int", 0)
    mboard = _optional("mboard", "int", 0)
    all_chan = _optional("chan", "int", _ALL_INDEXES)
    all_mboards = _optional("mboard", "int", _ALL_INDEXES)
    lo_name = _optional("name", "str", "all")
    return {
        "set_rx_subdev_spec": [
            overload(
                "default",
                [parameter("spec", "uhd.usrp.SubdevSpec"), all_mboards],
                returns="None",
            )
        ],
        "get_rx_subdev_spec": [
            overload("default", [mboard], returns="uhd.usrp.SubdevSpec")
        ],
        "get_rx_subdev_name": [overload("default", [chan], returns="str")],
        "set_rx_rate": [
            overload(
                "default",
                [parameter("rate", "float"), all_chan],
                returns="None",
            )
        ],
        "get_rx_rates": [
            overload("default", [chan], returns="uhd.types.MetaRange")
        ],
        "set_rx_spp": [
            overload(
                "default",
                [parameter("spp", "int"), all_chan],
                returns="None",
            )
        ],
        "get_rx_freq_range": [
            overload("default", [chan], returns="uhd.types.MetaRange")
        ],
        "get_fe_rx_freq_range": [
            overload("default", [chan], returns="uhd.types.MetaRange")
        ],
        "get_rx_lo_names": [
            overload("default", [chan], returns="list[str]")
        ],
        "set_rx_lo_source": [
            overload(
                "default",
                [parameter("src", "str"), lo_name, chan],
                returns="None",
            )
        ],
        "get_rx_lo_source": [
            overload("default", [lo_name, chan], returns="str")
        ],
        "get_rx_lo_sources": [
            overload("default", [lo_name, chan], returns="list[str]")
        ],
        "set_rx_lo_export_enabled": [
            overload(
                "default",
                [parameter("enb", "bool"), lo_name, chan],
                returns="None",
            )
        ],
        "get_rx_lo_export_enabled": [
            overload("default", [lo_name, chan], returns="bool")
        ],
        "set_rx_lo_freq": [
            overload(
                "default",
                [
                    parameter("freq", "float"),
                    parameter("name", "str"),
                    chan,
                ],
                returns="float",
            )
        ],
        "get_rx_lo_freq": [
            overload(
                "default",
                [parameter("name", "str"), chan],
                returns="float",
            )
        ],
        "get_rx_lo_freq_range": [
            overload(
                "default",
                [parameter("name", "str"), chan],
                returns="uhd.types.MetaRange",
            )
        ],
        "get_rx_gain_range": [
            overload(
                "name_chan",
                [parameter("name", "str"), chan],
                returns="uhd.types.MetaRange",
            ),
            overload("chan", [chan], returns="uhd.types.MetaRange"),
        ],
        "get_rx_gain_names": [
            overload("default", [chan], returns="list[str]")
        ],
        "set_normalized_rx_gain": [
            overload(
                "default",
                [parameter("gain", "float"), chan],
                returns="None",
            )
        ],
        "get_normalized_rx_gain": [
            overload("default", [chan], returns="float")
        ],
        "set_rx_agc": [
            overload(
                "default",
                [parameter("enable", "bool"), chan],
                returns="None",
            )
        ],
        "set_rx_gain_profile": [
            overload(
                "default",
                [parameter("profile", "str"), chan],
                returns="None",
            )
        ],
        "get_rx_gain_profile": [
            overload("default", [chan], returns="str")
        ],
        "get_rx_gain_profile_names": [
            overload("default", [chan], returns="list[str]")
        ],
        "has_rx_power_reference": [
            overload("default", [chan], returns="bool")
        ],
        "set_rx_power_reference": [
            overload(
                "default",
                [parameter("power_dbm", "float"), chan],
                returns="None",
            )
        ],
        "get_rx_power_reference": [
            overload("default", [chan], returns="float")
        ],
        "get_rx_power_range": [
            overload("default", [chan], returns="uhd.types.MetaRange")
        ],
        "set_rx_antenna": [
            overload(
                "default",
                [parameter("ant", "str"), chan],
                returns="None",
            )
        ],
        "get_rx_antenna": [overload("default", [chan], returns="str")],
        "get_rx_antennas": [
            overload("default", [chan], returns="list[str]")
        ],
        "set_rx_bandwidth": [
            overload(
                "default",
                [parameter("bandwidth", "float"), chan],
                returns="None",
            )
        ],
        "get_rx_bandwidth": [
            overload("default", [chan], returns="float")
        ],
        "get_rx_bandwidth_range": [
            overload("default", [chan], returns="uhd.types.MetaRange")
        ],
        "get_rx_sensor_names": [
            overload("default", [chan], returns="list[str]")
        ],
        "get_rx_sensor": [
            overload(
                "default",
                [parameter("name", "str"), chan],
                returns="uhd.types.SensorValue",
            )
        ],
        "set_rx_dc_offset": [
            overload(
                "offset",
                [parameter("offset", "complex"), chan],
                returns="None",
            ),
            overload(
                "enable",
                [parameter("enb", "bool"), chan],
                returns="None",
            ),
        ],
        "set_rx_iq_balance": [
            overload(
                "correction",
                [parameter("correction", "complex"), chan],
                returns="None",
            ),
            overload(
                "enable",
                [parameter("enb", "bool"), chan],
                returns="None",
            ),
        ],
        "get_rx_dboard_iface": [
            overload("default", [chan], returns="uhd.usrp.dboard_iface")
        ],
    }


def _tx_signatures() -> dict[str, list[dict]]:
    chan = _optional("chan", "int", 0)
    mboard = _optional("mboard", "int", 0)
    all_chan = _optional("chan", "int", _ALL_INDEXES)
    all_mboards = _optional("mboard", "int", _ALL_INDEXES)
    lo_name = _optional("name", "str", "all")
    return {
        "set_tx_subdev_spec": [
            overload(
                "default",
                [parameter("spec", "uhd.usrp.SubdevSpec"), all_mboards],
                returns="None",
            )
        ],
        "get_tx_subdev_spec": [
            overload("default", [mboard], returns="uhd.usrp.SubdevSpec")
        ],
        "get_tx_subdev_name": [overload("default", [chan], returns="str")],
        "set_tx_rate": [
            overload(
                "default",
                [parameter("rate", "float"), all_chan],
                returns="None",
            )
        ],
        "get_tx_rates": [
            overload("default", [chan], returns="uhd.types.MetaRange")
        ],
        "get_tx_freq_range": [
            overload("default", [chan], returns="uhd.types.MetaRange")
        ],
        "get_fe_tx_freq_range": [
            overload("default", [chan], returns="uhd.types.MetaRange")
        ],
        "get_tx_lo_names": [
            overload("default", [chan], returns="list[str]")
        ],
        "set_tx_lo_source": [
            overload(
                "default",
                [parameter("src", "str"), lo_name, chan],
                returns="None",
            )
        ],
        "get_tx_lo_source": [
            overload("default", [lo_name, chan], returns="str")
        ],
        "get_tx_lo_sources": [
            overload("default", [lo_name, chan], returns="list[str]")
        ],
        "set_tx_lo_export_enabled": [
            overload(
                "default",
                [parameter("enb", "bool"), lo_name, chan],
                returns="None",
            )
        ],
        "get_tx_lo_export_enabled": [
            overload("default", [lo_name, chan], returns="bool")
        ],
        "set_tx_lo_freq": [
            overload(
                "default",
                [
                    parameter("freq", "float"),
                    parameter("name", "str"),
                    chan,
                ],
                returns="float",
            )
        ],
        "get_tx_lo_freq": [
            overload(
                "default",
                [parameter("name", "str"), chan],
                returns="float",
            )
        ],
        "get_tx_lo_freq_range": [
            overload(
                "default",
                [parameter("name", "str"), chan],
                returns="uhd.types.MetaRange",
            )
        ],
        "get_tx_gain_range": [
            overload(
                "name_chan",
                [parameter("name", "str"), chan],
                returns="uhd.types.MetaRange",
            ),
            overload("chan", [chan], returns="uhd.types.MetaRange"),
        ],
        "get_tx_gain_names": [
            overload("default", [chan], returns="list[str]")
        ],
        "set_normalized_tx_gain": [
            overload(
                "default",
                [parameter("gain", "float"), chan],
                returns="None",
            )
        ],
        "get_normalized_tx_gain": [
            overload("default", [chan], returns="float")
        ],
        "set_tx_gain_profile": [
            overload(
                "default",
                [parameter("profile", "str"), chan],
                returns="None",
            )
        ],
        "get_tx_gain_profile": [
            overload("default", [chan], returns="str")
        ],
        "get_tx_gain_profile_names": [
            overload("default", [chan], returns="list[str]")
        ],
        "has_tx_power_reference": [
            overload("default", [chan], returns="bool")
        ],
        "set_tx_power_reference": [
            overload(
                "default",
                [parameter("power_dbm", "float"), chan],
                returns="None",
            )
        ],
        "get_tx_power_reference": [
            overload("default", [chan], returns="float")
        ],
        "get_tx_power_range": [
            overload("default", [chan], returns="uhd.types.MetaRange")
        ],
        "set_tx_antenna": [
            overload(
                "default",
                [parameter("ant", "str"), chan],
                returns="None",
            )
        ],
        "get_tx_antenna": [overload("default", [chan], returns="str")],
        "get_tx_antennas": [
            overload("default", [chan], returns="list[str]")
        ],
        "set_tx_bandwidth": [
            overload(
                "default",
                [parameter("bandwidth", "float"), chan],
                returns="None",
            )
        ],
        "get_tx_bandwidth": [
            overload("default", [chan], returns="float")
        ],
        "get_tx_bandwidth_range": [
            overload("default", [chan], returns="uhd.types.MetaRange")
        ],
        "get_tx_sensor_names": [
            overload("default", [chan], returns="list[str]")
        ],
        "get_tx_sensor": [
            overload(
                "default",
                [parameter("name", "str"), chan],
                returns="uhd.types.SensorValue",
            )
        ],
        "set_tx_dc_offset": [
            overload(
                "default",
                [parameter("offset", "complex"), chan],
                returns="None",
            )
        ],
        "set_tx_iq_balance": [
            overload(
                "default",
                [parameter("correction", "complex"), chan],
                returns="None",
            )
        ],
        "get_tx_dboard_iface": [
            overload("default", [chan], returns="uhd.usrp.dboard_iface")
        ],
    }


def _interface_signatures() -> dict[str, list[dict]]:
    chan = _optional("chan", "int", 0)
    mboard = _optional("mboard", "int", 0)
    all_mboards = _optional("mboard", "int", _ALL_INDEXES)
    return {
        "get_rx_stream": [
            overload(
                "default",
                [_positional("stream_args", "uhd.usrp.StreamArgs")],
                returns="uhd.usrp.RXStreamer",
            )
        ],
        "get_tx_stream": [
            overload(
                "default",
                [_positional("stream_args", "uhd.usrp.StreamArgs")],
                returns="uhd.usrp.TXStreamer",
            )
        ],
        "get_gpio_banks": [
            overload(
                "default",
                [_positional("mboard", "int")],
                returns="list[str]",
            )
        ],
        "set_gpio_attr": [
            overload(
                "default",
                [
                    parameter("bank", "str"),
                    parameter("attr", "str"),
                    parameter("value", "int"),
                    _optional("mask", "int", (1 << 32) - 1),
                    mboard,
                ],
                returns="None",
            )
        ],
        "get_gpio_attr": [
            overload(
                "default",
                [
                    parameter("bank", "str"),
                    parameter("attr", "str"),
                    mboard,
                ],
                returns="int",
            )
        ],
        "get_gpio_srcs": [
            overload(
                "default",
                [parameter("bank", "str"), mboard],
                returns="list[str]",
            )
        ],
        "get_gpio_src": [
            overload(
                "default",
                [parameter("bank", "str"), mboard],
                returns="list[str]",
            )
        ],
        "set_gpio_src": [
            overload(
                "default",
                [
                    parameter("bank", "str"),
                    parameter("src", "list[str]"),
                    mboard,
                ],
                returns="None",
            )
        ],
        "get_gpio_src_banks": [
            overload("default", [mboard], returns="list[str]")
        ],
        "get_rx_filter_names": [
            overload(
                "default",
                [_positional("chan", "int")],
                returns="list[str]",
            )
        ],
        "get_rx_filter": [
            overload(
                "default",
                [
                    _positional("name", "str"),
                    _positional("chan", "int"),
                ],
                returns="uhd.filters.FilterInfoBase",
            )
        ],
        "set_rx_filter": [
            overload(
                "default",
                [
                    _positional("name", "str"),
                    _positional("filter", "uhd.filters.FilterInfoBase"),
                    _positional("chan", "int"),
                ],
                returns="None",
            )
        ],
        "get_tx_filter_names": [
            overload(
                "default",
                [_positional("chan", "int")],
                returns="list[str]",
            )
        ],
        "get_tx_filter": [
            overload(
                "default",
                [
                    _positional("name", "str"),
                    _positional("chan", "int"),
                ],
                returns="uhd.filters.FilterInfoBase",
            )
        ],
        "set_tx_filter": [
            overload(
                "default",
                [
                    _positional("name", "str"),
                    _positional("filter", "uhd.filters.FilterInfoBase"),
                    _positional("chan", "int"),
                ],
                returns="None",
            )
        ],
        "set_user_register": [
            overload(
                "default",
                [
                    parameter("addr", "int"),
                    parameter("data", "int"),
                    all_mboards,
                ],
                returns="None",
            )
        ],
        "get_user_settings_iface": [
            overload(
                "default",
                [chan],
                returns="uhd.usrp.user_settings_iface",
            )
        ],
    }


def _convenience_signatures() -> dict[str, list[dict]]:
    return {
        "recv_num_samps": [
            overload(
                "default",
                [
                    parameter("num_samps", "int"),
                    parameter("freq", "float"),
                    _optional("rate", "float", 1_000_000.0),
                    _optional("channels", "list[int]", [0]),
                    _optional("gain", "float", 10),
                    _optional(
                        "start_time",
                        "uhd.types.TimeSpec|None",
                        None,
                    ),
                    _optional(
                        "streamer",
                        "uhd.usrp.RXStreamer|None",
                        None,
                    ),
                ],
                returns="ndarray",
            )
        ],
        "send_waveform": [
            overload(
                "default",
                [
                    parameter("waveform_proto", "ndarray"),
                    parameter("duration", "float"),
                    parameter("freq", "float"),
                    _optional("rate", "float", 1_000_000.0),
                    _optional("channels", "list[int]", [0]),
                    _optional("gain", "float", 10),
                    _optional(
                        "start_time",
                        "uhd.types.TimeSpec|None",
                        None,
                    ),
                    _optional(
                        "streamer",
                        "uhd.usrp.TXStreamer|None",
                        None,
                    ),
                ],
                returns="int",
            )
        ],
    }


def _fallback_overload() -> list[dict]:
    return [
        overload(
            "native",
            [
                parameter("args", "list", kind="var_positional"),
                parameter("kwargs", "dict", kind="var_keyword"),
            ],
            returns="any",
            doc="Signature is verified from the pinned UHD module on the target server.",
        )
    ]


def _enum(path: str, values: Iterable[str]) -> dict:
    return object_type(path, kind="enum", values=values)


def _objects() -> list[dict]:
    value = lambda path, codec, **kwargs: object_type(  # noqa: E731
        path, kind="value_class", codec=codec, **kwargs
    )
    return [
        object_type("uhd", kind="namespace"),
        object_type("uhd.usrp", kind="namespace"),
        object_type("uhd.types", kind="namespace"),
        object_type("uhd.filters", kind="namespace"),
        object_type("uhd.property", kind="namespace"),
        value(
            "uhd.types.TimeSpec",
            "uhd.time_spec.v1",
            aliases=["uhd.libpyuhd.types.time_spec"],
            constructors=[
                overload("real_secs", [parameter("real_secs", "float")], returns="uhd.types.TimeSpec"),
                overload(
                    "full_frac",
                    [parameter("full_secs", "int"), parameter("frac_secs", "float")],
                    returns="uhd.types.TimeSpec",
                ),
            ],
            methods=[
                "get_real_secs", "get_full_secs", "get_frac_secs", "to_ticks",
                "get_tick_count", "from_ticks",
            ],
        ),
        value(
            "uhd.types.DeviceAddr",
            "uhd.device_addr.v1",
            aliases=["uhd.libpyuhd.types.device_addr"],
            methods=["to_string", "keys", "get", "update"],
        ),
        value("uhd.types.Range", "uhd.range.v1", methods=["start", "stop", "step", "clip"]),
        value("uhd.types.MetaRange", "uhd.meta_range.v1", methods=["start", "stop", "step", "clip"]),
        value(
            "uhd.types.TuneRequest",
            "uhd.tune_request.v1",
            aliases=["uhd.libpyuhd.types.tune_request"],
            mutability="inout",
        ),
        value("uhd.types.TuneResult", "uhd.tune_result.v1"),
        value("uhd.usrp.SubdevSpec", "uhd.subdev_spec.v1"),
        value("uhd.usrp.SubdevSpecPair", "uhd.subdev_spec_pair.v1"),
        value("uhd.usrp.StreamArgs", "uhd.stream_args.v1", mutability="inout"),
        value("uhd.types.StreamCMD", "uhd.stream_cmd.v1", mutability="inout"),
        value("uhd.types.RXMetadata", "uhd.rx_metadata.v1", mutability="inout"),
        value("uhd.types.TXMetadata", "uhd.tx_metadata.v1", mutability="inout"),
        value("uhd.types.TXAsyncMetadata", "uhd.tx_async_metadata.v1", mutability="inout"),
        value("uhd.types.SensorValue", "uhd.sensor_value.v1"),
        value(
            "uhd.filters.FilterInfoBase",
            "uhd.filter.v1",
            constructors=[
                overload(
                    "default",
                    [
                        parameter(
                            "filter_type",
                            "uhd.filters.FilterType",
                            kind="positional_only",
                        ),
                        parameter("bypassed", "bool", kind="positional_only"),
                        parameter("position", "int", kind="positional_only"),
                    ],
                    returns="uhd.filters.FilterInfoBase",
                )
            ],
            methods=["is_bypassed", "get_type"],
        ),
        object_type(
            "uhd.filters.AnalogFilterBase",
            kind="value_class",
            constructors=[
                overload(
                    "default",
                    [
                        parameter(
                            "filter_type",
                            "uhd.filters.FilterType",
                            kind="positional_only",
                        ),
                        parameter("bypassed", "bool", kind="positional_only"),
                        parameter("position", "int", kind="positional_only"),
                        parameter("analog_type", "str", kind="positional_only"),
                    ],
                    returns="uhd.filters.AnalogFilterBase",
                )
            ],
            methods=["is_bypassed", "get_type", "get_analog_type"],
        ),
        object_type(
            "uhd.filters.AnalogFilterLP",
            kind="value_class",
            constructors=[
                overload(
                    "default",
                    [
                        parameter(
                            "filter_type",
                            "uhd.filters.FilterType",
                            kind="positional_only",
                        ),
                        parameter("bypassed", "bool", kind="positional_only"),
                        parameter("position", "int", kind="positional_only"),
                        parameter("analog_type", "str", kind="positional_only"),
                        parameter("cutoff", "float", kind="positional_only"),
                        parameter("rolloff", "float", kind="positional_only"),
                    ],
                    returns="uhd.filters.AnalogFilterLP",
                )
            ],
            methods=[
                "is_bypassed", "get_type", "get_analog_type",
                "get_cutoff", "get_rolloff", "set_cutoff",
            ],
        ),
        object_type(
            "uhd.filters.DigitalFilterBaseI16",
            kind="value_class",
            constructors=[
                overload(
                    "default",
                    [
                        parameter(
                            "filter_type",
                            "uhd.filters.FilterType",
                            kind="positional_only",
                        ),
                        parameter("bypassed", "bool", kind="positional_only"),
                        parameter("position", "int", kind="positional_only"),
                        parameter("input_rate", "float", kind="positional_only"),
                        parameter("interpolation", "int", kind="positional_only"),
                        parameter("decimation", "int", kind="positional_only"),
                        parameter("tap_full_scale", "int", kind="positional_only"),
                        parameter("max_num_taps", "int", kind="positional_only"),
                        parameter("taps", "list[int]", kind="positional_only"),
                    ],
                    returns="uhd.filters.DigitalFilterBaseI16",
                )
            ],
            methods=[
                "is_bypassed", "get_type", "get_output_rate",
                "get_input_rate", "get_interpolation", "get_decimation",
                "get_tap_full_scale", "get_taps",
            ],
        ),
        object_type(
            "uhd.filters.DigitalFilterFIRI16",
            kind="value_class",
            constructors=[
                overload(
                    "default",
                    [
                        parameter(
                            "filter_type",
                            "uhd.filters.FilterType",
                            kind="positional_only",
                        ),
                        parameter("bypassed", "bool", kind="positional_only"),
                        parameter("position", "int", kind="positional_only"),
                        parameter("input_rate", "float", kind="positional_only"),
                        parameter("interpolation", "int", kind="positional_only"),
                        parameter("decimation", "int", kind="positional_only"),
                        parameter("tap_full_scale", "int", kind="positional_only"),
                        parameter("max_num_taps", "int", kind="positional_only"),
                        parameter("taps", "list[int]", kind="positional_only"),
                    ],
                    returns="uhd.filters.DigitalFilterFIRI16",
                )
            ],
            methods=[
                "is_bypassed", "get_type", "get_output_rate",
                "get_input_rate", "get_interpolation", "get_decimation",
                "get_tap_full_scale", "get_taps", "set_taps",
            ],
        ),
        _enum(
            "uhd.filters.FilterType",
            [
                "analog_low_pass",
                "analog_band_pass",
                "digital_i16",
                "digital_fir_i16",
            ],
        ),
        _enum("uhd.types.StreamMode", ["num_done", "num_more", "stop_cont", "start_cont"]),
        _enum(
            "uhd.types.RXMetadataErrorCode",
            ["none", "timeout", "overflow", "late_command", "broken_chain", "alignment", "bad_packet"],
        ),
        _enum(
            "uhd.types.TXMetadataEventCode",
            [
                "burst_ack", "underflow", "seq_error", "time_error",
                "underflow_in_packet", "seq_error_in_burst",
            ],
        ),
        object_type(
            "uhd.usrp.MultiUSRP",
            kind="remote_handle",
            mutability="remote_handle",
            ownership={"scope": "session", "close": True, "context_manager": True},
        ),
        object_type(
            "uhd.usrp.RXStreamer",
            kind="remote_handle",
            mutability="remote_handle",
            ownership={
                "scope": "session",
                "parent": "uhd.usrp.MultiUSRP",
                "concurrency": "single_reader",
                "close": True,
                "context_manager": True,
            },
        ),
        object_type(
            "uhd.usrp.TXStreamer",
            kind="remote_handle",
            mutability="remote_handle",
            ownership={
                "scope": "session",
                "parent": "uhd.usrp.MultiUSRP",
                "concurrency": "single_sender",
                "close": True,
                "context_manager": True,
            },
        ),
        object_type(
            "uhd.property_tree",
            kind="remote_handle",
            mutability="remote_handle",
            ownership={"scope": "session", "default_access": "read_write"},
        ),
        *[
            object_type(
                f"uhd.property.{suffix}",
                kind="remote_handle",
                mutability="remote_handle",
                ownership={
                    "scope": "session",
                    "parent": "uhd.property_tree",
                    "default_access": "read_write",
                },
            )
            for suffix in (
                "bool",
                "int",
                "double",
                "str",
                "device_addr",
                "dboard_iface",
            )
        ],
        object_type(
            "uhd.usrp.radio_control",
            kind="remote_handle",
            mutability="remote_handle",
            ownership={"scope": "session", "default_access": "read_write"},
        ),
        object_type(
            "uhd.usrp.mboard_controller",
            kind="remote_handle",
            mutability="remote_handle",
            ownership={"scope": "session", "default_access": "read_write"},
        ),
        object_type(
            "uhd.usrp.dboard_iface",
            kind="remote_handle",
            mutability="remote_handle",
            ownership={"scope": "session", "default_access": "read_write"},
        ),
        object_type(
            "uhd.usrp.user_settings_iface",
            kind="remote_handle",
            mutability="remote_handle",
            ownership={"scope": "session", "default_access": "read_write"},
        ),
    ]


def _streamer_methods() -> list[dict]:
    return [
        method(
            "get_num_channels", "uhd.usrp.RXStreamer",
            [overload("default", returns="int")], execution="server_handle",
        ),
        method(
            "get_max_num_samps", "uhd.usrp.RXStreamer",
            [overload("default", returns="int")], execution="server_handle",
        ),
        method(
            "issue_stream_cmd", "uhd.usrp.RXStreamer",
            [
                overload(
                    "default",
                    [_positional("stream_cmd", "uhd.types.StreamCMD")],
                )
            ],
            execution="server_handle",
        ),
        method(
            "recv", "uhd.usrp.RXStreamer",
            [
                overload(
                    "default",
                    [
                        parameter(
                            "buffs", "ndarray", direction="out",
                            ndarray={"writable": True, "dtype_from": "stream.cpu_format", "channel_major": True},
                        ),
                        parameter("metadata", "uhd.types.RXMetadata", direction="inout"),
                        _optional("timeout", "float", 0.1),
                    ],
                    returns="int",
                )
            ],
            execution="sample_stream",
            mutations=["buffs", "metadata"],
        ),
        method(
            "get_num_channels", "uhd.usrp.TXStreamer",
            [overload("default", returns="int")], execution="server_handle",
        ),
        method(
            "get_max_num_samps", "uhd.usrp.TXStreamer",
            [overload("default", returns="int")], execution="server_handle",
        ),
        method(
            "send", "uhd.usrp.TXStreamer",
            [
                overload(
                    "default",
                    [
                        parameter("buffs", "ndarray", ndarray={"channel_major": True}),
                        parameter("metadata", "uhd.types.TXMetadata"),
                        _optional("timeout", "float", 0.1),
                    ],
                    returns="int",
                )
            ],
            execution="sample_stream",
        ),
        method(
            "recv_async_msg", "uhd.usrp.TXStreamer",
            [
                overload(
                    "mutate_metadata",
                    [
                        parameter("async_metadata", "uhd.types.TXAsyncMetadata", direction="inout"),
                        _optional("timeout", "float", 0.1),
                    ],
                    returns="bool",
                ),
                overload(
                    "return_metadata",
                    [_optional("timeout", "float", 0.1)],
                    returns="uhd.types.TXAsyncMetadata|None",
                ),
            ],
            execution="server_handle",
            mutations=["async_metadata"],
        ),
    ]


def _property_tree_methods() -> list[dict]:
    methods = [
        method(
            name,
            "uhd.property_tree",
            [
                overload(
                    "default",
                    [parameter("path", "str")],
                    returns=returns,
                )
            ],
            execution="server_handle",
        )
        for name, returns in (
            ("subtree", "uhd.property_tree"),
            ("exists", "bool"),
            ("list", "list[str]"),
        )
    ]
    for name, returns in (
        ("access_bool", "uhd.property.bool"),
        ("access_int", "uhd.property.int"),
        ("access_double", "uhd.property.double"),
        ("access_str", "uhd.property.str"),
        ("access_device_addr", "uhd.property.device_addr"),
        ("access_dboard_iface", "uhd.property.dboard_iface"),
    ):
        methods.append(
            method(
                name,
                "uhd.property_tree",
                [
                    overload(
                        "default",
                        [_positional("path", "str")],
                        returns=returns,
                    )
                ],
                execution="server_handle",
            )
        )

    property_types = {
        "uhd.property.bool": "bool",
        "uhd.property.int": "int",
        "uhd.property.double": "float",
        "uhd.property.str": "str",
        "uhd.property.device_addr": "uhd.types.DeviceAddr",
        "uhd.property.dboard_iface": "uhd.usrp.dboard_iface",
    }
    for owner, value_type in property_types.items():
        for name in ("get", "get_desired"):
            methods.append(
                method(
                    name,
                    owner,
                    [overload("default", returns=value_type)],
                    execution="server_handle",
                )
            )
        for name in ("set", "set_coerced"):
            methods.append(
                method(
                    name,
                    owner,
                    [
                        overload(
                            "default",
                            [_positional("value", value_type)],
                            returns="None",
                        )
                    ],
                    execution="server_handle",
                )
            )
    return methods


CAPABILITY_FIELDS = (
    "remote_device_type", "hardware_profile", "native_product", "native_name",
    "native_serial", "uhd_version", "uhd_abi", "firmware_version",
    "fpga_version", "fpga_image", "transport_type", "usb_speed",
    "transport_link_rate_bps",
    "rx_channel_count", "tx_channel_count", "rx_frequency_ranges_per_channel",
    "tx_frequency_ranges_per_channel", "rx_gain_ranges_per_channel",
    "tx_gain_ranges_per_channel", "rx_bandwidth_ranges_per_channel",
    "tx_bandwidth_ranges_per_channel", "master_clock_rate_range", "time_sources",
    "clock_sources", "gpio_banks", "sensors", "supported_cpu_formats",
    "supported_otw_formats", "maximum_remote_payload_bytes",
    "supported_streaming_protocol_versions",
    "remote_resource_limits", "advanced_interfaces",
)

ERRORS = (
    "RemoteRFTransportError", "RemoteRFSessionExpiredError",
    "RemoteRFReservationError",
    "RemoteRFStaleHandleError", "RemoteRFProtocolError",
    "RemoteRFOverloadError",
    "RemoteRFServerOverloadedError", "RemoteRFNativeUHDError",
)


def build_usrp_schema_v2(driver_version: str = "0.0.1") -> dict:
    signatures = _signatures()
    for additions in (
        _control_signatures(),
        _rx_signatures(),
        _tx_signatures(),
        _interface_signatures(),
        _convenience_signatures(),
    ):
        signatures.update(additions)
    methods: list[dict] = []
    coverage: dict[str, str] = {}
    for name in MULTIUSRP_METHODS:
        execution = "server_optimized" if name in {"recv_num_samps", "send_waveform"} else "server_control"
        availability = {"runtime_member": name}
        if name in OPTIONAL_METHODS:
            availability["optional"] = True
        methods.append(
            method(
                name,
                "uhd.usrp.MultiUSRP",
                signatures.get(name, _fallback_overload()),
                execution=execution,
                availability=availability,
            )
        )
        coverage[f"uhd.usrp.MultiUSRP.{name}"] = (
            "implemented_with_documented_remote_difference"
            if name in {"recv_num_samps", "send_waveform"}
            else "implemented"
            if name in signatures
            else "deferred"
        )

    for item in _streamer_methods():
        methods.append(item)
        coverage[f"{item['owner']}.{item['name']}"] = "implemented"

    for item in _property_tree_methods():
        methods.append(item)
        coverage[f"{item['owner']}.{item['name']}"] = "implemented"

    declared_owners = {item["owner"] for item in methods}
    for item in _objects():
        path = item["python_path"]
        if item["kind"] == "value_class":
            coverage[path] = "implemented"
            for member in item.get("methods", ()):
                coverage[f"{path}.{member}"] = "implemented"
        elif item["kind"] == "enum":
            coverage[path] = "implemented"
        elif (
            item["kind"] == "remote_handle"
            and path not in {
                "uhd.usrp.MultiUSRP",
                "uhd.usrp.RXStreamer",
                "uhd.usrp.TXStreamer",
            }
            and path not in declared_owners
        ):
            coverage[f"{path}.*"] = (
                "unsupported_by_hardware_native_equivalent"
                if path in USRP2901_UNSUPPORTED_HANDLE_TYPES
                else "deferred"
            )

    return build_schema(
        device_type="usrp",
        client_class="MultiUSRP",
        driver_version=driver_version,
        native_api={
            "family": TARGET_API_FAMILY,
            "version": TARGET_UHD_VERSION,
            "abi": "runtime-checked",
            "generator_version": "remoterf-uhd-manifest-v1",
        },
        hardware_profiles=["usrp2901", "b200", "b210"],
        objects=_objects(),
        methods=methods,
        errors=[{"code": name, "python_class": name} for name in ERRORS],
        capability_fields=CAPABILITY_FIELDS,
        coverage=coverage,
        deprecations=[],
    )


def assert_release_coverage(schema: dict) -> None:
    deferred = sorted(
        key for key, value in dict(schema.get("coverage") or {}).items()
        if value == "deferred"
    )
    if deferred:
        raise RuntimeError("UHD manifest contains deferred entries: " + ", ".join(deferred))
