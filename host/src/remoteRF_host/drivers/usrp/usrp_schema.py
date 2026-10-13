# Copyright (C) 2026 RemoteRF
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Last edit: Jun 26 16:37

from remoteRF_host.common.idl import DeviceSchema, idl_client, idl_expose, idl_register
from remoteRF_host.drivers.usrp.uhd_manifest import build_usrp_schema_v2
from remoteRF_host.drivers.usrp.profiles import (
    infer_inventory_profile,
    resolve_live_profile,
    validate_profile_inventory,
)

c = idl_client

import itertools
import os
import subprocess
import sys
import threading


def _configure_uhd_console_logging():
    """Keep native UHD logs out of the interactive server console by default."""
    os.environ["UHD_LOG_CONSOLE_LEVEL"] = os.getenv(
        "REMOTERF_UHD_CONSOLE_LEVEL",
        "off",
    )


_configure_uhd_console_logging()

try:
    import uhd
except Exception as exc:  # UHD is optional until a configured USRP session opens.
    uhd = None
    _UHD_IMPORT_ERROR = exc
else:
    _UHD_IMPORT_ERROR = None


_STREAM_USAGE = (
    "Use remoterf.uhd.get_rx_stream(usrp, stream_args) or "
    "remoterf.uhd.get_tx_stream(usrp, stream_args) on the client. "
    "If using the generated client directly, first call get_rx_stream/get_tx_stream "
    "and then pass {'handle': streamer_payload['handle'], ...} to stream_* calls."
)

# UHD 4.10's public API documents these OTW tokens, but does not expose a
# per-device enumeration call.  They are candidates only: support is decided
# by asking the connected device to construct an inactive native RX streamer.
_UHD_OTW_FORMAT_CANDIDATES = ("sc16", "sc12", "sc8")
_OTW_PROBE_CPU_FORMAT = "fc32"


def _require_uhd():
    if uhd is None:
        message = (
            "USRP support requires the UHD 4.10 Python module on the machine "
            "that owns the hardware"
        )
        if _UHD_IMPORT_ERROR is not None:
            message += f": {_UHD_IMPORT_ERROR}"
        raise RuntimeError(message) from _UHD_IMPORT_ERROR
    return uhd


def _looks_like_device_args(value):
    return isinstance(value, str) and ("=" in value or "," in value)


def _device_args(value):
    if value is None:
        return ""
    if isinstance(value, dict):
        return ",".join(
            f"{key}={item}" for key, item in value.items() if item is not None
        )
    return str(value)


def _remote_transport_args(value):
    """Add buffering for UI/processing gaps between remote RX batches."""
    args = _device_args(value).strip().strip(",")
    keys = {
        item.split("=", 1)[0].strip().lower()
        for item in args.split(",")
        if "=" in item
    }
    if "num_recv_frames" in keys:
        return args

    raw_frames = os.getenv("REMOTERF_USRP_NUM_RECV_FRAMES", "256")
    try:
        frames = int(raw_frames)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "REMOTERF_USRP_NUM_RECV_FRAMES must be a positive integer"
        ) from exc
    if frames <= 0:
        raise ValueError(
            "REMOTERF_USRP_NUM_RECV_FRAMES must be a positive integer"
        )
    setting = f"num_recv_frames={frames}"
    return f"{args},{setting}" if args else setting


def _usrp_args(args=None, serial=None, addr=None, **kwargs):
    args = args or kwargs.pop("device_args", None) or kwargs.pop("init_args", None)
    type_hint = kwargs.pop("type", None) or kwargs.pop("device_type", None)
    profile_name = kwargs.pop("profile", None)

    if args is None and _looks_like_device_args(serial):
        args = serial
        serial = None

    if args is None and _looks_like_device_args(addr):
        args = addr
        addr = None

    if args is None:
        inventory = {
            "profile": profile_name,
            "type": type_hint,
            "serial": serial,
            "addr": addr,
        }
        profile = infer_inventory_profile(inventory)
        if profile_name:
            validate_profile_inventory(profile, inventory)
        resolved_type = type_hint or profile.uhd_device_type
        parts = [f"type={resolved_type}"] if resolved_type else []
        if serial:
            parts.append(f"serial={serial}")
        if addr:
            parts.append(f"addr={addr}")
        for key, value in kwargs.items():
            if value is not None:
                parts.append(f"{key}={value}")
        args = ",".join(parts)
    elif profile_name:
        inventory = {
            "profile": profile_name,
            "type": type_hint,
            "args": args,
        }
        profile = infer_inventory_profile(inventory)
        validate_profile_inventory(profile, inventory)
        arg_text = _device_args(args).strip().strip(",")
        arg_keys = {
            item.split("=", 1)[0].strip().lower()
            for item in arg_text.split(",")
            if "=" in item
        }
        if profile.uhd_device_type and "type" not in arg_keys:
            args = f"type={profile.uhd_device_type},{arg_text}"

    return _remote_transport_args(args)


# A cold B2xx open (firmware + FPGA image) took ~68 s inside MultiUSRP(),
# which holds the GIL, so the whole lab stopped answering. A child process
# pays that instead while this one waits without the GIL; the open after it
# is warm (~2.5 s).
# ponytail: "warm" is per process; a USB replug while the Server runs makes
# the next open cold in-process again. Clear the mark on hotplug if that bites.
_PRELOAD_TIMEOUT = 180.0
_preloaded = set()
_preload_locks = {}
_preload_guard = threading.Lock()


def _preload_image(args):
    if str(os.getenv("REMOTERF_USRP_PRELOAD", "1")).strip().lower() in {"0", "false", "no", "off"}:
        return
    with _preload_guard:
        lock = _preload_locks.setdefault(args, threading.Lock())
    # One device, one driver at a time: an open waits here for a pre-load.
    with lock:
        if args in _preloaded:
            return
        try:
            done = subprocess.run(
                [sys.executable, "-c", "import sys, uhd; uhd.usrp.MultiUSRP(sys.argv[1])", args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_PRELOAD_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"Warning: USRP image pre-load for {args!r} failed: {exc}")
            return
        if done.returncode == 0:
            _preloaded.add(args)
        else:
            print(f"Warning: USRP image pre-load for {args!r} exited {done.returncode}")


def _connect_usrp(args=None, serial=None, addr=None, **kwargs):
    uhd_module = _require_uhd()
    args = _usrp_args(args, serial, addr, **kwargs)
    _preload_image(args)
    dev = uhd_module.usrp.MultiUSRP(args)
    _preloaded.add(args)
    return dev


def _payload_type(value):
    if isinstance(value, dict):
        return value.get("__uhd_type__")
    return None


def _tune_request_policy(value, current):
    """Translate a portable policy name back to UHD's native enum value."""
    if not isinstance(value, str):
        return value
    name = value.rsplit(".", 1)[-1].upper()
    policy_types = (
        type(current),
        getattr(getattr(uhd, "types", None), "TuneRequestPolicy", None),
        getattr(getattr(uhd, "types", None), "tune_request_policy", None),
        getattr(
            getattr(getattr(uhd, "libpyuhd", None), "types", None),
            "tune_request_policy",
            None,
        ),
    )
    for policy_type in policy_types:
        if policy_type is None:
            continue
        for candidate in (name, name.lower(), f"POLICY_{name}"):
            native = getattr(policy_type, candidate, None)
            if native is not None:
                return native
    return value


def _require_dict(value, method):
    if not isinstance(value, dict):
        raise TypeError(
            f"{method} expects a dict payload. Got {type(value).__name__}. "
            f"{_STREAM_USAGE}"
        )


def _require_key(value, key, method):
    if key not in value:
        raise KeyError(
            f"{method} payload is missing {key!r}. {_STREAM_USAGE}"
        )


def _handle(value, method):
    if isinstance(value, dict):
        _require_key(value, "handle", method)
        value = value["handle"]
    if not isinstance(value, str):
        raise TypeError(
            f"{method} expects a streamer handle string. "
            f"Got {type(value).__name__}. {_STREAM_USAGE}"
        )
    return value


def _time_spec_payload(value):
    return {
        "__uhd_type__": "TimeSpec",
        "secs": value.get_real_secs(),
    }


def _construct(value):
    if isinstance(value, dict) and value.get("__remoterf_uhd_helper__") == "stream":
        return _construct(value["stream_args"])

    kind = _payload_type(value)
    if kind is None and isinstance(value, dict):
        if "cpu_format" in value and "otw_format" in value:
            kind = "StreamArgs"
        elif "secs" in value:
            kind = "TimeSpec"
        elif "spec" in value:
            kind = "SubdevSpec"
        elif "target_freq" in value or "freq" in value:
            uhd_module = _require_uhd()
            return uhd_module.libpyuhd.types.tune_request(
                value.get("target_freq", value.get("freq"))
            )

    if kind is None:
        return value

    _require_uhd()

    if kind == "SubdevSpec":
        return uhd.usrp.SubdevSpec(value["spec"])

    if kind == "TuneRequest":
        # Older generated clients used ``args`` for constructor arguments.
        # Current TuneRequest snapshots use that same key for UHD's DeviceAddr
        # field, so only sequences may be interpreted as constructor arguments.
        raw_args = value.get("args", ())
        legacy_constructor_args = isinstance(raw_args, (list, tuple))
        args = (
            [_construct(item) for item in raw_args]
            if legacy_constructor_args
            else []
        )
        kwargs = {
            key: _construct(item)
            for key, item in value.get("kwargs", {}).items()
        }
        constructor = getattr(getattr(uhd, "types", None), "TuneRequest", None)
        if constructor is None:
            constructor = uhd.libpyuhd.types.tune_request
        if not args and "target_freq" in value:
            args = [value["target_freq"]]
            if value.get("lo_offset") is not None:
                args.append(value["lo_offset"])
        obj = constructor(*args, **kwargs)
        # TuneRequest(f, lo) places the RF LO manually at f + lo. Clients before
        # this fix modelled only the offset and send AUTO / 0.0 for the RF
        # fields next to it; applied, those defaults would undo the offset.
        keep_rf = (
            value.get("lo_offset") is not None
            and str(value.get("rf_freq_policy", "")).rsplit(".", 1)[-1].upper() == "AUTO"
            and not value.get("rf_freq")
        )
        for field in (
            "rf_freq", "dsp_freq", "rf_freq_policy", "dsp_freq_policy",
            "args",
        ):
            if field == "args" and legacy_constructor_args:
                continue
            if keep_rf and field in {"rf_freq", "rf_freq_policy"}:
                continue
            if field in value and hasattr(obj, field):
                converted = _construct(value[field])
                if field in {"rf_freq_policy", "dsp_freq_policy"}:
                    converted = _tune_request_policy(
                        converted,
                        getattr(obj, field),
                    )
                setattr(obj, field, converted)
        return obj

    if kind == "DeviceAddr":
        constructor = getattr(getattr(uhd, "types", None), "DeviceAddr", None)
        if constructor is None:
            constructor = uhd.libpyuhd.types.device_addr
        raw = value.get("value", value.get("items", value.get("args", "")))
        if isinstance(raw, dict):
            raw = _device_args(raw)
        return constructor(raw)

    if kind == "TimeSpec":
        return uhd.types.TimeSpec(value["secs"])

    if kind == "StreamArgs":
        obj = uhd.usrp.StreamArgs(value["cpu_format"], value["otw_format"])
        obj.channels = value.get("channels", [])
        raw_args = value.get("args")
        if raw_args:
            # Dynamic v2 represents StreamArgs.args as a tagged DeviceAddr.
            # Preserve that type instead of flattening the envelope itself
            # into invalid keys such as ``__uhd_type__`` and ``items``.
            obj.args = (
                _construct(raw_args)
                if _payload_type(raw_args) == "DeviceAddr"
                else _device_args(raw_args)
            )
        return obj

    if kind == "TXMetadata":
        return _tx_metadata(value)

    if kind == "RXMetadata":
        metadata = uhd.types.RXMetadata()
        reset = getattr(metadata, "reset", None)
        if callable(reset):
            reset()
        return metadata

    if kind in {"TXAsyncMetadata", "AsyncMetadata"}:
        constructor = getattr(uhd.types, "TXAsyncMetadata", None)
        if constructor is None:
            constructor = getattr(uhd.types, "AsyncMetadata")
        return constructor()

    if kind == "FilterInfoBase":
        filter_type = getattr(
            uhd.filters.FilterType,
            str(value["filter_type"]).split(".")[-1],
        )
        native_class = str(value.get("native_class") or "filter_info_base")
        common = [
            filter_type,
            bool(value.get("bypassed", False)),
            int(value.get("position", 0)),
        ]
        if native_class == "analog_filter_lp":
            return uhd.filters.AnalogFilterLP(
                *common,
                str(value.get("analog_type", "")),
                float(value["cutoff"]),
                float(value["rolloff"]),
            )
        if native_class == "analog_filter_base":
            return uhd.filters.AnalogFilterBase(
                *common,
                str(value.get("analog_type", "")),
            )
        if native_class in {
            "digital_filter_base_i16",
            "digital_filter_fir_i16",
        }:
            constructor = (
                uhd.filters.DigitalFilterFIRI16
                if native_class == "digital_filter_fir_i16"
                else uhd.filters.DigitalFilterBaseI16
            )
            return constructor(
                *common,
                float(value["input_rate"]),
                int(value["interpolation"]),
                int(value["decimation"]),
                int(value["tap_full_scale"]),
                int(value["max_num_taps"]),
                [int(item) for item in value.get("taps", ())],
            )
        return uhd.filters.FilterInfoBase(*common)

    if kind == "StreamCMD":
        mode_name = value["mode"]
        try:
            mode = getattr(uhd.types.StreamMode, mode_name)
        except AttributeError:
            raise ValueError(
                f"Unsupported StreamCMD mode {mode_name!r}. "
                "Use one of: start_cont, stop_cont, num_done, num_more."
            )
        obj = uhd.types.StreamCMD(mode)
        obj.stream_now = value.get("stream_now", True)
        if value.get("time_spec") is not None:
            obj.time_spec = _construct(value["time_spec"])
        if value.get("num_samps") is not None:
            obj.num_samps = value["num_samps"]
        return obj

    raise ValueError(f"Unknown UHD payload type: {kind}")


def _rx_metadata_payload(metadata):
    time_spec = None
    if hasattr(metadata, "time_spec"):
        time_spec = _time_spec_payload(metadata.time_spec)

    return {
        "error_code": str(metadata.error_code).split(".")[-1],
        "error_code_repr": str(metadata.error_code),
        "has_time_spec": getattr(metadata, "has_time_spec", None),
        "time_spec": time_spec,
        "out_of_sequence": getattr(metadata, "out_of_sequence", None),
        "fragment_offset": getattr(metadata, "fragment_offset", None),
        "more_fragments": getattr(metadata, "more_fragments", None),
    }


def _tx_metadata(value):
    if value is None:
        value = {}
    if not isinstance(value, dict):
        return value

    _require_uhd()
    metadata = uhd.types.TXMetadata()
    metadata.has_time_spec = bool(value.get("has_time_spec", False))
    if value.get("time_spec") is not None:
        metadata.time_spec = _construct(value["time_spec"])
    metadata.start_of_burst = bool(value.get("start_of_burst", False))
    metadata.end_of_burst = bool(value.get("end_of_burst", False))
    return metadata


def _uhd_client_objects():
    time_spec = c.payload_class(
        "TimeSpec",
        {"secs": {"default": 0.0, "coerce": "float"}},
        init="timespec",
        methods=[
            c.method("timespec_get_real_secs"),
            c.method("timespec_get_full_secs"),
            c.method("timespec_get_frac_secs"),
            c.method("timespec_to_ticks"),
            c.method("timespec_get_tick_count"),
            c.method("timespec_float"),
            c.method("payload_as_payload"),
        ],
        operators=["timespec_numeric"],
    )

    stream_args = c.payload_class(
        "StreamArgs",
        {
            "cpu_format": {"coerce": "str"},
            "otw_format": {"coerce": "str"},
            "args": {"default": {}, "payload": True},
            "channels": {"default": [], "coerce": "list"},
        },
        init="stream_args",
        methods=[c.method("payload_as_payload")],
    )

    stream_cmd = c.payload_class(
        "StreamCMD",
        {
            "mode": {"coerce": "enum_value"},
            "stream_now": {"default": True, "coerce": "bool"},
            "time_spec": {"default": None, "payload": True},
            "num_samps": {"default": None},
        },
        init="stream_cmd",
        methods=[c.method("payload_as_payload")],
    )

    rx_metadata = c.strict_class(
        [
            "error_code",
            "error_code_repr",
            "time_spec",
            "out_of_sequence",
            "fragment_offset",
            "more_fragments",
        ],
        init="rx_metadata",
        methods=[
            c.method("metadata_update"),
            c.method("metadata_strerror"),
        ],
    )

    tx_metadata = c.strict_class(
        ["has_time_spec", "time_spec", "end_of_burst"],
        init="tx_metadata",
        methods=[c.method("payload_as_payload")],
    )

    streamer_methods = [
        c.method("streamer_get_max_num_samps"),
        c.method("streamer_issue_stream_cmd"),
        c.method("streamer_close"),
    ]

    rx_streamer = c.proxy_class(
        ["usrp", "handle"],
        init="streamer_handle",
        methods=[*streamer_methods, c.method("rx_streamer_recv")],
    )

    tx_streamer = c.proxy_class(
        ["usrp", "handle"],
        init="streamer_handle",
        methods=[*streamer_methods, c.method("tx_streamer_send")],
    )

    return {
        "uhd": c.module(
            {
                "payload": c.function("uhd_payload"),
                "get_rx_stream": c.function("uhd_get_rx_stream"),
                "get_tx_stream": c.function("uhd_get_tx_stream"),
                "close_all_streams": c.function("uhd_close_all_streams"),
                "streamer": c.function("uhd_streamer"),
                "RXStreamer": rx_streamer,
                "TXStreamer": tx_streamer,
                "usrp": c.namespace(
                    {
                        "SubdevSpec": c.function("uhd_subdev_spec"),
                        "StreamArgs": stream_args,
                    }
                ),
                "types": c.namespace(
                    {
                        "TimeSpec": time_spec,
                        "StreamCMD": stream_cmd,
                        "StreamMode": c.enum(
                            ["num_done", "num_more", "stop_cont", "start_cont"]
                        ),
                        "RXMetadata": rx_metadata,
                        "TXMetadata": tx_metadata,
                        "RXMetadataErrorCode": c.enum(
                            [
                                "none",
                                "timeout",
                                "overflow",
                                "late_command",
                                "broken_chain",
                                "alignment",
                                "bad_packet",
                            ]
                        ),
                    }
                ),
                "libpyuhd": c.namespace(
                    {
                        "types": c.namespace(
                            {
                                "tune_request": c.function("uhd_tune_request"),
                            }
                        ),
                    }
                ),
            },
            exports=[
                "usrp",
                "types",
                "libpyuhd",
                "payload",
                "get_rx_stream",
                "get_tx_stream",
                "close_all_streams",
                "streamer",
                "RXStreamer",
                "TXStreamer",
            ],
            bind_client_class_to="usrp",
        )
    }


@idl_register("usrp")
class UsrpSchema(DeviceSchema):
    device_type = "usrp"
    client_class = "MultiUSRP"
    client_objects = _uhd_client_objects()
    driver_version = "0.0.7"
    session_scoped = True

    def __init__(self):
        super().__init__()
        self._inventory = {}
        self._legacy_device = False

    @staticmethod
    def make_device(**kwargs):
        return _connect_usrp(**kwargs)

    def bind_inventory(self, init_kwargs):
        """Bind stable inventory data without opening USB/UHD at server startup."""
        self._inventory = dict(init_kwargs or {})

    def open_native_device(self):
        return _connect_usrp(**self._inventory)

    def prepare_for_holder(self):
        """A reservation started: load a cold image now, not in the holder's open."""
        if uhd is not None:
            _preload_image(_usrp_args(**self._inventory))

    def create_session_schema(self):
        """Create an isolated, live adapter for one authenticated reservation."""
        clone = type(self)()
        clone.bind_inventory(self._inventory)
        clone.bind(clone.open_native_device())
        return clone

    def close_native_device(self):
        self.call_close_all_streams()
        device = self.device
        self.device = None
        close = getattr(device, "close", None)
        if callable(close):
            close()

    def dispatch(self, method_name, args):
        # V1 compatibility: old clients still work, but share one lazily-opened
        # adapter exactly as they did before session-scoped inventory support.
        if self.device is None:
            self.bind(self.open_native_device())
            self._legacy_device = True
        return super().dispatch(method_name, args)

    def get_idl_v2(self):
        return build_usrp_schema_v2(self.driver_version)

    def _probe_rx_stream_formats(self, rx_count):
        """Ask native UHD which RX OTW formats this live device accepts.

        Streamers are constructed and immediately released without issuing a
        stream command or receiving samples.  The result is cached because
        streamer construction configures native transport/DSP resources and
        should happen only while the newly opened session is otherwise idle.
        """
        cached = getattr(self, "_rx_stream_format_probe_cache", None)
        if cached is not None:
            return cached

        channels = [0] if rx_count else []
        result = {
            "status": "runtime_probed" if channels else "unavailable",
            "method": "native_rx_streamer_creation",
            "cpu_format": _OTW_PROBE_CPU_FORMAT,
            "channels": channels,
            "default": None,
            "formats": [],
        }
        if not channels:
            result["reason"] = "device_has_no_rx_channels"
            self._rx_stream_format_probe_cache = result
            return result

        probe_enabled = str(
            os.getenv("REMOTERF_USRP_PROBE_RX_OTW_FORMATS", "1")
        ).strip().lower()
        if probe_enabled in {
            "0",
            "false",
            "no",
            "off",
        }:
            result["status"] = "disabled"
            result["reason"] = "REMOTERF_USRP_PROBE_RX_OTW_FORMATS"
            self._rx_stream_format_probe_cache = result
            return result

        if getattr(self, "_usrp_streamers", None):
            result["status"] = "skipped"
            result["reason"] = "active_remote_streamers"
            self._rx_stream_format_probe_cache = result
            return result

        stream_args_type = getattr(
            getattr(_require_uhd(), "usrp", None),
            "StreamArgs",
            None,
        )
        native_get_rx_stream = getattr(self.device, "get_rx_stream", None)
        if stream_args_type is None or not callable(native_get_rx_stream):
            result["status"] = "unavailable"
            result["reason"] = "native_rx_streamer_api_missing"
            self._rx_stream_format_probe_cache = result
            return result

        def attempt(otw_format):
            entry = {
                "otw_format": otw_format,
                "supported": False,
                "max_num_samps": None,
            }
            streamer = None
            try:
                stream_args = stream_args_type(
                    _OTW_PROBE_CPU_FORMAT,
                    otw_format,
                )
                stream_args.channels = list(channels)
                streamer = native_get_rx_stream(stream_args)
                entry["supported"] = True
                get_max_num_samps = getattr(streamer, "get_max_num_samps", None)
                if callable(get_max_num_samps):
                    try:
                        entry["max_num_samps"] = int(get_max_num_samps())
                    except Exception:
                        pass
            except Exception as exc:
                entry["native_error_type"] = type(exc).__name__
                entry["native_error"] = str(exc)[:1024]
            finally:
                # Native UHD streamers have no close() method. Dropping the
                # final Python reference releases their transport resources.
                streamer = None
            return entry

        result["default"] = attempt("")
        result["formats"] = [
            attempt(otw_format)
            for otw_format in _UHD_OTW_FORMAT_CANDIDATES
        ]
        self._rx_stream_format_probe_cache = result
        return result

    def invoke_native(self, method_name, args, positional_args=None):
        """Invoke a pinned UHD member while reconstructing tagged value inputs."""
        if self.device is None:
            raise RuntimeError("USRP session is not open")
        target = getattr(self.device, method_name)
        positional = [_construct(item) for item in (positional_args or ())]
        keywords = {str(key): _construct(item) for key, item in dict(args or {}).items()}
        return target(*positional, **keywords)

    @staticmethod
    def _version_value(*names):
        uhd_module = _require_uhd()
        for name in names:
            value = getattr(uhd_module, name, None)
            if callable(value):
                try:
                    return str(value())
                except Exception:
                    continue
            if value:
                return str(value)
        return ""

    def build_session_metadata_v2(self):
        device = self.device
        if device is None:
            raise RuntimeError("USRP session is not open")

        def call(name, *args, default=None):
            fn = getattr(device, name, None)
            if not callable(fn):
                return default
            try:
                return fn(*args)
            except Exception:
                return default

        rx_count = int(call("get_rx_num_channels", default=0) or 0)
        tx_count = int(call("get_tx_num_channels", default=0) or 0)
        rx_info = call("get_usrp_rx_info", 0, default={}) if rx_count else {}
        tx_info = call("get_usrp_tx_info", 0, default={}) if tx_count else {}
        info = dict(rx_info or {})
        info.update(dict(tx_info or {}))
        native_name = str(info.get("mboard_name") or "")
        product = (
            info.get("mboard_id")
            or call("get_mboard_name", 0, default="")
        )
        product_text = str(product or "")
        profile, profile_resolution = resolve_live_profile(
            self._inventory,
            native_name,
            product_text,
            info.get("rx_subdev_name"),
            info.get("tx_subdev_name"),
        )
        hardware_profile = profile.profile_id
        serial = (
            self._inventory.get("serial")
            or info.get("mboard_serial")
            or info.get("serial")
            or ""
        )
        tree = call("get_tree", default=None)

        def tree_scalar(path):
            if tree is None:
                return ""
            for accessor in ("access_str", "access_int", "access_double"):
                try:
                    return getattr(tree, accessor)(path).get()
                except Exception:
                    continue
            return ""

        firmware_version = str(tree_scalar("/mboards/0/fw_version"))
        fpga_version = str(tree_scalar("/mboards/0/fpga_version"))
        usb_version = str(tree_scalar("/mboards/0/usb_version"))
        link_rate = tree_scalar("/mboards/0/link_max_rate")
        transport_is_network = (
            profile.transport == "ethernet"
            or bool(self._inventory.get("addr"))
        )
        transport_address = str(self._inventory.get("addr") or "")
        if transport_is_network and not link_rate and profile.default_link_rate_bps:
            link_rate = profile.default_link_rate_bps
        if transport_is_network:
            transport_type = "ethernet"
        elif profile.transport != "runtime_detected":
            transport_type = profile.transport
        else:
            transport_type = "usb" if usb_version else "unknown"

        def ranges(method_name, count):
            return [call(method_name, chan, default=None) for chan in range(count)]

        rx_format_probe = self._probe_rx_stream_formats(rx_count)
        supported_otw_formats = [
            str(entry["otw_format"])
            for entry in rx_format_probe.get("formats", [])
            if entry.get("supported") and entry.get("otw_format")
        ]
        stream_format_capabilities = {
            "rx": rx_format_probe,
            "tx": {
                "status": "not_probed",
                "reason": "tx_capability_probe_requires_explicit_admin_qualification",
            },
        }

        return {
            "remote_device_type": "usrp",
            "hardware_profile": hardware_profile,
            "device_profile": profile.public_definition(),
            "profile_resolution": profile_resolution,
            "native_product": product_text,
            "native_name": native_name,
            "native_serial": str(serial),
            "uhd_version": self._version_value("get_version_string", "get_version"),
            "uhd_abi": self._version_value("get_abi_string", "get_abi"),
            "firmware_version": firmware_version,
            "fpga_version": fpga_version,
            "fpga_image": fpga_version,
            "transport_type": transport_type,
            "transport_address": transport_address,
            "usb_speed": "" if transport_is_network else usb_version,
            "transport_link_rate_bps": link_rate,
            "rx_channel_count": rx_count,
            "tx_channel_count": tx_count,
            "rx_frequency_ranges_per_channel": ranges("get_rx_freq_range", rx_count),
            "tx_frequency_ranges_per_channel": ranges("get_tx_freq_range", tx_count),
            "rx_gain_ranges_per_channel": ranges("get_rx_gain_range", rx_count),
            "tx_gain_ranges_per_channel": ranges("get_tx_gain_range", tx_count),
            "rx_bandwidth_ranges_per_channel": ranges("get_rx_bandwidth_range", rx_count),
            "tx_bandwidth_ranges_per_channel": ranges("get_tx_bandwidth_range", tx_count),
            "master_clock_rate_range": call("get_master_clock_rate_range", default=None),
            "time_sources": call("get_time_sources", 0, default=[]),
            "clock_sources": call("get_clock_sources", 0, default=[]),
            "gpio_banks": call("get_gpio_banks", 0, default=[]),
            "sensors": call("get_mboard_sensor_names", 0, default=[]),
            "supported_cpu_formats": ["fc32", "fc64", "sc16"],
            "supported_otw_formats": supported_otw_formats,
            "stream_format_capabilities": stream_format_capabilities,
            "advanced_interfaces": {
                "property_tree": tree is not None,
                "filters": True,
                "radio_control": False,
                "mboard_controller": False,
                "dboard_iface": False,
                "user_settings_iface": False,
            },
            "maximum_remote_payload_bytes": 4 * 1024 * 1024,
            "supported_streaming_protocol_versions": ["1.0"],
        }

    def _streamers(self):
        if not hasattr(self, "_usrp_streamers"):
            self._usrp_streamers = {}
            self._usrp_stream_ids = itertools.count(1)
        return self._usrp_streamers

    def _put_streamer(self, direction, streamer):
        streamers = self._streamers()
        handle = f"{direction}:{next(self._usrp_stream_ids)}"
        streamers[handle] = streamer
        return {"__uhd_type__": f"{direction.upper()}Streamer", "handle": handle}

    def _get_streamer(self, handle):
        handle = _handle(handle, "streamer lookup")
        streamers = self._streamers()
        if handle not in streamers:
            existing = ", ".join(streamers.keys()) or "none"
            raise KeyError(
                f"Unknown USRP streamer handle {handle!r}. "
                "Create a streamer first with get_rx_stream/get_tx_stream. "
                f"Existing handles: {existing}. {_STREAM_USAGE}"
            )
        return streamers[handle]

    # region init / repr

    @idl_expose(kind="get")
    def get_repr(self):
        return repr(self.device)

    # endregion

    # region explicit MultiUSRP calls used by simple_send.py

    @idl_expose(kind="call")
    def call_set_tx_subdev_spec(self, spec, mboard=0):
        self.device.set_tx_subdev_spec(_construct(spec), mboard)

    @idl_expose(kind="call")
    def call_set_tx_antenna(self, antenna, chan=0):
        self.device.set_tx_antenna(antenna, chan)

    @idl_expose(kind="call")
    def call_set_rx_subdev_spec(self, spec, mboard=0):
        self.device.set_rx_subdev_spec(_construct(spec), mboard)

    @idl_expose(kind="call")
    def call_set_rx_antenna(self, antenna, chan=0):
        self.device.set_rx_antenna(antenna, chan)

    # endregion

    # region explicit MultiUSRP calls used by usrp_utils.py

    @idl_expose(
        kind="call",
        client_return=c.ctor("uhd.types.TimeSpec", "$result"),
    )
    def call_get_time_now(self):
        return _time_spec_payload(self.device.get_time_now())

    @idl_expose(kind="call")
    def call_get_rx_num_channels(self):
        return self.device.get_rx_num_channels()

    @idl_expose(kind="call")
    def call_get_tx_num_channels(self):
        return self.device.get_tx_num_channels()

    @idl_expose(kind="call")
    def call_set_clock_source(self, source, mboard=0):
        self.device.set_clock_source(source, mboard)

    @idl_expose(kind="call")
    def call_set_time_source(self, source, mboard=0):
        self.device.set_time_source(source, mboard)

    @idl_expose(kind="call")
    def call_set_time_unknown_pps(self, value):
        self.device.set_time_unknown_pps(_construct(value))

    @idl_expose(kind="call")
    def call_set_time_now(self, value):
        self.device.set_time_now(_construct(value))

    @idl_expose(kind="call")
    def call_set_time_next_pps(self, value):
        self.device.set_time_next_pps(_construct(value))

    @idl_expose(
        kind="call",
        client_return=c.ctor("uhd.types.TimeSpec", "$result"),
    )
    def call_get_time_last_pps(self):
        return _time_spec_payload(self.device.get_time_last_pps())

    @idl_expose(kind="call")
    def call_get_tx_subdev_spec(self, mboard=0):
        return str(self.device.get_tx_subdev_spec(mboard))

    @idl_expose(kind="call")
    def call_get_rx_subdev_spec(self, mboard=0):
        return str(self.device.get_rx_subdev_spec(mboard))

    @idl_expose(kind="call")
    def call_get_rx_rate(self, chan=0):
        return self.device.get_rx_rate(chan)

    @idl_expose(kind="call")
    def call_get_tx_rate(self, chan=0):
        return self.device.get_tx_rate(chan)

    @idl_expose(kind="call")
    def call_set_master_clock_rate(self, rate, mboard=None):
        if mboard is not None:
            self.device.set_master_clock_rate(rate, mboard)
        else:
            self.device.set_master_clock_rate(rate)

    @idl_expose(kind="call")
    def call_get_mboard_sensor(self, name, mboard=0):
        return str(self.device.get_mboard_sensor(name, mboard))

    @idl_expose(kind="call")
    def call_set_rx_rate(self, rate, chan=0):
        self.device.set_rx_rate(rate, chan)

    @idl_expose(kind="call")
    def call_set_rx_freq(self, tune_request, chan=0):
        self.device.set_rx_freq(_construct(tune_request), chan)

    @idl_expose(kind="call")
    def call_set_rx_gain(self, gain, chan=0):
        self.device.set_rx_gain(gain, chan)

    @idl_expose(kind="call")
    def call_set_rx_dc_offset(self, enable, chan=0):
        self.device.set_rx_dc_offset(enable, chan)

    @idl_expose(kind="call")
    def call_set_tx_rate(self, rate, chan=0):
        self.device.set_tx_rate(rate, chan)

    @idl_expose(kind="call")
    def call_set_tx_freq(self, tune_request, chan=0):
        self.device.set_tx_freq(_construct(tune_request), chan)

    @idl_expose(kind="call")
    def call_set_tx_gain(self, gain, chan=0):
        self.device.set_tx_gain(gain, chan)

    @idl_expose(
        kind="call",
        client_return=c.ctor("uhd.RXStreamer", "$self", "$result"),
    )
    def call_get_rx_stream(self, stream_args):
        return self._put_streamer("rx", self.device.get_rx_stream(_construct(stream_args)))

    @idl_expose(
        kind="call",
        client_return=c.ctor("uhd.TXStreamer", "$self", "$result"),
    )
    def call_get_tx_stream(self, stream_args):
        return self._put_streamer("tx", self.device.get_tx_stream(_construct(stream_args)))

    # endregion

    # region stream handle calls used by remoterf.uhd helpers

    @idl_expose(kind="call")
    def call_stream_get_max_num_samps(self, handle):
        return self._get_streamer(_handle(handle, "stream_get_max_num_samps")).get_max_num_samps()

    @idl_expose(kind="call")
    def call_stream_issue_stream_cmd(self, value):
        _require_dict(value, "stream_issue_stream_cmd")
        _require_key(value, "handle", "stream_issue_stream_cmd")
        _require_key(value, "stream_cmd", "stream_issue_stream_cmd")
        handle = _handle(value["handle"], "stream_issue_stream_cmd")
        stream_cmd = value["stream_cmd"]
        self._get_streamer(handle).issue_stream_cmd(_construct(stream_cmd))

    @idl_expose(kind="call")
    def call_stream_recv(self, value):
        _require_dict(value, "stream_recv")
        _require_key(value, "handle", "stream_recv")
        _require_key(value, "recv_buffer", "stream_recv")
        handle = _handle(value["handle"], "stream_recv")
        recv_buffer = value["recv_buffer"]
        timeout = value.get("timeout", 0.1)
        _require_uhd()
        metadata = uhd.types.RXMetadata()
        count = self._get_streamer(handle).recv(
            recv_buffer,
            metadata,
            timeout,
        )
        return count, recv_buffer, _rx_metadata_payload(metadata)

    @idl_expose(kind="call")
    def call_stream_send(self, value):
        _require_dict(value, "stream_send")
        _require_key(value, "handle", "stream_send")
        _require_key(value, "samples", "stream_send")
        handle = _handle(value["handle"], "stream_send")
        samples = value["samples"]
        metadata = value.get("metadata")
        timeout = value.get("timeout", 0.1)
        return self._get_streamer(handle).send(samples, _tx_metadata(metadata), timeout)

    @idl_expose(kind="call")
    def call_stream_close(self, handle):
        self._streamers().pop(_handle(handle, "stream_close"), None)

    @idl_expose(kind="call")
    def call_close_all_streams(self):
        count = len(self._streamers())
        self._streamers().clear()
        return count

    # endregion
