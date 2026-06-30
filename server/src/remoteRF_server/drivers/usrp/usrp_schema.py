# Last edit: Jun 26 16:37

from remoteRF_server.common.idl import DeviceSchema, idl_client, idl_expose, idl_register

c = idl_client

import itertools
import uhd


_STREAM_USAGE = (
    "Use remoterf.uhd.get_rx_stream(usrp, stream_args) or "
    "remoterf.uhd.get_tx_stream(usrp, stream_args) on the client. "
    "If using the generated client directly, first call get_rx_stream/get_tx_stream "
    "and then pass {'handle': streamer_payload['handle'], ...} to stream_* calls."
)


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


def _connect_usrp(args=None, serial=None, addr=None, **kwargs):
    args = args or kwargs.pop("device_args", None) or kwargs.pop("init_args", None)

    if args is None and _looks_like_device_args(serial):
        args = serial
        serial = None

    if args is None and _looks_like_device_args(addr):
        args = addr
        addr = None

    if args is None:
        parts = []
        if serial:
            parts.append(f"serial={serial}")
        if addr:
            parts.append(f"addr={addr}")
        for key, value in kwargs.items():
            if value is not None:
                parts.append(f"{key}={value}")
        args = ",".join(parts)

    args = _device_args(args)
    dev = uhd.usrp.MultiUSRP(args)
    print(f"Connected to USRP with args={args!r}")
    return dev


def _payload_type(value):
    if isinstance(value, dict):
        return value.get("__uhd_type__")
    return None


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
            return uhd.libpyuhd.types.tune_request(value.get("target_freq", value.get("freq")))

    if kind is None:
        return value

    if kind == "SubdevSpec":
        return uhd.usrp.SubdevSpec(value["spec"])

    if kind == "TuneRequest":
        args = [_construct(item) for item in value.get("args", ())]
        kwargs = {
            key: _construct(item)
            for key, item in value.get("kwargs", {}).items()
        }
        return uhd.libpyuhd.types.tune_request(*args, **kwargs)

    if kind == "TimeSpec":
        return uhd.types.TimeSpec(value["secs"])

    if kind == "StreamArgs":
        obj = uhd.usrp.StreamArgs(value["cpu_format"], value["otw_format"])
        obj.channels = value.get("channels", [])
        if value.get("args"):
            obj.args = _device_args(value["args"])
        return obj

    if kind == "TXMetadata":
        return _tx_metadata(value)

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

    metadata = uhd.types.TXMetadata()
    metadata.has_time_spec = bool(value.get("has_time_spec", False))
    if value.get("time_spec") is not None:
        metadata.time_spec = _construct(value["time_spec"])
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
    driver_version = "0.0.1"

    @staticmethod
    def make_device(**kwargs):
        return _connect_usrp(**kwargs)

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
