"""contrib/drivers with fakes only: no serial port, BlueZ or radio is touched."""

import enum
import importlib.util
import queue
import struct
import sys
import time
import types
from pathlib import Path

import pytest
import serial

from remoteRF_server.common.idl import schema as idl_schema

CONTRIB = Path(__file__).resolve().parents[1] / "contrib" / "drivers"


def _load(name, fakes):
    saved = dict(idl_schema._DRIVER_REGISTRY)
    missing = {key: value for key, value in fakes.items() if key not in sys.modules}
    sys.modules.update(missing)
    try:
        spec = importlib.util.spec_from_file_location(f"contrib_{name}", CONTRIB / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        for key in missing:
            sys.modules.pop(key, None)
        idl_schema._DRIVER_REGISTRY.clear()
        idl_schema._DRIVER_REGISTRY.update(saved)
    return module


def _wait(condition, timeout=3.0):
    end = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < end, "timed out"
        time.sleep(0.005)


# -- GPS --------------------------------------------------------------------


class RMC:
    def __init__(self, latitude, longitude):
        self.status, self.latitude, self.longitude = "A", latitude, longitude
        self.spd_over_grnd = self.timestamp = self.datestamp = None


class _FakeNmea(types.ModuleType):
    FIXES = {"$FIX1": RMC(34.07, -118.44), "$FIX2": RMC(34.08, -118.45)}

    def __init__(self):
        super().__init__("pynmea2")
        self.types = types.SimpleNamespace(talker=types.SimpleNamespace(RMC=RMC, GGA=type("GGA", (), {}), GLL=type("GLL", (), {})))

    def parse(self, line):
        return self.FIXES[line]


class FakePort:
    """One USB receiver behind a fixed path; unplugging fails reads and opens."""

    def __init__(self):
        self.plugged, self.lines, self.opened = True, queue.Queue(), []

    def Serial(self, port, baud, timeout):
        if not self.plugged:
            raise serial.SerialException(f"could not open port {port}")
        handle = types.SimpleNamespace(port=port, closed=False)
        handle.readline = lambda: self._readline(handle)
        handle.close = lambda: setattr(handle, "closed", True)
        self.opened.append(handle)
        return handle

    def _readline(self, handle):
        if not self.plugged or handle.closed:
            raise serial.SerialException("device reports readiness to read but returned no data")
        try:
            return self.lines.get(timeout=0.01)
        except queue.Empty:
            return b""


@pytest.fixture(scope="module")
def gps():
    return _load("gps_schema", {"pynmea2": _FakeNmea()})


def test_gps_reopens_its_port_after_a_replug_and_marks_old_data_stale(gps, monkeypatch):
    port = FakePort()
    monkeypatch.setattr(gps.serial, "Serial", port.Serial)
    monkeypatch.setattr(gps.GpsDevice, "RECONNECT_INTERVAL", 0.01)
    path = "/dev/serial/by-id/usb-u-blox_7-if00"
    dev = gps.GpsDevice(port=path)
    schema = gps.GpsSchema()
    schema.bind(dev)
    try:
        port.lines.put(b"$FIX1\r\n")
        _wait(lambda: dev.get_lat_long() == (34.07, -118.44))
        assert schema.dispatch("get_connected", {}) is True

        port.plugged = False
        _wait(lambda: not dev.get_position()["connected"])
        position = dev.get_position()
        assert position["stale"] and not position["has_fix"]
        assert (position["latitude"], position["longitude"]) == (34.07, -118.44)
        assert dev.get_lat_long() is None
        assert schema.dispatch("get_connected", {}) is False

        port.plugged = True
        _wait(lambda: dev.get_position()["connected"])
        assert dev.get_position()["stale"]
        port.lines.put(b"$FIX2\r\n")
        _wait(lambda: not dev.get_position()["stale"])
        assert dev.get_lat_long() == (34.08, -118.45)
    finally:
        dev.close()
    assert len(port.opened) == 2 and {handle.port for handle in port.opened} == {path}
    assert all(handle.closed for handle in port.opened)
    assert gps.GpsSchema.driver_version == "0.1.2"


# -- Bluetooth --------------------------------------------------------------


class MessageType(enum.Enum):
    METHOD_RETURN = 2
    ERROR = 3


class Variant:
    def __init__(self, signature, value):
        self.signature, self.value = signature, value


class Message:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class FakeBus:
    """BlueZ on the system bus: adapters by name, and every call it saw."""

    adapters: dict = {}
    calls: list = []

    def __init__(self, bus_type=None):
        pass

    async def connect(self):
        return self

    def disconnect(self):
        pass

    async def call(self, msg):
        name = msg.path.rsplit("/", 1)[1]
        FakeBus.calls.append((msg.member, name))
        props = FakeBus.adapters.get(name)
        if props is None:
            return Message(message_type=MessageType.ERROR, error_name="org.freedesktop.DBus.Error.UnknownObject", body=["gone"])
        if msg.member == "GetAll":
            body = [{"Address": Variant("s", "00:11:22:33:44:55"), "Version": Variant("y", 6)}]
        elif msg.member == "Get":
            body = [Variant("b", props[msg.body[1]])]
        else:
            props[msg.body[1]] = msg.body[2].value
            body = []
        return Message(message_type=MessageType.METHOD_RETURN, error_name=None, body=body)


@pytest.fixture(scope="module")
def bt():
    dbus = types.ModuleType("dbus_fast")
    dbus.Message, dbus.Variant = Message, Variant
    aio = types.ModuleType("dbus_fast.aio")
    aio.MessageBus = FakeBus
    constants = types.ModuleType("dbus_fast.constants")
    constants.BusType = types.SimpleNamespace(SYSTEM="system")
    constants.MessageType = MessageType
    return _load("bluetooth_schema", {"dbus_fast": dbus, "dbus_fast.aio": aio, "dbus_fast.constants": constants})


@pytest.fixture
def sysfs(bt, tmp_path, monkeypatch):
    base = tmp_path / "class" / "bluetooth"
    base.mkdir(parents=True)
    monkeypatch.setattr(bt, "_SYSFS_BLUETOOTH", base)
    monkeypatch.setattr(FakeBus, "adapters", {})
    monkeypatch.setattr(FakeBus, "calls", [])

    def plug(name, vendor, product, product_name):
        usb = tmp_path / "devices" / f"usb-{name}"
        (usb / "bluetooth" / name).mkdir(parents=True)
        for key, value in (("idVendor", vendor), ("idProduct", product), ("product", product_name)):
            (usb / key).write_text(value + "\n")
        (base / name).symlink_to(usb / "bluetooth" / name)
        FakeBus.adapters[name] = {"Powered": True, "Discovering": False}

    def unplug(name):
        (base / name).unlink()
        FakeBus.adapters.pop(name)

    return plug, unplug


def test_auto_detect_never_falls_back_to_another_adapter(bt, sysfs):
    plug, _ = sysfs
    plug("hci0", "8087", "0026", "Built-in Bluetooth")
    assert bt.BluetoothSchema.make_device() is None
    assert bt.BluetoothSchema.make_device(allow_fallback=True).adapter_name == "hci0"
    assert bt.BluetoothSchema.make_device(adapter="hci0").adapter_name == "hci0"
    plug("hci1", "0a12", "0001", "CSR8510 A10")
    dev = bt.BluetoothSchema.make_device()
    assert (dev.adapter_name, dev.is_zexmte, dev.bd_address) == ("hci1", True, "00:11:22:33:44:55")
    assert bt.BluetoothSchema.driver_version == "0.1.2"


def test_a_renumbered_csr_is_found_again_when_bluez_forgets_it(bt, sysfs):
    plug, unplug = sysfs
    plug("hci0", "8087", "0026", "Built-in Bluetooth")
    plug("hci1", "0a12", "0001", "CSR8510 A10")
    dev = bt.BluetoothSchema.make_device()
    pinned = bt.BluetoothSchema.make_device(adapter="hci1")
    unplug("hci1")
    plug("hci2", "0a12", "0001", "CSR8510 A10")
    FakeBus.calls.clear()

    assert bt._run_coroutine_sync(dev.get_powered_async) is True
    assert dev.adapter_name == "hci2"
    assert FakeBus.calls == [("Get", "hci1"), ("Get", "hci2")]
    assert bt._run_coroutine_sync(dev.set_powered_async, False) is True
    assert FakeBus.adapters["hci2"]["Powered"] is False
    # A pinned adapter is not swapped for another one, and an error is no success.
    assert bt._run_coroutine_sync(pinned.set_powered_async, True) is False
    assert pinned.adapter_name == "hci1"


# -- Pluto+ ------------------------------------------------------------------


class FakeIio:
    def __init__(self, kind, uri, serial):
        self.kind, self.uri = kind, uri
        self._ctx = types.SimpleNamespace(attrs={"hw_serial": serial})


@pytest.fixture()
def pluto_plus(monkeypatch, tmp_path):
    adi = types.ModuleType("adi")
    adi.opened, adi.serial = [], "1044ab"

    def opener(kind):
        def open_(uri):
            adi.opened.append(f"{kind} {uri}")
            return FakeIio(kind, uri, adi.serial)
        return open_

    adi.Pluto, adi.ad9361 = opener("Pluto"), opener("ad9361")
    monkeypatch.setitem(sys.modules, "adi", adi)  # PoePluto imports adi when it boots
    module = _load("pluto_plus_schema", {})
    monkeypatch.setattr(module, "adi", adi)
    from remoteRF_server.drivers.adalm_pluto import poe

    module.switch = []
    (tmp_path / "poe_switch_password").write_text("secret\n")
    monkeypatch.setattr(module, "get_remoterf_root", lambda: tmp_path)
    monkeypatch.setattr(poe, "set_poe", lambda **kw: module.switch.append((kw["port"], kw["on"], kw["password"])))
    monkeypatch.setattr(poe, "_iiod_up", lambda ip: True)
    return module


def test_pluto_plus_opens_both_channels_over_ethernet_and_checks_its_serial(pluto_plus):
    adi = pluto_plus.adi
    dev = pluto_plus.PlutoPlusSchema.make_device(ip="192.168.4.201", serial="1044AB")
    assert adi.opened == ["ad9361 ip:192.168.4.201"]
    assert dev.rx_enabled_channels == dev.tx_enabled_channels == [0, 1]
    with pytest.raises(RuntimeError, match="expected 10449f"):
        pluto_plus.PlutoPlusSchema.make_device(ip="192.168.4.201", serial="10449f")
    with pytest.raises(ValueError, match="init.ip"):
        pluto_plus.PlutoPlusSchema.make_device(serial="1044ab")


def test_a_poe_pluto_plus_starts_off_and_boots_as_2r2t(pluto_plus):
    adi = pluto_plus.adi
    schema = pluto_plus.PlutoPlusSchema()
    schema.bind(pluto_plus.PlutoPlusSchema.make_device(poe=True, ip="192.168.4.201", poe_port="ether23",
                                                       serial="1044ab", rx_enabled_channels=[1]))
    assert pluto_plus.switch == [("ether23", False, "secret")] and adi.opened == []

    assert schema.dispatch("get_rx_enabled_channels", {}) == [1]
    assert schema.dispatch("get_tx_enabled_channels", {}) == [0, 1]
    assert pluto_plus.switch[-1] == ("ether23", True, "secret")
    assert adi.opened == ["Pluto ip:192.168.4.201", "ad9361 ip:192.168.4.201"]

    schema.reset_for_next_holder()  # the reservation ended: off again
    assert pluto_plus.switch[-1] == ("ether23", False, "secret")


# -- KrakenSDR --------------------------------------------------------------


@pytest.fixture(scope="module")
def kraken():
    return _load("kraken_sdr_schema", {})


class FakeTuner:
    def __init__(self, serial, opened):
        self.serial, self.closed, self.resets = serial, False, 0
        self.native = types.SimpleNamespace(center_freq=0.0, sample_rate=0.0, gain=0.0, valid_gains_db=[0.0, 49.6],
                                            reset_buffer=self._reset, read_samples=self._read)
        opened.append(self)

    def _reset(self):
        self.resets += 1

    def _read(self, n):
        assert n % 256 == 0  # whole 512-byte USB packets
        return [complex(int(self.serial), 0)] * n

    def close(self):
        self.closed = True


@pytest.mark.parametrize("has_reset", [True, False])
def test_kraken_tunes_and_reads_all_five_tuners(kraken, monkeypatch, has_reset):
    opened = []

    def connect(serial):
        tuner = FakeTuner(serial, opened)
        if not has_reset:  # pyrtlsdr 0.5.0's RtlSdrAio
            del tuner.native.reset_buffer
        return tuner

    monkeypatch.setattr(kraken, "_connect_rtl_sdr", connect)
    schema = kraken.KrakenSdrSchema()
    schema.bind(kraken.KrakenSdrSchema.make_device())
    assert [t.serial for t in opened] == ["1000", "1001", "1002", "1003", "1004"]

    schema.set_center_freq(433_920_000)
    schema.set_gain("auto")
    assert {t.native.center_freq for t in opened} == {433_920_000.0} and {t.native.gain for t in opened} == {"auto"}
    reads = schema.call_read_samples(1000)
    assert [len(r) for r in reads] == [1000] * 5 and [r[0].real for r in reads] == [1000, 1001, 1002, 1003, 1004]
    assert all(t.resets == int(has_reset) for t in opened)
    with pytest.raises(ValueError):
        schema.call_read_samples(kraken._MAX_COMPLEX64_SAMPLES)

    schema.device.close()
    assert all(t.closed for t in opened)


def test_kraken_closes_the_open_tuners_when_one_is_missing(kraken, monkeypatch):
    opened = []

    def connect(serial):
        if serial == "1002":
            raise RuntimeError("no RTL-SDR found with serial '1002'")
        return FakeTuner(serial, opened)

    monkeypatch.setattr(kraken, "_connect_rtl_sdr", connect)
    with pytest.raises(RuntimeError, match="1002"):
        kraken.KrakenSdrSchema.make_device()
    assert [t.closed for t in opened] == [True, True]


# -- RFbeam K-MD7 ------------------------------------------------------------


def _packet(header, payload=b""):
    return header + struct.pack("<I", len(payload)) + payload


class FakeRadar:
    """The K-MD7's UART: answers each command with RESP and its data packets."""

    VERSION = b"K-MD7_APP-RFB-0205\0"

    def __init__(self):
        self.sent, self.opened, self.rx, self.closed, self.timeout = [], [], b"", False, 1.0

    def open(self, port, baud, parity, timeout):
        self.opened.append((port, baud, parity))
        return self

    def write(self, data):
        self.sent.append(data)
        header = data[:4]
        reply = {
            b"INIT": _packet(b"RESP", b"\0") + _packet(b"VERS", self.VERSION),
            b"GRPS": _packet(b"RESP", b"\0") + _packet(b"RPST", self.VERSION + b"\x01\x00\x00\x0c"),
            b"GNFD": _packet(b"RESP", b"\0") + _packet(b"PDAT", b"\x01\x02") + _packet(b"TDAT"),
            b"RBFR": _packet(b"RESP", b"\0"),
            b"GBYE": _packet(b"RESP", b"\0"),
        }.get(header, _packet(b"RESP", b"\x01"))
        self.rx += reply

    def read(self, n):
        data, self.rx = self.rx[:n], self.rx[n:]
        return data

    def reset_input_buffer(self):
        self.rx = b""

    def close(self):
        self.closed = True


@pytest.fixture(scope="module")
def kmd7():
    return _load("rfbeam_kmd7_schema", {})


def test_kmd7_speaks_the_rfbeam_protocol_and_keeps_the_link_commands(kmd7, monkeypatch):
    radar = FakeRadar()
    monkeypatch.setattr(kmd7.serial, "Serial", radar.open)
    schema = kmd7.KMD7Schema()
    schema.bind(kmd7.KMD7Schema.make_device(port="/dev/serial/by-id/usb-FTDI_FT230X_Basic_UART_X-if00-port0"))
    assert radar.opened == [("/dev/serial/by-id/usb-FTDI_FT230X_Basic_UART_X-if00-port0", 115200, serial.PARITY_EVEN)]
    assert radar.sent == [_packet(b"INIT", struct.pack("<I", 0))]  # stays at 115200

    assert schema.get_version() == "K-MD7_APP-RFB-0205"
    assert schema.get_parameters().startswith(b"K-MD7_APP-RFB-0205")
    assert schema.call_frame(0x0C) == {"PDAT": b"\x01\x02", "TDAT": b""}
    assert radar.sent[-1] == _packet(b"GNFD", struct.pack("<I", 0x0C))
    assert schema.call_command("RBFR", 2) == {}
    assert radar.sent[-1] == _packet(b"RBFR", struct.pack("<i", 2))
    for header in ("INIT", "GBYE", "rbfr", "RBFR; GBYE"):
        with pytest.raises(ValueError):
            schema.call_command(header, 1)
    with pytest.raises(RuntimeError, match="error 1"):
        schema.call_command("XXXX")

    schema.device.close()
    assert radar.sent[-1] == _packet(b"GBYE") and radar.closed


def test_kmd7_needs_a_port(kmd7):
    with pytest.raises(ValueError, match="init.port"):
        kmd7.KMD7Schema.make_device()
