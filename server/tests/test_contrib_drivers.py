"""contrib/drivers with fakes only: no serial port, BlueZ or radio is touched."""

import enum
import importlib.util
import queue
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


# -- simulated SDR ----------------------------------------------------------


def test_sim_sdr_matches_bundled_client_and_returns_tone():
    import re

    import numpy as np

    sim = _load("sim_sdr_schema", {})
    client = Path(__file__).resolve().parents[2] / "client/src/remoterf/drivers/sim_sdr/sim_sdr_remote.py"
    bundled = re.search(r'_SCHEMA_HASH = "([^"]+)"', client.read_text()).group(1)
    assert sim.SimSdrSchema().get_idl_hash() == bundled

    dev = sim.SimSdrSchema.make_device()
    dev.rx_buffer_size = 4096
    iq = dev.rx()
    assert iq.shape == (4096,) and iq.dtype == np.complex64
    assert int(np.argmax(np.abs(np.fft.fft(iq)))) == 512
