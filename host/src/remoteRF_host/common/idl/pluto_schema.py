from remoteRF_host.common.idl import DeviceSchema, idl_expose, idl_register

import re
import subprocess

import adi


def connect_pluto(*, serial: str):
    serial = (serial or "").strip()
    if not serial:
        print("A Pluto serial must be provided")
        return None

    try:
        out = subprocess.check_output(
            ["iio_info", "-s"],
            text=True,
            stderr=subprocess.STDOUT,
        )

        usb = None
        for line in out.splitlines():
            if (f"serial={serial}" in line) or (f"hw_serial={serial}" in line):
                m = re.search(r"\[usb:([^\]]+)\]", line)
                if m:
                    usb = m.group(1).strip()
                    break

        if not usb:
            print(f"No device found with serial {serial}")
            return None

        dev = adi.Pluto(f"usb:{usb}")
        print(f"Connected to Pluto serial={serial} via usb:{usb}")
        return dev

    except Exception as e:
        print(f"Failed to connect to Pluto serial={serial}: {e}")
        return None


@idl_register("pluto")
class PlutoSchema(DeviceSchema):
    device_type = "pluto"
    driver_version = "0.0.1"

    @staticmethod
    def make_device(**kwargs):
        serial = kwargs.get("serial")
        return connect_pluto(serial=serial)

    @idl_expose(kind="get")
    def get_filter(self):
        return self.device.filter

    @idl_expose(kind="set")
    def set_filter(self, value):
        self.device.filter = value

    @idl_expose(kind="get")
    def get_loopback(self):
        return self.device.loopback

    @idl_expose(kind="set")
    def set_loopback(self, value):
        self.device.loopback = value

    @idl_expose(kind="get")
    def get_gain_control_mode_chan0(self):
        return self.device.gain_control_mode_chan0

    @idl_expose(kind="set")
    def set_gain_control_mode_chan0(self, value):
        self.device.gain_control_mode_chan0 = value

    @idl_expose(kind="get")
    def get_hardwaregain_chan0(self):
        return self.device.hardwaregain_chan0

    @idl_expose(kind="set")
    def set_hardwaregain_chan0(self, value):
        self.device.hardwaregain_chan0 = value

    @idl_expose(kind="get")
    def get_tx_hardwaregain_chan0(self):
        return self.device.tx_hardwaregain_chan0

    @idl_expose(kind="set")
    def set_tx_hardwaregain_chan0(self, value):
        self.device.tx_hardwaregain_chan0 = value

    @idl_expose(kind="get")
    def get_rx_rf_bandwidth(self):
        return self.device.rx_rf_bandwidth

    @idl_expose(kind="set")
    def set_rx_rf_bandwidth(self, value):
        self.device.rx_rf_bandwidth = value

    @idl_expose(kind="get")
    def get_tx_rf_bandwidth(self):
        return self.device.tx_rf_bandwidth

    @idl_expose(kind="set")
    def set_tx_rf_bandwidth(self, value):
        self.device.tx_rf_bandwidth = value

    @idl_expose(kind="get")
    def get_sample_rate(self):
        return self.device.sample_rate

    @idl_expose(kind="set")
    def set_sample_rate(self, value):
        self.device.sample_rate = value

    @idl_expose(kind="get")
    def get_rx_lo(self):
        return self.device.rx_lo

    @idl_expose(kind="set")
    def set_rx_lo(self, value):
        self.device.rx_lo = value

    @idl_expose(kind="get")
    def get_tx_lo(self):
        return self.device.tx_lo

    @idl_expose(kind="set")
    def set_tx_lo(self, value):
        self.device.tx_lo = value

    @idl_expose(kind="get")
    def get_tx_cyclic_buffer(self):
        return self.device.tx_cyclic_buffer

    @idl_expose(kind="set")
    def set_tx_cyclic_buffer(self, value):
        self.device.tx_cyclic_buffer = value

    @idl_expose(kind="call")
    def call_rx(self):
        return self.device.rx()

    @idl_expose(kind="get")
    def get_rx_buffer_size(self):
        return self.device.rx_buffer_size

    @idl_expose(kind="set")
    def set_rx_buffer_size(self, value):
        self.device.rx_buffer_size = value

    @idl_expose(kind="call")
    def call_rx_destroy_buffer(self):
        self.device.rx_destroy_buffer()

    @idl_expose(kind="call")
    def call_tx(self, value):
        self.device.tx(value)

    @idl_expose(kind="call")
    def call_tx_destroy_buffer(self):
        self.device.tx_destroy_buffer()

    @idl_expose(kind="call")
    def call_disable_dds(self):
        self.device.disable_dds()

    @idl_expose(kind="call")
    def call_ip(self):
        try:
            return str(self.device.uri)
        except AttributeError:
            return str(self.device._uri_auto)

    @idl_expose(kind="get")
    def get_repr(self):
        return repr(self.device)

    @idl_expose(kind="get")
    def get_rx_dec8_filter_en(self):
        return bool(self.device.rx_dec8_filter_en)

    @idl_expose(kind="set")
    def set_rx_dec8_filter_en(self, value):
        self.device.rx_dec8_filter_en = value

    @idl_expose(kind="get")
    def get_tx_int8_filter_en(self):
        return bool(self.device.tx_int8_filter_en)

    @idl_expose(kind="set")
    def set_tx_int8_filter_en(self, value):
        self.device.tx_int8_filter_en = value

    @idl_expose(kind="get")
    def get_rates(self):
        return self.device._get_rates(self.device._rxadc, False)
