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

"""Pluto+ (ADALM-Pluto+ clone: AD9363/AD9361, 2R2T, Gigabit Ethernet) on the network.

The built-in adalm_pluto_mimo controls (both channels' gains, enabled channels,
DDS, power) over Ethernet: init.ip is the board's static ipaddr_eth. With
init.poe it is powered from a PoE switch port like a PoE adalm_pluto (init.ip,
init.poe_port, optional poe_switch / poe_user): off until a reservation starts.
"""

import adi

from remoteRF_server.common.idl import idl_register
from remoteRF_server.common.utils import get_remoterf_root
from remoteRF_server.drivers.adalm_pluto.pluto_mimo_schema import (
    PlutoMIMOSchema,
    _apply_initial_settings,
    _normalize_channels,
)
from remoteRF_server.drivers.adalm_pluto.poe import PoePluto, is_poe


def open_2r2t(uri, init, serial=""):
    dev = adi.ad9361(uri)
    found = str(dev._ctx.attrs.get("hw_serial", "")).strip()
    if serial and found.lower() != serial.lower():
        raise RuntimeError(f"{uri} is Pluto {found}, expected {serial}")
    dev.rx_enabled_channels = _normalize_channels(init.get("rx_enabled_channels"), [0, 1])
    dev.tx_enabled_channels = _normalize_channels(init.get("tx_enabled_channels"), [0, 1])
    _apply_initial_settings(dev, init)
    return dev


class PoePlutoPlus(PoePluto):
    """A PoE Pluto that is opened as a 2R2T AD9361 after each boot."""

    def __init__(self, *, init, **kwargs):
        super().__init__(**kwargs)
        vars(self)["_init"] = init

    def _boot(self):
        super()._boot()  # power, wait for IIOD, check the serial (as a single-channel Pluto)
        vars(self)["_pluto"] = open_2r2t(self.uri, self._init)


def poe_pluto_plus(init):
    ip = str(init.get("ip") or "").strip()
    port = str(init.get("poe_port") or "").strip()
    if not ip or not port:
        raise ValueError("a PoE pluto_plus needs init.ip and init.poe_port")
    pw_file = get_remoterf_root() / "poe_switch_password"
    pluto = PoePlutoPlus(
        init=init,
        ip=ip,
        port=port,
        serial=init.get("serial", ""),
        switch=str(init.get("poe_switch") or "192.168.88.1"),
        user=str(init.get("poe_user") or "admin"),
        password=pw_file.read_text().strip() if pw_file.exists() else "",
    )
    try:
        pluto.power_down()
    except Exception as e:
        print(f"Warning: could not switch Pluto+ {pluto.uri} off on {port}: {e}")
    return pluto


@idl_register("pluto_plus")
class PlutoPlusSchema(PlutoMIMOSchema):

    device_type = "pluto_plus"
    client_class = "PlutoPlus"
    driver_version = "0.0.1"

    @staticmethod
    def make_device(**kwargs):
        if is_poe(kwargs):
            return poe_pluto_plus(kwargs)
        ip = str(kwargs.get("ip") or "").strip()
        if not ip:
            raise ValueError("a pluto_plus needs init.ip (its static ipaddr_eth)")
        return open_2r2t(f"ip:{ip}", kwargs, str(kwargs.get("serial") or "").strip())
