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

# MultiUSRPPhaser = native RemoteRF MultiUSRP + local CN0566 Phaser control
#
# Device example:
#
# devices:
#   - device_id: 1
#     device_type: usrp_phaser
#     name: USRP N210*2 (MIMO) + Phaser
#     init:
#       profile: generic_usrp
#       device_args: "addr0=192.168.10.3,addr1=192.168.10.4"
#       phaser_uri: "ip:localhost"

from remoteRF_server.common.idl import (
    build_schema_v2,
    idl_client,
    idl_expose,
    idl_register,
    idl_v2_method,
    idl_v2_overload,
    idl_v2_parameter,
)
from remoteRF_server.drivers.usrp.usrp_schema import UsrpSchema

c = idl_client

try:
    from adi.cn0566 import CN0566
except Exception as exc:
    CN0566 = None
    _PHASER_IMPORT_ERROR = exc
else:
    _PHASER_IMPORT_ERROR = None


_PHASER_OWNER = "uhd.usrp.MultiUSRP"


def _require_phaser_module():
    if CN0566 is None:
        message = (
            "USRP+Phaser support requires pyadi-iio with adi.cn0566 "
            "on the RemoteRF host"
        )
        if _PHASER_IMPORT_ERROR is not None:
            message += f": {_PHASER_IMPORT_ERROR}"
        raise RuntimeError(message) from _PHASER_IMPORT_ERROR
    return CN0566


def _v2_param(name, wire_type="any", *, required=True, default=None):
    """Create a Dynamic IDL v2 parameter descriptor."""
    return idl_v2_parameter(
        name,
        wire_type,
        required=required,
        default=default,
    )


def _phaser_v2_method(name, parameters=(), *, returns="None", mutations=(), doc=""):
    """Describe one Phaser control call in the v2 manifest."""
    return idl_v2_method(
        name,
        _PHASER_OWNER,
        [idl_v2_overload("default", parameters, returns=returns, doc=doc)],
        execution="server_control",
        mutations=mutations,
        doc=doc,
    )


def _phaser_v2_methods():
    """Return the v2 descriptors for the flat Phaser control surface."""
    return [
        _phaser_v2_method(
            "phaser_init",
            [_v2_param("uri", "str|None", required=False, default=None)],
            returns="dict[str,any]",
            mutations=("phaser",),
            doc="Open or re-open the CN0566 controller.",
        ),
        _phaser_v2_method(
            "phaser_configure_rx",
            returns="bool",
            mutations=("phaser",),
            doc="Configure the CN0566 controller for RX mode.",
        ),
        _phaser_v2_method(
            "phaser_set_lo_freq",
            [
                _v2_param("signal_freq", "float"),
                _v2_param("if_freq", "float"),
                _v2_param("offset", "float", required=False, default=0.0),
            ],
            returns="dict[str,any]",
            mutations=("phaser",),
            doc="Configure the CN0566 LO/PLL frequency.",
        ),
        _phaser_v2_method(
            "phaser_set_gain",
            [
                _v2_param("channel", "int"),
                _v2_param("gain", "int"),
                _v2_param("apply_cal", "bool", required=False, default=False),
            ],
            returns="int",
            mutations=("phaser",),
            doc="Set the gain of one Phaser channel.",
        ),
        _phaser_v2_method(
            "phaser_set_gain_all",
            [
                _v2_param("gain", "int"),
                _v2_param("apply_cal", "bool", required=False, default=False),
            ],
            returns="int",
            mutations=("phaser",),
            doc="Set the gain of all Phaser channels.",
        ),
        _phaser_v2_method(
            "phaser_set_gains",
            [
                _v2_param("gains", "list[int]"),
                _v2_param("apply_cal", "bool", required=False, default=False),
            ],
            returns="list[int]",
            mutations=("phaser",),
            doc="Set the gain of all eight Phaser channels.",
        ),
        _phaser_v2_method(
            "phaser_set_phase",
            [
                _v2_param("channel", "int"),
                _v2_param("phase_deg", "float"),
                _v2_param("latch", "bool", required=False, default=True),
            ],
            returns="float",
            mutations=("phaser",),
            doc="Set the RX phase of one Phaser channel.",
        ),
        _phaser_v2_method(
            "phaser_set_phases",
            [
                _v2_param("phases_deg", "list[float]"),
                _v2_param("latch", "bool", required=False, default=True),
            ],
            returns="list[float]",
            mutations=("phaser",),
            doc="Set the RX phases of all eight Phaser channels.",
        ),
        _phaser_v2_method(
            "phaser_set_rx_beam_angle",
            [
                _v2_param("beam_angle_deg", "float"),
                _v2_param("signal_freq", "float|None", required=False, default=None),
            ],
            returns="dict[str,any]",
            mutations=("phaser",),
            doc="Set the CN0566 RX beam angle.",
        ),
        _phaser_v2_method(
            "phaser_latch_rx",
            returns="bool",
            mutations=("phaser",),
            doc="Latch pending RX phase settings.",
        ),
        _phaser_v2_method(
            "phaser_set_tx_switch",
            [_v2_param("value", "int")],
            returns="int",
            mutations=("phaser",),
            doc="Set the CN0566 TX output switch.",
        ),
        _phaser_v2_method(
            "phaser_set_tx_path",
            [_v2_param("enabled", "bool")],
            returns="bool",
            mutations=("phaser",),
            doc="Enable or disable the CN0566 TX input/output path.",
        ),
        _phaser_v2_method(
            "phaser_get_state",
            returns="dict[str,any]",
            doc="Return software-visible Phaser state.",
        ),
    ]


@idl_register("usrp_phaser")
class UsrpPhaserSchema(UsrpSchema):
    """Native RemoteRF USRP schema with flat CN0566 Phaser controls."""

    device_type = "usrp_phaser"
    client_class = "MultiUSRPPhaser"
    driver_version = "0.1.0"

    def __init__(self):
        super().__init__()
        self.phaser = None
        self._phaser_uri = "ip:localhost"

    # ------------------------------------------------------------------
    # Inventory / session lifecycle
    # ------------------------------------------------------------------

    def bind_inventory(self, init_kwargs):
        """
        Keep Phaser-only arguments away from UHD device arguments.

        The parent UsrpSchema receives only its native USRP inventory.
        """
        init_kwargs = dict(init_kwargs or {})
        self._phaser_uri = str(init_kwargs.pop("phaser_uri", "ip:localhost"))
        super().bind_inventory(init_kwargs)

    def create_session_schema(self):
        """
        Preserve both the native USRP inventory and Phaser configuration
        when RemoteRF creates a reservation-scoped schema instance.
        """
        clone = type(self)()

        inventory = dict(getattr(self, "_inventory", {}) or {})
        inventory["phaser_uri"] = self._phaser_uri

        clone.bind_inventory(inventory)
        clone.bind(clone.open_native_device())
        return clone

    def close_native_device(self):
        # CN0566/pyadi-iio does not require an explicit close in normal use.
        # Drop the Python reference before closing the parent USRP resources.
        self.phaser = None
        super().close_native_device()

    def _get_phaser(self):
        """Lazily create the local CN0566 controller."""
        if self.phaser is None:
            phaser_cls = _require_phaser_module()
            self.phaser = phaser_cls(uri=self._phaser_uri)
        return self.phaser

    # ------------------------------------------------------------------
    # Dynamic IDL v2
    # ------------------------------------------------------------------

    def get_idl_v2(self):
        """Return the stock UHD v2 manifest extended with Phaser methods.

        ``DeviceSchema.get_idl_v2()`` does not exist in remoterf-host 1.1.x.
        ``UsrpSchema.get_idl_v2()`` returns the pinned UHD manifest, so the
        Phaser methods have to be added explicitly and the schema hash must
        be rebuilt.
        """
        base = super().get_idl_v2()
        phaser_methods = _phaser_v2_methods()

        coverage = dict(base.get("coverage") or {})
        coverage.update(
            {
                f"{item['owner']}.{item['name']}": "implemented"
                for item in phaser_methods
            }
        )

        # UHD's legacy Python binding accepts 0/1 for the enable overload of
        # set_rx_dc_offset(), while Dynamic IDL v2 normally distinguishes bool
        # and int. Preserve the existing local-USRP call style.
        methods = [dict(item) for item in base["methods"]]
        for item in methods:
            if item.get("name") != "set_rx_dc_offset":
                continue
            for overload in item.get("overloads", ()):
                if overload.get("id") != "enable":
                    continue
                for parameter in overload.get("parameters", ()):
                    if parameter.get("name") == "enb":
                        parameter["type"] = "bool|int"

        # The Phaser host runs UHD 3.15 while the stock manifest is pinned to
        # 4.10. The session opener no longer gates on it; dropping the pin
        # also keeps clients that still compare versions from refusing.
        native_api = dict(base["native_api"])
        native_api.pop("version", None)

        return build_schema_v2(
            device_type=self.device_type,
            client_class=self.client_class,
            driver_version=self.driver_version,
            native_api=native_api,
            hardware_profiles=base["hardware_profiles"],
            hardware_profile_definitions=base.get(
                "hardware_profile_definitions", ()
            ),
            objects=base["objects"],
            methods=[*methods, *phaser_methods],
            errors=base["errors"],
            capability_fields=base["capability_fields"],
            coverage=coverage,
            deprecations=base.get("deprecations", ()),
        )

    def invoke_native(self, method_name, args, positional_args=None):
        """Route v2 Phaser calls while preserving normal UHD dispatch."""
        if method_name.startswith("phaser_"):
            target = getattr(self, f"call_{method_name}")
            return target(
                *(positional_args or ()),
                **(args or {}),
            )

        return super().invoke_native(
            method_name,
            args,
            positional_args=positional_args,
        )

    # ------------------------------------------------------------------
    # Flat Phaser control API (v1 compatibility and v2 dispatch targets)
    # ------------------------------------------------------------------

    @idl_expose(kind="call")
    def call_phaser_init(self, uri=None):
        """Open/re-open the CN0566 controller."""
        if uri is not None:
            self._phaser_uri = str(uri)
            self.phaser = None

        self._get_phaser()
        return {
            "connected": True,
            "uri": self._phaser_uri,
        }

    @idl_expose(kind="call")
    def call_phaser_configure_rx(self):
        phaser = self._get_phaser()
        phaser.configure(device_mode="rx")
        return True

    @idl_expose(kind="call")
    def call_phaser_set_lo_freq(self, signal_freq, if_freq, offset=0.0):
        """Configure the CN0566 PLL frequency."""
        phaser = self._get_phaser()

        signal_freq = float(signal_freq)
        if_freq = float(if_freq)
        offset = float(offset)

        phaser.SignalFreq = signal_freq
        programmed = int(signal_freq + if_freq - offset) // 4
        phaser.frequency = programmed

        return {
            "signal_freq": signal_freq,
            "if_freq": if_freq,
            "offset": offset,
            "phaser_frequency": programmed,
        }

    @idl_expose(kind="call")
    def call_phaser_set_gain(self, channel, gain, apply_cal=False):
        channel = int(channel)
        gain = int(gain)

        if not 0 <= channel < 8:
            raise ValueError("Phaser channel must be in [0, 7]")
        if not 0 <= gain <= 127:
            raise ValueError("Phaser gain must be in [0, 127]")

        self._get_phaser().set_chan_gain(
            channel,
            gain,
            apply_cal=bool(apply_cal),
        )
        return gain

    @idl_expose(kind="call")
    def call_phaser_set_gain_all(self, gain, apply_cal=False):
        gain = int(gain)
        if not 0 <= gain <= 127:
            raise ValueError("Phaser gain must be in [0, 127]")

        phaser = self._get_phaser()
        for channel in range(8):
            phaser.set_chan_gain(
                channel,
                gain,
                apply_cal=bool(apply_cal),
            )
        return gain

    @idl_expose(kind="call")
    def call_phaser_set_gains(self, gains, apply_cal=False):
        gains = [int(value) for value in gains]
        if len(gains) != 8:
            raise ValueError("phaser_set_gains expects exactly 8 gain values")
        if any(value < 0 or value > 127 for value in gains):
            raise ValueError("All Phaser gains must be in [0, 127]")

        phaser = self._get_phaser()
        for channel, gain in enumerate(gains):
            phaser.set_chan_gain(
                channel,
                gain,
                apply_cal=bool(apply_cal),
            )
        return gains

    @idl_expose(kind="call")
    def call_phaser_set_phase(self, channel, phase_deg, latch=True):
        channel = int(channel)
        phase_deg = float(phase_deg) % 360.0

        if not 0 <= channel < 8:
            raise ValueError("Phaser channel must be in [0, 7]")

        phaser = self._get_phaser()
        phaser.elements.get(channel + 1).rx_phase = phase_deg

        if bool(latch):
            phaser.latch_rx_settings()

        return phase_deg

    @idl_expose(kind="call")
    def call_phaser_set_phases(self, phases_deg, latch=True):
        phases = [float(value) % 360.0 for value in phases_deg]
        if len(phases) != 8:
            raise ValueError("phaser_set_phases expects exactly 8 phase values")

        phaser = self._get_phaser()
        for channel, phase_deg in enumerate(phases):
            phaser.elements.get(channel + 1).rx_phase = phase_deg

        if bool(latch):
            phaser.latch_rx_settings()

        return phases

    @idl_expose(kind="call")
    def call_phaser_set_rx_beam_angle(self, beam_angle_deg, signal_freq=None):
        """Steer the CN0566 RX array toward a physical beam angle."""
        import math

        phaser = self._get_phaser()

        beam_angle_deg = float(beam_angle_deg)
        if not -90.0 <= beam_angle_deg <= 90.0:
            raise ValueError("Phaser RX beam angle must be in [-90, 90] degrees")

        if signal_freq is None:
            signal_freq = getattr(phaser, "SignalFreq", None)
            if signal_freq is None:
                raise RuntimeError(
                    "Phaser SignalFreq is not set. Call phaser_set_lo_freq() "
                    "first or provide signal_freq explicitly."
                )

        signal_freq = float(signal_freq)
        if signal_freq <= 0:
            raise ValueError("signal_freq must be positive")

        c = 299792458.0
        d = 0.014  # CN0566 antenna element spacing [m]

        phase_diff_deg = (
            360.0
            * signal_freq
            * d
            / c
            * math.sin(math.radians(beam_angle_deg))
        )

        phaser.set_beam_phase_diff(phase_diff_deg)

        return {
            "beam_angle_deg": beam_angle_deg,
            "signal_freq": signal_freq,
            "phase_diff_deg": phase_diff_deg,
        }

    @idl_expose(kind="call")
    def call_phaser_latch_rx(self):
        self._get_phaser().latch_rx_settings()
        return True

    @idl_expose(kind="call")
    def call_phaser_set_tx_switch(self, value):
        """Set the CN0566 TX output switch directly."""
        value = int(value)
        if value not in (0, 1):
            raise ValueError("Phaser TX switch must be 0 or 1")

        phaser = self._get_phaser()
        phaser._gpios.gpio_tx_sw = value
        return value

    @idl_expose(kind="call")
    def call_phaser_set_tx_path(self, enabled):
        """Route the CN0566 LO to the TX circuitry."""
        enabled = bool(enabled)
        phaser = self._get_phaser()
        phaser._gpios.gpio_vctrl_1 = int(enabled)
        phaser._gpios.gpio_vctrl_2 = int(enabled)
        if enabled:
            # The GUI writes this last to enable the PLL and commit the
            # configured frequency/path settings.
            phaser.enable = 0
        return enabled

    @idl_expose(kind="call")
    def call_phaser_get_state(self):
        """Return software-visible Phaser state without changing hardware."""
        phaser = self._get_phaser()

        gains = []
        phases = []
        for channel in range(8):
            element = phaser.elements.get(channel + 1)
            gains.append(getattr(element, "rx_gain", None))
            phases.append(getattr(element, "rx_phase", None))

        gpio_tx_sw = None
        gpios = getattr(phaser, "_gpios", None)
        if gpios is not None:
            try:
                gpio_tx_sw = int(gpios.gpio_tx_sw)
            except Exception:
                gpio_tx_sw = None

        return {
            "connected": True,
            "uri": self._phaser_uri,
            "signal_freq": getattr(phaser, "SignalFreq", None),
            "frequency": getattr(phaser, "frequency", None),
            "rx_gains": gains,
            "rx_phases": phases,
            "gpio_tx_sw": gpio_tx_sw,
        }
