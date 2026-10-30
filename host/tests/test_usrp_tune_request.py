"""TuneRequest(f, lo) keeps its LO offset through _construct, whatever RF
defaults an older Client sends next to it."""

import types

from remoteRF_host.drivers.usrp import usrp_schema


class _Policy:
    AUTO = object()
    MANUAL = object()
    NONE = object()


class _DeviceAddr:
    def __init__(self, value=""):
        self.value = value


class _TuneRequest:
    # As UHD's tune_request_t(target, lo_off): an offset places the RF LO
    # manually at target + offset.
    def __init__(self, target_freq=0.0, lo_off=None):
        self.target_freq = float(target_freq)
        self.rf_freq = 0.0 if lo_off is None else float(target_freq) + float(lo_off)
        self.dsp_freq = 0.0
        self.rf_freq_policy = _Policy.AUTO if lo_off is None else _Policy.MANUAL
        self.dsp_freq_policy = _Policy.AUTO
        self.args = _DeviceAddr()


def _tune(**rf):
    return usrp_schema._construct({
        "__uhd_type__": "TuneRequest", "target_freq": 915e6, "lo_offset": 5e6,
        "dsp_freq": 0.0, "dsp_freq_policy": "AUTO",
        "args": {"__uhd_type__": "DeviceAddr", "items": {}}, **rf,
    })


def test_an_lo_offset_survives_an_older_clients_rf_defaults(monkeypatch):
    fake_types = types.SimpleNamespace(TuneRequest=_TuneRequest, TuneRequestPolicy=_Policy, DeviceAddr=_DeviceAddr)
    monkeypatch.setattr(usrp_schema, "uhd", types.SimpleNamespace(types=fake_types))

    tune = _tune(rf_freq=0.0, rf_freq_policy="AUTO")
    assert tune.rf_freq_policy is _Policy.MANUAL and tune.rf_freq == 920e6
    # A current Client sends UHD's own state; an explicit RF choice wins.
    assert _tune(rf_freq=921e6, rf_freq_policy="MANUAL").rf_freq == 921e6
