from __future__ import annotations

import datetime as dt
import json
import sys
import threading
import time
import types
from unittest.mock import MagicMock

import numpy as np
import pytest

from remoteRF_server.drivers import bluetooth_diag, gps_diag, kraken_sdr_diag, rfbeam_kmd7_diag
from remoteRF_server.drivers.adalm_pluto import pluto_diag
from remoteRF_server.drivers.adalm_pluto.poe import PoePluto
from remoteRF_server.drivers.rtl_sdr import rtl_sdr_diag
from remoteRF_server.drivers.usrp import usrp_diag
from remoteRF_server.server import device_manager as dm
from remoteRF_server.server import diag
from remoteRF_server.server.commands import resolve


def state(name, dev, dtype, reserved=False):
    return dm._DeviceState(dev=dev, origin="local", online=dev is not None,
                           salt="s" if reserved else "", hsh="h" if reserved else "",
                           name=name, ident="", dtype=dtype)


class Attrs:
    """get_x/set_x over a dict, like a schema."""

    def __getattr__(self, name):
        if name.startswith("get_"):
            return lambda: self.attrs[name[4:]]
        if name.startswith("set_"):
            return lambda value: self.set(name[4:], value)
        raise AttributeError(name)

    def set(self, key, value):
        self.attrs[key] = value


class FakePluto(Attrs):
    def __init__(self, lo_off=0, dead_rx=False, coax_min_tx=None):
        self.attrs = dict(sample_rate=30_720_000, rx_lo=2_400_000_000, tx_lo=2_400_000_000,
                          rx_rf_bandwidth=18_000_000, tx_rf_bandwidth=18_000_000,
                          gain_control_mode_chan0="slow_attack", rx_hardwaregain_chan0=71,
                          tx_hardwaregain_chan0=-10, rx_buffer_size=1024, loopback=0, tx_cyclic_buffer=False)
        self.lo_off, self.dead_rx, self.coax_min_tx = lo_off, dead_rx, coax_min_tx
        self.tx = None
        self.dds = True  # on at boot, like the AD936x DDS core
        self.retuned_while_live = 0
        self.tx_gains_while_sending = []
        self.device = types.SimpleNamespace(
            _ctx=types.SimpleNamespace(attrs={"hw_model": "Analog Devices PlutoSDR Rev.C", "hw_serial": "1044ab",
                                              "fw_version": "v0.38"}),
            rx=self._rx, _get_iio_attr=lambda *a: 41_500)

    def get_rx_lo(self):
        return self.attrs["rx_lo"] + self.lo_off

    def set(self, key, value):
        if key in ("tx_lo", "sample_rate", "tx_rf_bandwidth") and (self.dds or self.tx is not None):
            self.retuned_while_live += 1
        self.attrs[key] = value

    def call_tx(self, data):
        self.tx = np.asarray(data)
        self.tx_gains_while_sending.append(self.attrs["tx_hardwaregain_chan0"])

    def call_tx_destroy_buffer(self):
        self.tx = None

    def call_rx_destroy_buffer(self):
        pass

    def call_disable_dds(self):
        self.dds = False

    def _rx(self):
        n = self.attrs["rx_buffer_size"]
        if self.dead_rx:
            return np.zeros(n, dtype=np.complex64)
        noise = (np.random.randn(n) + 1j * np.random.randn(n)) * 4
        coax = self.coax_min_tx is not None and self.attrs["tx_hardwaregain_chan0"] >= self.coax_min_tx
        if self.tx is not None and (self.attrs["loopback"] == 1 or coax):
            return np.resize(self.tx, n) + noise
        return noise


class FakeRtl(Attrs):
    def __init__(self, short=False):
        self.attrs = dict(sample_rate=2_400_000, center_freq=100_000_000, gain=20.7)
        self.short = short

    def get_tuner_type(self):
        return "R828D"

    def get_serial_number(self):
        return "00000001"

    def get_valid_gains_db(self):
        return [0.0, 9.0, 20.7, 49.6]

    def call_reset_buffer(self):
        pass

    def call_read_bytes(self, n):
        data = np.random.randint(90, 165, n, dtype=np.uint8).tobytes()
        return data[: n - 512] if self.short else data

    def call_read_samples(self, n):
        return ((np.random.randn(n) + 1j * np.random.randn(n)) * 0.1).astype(np.complex64)


class FakeKraken(Attrs):
    def __init__(self, stuck_channel=None):
        self.attrs = dict(sample_rate=2_400_000, center_freq=433_920_000, gain=20.7)
        self.stuck_channel = stuck_channel

    def get_gain(self):
        return [self.attrs["gain"]] * 5

    def get_num_channels(self):
        return 5

    def get_serials(self):
        return ["1000", "1001", "1002", "1003", "1004"]

    def get_tuner_type(self):
        return "R820T"

    def get_valid_gains_db(self):
        return [0.0, 20.7, 49.6]

    def call_read_samples(self, n):
        reads = [((np.random.randn(n) + 1j * np.random.randn(n)) * 0.1).astype(np.complex64) for _ in range(5)]
        if self.stuck_channel is not None:
            reads[self.stuck_channel][:] = 0.5
        return reads


class FakeKmd7:
    def __init__(self, version="K-MD7_APP-RFB-0205"):
        self.version = version
        self.frames = []

    def get_version(self):
        return self.version

    def get_parameters(self):
        return self.version.encode() + b"\0\x01\x00\x00\x0c"

    def call_frame(self, flags):
        self.frames.append(flags)
        return {"DONE": (16).to_bytes(4, "little")}


class Range:
    def __init__(self, a, b):
        self.a, self.b = a, b

    def start(self):
        return self.a

    def stop(self):
        return self.b


class FakeUsrp:
    def __init__(self, rx_error=False):
        self.v = {}
        self.rx_error = rx_error
        self.closed = False

    def get_usrp_rx_info(self, chan):
        return {"mboard_id": "B200mini", "mboard_serial": "31F0000"}

    def set_rx_rate(self, r, c): self.v["rate"] = r
    def get_rx_rate(self, c): return self.v["rate"]
    def set_rx_freq(self, tr, c): self.v["freq"] = tr.f
    def get_rx_freq(self, c): return self.v["freq"]
    def get_rx_freq_range(self, c): return Range(70e6, 6e9)
    def set_rx_gain(self, g, c): self.v["gain"] = g
    def get_rx_gain(self, c): return self.v["gain"]
    def get_rx_gain_range(self, c): return Range(0, 76)

    def get_rx_stream(self, args):
        usrp = self

        class Streamer:
            def get_max_num_samps(self): return 2040
            def issue_stream_cmd(self, cmd): pass

            def recv(self, buf, meta, timeout):
                meta.error_code = "overflow" if usrp.rx_error else "none"
                buf[0, :] = 0.01 + 0.01j
                return buf.shape[1]

        return Streamer()


fake_uhd = types.SimpleNamespace(
    types=types.SimpleNamespace(
        TuneRequest=lambda f: types.SimpleNamespace(f=f),
        RXMetadata=lambda: types.SimpleNamespace(error_code="none", strerror=lambda: "overflow"),
        StreamCMD=lambda mode: types.SimpleNamespace(),
        StreamMode=types.SimpleNamespace(num_done="num_done"),
        RXMetadataErrorCode=types.SimpleNamespace(none="none")),
    usrp=types.SimpleNamespace(StreamArgs=lambda a, b: types.SimpleNamespace()))


class FakeUsrpSchema:
    def __init__(self, rx_error=False):
        self.device = None
        self.prepared = False
        self.live = types.SimpleNamespace(device=FakeUsrp(rx_error), close_native_device=MagicMock())

    def prepare_for_holder(self):
        self.prepared = True

    def create_session_schema(self):
        assert self.prepared, "the cold image pre-load comes first"
        return self.live


class FakeGps:
    def __init__(self, alive=True, fix=False):
        self.alive, self.fix, self.n = alive, fix, 0

    def call_read_raw(self, count):
        if self.alive:
            self.n += 1
        return [_nmea(f"GPGGA,{self.n:06d}.00,,,,,0,00,,,,,,,"), _nmea("GPRMC,,V,,,,,,,,,,N")]

    def get_has_fix(self): return self.fix
    def get_satellites(self): return 7
    def get_fix_quality(self): return 1


def _nmea(body):
    check = 0
    for c in body:
        check ^= ord(c)
    return f"${body}*{check:02X}"


class FakeBt:
    def __init__(self, powered=True):
        self.powered = powered
        self.scans = 0

        self.device = types.SimpleNamespace(device_cache={}, last_scan_time=0.0)

    def get_powered(self): return self.powered
    def get_address(self): return "00:11:22:33:44:55"

    def call_scan_summary(self, timeout):
        self.scans += 1
        self.device.device_cache, self.device.last_scan_time = {"aa:bb": {}}, time.time()
        return {"total_devices": 3}


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.setattr(dm, "_devices", {})
    monkeypatch.setattr(dm, "_diag_until", {})
    monkeypatch.setattr(diag, "_live_session", lambda gid: False)
    monkeypatch.setattr(diag, "_reservation_windows", lambda gid: [])
    monkeypatch.setattr(diag, "_inits", lambda: {})
    monkeypatch.setattr(usrp_diag, "_uhd", lambda: fake_uhd)
    monkeypatch.setattr(gps_diag, "LISTEN_S", 1)


def run_one(st, init=None, gid=1):
    dm._devices.clear()
    dm._devices[gid] = st
    row = diag._plan(False)[0]
    assert "status" not in row, row.get("status")
    display = diag._Display(open("/dev/null", "w"))
    diag._run_one(row, init or {}, display, -1, 0)
    display.out.close()
    return row, {t["name"]: t for t in row["tests"]}


def statuses(tests):
    return {name: t["status"] for name, t in tests.items()}


# ---- per-type scripts ----

def test_pluto_passes_and_restores_settings():
    fake = FakePluto()
    row, tests = run_one(state("Pluto 01", fake, "adalm_pluto"))
    assert row["status"] == "ok", tests
    assert statuses(tests) == {**{n: "pass" for n in tests}, "channel 1": "skip", "coax loopback": "skip"}
    assert tests["temperature"]["values"]["celsius"] == 41.5
    assert all(v["snr_db"] > 20 for v in tests["loopback tone"]["values"].values())
    assert fake.attrs["sample_rate"] == 30_720_000 and fake.attrs["loopback"] == 0
    assert fake.attrs["gain_control_mode_chan0"] == "slow_attack" and fake.tx is None
    assert max(fake.tx_gains_while_sending) == pluto_diag.TX_MIN_DB  # nothing radiates
    assert fake.retuned_while_live == 0  # the boot DDS tone was off before the first retune
    assert fake.attrs["tx_cyclic_buffer"] is False and fake.attrs["tx_hardwaregain_chan0"] == -10


@pytest.mark.parametrize("dtype", ["adalm_pluto_mimo", "pluto_plus"])
def test_pluto_mimo_tones_on_both_channels_and_restores(dtype):
    fake = FakePluto()
    fake.attrs.update(gain_control_mode_chan1="slow_attack", rx_hardwaregain_chan1=71, tx_hardwaregain_chan1=0,
                      tx_enabled_channels=[0, 1], rx_enabled_channels=[0, 1])
    row, tests = run_one(state("MIMO", fake, dtype))
    assert row["status"] == "ok", tests
    assert tests["channel 1"]["status"] == "pass" and tests["channel 1"]["values"]["snr_db"] > 20
    assert fake.attrs["tx_enabled_channels"] == fake.attrs["rx_enabled_channels"] == [0, 1]
    assert fake.attrs["tx_hardwaregain_chan1"] == 0 and fake.attrs["gain_control_mode_chan1"] == "slow_attack"
    assert fake.attrs["loopback"] == 0 and max(fake.tx_gains_while_sending) == pluto_diag.TX_MIN_DB


def test_pluto_failures_are_named():
    _, tests = run_one(state("Pluto 02", FakePluto(lo_off=1_000_000), "adalm_pluto"))
    assert tests["lo tuning"]["status"] == "fail" and "RX LO" in tests["lo tuning"]["detail"]
    _, tests = run_one(state("Pluto 03", FakePluto(dead_rx=True), "adalm_pluto"), gid=2)
    assert tests["rx buffers"]["status"] == tests["loopback tone"]["status"] == "fail"


def test_multitap_coax_steps_tx_up_but_never_past_minus_10():
    fake = FakePluto(coax_min_tx=-30)
    _, tests = run_one(state("Tap", fake, "adalm_pluto"), init={"multi_tap": True})
    assert tests["coax loopback"]["status"] == "pass"
    assert tests["coax loopback"]["values"]["tx_db"] == -30
    fake = FakePluto(coax_min_tx=0)  # cable missing: gives up at -10 dB
    _, tests = run_one(state("Tap", fake, "adalm_pluto"), init={"multi_tap": True}, gid=2)
    assert tests["coax loopback"]["status"] == "fail"
    assert max(fake.tx_gains_while_sending) == -10


@pytest.mark.parametrize("reserved_midway,powered_down", [(False, True), (True, False)])
def test_poe_pluto_boots_and_returns_to_standby(reserved_midway, powered_down):
    native = MagicMock(spec=PoePluto)
    native.power_state = "standby"
    schema = FakePluto()
    schema.device = native
    schema.call_power_down = MagicMock()
    st = state("Pluto 04", schema, "adalm_pluto")
    native.power_up.side_effect = lambda: setattr(st, "salt", "s") or setattr(st, "hsh", "h") if reserved_midway else None
    dm._devices[1] = st
    assert diag._plan(True)[0]["eta"] > 30  # standby: the boot is in the ETA
    run_one(st)
    native.power_up.assert_called_once()
    assert schema.call_power_down.called is powered_down


def test_gate_failure_skips_the_rest_but_still_restores():
    native = MagicMock(spec=PoePluto)
    native.power_state = "standby"
    native.power_up.side_effect = RuntimeError("did not boot within 45 s")
    schema = types.SimpleNamespace(device=native, call_power_down=MagicMock())
    row, tests = run_one(state("Pluto 05", schema, "adalm_pluto"))
    assert tests["power"]["status"] == "fail" and "45 s" in tests["power"]["detail"]
    assert tests["gain"] == {"name": "gain", "status": "skip", "detail": "not run: power failed"}
    assert tests["restore"]["status"] == "pass"
    schema.call_power_down.assert_called_once()
    assert row["status"] == "issues"


def test_rtl_pass_and_short_read():
    fake = FakeRtl()
    row, tests = run_one(state("RTL 01", fake, "rtl_sdr"))
    assert row["status"] == "ok", tests
    assert fake.attrs == {"sample_rate": 2_400_000, "center_freq": 100_000_000, "gain": 20.7}
    _, tests = run_one(state("RTL 02", FakeRtl(short=True), "rtl_sdr"), gid=2)
    assert tests["byte reads"]["status"] == "fail"


class FakeRtlBlogV4(FakeRtl):
    """R828D on the installed librtlsdr: gain reads back 0 and there is no reset_buffer."""

    def get_gain(self):
        return 0

    def call_reset_buffer(self):
        raise RuntimeError("the installed PyRtlSdr/librtlsdr runtime does not support reset_buffer")


def test_rtl_blog_v4_unreported_gain_and_no_reset_buffer_pass():
    row, tests = run_one(state("RTLSDR 0", FakeRtlBlogV4(), "rtl_sdr"))
    assert row["status"] == "ok", tests
    assert "does not report gain" in tests["gain"]["detail"]


def test_kraken_reads_all_five_and_restores():
    fake = FakeKraken()
    row, tests = run_one(state("Kraken", fake, "kraken_sdr"))
    assert row["status"] == "ok", tests
    assert len(tests["iq samples"]["values"]["dbfs"]) == 5
    assert fake.attrs == {"sample_rate": 2_400_000, "center_freq": 433_920_000, "gain": 20.7}
    _, tests = run_one(state("Kraken", FakeKraken(stuck_channel=3), "kraken_sdr"), gid=2)
    assert tests["iq samples"]["status"] == "fail" and "channel 3" in tests["iq samples"]["detail"]


def test_kmd7_is_read_only_and_names_the_wrong_sensor():
    fake = FakeKmd7()
    row, tests = run_one(state("K-MD7", fake, "rfbeam_kmd7"))
    assert row["status"] == "ok", tests
    assert tests["version"]["detail"] == "K-MD7_APP-RFB-0205" and fake.frames == [0x20]
    assert tests["frame"]["values"]["frame"] == 16
    _, tests = run_one(state("K-LD7", FakeKmd7("K-LD7_APP-RFB-0103"), "rfbeam_kmd7"), gid=2)
    assert tests["version"]["status"] == "fail" and tests["frame"]["status"] == "skip"


def test_usrp_rx_only_preloads_then_closes():
    schema = FakeUsrpSchema()
    row, tests = run_one(state("B205", schema, "usrp"))
    assert row["status"] == "ok", tests
    assert tests["rx stream"]["values"]["samples"] >= usrp_diag.STREAM_N
    schema.live.close_native_device.assert_called_once()
    assert not any(hasattr(schema.live.device, a) for a in ("set_tx_freq", "get_tx_stream"))
    _, tests = run_one(state("B205", FakeUsrpSchema(rx_error=True), "usrp"), gid=2)
    assert tests["rx stream"]["status"] == "fail" and "overflow" in tests["rx stream"]["detail"]


def test_gps_live_dead_and_optional_fix():
    _, tests = run_one(state("GPS", FakeGps(), "gps"))
    assert statuses(tests) == {"nmea liveness": "pass", "sentence types": "pass", "checksums": "pass", "fix": "skip"}
    _, tests = run_one(state("GPS", FakeGps(fix=True), "gps"), gid=2)
    assert tests["fix"]["values"]["satellites"] == 7
    row, tests = run_one(state("GPS", FakeGps(alive=False), "gps"), gid=3)
    assert tests["nmea liveness"]["status"] == "fail" and tests["checksums"]["status"] == "skip"


def test_bluetooth_powered_and_not():
    bt = FakeBt()
    _, tests = run_one(state("BT", bt, "bluetooth"))
    assert statuses(tests) == {"adapter": "pass", "scan": "pass", "restore": "pass"}
    assert bt.device.device_cache == {}  # the next holder does not get diag's scan
    bt = FakeBt(powered=False)
    _, tests = run_one(state("BT", bt, "bluetooth"), gid=2)
    assert tests["adapter"]["status"] == "fail" and bt.scans == 0


def test_timeout_halts_the_device_and_holds_it_until_the_test_ends(monkeypatch):
    block, after = threading.Event(), {}

    def stuck(ctx):
        block.wait()
        try:
            ctx["schema"].get_powered()
        except RuntimeError as exc:
            after["error"] = str(exc)

    monkeypatch.setattr(diag, "STRAY_WAIT_S", 0.1)
    monkeypatch.setattr(bluetooth_diag, "TESTS", [("adapter", 0, 0.2, stuck),
                                                   ("scan", 0, 1, lambda ctx: "ok")])
    st = state("BT", FakeBt(), "bluetooth")
    row, tests = run_one(st)
    assert tests["adapter"]["detail"] == "no answer after 0.2 s"
    assert tests["scan"]["detail"] == "not run: adapter timed out"
    assert tests["restore"]["status"] == "pass" and tests["release"]["status"] == "fail"
    assert dm.diag_blocks(1) and st.io_lock.acquire(blocking=False)  # refused, not deadlocked
    st.io_lock.release()
    block.set()
    deadline = time.monotonic() + 5
    while dm.diag_blocks(1) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not dm.diag_blocks(1)
    assert after == {"error": "diag stopped this test"}  # the abandoned thread cannot drive it


def test_reservation_or_session_that_starts_mid_run_is_respected(monkeypatch):
    a, b = state("RTL A", FakeRtl(), "rtl_sdr"), state("RTL B", FakeRtl(), "rtl_sdr")
    dm._devices.update({1: a, 2: b})
    rows = diag._plan(False)
    b.salt, b.hsh = "s", "h"  # reserved after the plan
    display = diag._Display(open("/dev/null", "w"))
    for row in rows:
        diag._run_one(row, {}, display, -1, 0)
    assert rows[0]["status"] == "ok" and rows[1]["status"] == "skipped: reserved now" and not rows[1]["tests"]

    def reserve_now(ctx):
        a.salt, a.hsh = "s", "h"
        return "ok"

    monkeypatch.setattr(rtl_sdr_diag, "TESTS", [("tuner", 1, 5, reserve_now)] + rtl_sdr_diag.TESTS[1:])
    a.salt = a.hsh = ""
    row = diag._plan(False)[0]
    diag._run_one(row, {}, display, -1, 0)
    assert row["tests"][1]["detail"] == "not run: a reservation started"
    b.salt = b.hsh = ""
    row = diag._plan(True)[1]
    assert "status" not in row
    monkeypatch.setattr(diag, "_live_session", lambda gid: gid == 2)  # a v2 open in flight after the plan
    diag._run_one(row, {}, display, -1, 0, force=True)
    assert row["status"] == "skipped: in a live session" and not dm._diag_until
    display.out.close()


def test_v2_open_refused_under_diag(monkeypatch):
    from remoteRF_server.server import dynamic_v2

    monkeypatch.setattr(dynamic_v2, "_refuse_partner_token", lambda token: None)
    monkeypatch.setattr(dynamic_v2, "resolve_gid_for_token", lambda token: 3)
    monkeypatch.setattr(dynamic_v2, "get_local_device_context", lambda gid: {"schema": object()})
    monkeypatch.setattr(dynamic_v2.SessionManager, "schema_for_token", lambda self, token: {"schema_hash": "h"})
    manager = dynamic_v2.SessionManager()
    dm.diag_hold(3, time.time() + 60)
    with pytest.raises(dynamic_v2.RemoteRFReservationError, match="diagnostics"):
        manager.open("tok")
    assert not manager.busy(3)


# ---- selection, gating, ETA ----

def test_reserved_and_soon_reserved_devices_are_skipped(monkeypatch):
    now = dt.datetime.now()
    dm._devices.update({1: state("RTL now", FakeRtl(), "rtl_sdr", reserved=True),
                        2: state("RTL soon", FakeRtl(), "rtl_sdr"),
                        3: state("RTL later", FakeRtl(), "rtl_sdr"),
                        4: state("Phaser", object(), "usrp_phaser"),
                        5: state("Gone", None, "rtl_sdr")})
    windows = {2: [(now + dt.timedelta(minutes=1), now + dt.timedelta(hours=1))],
               3: [(now + dt.timedelta(hours=3), now + dt.timedelta(hours=4))]}
    monkeypatch.setattr(diag, "_reservation_windows", lambda gid: windows.get(gid, []))
    rows = {r["device_id"]: r.get("status") for r in diag._plan(False)}
    assert rows == {1: "skipped: reserved now", 2: f"skipped: reserved from {(now + dt.timedelta(minutes=1)):%H:%M}",
                    3: None, 4: "no diag script", 5: "issues"}
    assert {r["device_id"]: r.get("status") for r in diag._plan(True)}[1] is None  # --force tests it
    monkeypatch.setattr(diag, "_live_session", lambda gid: gid == 1)
    assert diag._plan(True)[0]["status"] == "skipped: in a live session"


def test_device_under_diag_refuses_calls_and_overlapping_reservations():
    st = state("RTL", FakeRtl(), "rtl_sdr")
    dm._devices[7] = st
    seen = {}

    def probe(ctx):
        seen["blocks"] = dm.diag_blocks(7)
        seen["other"] = dm.diag_blocks(8)
        seen["soon"] = dm.diag_blocks(7, time.time() + 5)
        seen["tomorrow"] = dm.diag_blocks(7, time.time() + 86400)
        with pytest.raises(RuntimeError, match="diagnostics"):
            with dm.acquire_device_by_gid(7):
                pass
        return "ok"

    diag_mod = types.SimpleNamespace(TESTS=[("probe", 1, 5, probe)])
    row = {"device_id": 7, "st": st, "mod": diag_mod, "eta": 1, "tests": []}
    diag._run_one(row, {}, diag._Display(open("/dev/null", "w")), -1, 0)
    assert seen == {"blocks": True, "other": False, "soon": True, "tomorrow": False}
    assert row["status"] == "ok" and not dm._diag_until and not dm.diag_blocks(7)
    assert st.io_lock.acquire(blocking=False)


def test_force_pauses_everything_and_always_releases(tmp_path, monkeypatch, capfd):
    st = state("RTL", FakeRtl(), "rtl_sdr", reserved=True)
    dm._devices[1] = st
    seen = {}

    def interrupted(ctx):
        seen["host device"] = dm.diag_blocks(99)
        raise KeyboardInterrupt

    monkeypatch.setattr(rtl_sdr_diag, "TESTS", [("tuner", 1, 5, interrupted)])
    assert diag.run(force=True, cfg_dir=tmp_path) == 1
    assert seen == {"host device": True}
    assert dm._diag_until == {} and not dm.diag_blocks(1)
    assert st.io_lock.acquire(blocking=False)
    out = capfd.readouterr().out
    assert "pauses every client's device traffic" in out and "tests reserved devices: RTL" in out
    assert "interrupted" in out


def test_force_needs_confirmation_at_a_terminal(tmp_path, monkeypatch, capfd):
    dm._devices[1] = state("RTL", FakeRtl(), "rtl_sdr")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    assert diag.run(force=True, ask=lambda q: "n", cfg_dir=tmp_path) == 1
    assert "Cancelled." in capfd.readouterr().out
    assert not (tmp_path / "logs").exists()


def test_eta_math():
    mod = types.SimpleNamespace(TESTS=[("a", 2, 5, None), ("b", lambda schema: schema, 5, None)], TEARDOWN_S=(3, 9))
    assert diag.device_eta(mod, 10) == 15
    assert diag.device_eta(types.SimpleNamespace(TESTS=[("a", 1, 2, None)]), None) == 1
    assert (diag._fmt(0), diag._fmt(59.6), diag._fmt(61), diag._fmt(-4)) == ("0s", "1m 00s", "1m 01s", "0s")
    assert sum(diag.device_eta(m, FakePluto()) for m in (pluto_diag,)) < 60  # a USB Pluto: no boot


# ---- output ----

def test_non_tty_lines_panel_files_and_copy(tmp_path, monkeypatch, capfd):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    dm._devices.update({1: state("RTL 01", FakeRtl(), "rtl_sdr"),
                        2: state("RTL 02", FakeRtl(short=True), "rtl_sdr"),
                        3: state("Phaser", object(), "usrp_phaser")})
    tables = []
    monkeypatch.setattr(diag, "print_table", lambda *a, **kw: tables.append(a))
    assert diag.run(copy=True, cfg_dir=tmp_path) == 1
    out = capfd.readouterr().out
    lines = out.splitlines()
    assert lines[0].startswith("Diagnosing 2 of 3 devices · ETA ~")
    assert lines[1].startswith("✓ [1] RTL 01 · 7/7 passed")
    assert lines[2].startswith("✗ [2] RTL 02 · 6/7 passed") and lines[2].endswith("failed: byte reads")
    assert lines[3].startswith("    byte reads: asked 512 bytes")
    assert lines[4] == "- [3] Phaser · no diag script" or lines[4] == "– [3] Phaser · no diag script"
    assert lines[5] == "1 of 2 devices passed · issues: RTL 02"
    assert "⠋" not in out and "\x1b[2K" not in out  # no spinner off a TTY
    (label, rows, columns), = tables
    assert label == "Diagnostics" and columns == ["device_id", "name", "type", "tests", "status", "failed"]
    assert [(r["tests"], r["status"], r["failed"]) for r in rows] == [
        ("7/7", "ok", "-"), ("6/7", "issues", "byte reads"), ("-", "no diag script", "-")]
    js = json.loads(next((tmp_path / "logs").glob("diag-*.json")).read_text())
    assert [d["status"] for d in js["devices"]] == ["ok", "issues", "no diag script"]
    downloads = tmp_path / "home" / "Downloads"
    assert sorted(p.suffix for p in downloads.iterdir()) == [".json", ".txt"]
    assert "FAIL  byte reads" in next(downloads.glob("*.txt")).read_text()
    assert next((tmp_path / "logs").glob("diag-*.log")).exists()


@pytest.mark.parametrize("answer,copied", [("y", True), ("n", False)])
def test_copy_prompt(tmp_path, monkeypatch, capfd, answer, copied):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    dm._devices[1] = state("BT", FakeBt(), "bluetooth")
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    asked = []
    assert diag.run(ask=lambda q: asked.append(q) or answer, cfg_dir=tmp_path) == 0
    assert asked == ["  Copy diag results to your Downloads folder? (y/n): "]
    assert (tmp_path / "home" / "Downloads").exists() is copied


def test_command_table_and_flags(capfd, monkeypatch):
    command, rest = resolve(["diag", "--force", "--copy"])
    assert command.names[0] == "diag" and rest == ["--force", "--copy"] and command.interactive
    from remoteRF_server.server import commands

    assert any(l.startswith("  diag ") for l in commands.help_text(in_daemon=True, section="Devices"))
    from remoteRF_server.server import grpc_server

    calls = []
    monkeypatch.setattr(diag, "run", lambda **kw: calls.append(kw) or 0)
    assert grpc_server.cmd_diag(["--bogus"]) == 2
    assert grpc_server.cmd_diag(["-c"]) == 0 and grpc_server.cmd_diag(["--FORCE", "--copy"]) == 0
    assert [(c["force"], c["copy"]) for c in calls] == [(False, True), (True, True)]


def test_device_under_diag_lists_offline_with_time_left(monkeypatch):
    monkeypatch.setattr(dm, "_sync_host_devices", lambda: None)
    dm._devices[7] = state("RTL", FakeRtl(), "rtl_sdr")
    assert dm._local_devices_str_snapshot()[7] == "RTL (online)"
    dm.diag_hold(7, time.time() + 150)
    assert dm._local_devices_str_snapshot()[7] == "RTL (offline: in diag, ~2m left)"
    assert dm.device_inventory_snapshot()[7]["online"] is False
    assert dm.describe_devices([7])[0]["online"] is False
    dm.diag_hold(7, float("inf"))
    assert dm._local_devices_str_snapshot()[7] == "RTL (offline: in diag)"
    dm.diag_release(7)
    assert dm.device_inventory_snapshot()[7]["online"] is True
