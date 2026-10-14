from __future__ import annotations

import ctypes
import io
import os
import pty
import sys
import threading
import time
import types
from unittest.mock import MagicMock

import pytest

from remoteRF_server.drivers.adalm_pluto.poe import PoePluto
from remoteRF_server.server import device_manager as dm
from remoteRF_server.server import startup_check as sc


def state(name, dev, dtype="custom", reserved=False):
    return dm._DeviceState(dev=dev, origin="local", online=dev is not None,
                           salt="s" if reserved else "", hsh="h" if reserved else "",
                           name=name, ident="", dtype=dtype)


class Rtl:
    def __init__(self, block=None, delay=0):
        self.block = block
        self.delay = delay
        self.reads = []

    def call_read_bytes(self, n):
        self.reads.append(n)
        time.sleep(self.delay)
        if self.block is not None:
            self.block.wait()


def opener(devices, noise=None):
    def open_devices(on_device):
        for gid, st in devices.items():
            on_device(gid, st.name)
            for line in (noise or {}).get(gid, []):
                os.write(2 if "error" in line else 1, line.encode() + b"\n")
            dm._devices[gid] = st
    return open_devices


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.setattr(dm, "_devices", {})
    monkeypatch.delenv("REMOTERF_STARTUP_TEST", raising=False)


def test_quiet_lines_summary_and_log(tmp_path, capfd):
    devices = {100: state("Pluto 00", object()), 101: state("RTL 01", None, "rtl_sdr"),
               102: state("RTL 02", Rtl(), "rtl_sdr")}

    def open_devices(on_device):
        opener(devices, {101: ["Found Rafael Micro R828D tuner", "usb_open error -3"]})(on_device)
        ctypes.CDLL(None).printf(b"RTL-SDR Blog V4 Detected\n")  # C stdio, buffered

    sc.run(open_devices, cfg_dir=tmp_path)
    out = capfd.readouterr().out
    assert out.splitlines() == [
        "✓ [100] Pluto 00 · operational",
        "✗ [101] RTL 01 · usb_open error -3",
        "✓ [102] RTL 02 · operational",
        "2 of 3 devices operational · issues: RTL 01",
        f"log: {next((tmp_path / 'logs').glob('startup-*.log'))}",
    ]
    assert devices[102].dev.reads == [512]
    log = next((tmp_path / "logs").glob("startup-*.log")).read_text()
    for text in ("Found Rafael Micro", "RTL-SDR Blog V4 Detected", "[101] RTL 01: ISSUE usb_open error -3"):
        assert text in log


def test_all_operational_and_test_off(tmp_path, capfd, monkeypatch):
    rtl = Rtl()
    sc.run(opener({7: state("RTL", rtl, "rtl_sdr")}), cfg_dir=tmp_path)
    assert capfd.readouterr().out.splitlines()[:2] == ["✓ [7] RTL · operational", "All 1 device operational"]

    monkeypatch.setenv("REMOTERF_STARTUP_TEST", "0")
    sc.run(opener({7: state("RTL", rtl, "rtl_sdr")}), cfg_dir=tmp_path)
    assert capfd.readouterr().out.splitlines()[:2] == ["✓ [7] RTL · opened", "All 1 device opened"]
    assert rtl.reads == [512]  # the second run did not test it


def test_timeout_and_deadline(tmp_path, capfd, monkeypatch):
    block = threading.Event()
    monkeypatch.setattr(sc, "CHECK_TIMEOUT_S", 0.3)
    t = time.monotonic()
    sc.run(opener({1: state("Hung", Rtl(block), "rtl_sdr")}), cfg_dir=tmp_path)
    assert time.monotonic() - t < 2
    out = capfd.readouterr().out
    assert "✗ [1] Hung · no answer after 0 s" in out
    assert "\x1b" not in out and not set(sc.FRAMES) & set(out)  # no spinner off a TTY

    monkeypatch.setattr(sc, "CHECK_TIMEOUT_S", 30)
    monkeypatch.setattr(sc, "DEADLINE_S", 0.4)
    t = time.monotonic()
    sc.run(opener({1: state("A", Rtl(block), "rtl_sdr"), 2: state("B", Rtl(block), "rtl_sdr")}), cfg_dir=tmp_path)
    assert time.monotonic() - t < 2
    assert capfd.readouterr().out.count("no answer after") == 2
    block.set()


def test_log_unavailable_still_opens_devices(tmp_path, monkeypatch):
    (tmp_path / "logs").write_text("not a directory")
    calls = []
    sc.run(calls.append, cfg_dir=tmp_path)
    assert calls == [None]

    (tmp_path / "logs").unlink()
    monkeypatch.setattr(sc.shutil, "disk_usage", lambda p: types.SimpleNamespace(free=0))
    sc.run(calls.append, cfg_dir=tmp_path)
    assert calls == [None, None]


def test_silent_failure_does_not_borrow_next_devices_output(tmp_path, capfd):
    devices = {20: state("GPS", None, "gps"), 30: state("RTL 01", Rtl(), "rtl_sdr")}
    sc.run(opener(devices, {30: ["RTL-SDR Blog V4 Detected"]}), cfg_dir=tmp_path)
    assert "✗ [20] GPS · not found" in capfd.readouterr().out


def test_buffered_print_is_the_failure_reason(tmp_path, capfd, monkeypatch):
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(open(1, "wb", closefd=False), line_buffering=False))
    devices = {10: state("BT", None, "bluetooth"), 20: state("GPS", Rtl(), "rtl_sdr")}

    def open_devices(on_device):
        for gid, st in devices.items():
            on_device(gid, st.name)
            if st.dev is None:
                print("make_device() failed for bluetooth: No adapter found")
            dm._devices[gid] = st

    sc.run(open_devices, cfg_dir=tmp_path)
    assert "✗ [10] BT · make_device() failed for bluetooth: No adapter found" in capfd.readouterr().out
    log = next((tmp_path / "logs").glob("startup-*.log")).read_text()
    assert log.index("No adapter found") < log.index("[10] BT: ISSUE")


def test_checks_run_concurrently(tmp_path, capfd, monkeypatch):
    monkeypatch.setattr(sc, "CHECK_TIMEOUT_S", 0.5)
    sc.run(opener({1: state("A", Rtl(delay=0.3), "rtl_sdr"), 2: state("B", Rtl(delay=0.3), "rtl_sdr")}),
           cfg_dir=tmp_path)
    assert "All 2 devices operational" in capfd.readouterr().out


def test_no_devices_and_machinery_failure_never_raise(tmp_path, capfd, monkeypatch):
    sc.run(opener({}), cfg_dir=tmp_path)
    out = capfd.readouterr().out.splitlines()
    assert out[0] == "No local devices opened" and out[1].startswith("log: ")

    monkeypatch.setattr(dm, "_state_lock", None)  # `with None:` raises inside the check
    sc.run(opener({1: state("A", Rtl(), "rtl_sdr")}), cfg_dir=tmp_path)
    assert "✗ startup check · failed" in capfd.readouterr().out
    logs = sorted((tmp_path / "logs").glob("startup-*.log"))
    assert any("startup check failed" in p.read_text() for p in logs)


def test_log_rotation(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    for i in range(15):
        (logs / f"startup-2026010{i:02d}.log").write_text("")
    sc.run(opener({}), cfg_dir=tmp_path)
    assert len(list(logs.glob("startup-*.log"))) == sc.KEEP_LOGS


@pytest.mark.parametrize("reserved,power_state,cycled,powered_down", [
    (False, "standby", True, True),
    (True, "standby", True, False),
    (True, "on", False, False),  # its reservation pre-warm already booted it
])
def test_poe_restore_rule(reserved, power_state, cycled, powered_down):
    native = MagicMock(spec=PoePluto)
    native._lock = threading.RLock()
    native.power_state = power_state
    native.sample_rate = 30_720_000
    schema = types.SimpleNamespace(device=native, call_power_down=MagicMock())
    sc._check(state("Pluto 00", schema, "adalm_pluto", reserved=reserved))
    assert native.power_cycle.called is cycled
    assert schema.call_power_down.called is powered_down


def test_poe_failure_still_returns_to_standby():
    native = MagicMock(spec=PoePluto)
    native._lock = threading.RLock()
    native.power_state = "standby"
    native.power_cycle.side_effect = RuntimeError("did not boot within 45 s")
    schema = types.SimpleNamespace(device=native, call_power_down=MagicMock())
    with pytest.raises(RuntimeError, match="45 s"):
        sc._check(state("Pluto 04", schema, "adalm_pluto"))
    schema.call_power_down.assert_called_once()


def test_tty_spinner_redraws_in_place():
    master, slave = pty.openpty()
    out = os.fdopen(slave, "w", encoding="utf-8")
    display = sc._Display(out)
    display.spin("[100] Pluto 00 · testing…")
    display.result(True, "[100] Pluto 00", "operational")
    out.flush()
    text = os.read(master, 4096).decode()
    out.close()
    os.close(master)
    assert "\r\x1b[2K" in text and "testing…" in text and "operational" in text
    assert text.index("testing…") < text.rindex("\r\x1b[2K") < text.index("✓")
