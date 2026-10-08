"""End-to-end client matrix against a live lab: one radio, every way in.

Each case is a fresh process (its own venv, Python version and HOME), so
nothing is warmed up the way a CLI session warms it -- exactly how a student's
script starts. Axes:

    python    3.12 / 3.13 / 3.14 venvs with the client from PyPI (--client)
    identity  native  an account at the lab itself (registered with --code)
              global  a RemoteRF Global account, logged in once into its own HOME:
                      HOME=~/remoterf-e2e/global-home <venv>/bin/remoterf -l
                      (never a copy of a real login: refresh tokens rotate, and a
                      second copy refreshing is treated as token theft)
    route     native: relay or auto (what `remoterf -l` picks); direct QUIC on/off
    entry     the app's reserve flow, a script whose FIRST network call is
              adi.Pluto(token), ensure_driver/install_driver_if_stale, a bad
              token, a cancelled token, refusals (cap, horizon, other group)

Every case also fails on asyncio noise or a traceback on stderr. Only --device
is ever reserved or driven; refusal probes name other ids but never get them.

    python e2e_matrix.py                         # the whole matrix
    python e2e_matrix.py --pythons 3.14 --identities global --only script
    python e2e_matrix.py --list

Output: ~/remoterf-e2e/runs/<stamp>/ (cases/<name>.log|json, summary.md).
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import time
import traceback
from datetime import datetime, timedelta
from pathlib import Path

BASE = Path.home() / "remoterf-e2e"
GLOBAL_HOME = BASE / "global-home"
HOST = "ucla.global.remoterf.net"
FS = 1_000_000
NOISE = re.compile(r"exception in shielded future|exception was never retrieved|Traceback \(most recent|Task was destroyed")


# =============================================================================
# Child side: runs inside a case's venv with that case's HOME
# =============================================================================

class Case:
    def __init__(self, args: dict):
        self.args, self.steps, self.issues, self.metrics = args, [], [], {}

    def step(self, name, fn, *, expect_error=False):
        t0 = time.monotonic()
        try:
            value = fn()
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {str(exc)[:300]}"
            self.steps.append({"step": name, "ok": expect_error, "s": round(time.monotonic() - t0, 2), "error": err})
            if not expect_error:
                self.fail(f"{name}: {err}")
                print(traceback.format_exc(), file=sys.stdout)
                raise Stop(name) from exc
            return exc
        self.steps.append({"step": name, "ok": not expect_error, "s": round(time.monotonic() - t0, 2),
                           "value": str(value)[:200]})
        if expect_error:
            self.fail(f"{name}: expected an error, got {str(value)[:200]!r}")
        return value

    def fail(self, text):
        self.issues.append(text)


class Stop(Exception):
    pass


def _acc(name, **kw):
    from remoterf.common.utils import map_arg, unmap_arg
    from remoterf.core.grpc_client import rpc_client

    response = rpc_client(function_name=f"ACC:{name}", args={k: map_arg(v) for k, v in kw.items()})
    return {k: unmap_arg(v) for k, v in response.results.items()}


def _window(minutes):
    start = datetime.now().replace(second=0, microsecond=0)
    return start, start + timedelta(minutes=minutes)


def _global_backend():
    from remoterf.deployment.backend import selected_backend

    backend = selected_backend()
    if not backend.resume():
        raise RuntimeError("the copied Global login did not resume")
    return backend


def _global_ref(backend, device):
    for row in backend.devices()["devices"]:
        if str(row["local_device_id"]) == str(device) and row.get("deployment_name") == HOST.split(".")[0]:
            return row["device_id"]
    raise RuntimeError(f"device {device} is not listed to this Global account")


def c_setup_native(c: Case):
    """Register (first time) and log in with remember, as `remoterf -r/-l` leaves a machine."""
    from remoterf.deployment import homes

    doc = c.step("discover", lambda: homes.discover(HOST))
    name = homes.home_name_for(HOST)
    home = homes.save_home(name, doc)
    if c.args["route"] == "auto":
        route = c.step("connect(auto)", lambda: homes.connect(name))
    else:
        route = next(r for r in home["routes"] if r["kind"] == c.args["route"])
        cert = c.step("probe route", lambda: homes._probe(route, 10))
        c.step("activate", lambda: str(homes.activate(name, home, route, cert)))
    c.metrics["route"] = {k: route.get(k) for k in ("kind", "host", "port")}
    un, pw = c.args["un"], c.args["pw"]
    if c.args.get("register"):
        reply = c.step("create_user", lambda: _acc("create_user", un=un, pw=pw, em=f"{un}@e2e.invalid", ec=c.args["code"]))
        if "UC" not in reply:
            c.fail(f"registration refused: {reply}")
            raise Stop("register")
    reply = c.step("login(remember)", lambda: _acc("login", un=un, pw=pw, remember=True))
    if "token" not in reply:
        c.fail(f"login gave no session token: {reply}")
        raise Stop("login")
    homes.remember_login(name, un, reply["token"])
    return {"session": reply["token"]}


def c_reserve(c: Case):
    """The app's own reserve flow: the token must be on screen before the driver step."""
    from remoterf.core import app, grpc_acc

    start, end = _window(c.args["minutes"])
    out = io.StringIO()
    if c.args["identity"] == "native":
        account = grpc_acc.RemoteRFAccount(c.args["un"], c.args["session"])
        app.account = account
        with contextlib.redirect_stdout(out):
            c.step("app reserve flow", lambda: app._native_reserve_slot(c.args["device"], start, (start, end), "s", "e"))
        m = re.search(r"Your Token -> (\S+)", out.getvalue())
        marker = "Your Token"
    else:
        backend = _global_backend()
        account = grpc_acc.RemoteRFAccount(backend=backend)
        app.account = account
        ref = c.step("find device ref", lambda: _global_ref(backend, c.args["device"]))
        with contextlib.redirect_stdout(out):
            c.step("app reserve flow", lambda: app._federated_reserve_slot(ref, start, (start, end), "s", "e"))
        m = re.search(r"Your Token -> (\S+)", out.getvalue())
        marker = "Your Token"
    text = out.getvalue()
    print(text)
    if not m:
        c.fail("the reserve flow printed no token/handle")
        raise Stop("token")
    driver_at = min([i for i in (text.find("Driver"), text.find("driver"), text.find("Warning")) if i >= 0], default=-1)
    if driver_at >= 0 and driver_at < text.find(marker):
        c.fail("driver output came before the token")
    return {"token": m.group(1), "start": int(start.timestamp())}


def c_script(c: Case):
    """A typical student script: nothing before adi.Pluto(token); then TX a tone and find it on RX."""
    import numpy as np

    t0 = time.monotonic()
    from remoterf.drivers.adalm_pluto import adi  # noqa: F401  (the documented import)

    sdr = c.step("adi.Pluto(token) as the first call", lambda: adi.Pluto(token=c.args["token"]))
    c.metrics["first_call_s"] = round(time.monotonic() - t0, 1)
    t1 = time.monotonic()
    c.step("first device call (a PoE Pluto boots here)", lambda: setattr(sdr, "sample_rate", FS))
    c.metrics["boot_s"] = round(time.monotonic() - t1, 1)
    for k, v in (("rx_lo", 2_400_000_000), ("tx_lo", 2_400_000_000), ("rx_rf_bandwidth", FS),
                 ("tx_rf_bandwidth", FS), ("gain_control_mode_chan0", "manual"),
                 ("rx_hardwaregain_chan0", 30), ("tx_hardwaregain_chan0", -10)):
        c.step(f"set {k}", lambda k=k, v=v: setattr(sdr, k, v))
    c.step("rx_destroy_buffer", sdr.rx_destroy_buffer)
    c.step("rx_buffer_size", lambda: setattr(sdr, "rx_buffer_size", 65536))
    c.step("loopback=1 (digital)", lambda: setattr(sdr, "loopback", 1))
    c.step("tx_destroy_buffer", sdr.tx_destroy_buffer)
    c.step("tx_cyclic_buffer", lambda: setattr(sdr, "tx_cyclic_buffer", True))
    readback = {k: c.step(f"get {k}", lambda k=k: getattr(sdr, k)) for k in ("sample_rate", "rx_lo", "loopback")}
    # the AD9361 quantizes: 1e6 reads back as 999999, 2.4 GHz as 2399999998
    if abs(float(readback["sample_rate"]) - FS) > 10 or abs(float(readback["rx_lo"]) - 2.4e9) > 10 or int(readback["loopback"]) != 1:
        c.fail(f"readback mismatch: {readback}")
    tone = 100e3
    n = np.arange(2 ** 14)
    c.step("tx tone", lambda: sdr.tx((2 ** 14 * 0.5 * np.exp(2j * np.pi * tone / FS * n)).astype(np.complex64)))
    lat = []
    for _ in range(4):
        t1 = time.monotonic()
        iq = np.asarray(c.step("rx", sdr.rx))
        lat.append(round(time.monotonic() - t1, 3))
    iq = iq[-8192:]
    spec = np.abs(np.fft.fftshift(np.fft.fft(iq * np.hanning(iq.size)))) ** 2
    freqs = np.fft.fftshift(np.fft.fftfreq(iq.size, 1 / FS))
    k = int(np.argmax(spec))
    peak, snr = float(freqs[k]), float(10 * np.log10(spec[k] / max(float(np.median(spec)), 1e-20)))
    c.metrics.update(rx_s=lat, tone_peak_hz=round(peak), tone_snr_db=round(snr, 1), rx_len=int(iq.size))
    if abs(peak - tone) > 2 * FS / 8192 or snr < 40:
        c.fail(f"loopback tone: peak {peak:.0f} Hz, SNR {snr:.1f} dB")
    c.step("tx_destroy_buffer (cleanup)", sdr.tx_destroy_buffer)
    from remoterf.core import direct_path

    c.metrics["path"] = direct_path.describe()
    want_direct = os.getenv("REMOTERF_DIRECT", "1") != "0"
    if not want_direct and c.metrics["path"].startswith("direct "):
        c.fail(f"REMOTERF_DIRECT=0 but the path says {c.metrics['path']!r}")


def c_ensure(c: Case):
    from remoterf.drivers import ensure_driver
    from remoterf.drivers.dynamic_device import install_driver_if_stale

    c.step("ensure_driver(token) first call", lambda: ensure_driver(token=c.args["token"]))
    c.step("install_driver_if_stale(token)", lambda: install_driver_if_stale(token=c.args["token"], current_hash="sha256:stale"))


def c_bad_token(c: Case):
    from remoterf.drivers.adalm_pluto import adi

    exc = c.step("adi.Pluto(bogus)", lambda: adi.Pluto(token="e2e-not-a-token"), expect_error=True)
    if isinstance(exc, (AttributeError, TypeError, KeyError)):
        c.fail(f"a bad token crashed the client instead of being refused: {type(exc).__name__}: {exc}")


def c_cancel_then_use(c: Case):
    if c.args["identity"] == "native":
        un, pw = c.args["un"], c.args["session"]
        rows = c.step("get_res", lambda: _acc("get_res", un=un, pw=pw))
        mine = [rid for rid, row in rows.items() if str(row).split(",")[:2] == [un, str(c.args["device"])]]
        if not mine:
            c.fail(f"own reservation not listed: {rows}")
        for rid in mine:
            c.step(f"cancel_res {rid}", lambda rid=rid: _acc("cancel_res", un=un, pw=pw, res_id=int(rid)))
    else:
        backend = _global_backend()
        ref = _global_ref(backend, c.args["device"])
        rows = [r for r in c.step("reservations", backend.reservations)["reservations"]
                if r["device_id"] == ref and int(r["start_time"]) == c.args["start"]]
        if not rows:
            c.fail("own reservation not listed")
        for r in rows:
            c.step(f"cancel {r['reservation_id']}", lambda r=r: backend.cancel(r["reservation_id"]))
    from remoterf.drivers.adalm_pluto import adi

    def use():
        sdr = adi.Pluto(token=c.args["token"])
        return sdr.sample_rate

    exc = c.step("use the cancelled token", use, expect_error=True)
    if isinstance(exc, (AttributeError, TypeError)):
        c.fail(f"a cancelled token crashed the client: {type(exc).__name__}: {exc}")


def c_refusals(c: Case):
    """The lab says no, cleanly, to what its rules forbid; nothing here may be granted."""
    from remoterf.core import grpc_acc

    dev, other = c.args["device"], c.args["other_device"]
    if c.args["identity"] == "native":
        un, pw = c.args["un"], c.args["session"]

        def res(d, start, end):
            return _acc("reserve_device", un=un, pw=pw, dd=d, st=int(start.timestamp()), et=int(end.timestamp()))
        start = datetime.now().replace(second=0, microsecond=0)
        probes = {
            "longer than the group allows (7 h)": res(dev, start, start + timedelta(hours=7)),
            "beyond the horizon (30 days out)": res(dev, start + timedelta(days=30), start + timedelta(days=30, minutes=20)),
            "end before start": res(dev, start + timedelta(minutes=20), start),
            "a device id that does not exist": res(987654, start, start + timedelta(minutes=10)),
            "wrong password": _acc("reserve_device", un=un, pw="wrong", dd=dev, st=int(start.timestamp()),
                                   et=int((start + timedelta(minutes=10)).timestamp())),
        }
        for label, reply in probes.items():
            if "Token" in reply:
                c.fail(f"granted: {label}")
                with contextlib.suppress(Exception):
                    _acc("cancel_res", un=un, pw=pw, res_id=-1)
            elif "ace" not in reply:
                c.fail(f"{label}: refused without an 'ace' message: {reply}")
            c.steps.append({"step": label, "ok": "Token" not in reply, "value": str(reply)[:200]})
    else:
        backend = _global_backend()
        account = grpc_acc.RemoteRFAccount(backend=backend)
        ref = _global_ref(backend, dev)
        dep = ref.split(":")[0]
        start = datetime.now().replace(second=0, microsecond=0)
        for label, d, s, e in (("longer than 30 min", ref, start, start + timedelta(minutes=45)),
                               ("a ucla device outside the global group", f"{dep}:{other}", start, start + timedelta(minutes=10)),
                               ("beyond the 7-day horizon", ref, start + timedelta(days=9), start + timedelta(days=9, minutes=10))):
            exc = c.step(label, lambda d=d, s=s, e=e: account.reserve_device(d, s, e), expect_error=True)
            if not isinstance(exc, Exception):
                c.fail(f"granted: {label} (cancel it by hand)")


def c_cli(c: Case):
    exe = Path(sys.executable).parent / "remoterf"
    for flag in ("--version", "--help"):
        p = c.step(f"remoterf {flag}", lambda flag=flag: subprocess.run([str(exe), flag], capture_output=True, text=True, timeout=60))
        if p.returncode != 0:
            c.fail(f"remoterf {flag} exited {p.returncode}: {p.stderr[-300:]}")
    c.metrics["version"] = p.stdout.strip()[:80] if p else None


CHILD = {"setup_native": c_setup_native, "reserve": c_reserve, "script": c_script, "ensure": c_ensure,
         "bad_token": c_bad_token, "cancel": c_cancel_then_use, "refusals": c_refusals, "cli": c_cli}


def child_main(kind: str, args: dict) -> int:
    c = Case(args)
    out = None
    try:
        out = CHILD[kind](c)
    except Stop:
        pass
    except Exception as exc:  # noqa: BLE001
        c.fail(f"crashed: {type(exc).__name__}: {exc}")
        traceback.print_exc(file=sys.stdout)
    print("E2E_RESULT " + json.dumps({"issues": c.issues, "steps": c.steps, "metrics": c.metrics, "out": out}, default=str))
    sys.stdout.flush()
    os._exit(0)  # a stuck background loop must not hold the case open


# =============================================================================
# Parent side: venvs, HOMEs, the plan, the report
# =============================================================================

def venv_for(py: str, client: str) -> Path:
    d = BASE / "venvs" / f"py{py}-{re.sub(r'[^A-Za-z0-9.]+', '_', client)}"
    exe = d / "bin" / "python"
    if not exe.exists():
        subprocess.run(["uv", "venv", "-q", "-p", py, str(d)], check=True)
        subprocess.run(["uv", "pip", "install", "-q", "-p", str(exe), client, "numpy"], check=True)
    return exe


def run_case(run_dir: Path, name: str, kind: str, *, exe: Path, home: Path, args: dict,
             direct: bool = True, timeout: int = 240) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("REMOTERF_", "VIRTUAL_ENV", "PYTHON"))}
    env.update(HOME=str(home), REMOTERF_DIRECT="1" if direct else "0", MPLBACKEND="Agg", PYTHONUNBUFFERED="1")
    t0 = time.monotonic()
    try:
        p = subprocess.run([str(exe), __file__, "--child", kind, json.dumps(args)], env=env, cwd=str(home),
                           capture_output=True, text=True, timeout=timeout)
        stdout, stderr, rc = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        rc = "timeout"
    seconds = round(time.monotonic() - t0, 1)
    line = next((ln for ln in reversed(stdout.splitlines()) if ln.startswith("E2E_RESULT ")), None)
    res = json.loads(line[len("E2E_RESULT "):]) if line else {"issues": [f"no result (rc={rc})"], "steps": [], "metrics": {}, "out": None}
    noise = [ln for ln in stderr.splitlines() if NOISE.search(ln)]
    if noise:
        res["issues"].append(f"stderr noise: {noise[0][:160]}")
    if rc == "timeout":
        res["issues"].append(f"timed out after {timeout}s (hang)")
    res.update(name=name, kind=kind, seconds=seconds, rc=rc, status="FAIL" if res["issues"] else "PASS")
    (run_dir / "cases" / name).parent.mkdir(parents=True, exist_ok=True)
    (run_dir / "cases" / f"{name}.log").write_text(f"$ {kind} {json.dumps(args)}\n--- stdout\n{stdout}\n--- stderr\n{stderr}")
    (run_dir / "cases" / f"{name}.json").write_text(json.dumps(res, indent=2, default=str))
    print(f"{res['status']:4}  {seconds:6.1f}s  {name}" + (f"  -- {res['issues'][0][:140]}" if res["issues"] else ""), flush=True)
    return res


def orchestrate(a) -> int:
    run_dir = BASE / "runs" / datetime.now().strftime("%Y%m%d-%H%M%S")
    (run_dir / "cases").mkdir(parents=True)
    results = []
    stamp = datetime.now().strftime("%m%d%H%M%S")
    native = {"un": f"e2e{stamp}", "pw": f"E2e-{stamp}-pw!", "code": a.code.rsplit("/", 1)[-1]}
    wanted = lambda kind: not a.only or any(o in kind for o in a.only.split(","))  # noqa: E731

    for py in a.pythons.split(","):
        exe = venv_for(py, a.client)
        tag = f"py{py}"
        homes = {}
        if "native" in a.identities:
            for route in ("relay", "auto"):
                h = run_dir / "homes" / f"{tag}-native-{route}"
                h.mkdir(parents=True)
                r = run_case(run_dir, f"{tag}/native-{route}/setup", "setup_native", exe=exe, home=h,
                             args={**native, "route": route, "register": not results})
                results.append(r)
                if r["status"] == "PASS":
                    homes[f"native-{route}"] = (h, {**native, "session": r["out"]["session"], "identity": "native"})
        if "global" in a.identities:
            if GLOBAL_HOME.joinpath(".config/remoterf-client/deployment/target-v2.json").exists():
                homes["global"] = (GLOBAL_HOME, {"identity": "global"})  # shared: one session, used in turn
            else:
                print(f"SKIP  global: log in once with HOME={GLOBAL_HOME} remoterf -l", flush=True)

        for label, (home, ident) in homes.items():
            base = {**ident, "device": a.device, "minutes": 20 if ident["identity"] == "global" else 30}
            n = f"{tag}/{label}"
            if wanted("reserve") or wanted("script") or wanted("ensure") or wanted("cancel"):
                r = run_case(run_dir, f"{n}/reserve", "reserve", exe=exe, home=home, args=base, timeout=300)
                results.append(r)
                if r["status"] != "PASS" and not (r["out"] or {}).get("token"):
                    continue
                held = {**base, **r["out"]}
                for direct in (True, False):
                    if wanted("script"):
                        results.append(run_case(run_dir, f"{n}/script-direct{'on' if direct else 'off'}", "script",
                                                exe=exe, home=home, args=held, direct=direct, timeout=300))
                if wanted("ensure"):
                    results.append(run_case(run_dir, f"{n}/ensure", "ensure", exe=exe, home=home, args=held))
                results.append(run_case(run_dir, f"{n}/cancel-then-use", "cancel", exe=exe, home=home, args=held))
            if wanted("refusals") and py == a.pythons.split(",")[0] and label in ("native-relay", "global"):
                results.append(run_case(run_dir, f"{n}/refusals", "refusals", exe=exe, home=home,
                                        args={**base, "other_device": a.other_device}))
        any_home = next(iter(homes.values()), (run_dir, {}))[0]
        if wanted("bad_token"):
            results.append(run_case(run_dir, f"{tag}/bad-token", "bad_token", exe=exe, home=any_home, args={}))
        if wanted("cli"):
            results.append(run_case(run_dir, f"{tag}/cli", "cli", exe=exe, home=any_home, args={}))

    fails = [r for r in results if r["status"] != "PASS"]
    lines = [f"# E2E matrix {run_dir.name}", "", f"client `{a.client}`, device {a.device}, pythons {a.pythons}", "",
             f"**{len(results) - len(fails)}/{len(results)} passed**", "", "| case | status | s | notes |", "|---|---|---|---|"]
    for r in results:
        m = r.get("metrics", {})
        note = "; ".join(r["issues"])[:200] or ", ".join(f"{k}={m[k]}" for k in ("first_call_s", "boot_s", "tone_snr_db", "path", "route") if k in m)
        lines.append(f"| {r['name']} | {r['status']} | {r['seconds']} | {note} |")
    (run_dir / "summary.md").write_text("\n".join(lines) + "\n")
    print(f"\n{len(results) - len(fails)}/{len(results)} passed -> {run_dir / 'summary.md'}")
    return 1 if fails else 0


def main() -> int:
    if len(sys.argv) >= 4 and sys.argv[1] == "--child":
        return child_main(sys.argv[2], json.loads(sys.argv[3]))
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pythons", default="3.12,3.13,3.14")
    ap.add_argument("--client", default="remoterf", help="pip spec, e.g. remoterf==2.1.10 or a wheel path")
    ap.add_argument("--identities", default="native,global")
    ap.add_argument("--device", type=int, default=103, help="the ONLY device reserved and driven")
    ap.add_argument("--other-device", type=int, default=104, help="a lab device outside the global group (refusal probe)")
    ap.add_argument("--code", default="ucla.global.remoterf.net/K50BI4", help="lab enrollment code for the native account")
    ap.add_argument("--only", default="", help="comma list of case kinds: reserve,script,ensure,cancel,refusals,bad_token,cli")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        print("\n".join(CHILD))
        return 0
    return orchestrate(a)


if __name__ == "__main__":
    sys.exit(main())
