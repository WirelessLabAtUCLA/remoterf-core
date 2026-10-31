#!/usr/bin/env python3
"""Tier 1 dev test with the real client: client -> dev Global -> test lab (SimSDRs).

Scenarios, each recorded on its own (one whose prerequisite did not pass is skipped):
  ready         /ready is 200
  login         the right password works; a wrong one and an unknown user are refused
  devices       at least one online simulated SDR (device_type sim_sdr)
  relay_rx      reserve the first free sim, rx N over the relay: complex, not all
                zero, the tone at sample_rate/8 (FFT bin N/8)
  direct_rx     the same over the direct path (REMOTERF_DIRECT=1)
  big_buffer    the largest power of two the relay frame holds, and twice that
  settings      sample_rate and rx_lo read back as set; the tone still at bin N/8
  bad_args      rx_buffer_size 0 and -1 refused, the device unharmed
  cancel_then_use  rx with a cancelled reservation's token refused
  bad_token     a made-up token refused
  bad_window    a window in the past, and one past the horizon, refused
  two_users     a second account is refused the first one's slot, holds another
                sim, and both rx at once
  two_sessions  two more logins of the account, each refreshed once: all still work
  logout        the old session is refused after logout (last: it ends them all)

Exit 0: every scenario passed (skips allowed); 1: a product failure; 2: dev
unreachable (no connection or no answer in time, the proxy's 502/503/504, /ready
not 200, or a hung device call while /ready fails too). Any unreachable failure
runs the whole suite once more 30 s later, and that run's verdict stands. The suite runs in a child process with a fresh HOME, so a
crash, a hang or asyncio noise on its stderr (at exit too) is caught here.
Always writes $DEV_SMOKE_RESULT (default ./dev-smoke-result.json):
  {"result": "pass"|"product"|"infra", "failed": [{"scenario", "detail"}],
   "passed": [scenario], "skipped": [{"scenario", "why"}]}
prints one ::error:: annotation per failure and appends a table to $GITHUB_STEP_SUMMARY.

Env: RRF_SMOKE_USER, RRF_SMOKE_PASSWORD (required); RRF_SMOKE_USER2 (optional,
same password; without it two_users is skipped); REMOTERF_GLOBAL_ORIGIN
(default https://dev.global.remoterf.net); DEV_SMOKE_UNLEASED (set by runs that
hold no dev lease: logout, which ends every session of the account, is skipped).
--register creates the account(s) first (dev Global signup; no email there), so a
new account stays unverified and reservations fail with native_account_required
until it is verified on the dev VPS with:
  docker exec remoterf-v2-live-deployment-1 remoterf-global-v2-admin --state-dir /state accounts verify <user>
Every federation dev deploy restores the seed DBs ($R/seed on the dev VPS), so
re-snapshot the seed afterwards or the account is gone after the next deploy.
"""
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

ORIGIN = os.environ.setdefault("REMOTERF_GLOBAL_ORIGIN", "https://dev.global.remoterf.net").rstrip("/")
USER, PASSWORD = os.environ.get("RRF_SMOKE_USER", ""), os.environ.get("RRF_SMOKE_PASSWORD", "")
N = 4096
SUITE_SECONDS = 200  # the parent kills the suite after this
SWEEP_SECONDS = 60  # kept free for a hung call's /ready check and the cancels
NOISE = re.compile(r"exception in shielded future|exception was never retrieved|Task was destroyed", re.I)
VERDICTS = ("pass", "infra", "product")  # worst last
# name, prerequisites, seconds before it counts as hung (a direct-path call has no timeout of its own)
SCENARIOS = [
    ("ready", (), 20),
    ("login", ("ready",), 60),
    ("devices", ("login",), 30),
    ("relay_rx", ("devices",), 90),
    ("direct_rx", ("relay_rx",), 60),
    ("big_buffer", ("relay_rx",), 100),
    ("settings", ("relay_rx",), 60),
    ("bad_args", ("relay_rx",), 100),
    ("cancel_then_use", ("relay_rx",), 60),
    ("bad_token", ("ready",), 60),
    ("bad_window", ("devices",), 60),
    ("two_users", ("devices",), 120),
    ("two_sessions", ("login",), 60),
    ("logout", ("login",), 30),
]


class Fail(Exception):
    """A product failure, in the check's own words."""


class Infra(Fail):
    """Dev is unreachable: not the change under test."""


class Skip(Exception):
    pass


def check(ok, what):
    if not ok:
        raise Fail(what)


def worse(a, b):
    return max(a, b, key=VERDICTS.index)


def one_line(text):
    return " ".join(str(text).split())


def ready_status():
    """/ready's HTTP status, or why there was none."""
    try:
        with urllib.request.urlopen(ORIGIN + "/ready", timeout=15) as reply:
            return reply.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception as exc:  # noqa: BLE001 - no answer at all
        return f"{type(exc).__name__}: {exc}"


def unreachable(exc):
    """Dev is down: no connection, no answer in time, or the proxy's 5xx."""
    from remoterf.deployment.http import AccountBackendError

    while exc is not None:
        if isinstance(exc, AccountBackendError) and (
            exc.unreachable or exc.code == "Account operation deadline exceeded"
        ):
            return True
        exc = exc.__cause__ or exc.__context__  # the client re-raises "from None": the context stays
    return False


def refused(call, *codes):
    """call() must fail cleanly: an error naming one of codes (REMOTERF_DEBUG=1
    appends the wire code to the client's sentence), not a 5xx or a traceback."""
    try:
        call()
    except Fail:
        raise
    except Exception as exc:  # noqa: BLE001 - judged here
        if unreachable(exc):
            raise Infra(f"{type(exc).__name__}: {exc}") from exc
        text = f"{getattr(exc, 'code', '')} {exc}"
        check(any(code in text for code in codes),
              f"want {' or '.join(codes)}, got {type(exc).__name__}: {one_line(exc)}")
        return
    raise Fail(f"accepted; want {' or '.join(codes)}")


def session(home=None):
    """An account backend; with home, its saved login lives apart, as on another
    machine (the credential store is a backend's only per-HOME state)."""
    from remoterf.deployment.backend import HttpsJsonAccountBackend
    from remoterf.deployment.state import origin

    backend = HttpsJsonAccountBackend(origin(ORIGIN))
    if home:
        backend.store.directory = Path(tempfile.mkdtemp(prefix=f"rrf-smoke-{home}-"))
    return backend


def minute():
    """This minute: the lab refuses only an end in the past, and wants 10 minutes."""
    return int(time.time()) // 60 * 60


def reserve(ctx, backend, dev, start, end=None):
    """Every reservation is made here, so sweep() can cancel whatever is left."""
    reservation = backend.reserve(dev["device_id"], start, end or start + 600)
    ctx["held"][reservation["reservation_id"]] = backend
    return reservation


def cancel(ctx, reservation):
    rid = reservation["reservation_id"]
    if rid in ctx["held"]:
        ctx["held"][rid].cancel(rid)
        del ctx["held"][rid]


def sweep(ctx):
    for rid, backend in list(ctx["held"].items()):
        try:
            backend.cancel(rid)
            del ctx["held"][rid]
        except Exception as exc:  # noqa: BLE001 - it ends with its window anyway
            print(f"     could not cancel {rid}: {one_line(exc)}", flush=True)


def reserve_free(ctx, backend, start, avoid=None):
    """The first sim this account can hold from start (5 sims, shared with other users)."""
    from remoterf.deployment.http import AccountBackendError

    codes = []
    for dev in ctx["sims"]:
        if dev["device_id"] == avoid:
            continue
        try:
            return dev, reserve(ctx, backend, dev, start)
        except AccountBackendError as exc:
            if unreachable(exc):
                raise Infra(f"reserve: {exc}") from exc
            codes.append(exc.code)
            print(f"     {dev['display_name']}: {exc.code}", flush=True)
    if codes and set(codes) == {"reservation_conflict"}:
        raise Infra("every sim is held by someone else")
    raise Fail(f"no sim to reserve: {', '.join(codes) or 'none left'}")


def tone(sdr, n):
    import numpy as np

    sdr.rx_buffer_size = n
    iq = np.asarray(sdr.rx())
    peak = int(np.argmax(np.abs(np.fft.fft(iq)))) if iq.shape == (n,) else -1
    check(iq.shape == (n,) and np.iscomplexobj(iq) and np.any(iq) and peak == n // 8,
          f"rx {iq.shape} {iq.dtype}, FFT peak bin {peak} (want {n // 8})")
    return f"rx {n} ok"


# ── scenarios: each returns its detail line, or raises Fail / Infra / Skip ──

def ready(ctx):
    status = ready_status()
    if status != 200:
        raise Infra(f"{ORIGIN}/ready: {status}")
    return ORIGIN


def login(ctx):
    from remoterf.deployment.state import origin, select_target

    backend = session()
    select_target({"origin": origin(ORIGIN), "transport": "https-json",
                   "deployment_id": backend.capabilities["deployment_id"]})
    if ctx["register"]:
        for name in filter(None, (USER, os.environ.get("RRF_SMOKE_USER2"))):
            backend.register(name, f"{name}@example.org", PASSWORD)
            print(f"     registered {name}", flush=True)
    backend.login(USER, PASSWORD)
    ctx["backend"] = backend
    stranger = session("stranger")  # a login clears its store first: not the saved one
    refused(lambda: stranger.login(USER, PASSWORD + "-wrong"), "invalid_credentials")
    refused(lambda: stranger.login(f"nobody-{secrets.token_hex(4)}", PASSWORD), "invalid_credentials")
    return f"{USER}; a wrong password and an unknown user refused"


def devices(ctx):
    listed = ctx["backend"].devices()["devices"]
    ctx["sims"] = [d for d in listed if d.get("device_type") == "sim_sdr" and d.get("online")]
    check(ctx["sims"], f"no online sim_sdr among {len(listed)} devices")
    return ", ".join(f"{d['display_name']}@{d['deployment_name']}" for d in ctx["sims"])


def relay_rx(ctx):
    from remoterf.drivers.sim_sdr import SimSDR

    dev, ctx["res"] = reserve_free(ctx, ctx["backend"], minute())
    ctx["sdr"] = SimSDR(ctx["res"]["token"])
    return f"{dev['display_name']}@{dev['deployment_name']}: {tone(ctx['sdr'], N)}"


def direct_rx(ctx):
    from remoterf.core import direct_path

    sdr, token = ctx["sdr"], ctx["res"]["token"]
    os.environ["REMOTERF_DIRECT"] = "1"  # read on every call (direct_path.enabled)
    try:
        sdr.ip()  # a device call opens the path; it comes up in the background
        deadline = time.monotonic() + 15
        while (path := direct_path.global_path(token)) is None and time.monotonic() < deadline:
            time.sleep(0.5)
        check(path is not None, f"no direct path in 15 s: {direct_path.describe()}")
        calls = path.calls
        detail = tone(sdr, N)
        # The client falls back to the relay silently: the SET and the rx must both have gone direct.
        check(path.calls - calls == 2 and path.describe().startswith("direct "),
              f"rx did not go direct: {path.describe()}")
        return f"{detail} over {path.describe()}"
    finally:
        os.environ["REMOTERF_DIRECT"] = "0"
        direct_path.stop()


def big_buffer(ctx):
    LIMIT = 768 * 1024  # federation-core MAX_DEVICE_RPC_RESPONSE_FRAME_BYTES; the client pins a core without it
    # The sim answers complex64, 8 bytes a sample (i16 only fits integer IQ); 4 KiB for the rest of the frame.
    fit = 1 << (((LIMIT - 4096) // 8).bit_length() - 1)
    sdr = ctx["sdr"]
    tone(sdr, fit)
    try:
        tone(sdr, 2 * fit)
        over = "correct data (paged)"
    except Fail:
        raise
    except Exception as exc:  # noqa: BLE001 - a clean refusal is fine too
        if unreachable(exc):
            raise Infra(f"{type(exc).__name__}: {exc}") from exc
        check("response_too_large" in str(exc),
              f"rx {2 * fit}: want correct data or response_too_large, got {type(exc).__name__}: {one_line(exc)}")
        over = "refused (response_too_large)"
    return f"rx {fit} fits the {LIMIT // 1024} KiB relay frame; rx {2 * fit}: {over}"


def settings(ctx):
    sdr = ctx["sdr"]
    want = (1_000_000 + 1000 * secrets.randbelow(1000), 900_000_000 + 1_000_000 * secrets.randbelow(100))
    sdr.sample_rate, sdr.rx_lo = want
    got = (sdr.sample_rate, sdr.rx_lo)
    check(got == want, f"set sample_rate, rx_lo {want}, read back {got}")
    return f"sample_rate, rx_lo {want}; {tone(sdr, N)}"


def bad_args(ctx):
    sdr = ctx["sdr"]
    sdr.rx_buffer_size = N
    for value in (0, -1):
        # The lab's own error names rx_buffer_size; through Global the lab reports any
        # device exception as device_unavailable (server federation/devices.py).
        refused(lambda: setattr(sdr, "rx_buffer_size", value), "rx_buffer_size", "device_unavailable")
    size = sdr.rx_buffer_size
    check(size == N, f"rx_buffer_size {size} after the refusals (want {N})")
    return f"0 and -1 refused; {tone(sdr, N)}"


def cancel_then_use(ctx):
    cancel(ctx, ctx["res"])
    refused(ctx["sdr"].rx, "invalid_device_token")  # Global drops the token with the reservation
    return "rx after cancel refused"


def bad_token(ctx):
    from remoterf.drivers.sim_sdr import SimSDR

    refused(lambda: SimSDR("rfg_" + secrets.token_urlsafe(32)), "invalid_device_token")  # Global's token shape
    return "made-up token refused"


def bad_window(ctx):
    backend, dev, now = ctx["backend"], ctx["sims"][0], minute()
    # The lab refuses an end in the past (a past start is fine while the end is
    # ahead); federation-core refuses any window over 365 days.
    refused(lambda: reserve(ctx, backend, dev, now - 7200, now - 3600), "reservation_in_past")
    refused(lambda: reserve(ctx, backend, dev, now, now + 366 * 86400),
            "invalid_reservation_time", "reservation_too_long")
    return "a window in the past and one past the 365-day horizon refused"


def two_users(ctx):
    from remoterf.deployment.http import AccountBackendError
    from remoterf.drivers.sim_sdr import SimSDR

    user2 = os.environ.get("RRF_SMOKE_USER2")
    if not user2:
        raise Skip("RRF_SMOKE_USER2 is not set")
    other = session("user2")
    try:
        other.login(user2, PASSWORD)
    except AccountBackendError as exc:
        if exc.code != "invalid_credentials":
            raise
        raise Skip(f"{user2} cannot log in with RRF_SMOKE_PASSWORD (create it with --register)") from None
    start = minute()
    mine_dev, mine = reserve_free(ctx, ctx["backend"], start)
    theirs = None
    try:
        refused(lambda: reserve(ctx, other, mine_dev, start), "reservation_conflict")
        theirs_dev, theirs = reserve_free(ctx, other, start, avoid=mine_dev["device_id"])
        # Device calls on rfg_ tokens carry no login, so one process stands in for two clients.
        sdrs = {USER: SimSDR(mine["token"]), user2: SimSDR(theirs["token"])}
        together = threading.Barrier(len(sdrs))
        errors = []

        def capture(who, sdr):
            try:
                together.wait(30)
                for _ in range(3):
                    tone(sdr, N)
            except Fail as exc:
                errors.append(Fail(f"{who}: {exc}"))
            except Exception as exc:  # noqa: BLE001 - raised below
                errors.append(exc)

        threads = [threading.Thread(target=capture, args=item, daemon=True) for item in sdrs.items()]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + 60
        for thread in threads:
            thread.join(max(0, deadline - time.monotonic()))
        if errors:
            raise errors[0]
        check(not any(thread.is_alive() for thread in threads), "rx at once: no answer in 60 s")
        return (f"{user2} refused {mine_dev['display_name']}'s slot; {USER} on {mine_dev['display_name']}, "
                f"{user2} on {theirs_dev['display_name']}: 3 rx each at once")
    finally:
        cancel(ctx, mine)
        if theirs is not None:
            cancel(ctx, theirs)


def two_sessions(ctx):
    a, b = session("a"), session("b")
    for backend in (a, b):
        backend.login(USER, PASSWORD)
    for backend in (a, b):
        backend.refresh()
    for backend in (a, b, ctx["backend"]):
        backend.devices()
    return "two more logins, each refreshed once: all three sessions list devices"


def logout(ctx):
    if os.environ.get("DEV_SMOKE_UNLEASED"):
        raise Skip(f"no dev lease: logout would end other runs' sessions of {USER}")
    backend = ctx["backend"]
    old = dict(backend.credentials)
    backend.logout()  # Global ends every session of the account
    backend.credentials = old
    refused(backend.me, "invalid_access_token")
    return "the old session is refused"


# ── the suite (child process) and its runner ──

def skip(record, name, why):
    record["skipped"].append({"scenario": name, "why": why})
    print(f"skip {name}: {why}", flush=True)


def fail(record, scenario, detail, kind="product"):
    # kind is the parent's (retry, order); main() drops it from the contract's JSON
    record["failed"].append({"scenario": scenario, "detail": one_line(detail), "kind": kind})
    record["result"] = worse(record["result"], kind)


def run(record, ctx, name, needs, seconds):
    missing = [need for need in needs if need not in record["passed"]]
    if missing:
        return skip(record, name, f"needs {', '.join(missing)}")
    box = {}

    def target():
        try:
            box["detail"] = globals()[name](ctx)
        except BaseException as exc:  # noqa: BLE001 - judged below
            box["exc"] = exc

    worker = threading.Thread(target=target, name=name, daemon=True)
    worker.start()
    worker.join(seconds)
    exc = box.get("exc")
    if worker.is_alive():
        from remoterf.core import direct_path

        # A dead direct path hangs this call and every later one on the token; closing it sends them to the relay.
        os.environ["REMOTERF_DIRECT"] = "0"
        direct_path.stop()
        exc = (Fail(f"no answer in {seconds} s") if ready_status() == 200
               else Infra(f"no answer in {seconds} s; /ready fails too"))
    if exc is None:
        record["passed"].append(name)
        print(f"ok   {name}: {box['detail']}", flush=True)
    elif isinstance(exc, Skip):
        skip(record, name, str(exc))
        print(f"::warning title=dev test::{name} skipped: {exc}", flush=True)
    else:
        kind = "infra" if isinstance(exc, Infra) or (not isinstance(exc, Fail) and unreachable(exc)) else "product"
        detail = one_line(exc if isinstance(exc, Fail) else f"{type(exc).__name__}: {exc}")
        if not isinstance(exc, Fail):
            traceback.print_exception(exc)
        fail(record, name, detail, kind)
        print(f"FAIL {name} ({kind}): {detail}", flush=True)


def save(record, out):
    Path(out + ".tmp").write_text(json.dumps(record, indent=1))
    os.replace(out + ".tmp", out)


def suite(out, register):
    record = {"result": "pass", "failed": [], "passed": [], "skipped": []}
    ctx = {"register": register, "held": {}}
    deadline = time.monotonic() + SUITE_SECONDS - SWEEP_SECONDS
    try:
        for name, needs, seconds in SCENARIOS:
            left = int(deadline - time.monotonic())
            if left <= 0:
                skip(record, name, "suite out of time")
                continue
            if name == "logout":
                sweep(ctx)  # the cancels need the session logout ends
            run(record, ctx, name, needs, min(seconds, left))
            save(record, out)
        if left <= 0 and record["result"] == "pass":
            fail(record, "suite", f"out of time after {SUITE_SECONDS - SWEEP_SECONDS} s")
    finally:
        sweep(ctx)
        save(record, out)


# ── the parent: runs the suite, retries an infra failure once, reports ──

def attempt(argv):
    """One run of the suite in a child with a fresh HOME (the client keeps its
    session and drivers there): its record, plus whatever the child could not say."""
    home = tempfile.mkdtemp(prefix="rrf-smoke-")
    out = os.path.join(home, "result.json")
    env = {**os.environ, "HOME": home, "REMOTERF_DIRECT": "0", "REMOTERF_DEBUG": "1"}
    env.pop("XDG_CONFIG_HOME", None)
    child = subprocess.Popen([sys.executable, __file__, "--suite", out, *argv], env=env,
                             stderr=subprocess.PIPE, text=True, errors="replace")
    lines = []

    def pump():
        for line in child.stderr:
            sys.stderr.write(line)
            lines.append(line)

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    hung = False
    try:
        child.wait(SUITE_SECONDS)
    except subprocess.TimeoutExpired:
        hung = True
        child.kill()
        child.wait()
    reader.join(5)
    try:
        record = json.loads(Path(out).read_text())
    except (OSError, ValueError):
        record = {"result": "pass", "failed": [], "passed": [], "skipped": []}
    if hung:
        fail(record, "suite", f"no result in {SUITE_SECONDS} s", "product" if ready_status() == 200 else "infra")
    elif child.returncode:
        last = next((line for line in reversed(lines) if line.strip()), "no output")
        fail(record, "suite", f"crashed (exit {child.returncode}): {last}")
    noise = [line for line in lines if NOISE.search(line)]
    if noise:
        fail(record, "asyncio_noise", f"{len(noise)} line(s) of asyncio noise on stderr, first: {noise[0]}")
    return record


def report(record):
    for failure in record["failed"]:
        print(f"::error title=dev test::{failure['scenario']}: {one_line(failure['detail']).replace('%', '%25')}")
    print("PASS" if record["result"] == "pass" else f"FAIL ({record['result']})", flush=True)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    rows = ([("❌", f["scenario"], f["detail"]) for f in record["failed"]]
            + [("⏭️", s["scenario"], s["why"]) for s in record["skipped"]]
            + [("✅", name, "") for name in record["passed"]])
    with open(path, "a", encoding="utf-8") as file:
        file.write(f"### Dev test: {record['result']}\n\n| | scenario | detail |\n|---|---|---|\n")
        for mark, name, detail in rows:
            cell = one_line(detail)[:300].replace("|", "\\|")
            file.write(f"| {mark} | {name} | {cell} |\n")
        file.write("\n")


def main():
    out = os.environ.get("DEV_SMOKE_RESULT") or "dev-smoke-result.json"
    argv = [arg for arg in sys.argv[1:] if arg == "--register"]
    try:
        if not (USER and PASSWORD):
            record = {"result": "infra", "passed": [], "skipped": [], "failed": [
                {"scenario": "suite", "detail": "RRF_SMOKE_USER and RRF_SMOKE_PASSWORD must be set"}]}
        else:
            record = attempt(argv)
            infra = [f["detail"] for f in record["failed"] if f.get("kind") == "infra"]
            if infra:
                print(f"dev unreachable ({infra[0]}); the whole suite again in 30 s", flush=True)
                time.sleep(30)
                record = attempt(argv)
    except Exception as exc:  # noqa: BLE001 - the result file is written whatever happens
        record = {"result": "product", "passed": [], "skipped": [], "failed": [
            {"scenario": "suite", "detail": one_line(f"{type(exc).__name__}: {exc}")}]}
    # Failures of the verdict's own kind first: stage1-dev reports failed[0].
    record["failed"] = [{"scenario": f["scenario"], "detail": f["detail"]} for f in
                        sorted(record["failed"], key=lambda f: f.get("kind", record["result"]) != record["result"])]
    Path(out).write_text(json.dumps(record, indent=1) + "\n")
    report(record)
    sys.exit({"pass": 0, "product": 1, "infra": 2}[record["result"]])


if __name__ == "__main__":
    if sys.argv[1:2] == ["--suite"]:
        suite(sys.argv[2], "--register" in sys.argv)
    else:
        main()
