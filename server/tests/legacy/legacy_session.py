"""One scripted session against a lab that never joined RemoteRF Global.

Run with the Server venv, the Server tree under test first on PYTHONPATH:

    PYTHONPATH=<server>/src .venv/bin/python tests/legacy/legacy_session.py \
        --client-src <client>/src --client-python <client venv python> --out leg.json

It drives a real Server runtime (fake radio, no hardware), started the way
`serverrf` starts it, in a temp HOME over TLS on this machine's LAN address --
not loopback, which the Server counts as relayed -- with the given client's own
CLI, then records every reply, the databases, the files written, the threads
left running and any traffic the guard (guard/sitecustomize.py) refused.
Output values are normalized so two versions can be compared step by step
(tests/legacy/test_legacy_pipeline.py does that).

LEGACY_HOME=<dir> keeps the lab there; LEGACY_REOPEN=1 then starts whatever
Server is on PYTHONPATH on that existing lab instead (an in-place upgrade).
"""

import argparse
import io
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sqlite3
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
KEEP = os.environ.get("LEGACY_HOME")
REOPEN = os.environ.get("LEGACY_REOPEN") == "1"
TMP = Path(KEEP) if KEEP else Path(tempfile.mkdtemp(prefix="rrf-legacy-"))
SERVER_HOME = TMP / "server"
CLIENT_HOME = TMP / "client"
EGRESS = TMP / ("egress-reopen.log" if REOPEN else "egress.log")
CODE, GROUP = "native-signup", "native-users"
KEEP_CODE, KEEP_GROUP = "keep-signup", "kept-users"  # a group that outlives the session
CLI_USER, WIRE_USER, PASSWORD = "jdoe", "wire-user", "localpass1"


def lan_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))  # TEST-NET: no packet is sent
        ip = s.getsockname()[0]
    if ipaddress.ip_address(ip).is_loopback:
        raise SystemExit("legacy harness needs a non-loopback interface")
    return ip


def free_port_pair() -> int:
    for _ in range(50):
        with socket.socket() as a:
            a.bind(("0.0.0.0", 0))
            port = a.getsockname()[1]
        try:
            with socket.socket() as a, socket.socket() as b:
                a.bind(("0.0.0.0", port))
                b.bind(("0.0.0.0", port + 1))
            return port
        except OSError:
            continue
    raise RuntimeError("no adjacent free ports")


IP, PORT = lan_ip(), free_port_pair()

# Everything below runs as a lab with no Global configuration at all.
for key in list(os.environ):
    if key.startswith(("REMOTERF_", "GLOBAL_", "XDG_")):
        del os.environ[key]
SERVER_HOME.mkdir(parents=True, exist_ok=True)
os.environ.update(
    HOME=str(SERVER_HOME),
    XDG_CONFIG_HOME=str(SERVER_HOME / ".config"),
    XDG_DATA_HOME=str(SERVER_HOME / ".local/share"),
    REMOTERF_BIND_HOST="0.0.0.0",
    GRPC_PORT=str(PORT),
    CERT_PORT=str(PORT + 1),
    LEGACY_EGRESS_LOG=str(EGRESS),
    LEGACY_LAN_IP=IP,
)
sys.path.insert(0, str(HERE / "guard"))
import sitecustomize  # noqa: E402,F401 - installs the egress guard here too

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][AB012]|[\x00-\x08\x0b-\x1f\x7f]")
_MASKS = [
    (re.compile(re.escape(str(TMP))), "<tmp>"),
    (re.compile(r"/(private/)?(var|tmp)/[^\s'\"]*"), "<path>"),
    (re.compile(re.escape(IP)), "<ip>"),
    (re.compile(rf"\b({PORT}|{PORT + 1})\b"), "<port>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2}(\.\d+)?)?([+-]\d{2}:?\d{2}|Z)?"), "<time>"),
    (re.compile(r"\b(Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*,? (\w{3,9} \d{1,2}|\d{1,2} \w{3,9})\b"), "<date>"),
    (re.compile(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b"), "<date>"),
    (re.compile(r"\b[0-9]+(\.[0-9]+)?\s?(ms|s|sec|seconds|min|minutes)\b ago"), "<ago>"),
    (re.compile(r"\b(?=[\w-]*\d)(?=[\w-]*[A-Za-z])[\w-]{24,}\b"), "<token>"),
    (re.compile(r"\b[A-Z0-9]{16}\b"), "<code>"),  # codes the console wizard generates (16 chars, below)
    (re.compile(r"\b1[6-9]\d{8}\b"), "<epoch>"),
]


def norm(value):
    if isinstance(value, dict):
        return {str(k): norm(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [norm(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if not isinstance(value, str):
        return value
    text = _ANSI.sub("", value.replace("\r", ""))
    for pattern, mask in _MASKS:
        text = pattern.sub(mask, text)
    # gRPC's own fork/poll logging carries pids and timestamps, not behaviour.
    lines = [line.rstrip() for line in text.split("\n") if not _GRPC_LOG.match(line)]
    return "\n".join(lines).strip("\n")


_GRPC_LOG = re.compile(r"^[IWE]\d{4} .*\.cc:\d+\]")
STEPS: list = []


def step(name: str, value) -> None:
    STEPS.append([name, norm(value)])


def certificate() -> Path:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "remoterf-legacy-harness")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address(IP)),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certs = SERVER_HOME / ".config/remoterf/certs"
    certs.mkdir(parents=True, exist_ok=True)
    pem = cert.public_bytes(serialization.Encoding.PEM)
    (certs / "ca.crt").write_bytes(pem)
    (certs / "server.crt").write_bytes(pem)
    (certs / "server.key").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    (certs / "server.key").chmod(0o600)
    return certs


# -----------------------------------------------------------------------------
# The client's own CLI, driven by prompts rather than by a fixed script, so the
# same session runs against any client version and records what it asked.
# -----------------------------------------------------------------------------

SHELL = r"[\w.@-]+(> |@remoterf: )"  # 2.1+ / 2.0.x shell prompts


def client_package(client_src: Path) -> str:
    # Exact names: macOS paths ignore case, and 2.0.x ships `remoteRF`.
    return "remoterf" if "remoterf" in os.listdir(client_src) else "remoteRF"


def client_env(client_src: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("REMOTERF_", "XDG_", "PYTHON", "GRPC_", "CERT_"))}
    env.update(
        HOME=str(CLIENT_HOME), TERM="dumb", PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring",
        PYTHONPATH=os.pathsep.join([str(HERE / "guard"), str(client_src)]),
    )
    return env


def cli(client_python: str, client_src: Path, args: list, answers: list, commands=()) -> str:
    import pexpect

    package = client_package(client_src)
    code = (
        "import sys, webbrowser; sys.argv[0] = 'remoterf';"
        "webbrowser.open = lambda *a, **k: (_ for _ in ()).throw(AssertionError('browser'));"
        f"from {package}.remoterf_cli import main; raise SystemExit(main())"
    )
    log = io.StringIO()
    child = pexpect.spawn(client_python, ["-c", code, *args], env=client_env(client_src), encoding="utf-8",
                          timeout=20, echo=False, cwd=str(CLIENT_HOME))
    child.logfile_read = log
    pending = [(pattern, list(replies)) for pattern, replies in answers]
    commands = list(commands) + ["exit"]
    patterns = [p for p, _ in pending] + [SHELL, pexpect.EOF, pexpect.TIMEOUT]
    for _ in range(40):
        index = child.expect(patterns)
        if index < len(pending):
            replies = pending[index][1]
            if not replies:
                log.write("\n[harness: no more answers; stopping]\n")
                break
            child.sendline(replies.pop(0))
        elif patterns[index] == SHELL:
            child.sendline(commands.pop(0) if commands else "exit")
        elif patterns[index] is pexpect.EOF:
            break
        else:
            log.write("\n[harness: TIMEOUT]\n")
            break
    else:
        log.write("\n[harness: 40 prompts; stopping]\n")
    child.close(force=True)
    log.write(f"\n[exit {child.exitstatus}]")
    return log.getvalue()


def client_answers(code=CODE, user=CLI_USER, password=PASSWORD, tries=1, choice="l"):
    return [
        (r"login or register to continue\. \(l/r\): ", [choice]),  # 2.0.x `-l` asks first
        (r"Terms of Service[^\n]*\[y/N\]: ", ["y"] * 3),
        (r"Continue with configuration\? \[y/N\]: ", ["y"]),
        (r"[Ee]nrollment [Cc]ode[^\n:]*: ", [code] * 2),
        (r"Account \(username@lab[^\n:]*: ", [user]),
        (r"Username[^\n:]*: ", [user] * tries),
        (r"Confirm Password[^\n:]*: ", [password]),
        (r"Password[^\n:]*: ", [password] * tries),
        (r"Email[^\n:]*: ", [f"{user}@example.org"]),
        (r"Hit enter to continue", [""]),
    ]


# -----------------------------------------------------------------------------
# The session
# -----------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--client-src", type=Path)
    parser.add_argument("--client-python")
    parser.add_argument("--out", required=True, type=Path)
    opts = parser.parse_args()

    import remoteRF_server
    from remoteRF_server.server import grpc_server, device_manager as devices

    meta = {"server": remoteRF_server.__file__}
    certs = SERVER_HOME / ".config/remoterf/certs"
    if not REOPEN:
        certificate()
        from remoteRF_server.server.user_group_handler import user_group_handler as groups

        gid = groups.create_user_group(group_name=GROUP, devices_whitelist=[7],
                                       max_reservation_time_sec=3600, max_reservations=2, lifetime_sec=0)
        groups.create_enrollment_codes(code_names=[CODE], group_id=gid, uses=6, duration_sec=0)
        kept = groups.create_user_group(group_name=KEEP_GROUP, devices_whitelist=[7],
                                        max_reservation_time_sec=3600, max_reservations=2, lifetime_sec=0)
        groups.create_enrollment_codes(code_names=[KEEP_CODE], group_id=kept, uses=2, duration_sec=0)

    # The defaults: what `serverrf` runs (host tunnel, reservation updates, status publisher).
    runtime = grpc_server.start_server_runtime(
        bind_host="0.0.0.0", grpc_port=PORT, certificate_port=PORT + 1, cert_dir=certs)
    if hasattr(grpc_server, "start_agent"):  # what `serverrf` does next on a Global-era Server
        grpc_server.start_agent()

    class FakeRadio:
        def close(self):
            pass

    # After startup: the runtime replaces devices registered before it.
    devices._devices[7] = devices._DeviceState(FakeRadio(), "local", True, "", "", "Fake radio", "fake", "test")
    from remoteRF_server.server.reservation import reservation_handler

    reservation_handler.update_devices()  # as startup does once devices are open: live tokens onto devices
    import grpc

    channel = grpc.secure_channel(f"{IP}:{PORT}", grpc.ssl_channel_credentials((certs / "ca.crt").read_bytes()))
    try:
        if REOPEN:
            reopen(channel, devices, grpc_server)
        else:
            # The client runs from its own HOME; keep the venv symlink (abspath, not resolve).
            client_src, client_python = opts.client_src.resolve(), os.path.abspath(opts.client_python)
            package = client_package(client_src)
            meta["client"] = subprocess.run(
                [client_python, "-c", f"import {package}; print({package}.__file__)"],
                env=client_env(client_src), capture_output=True, text=True, cwd=str(TMP)).stdout.strip()
            session(channel, devices, grpc_server, gid, client_src, client_python)
        time.sleep(1)  # let any background thread attempt what it would
        step("db", dump(SERVER_HOME / ".config/remoterf/db"))
        step("files", sorted(str(p.relative_to(SERVER_HOME)) for p in SERVER_HOME.rglob("*")
                             if p.is_file() and "__pycache__" not in p.parts))
        step("threads", sorted({re.sub(r"[-_ ]?\d+", "", t.name) for t in threading.enumerate()}))
        step("egress", sorted(set(EGRESS.read_text().split())) if EGRESS.exists() else [])
    finally:
        channel.close()
        runtime.stop(grace_sec=0)
        opts.out.write_text(json.dumps({"meta": meta, "steps": STEPS}, indent=1) + "\n")
        if not KEEP:
            shutil.rmtree(TMP, ignore_errors=True)


def acc_caller(channel):
    import grpc
    from remoteRF_server.common.grpc import grpc_pb2, grpc_pb2_grpc
    from remoteRF_server.common.utils import map_arg, unmap_arg

    stub = grpc_pb2_grpc.GenericRPCStub(channel)

    def acc(name, **args):
        try:
            reply = stub.Call(grpc_pb2.GenericRPCRequest(
                function_name="ACC:" + name, args={k: map_arg(v) for k, v in args.items()}), timeout=20)
            return {k: unmap_arg(v) for k, v in reply.results.items()}
        except grpc.RpcError as exc:
            return {"rpc_error": str(exc.code())}

    return acc


def acquirer(devices):
    def acquire(token):
        if not token:
            return "no token"
        try:
            with devices.acquire_device(token) as (device_id, _):
                return {"device": device_id}
        except Exception as exc:  # noqa: BLE001 - the refusal is the result
            return {"refused": type(exc).__name__}

    return acquire


def session(channel, devices, grpc_server, gid, client_src, client_python) -> None:
    from remoteRF_server.server import user_group_cli
    from remoteRF_server.server.reservation import reservation_handler
    from remoteRF_server.server.user_group_handler import user_group_handler as groups

    CLIENT_HOME.mkdir(parents=True)
    run = lambda args, answers, commands=(): cli(client_python, client_src, args, answers, commands)  # noqa: E731
    step("cli.configure", run(["-c", "-a", f"{IP}:{PORT}"], client_answers()))
    # 2.0.x has no -r: `-l` asks login or register.
    has_r = "--register" in (client_src / client_package(client_src) / "remoterf_cli.py").read_text()
    step("cli.register", run(["-r"] if has_r else ["-l"], client_answers(choice="r"),
                             ["perms", "getdev", "getres", "myres"]))
    step("cli.login", run(["-l"], client_answers(), ["getdev"]))
    for saved in CLIENT_HOME.rglob("credentials"):  # a remembered login would skip the password
        shutil.rmtree(saved, ignore_errors=True)
    step("cli.login_bad_password", run(["-l"], client_answers(password="wrong-password")))

    acc, acquire = acc_caller(channel), acquirer(devices)
    me = dict(un=WIRE_USER, pw=PASSWORD)
    step("acc.create_user", acc("create_user", **me, em="wire@example.org", ec=CODE))
    step("acc.create_user.duplicate_name", acc("create_user", **me, em="other@example.org", ec=CODE))
    step("acc.create_user.duplicate_email", acc("create_user", un="wire-two", pw=PASSWORD, em="wire@example.org", ec=CODE))
    step("acc.create_user.bad_code", acc("create_user", un="nocode", pw=PASSWORD, em="no@example.org", ec="invalid"))
    step("acc.create_user.short_password", acc("create_user", un="shortpw", pw="abc", em="s@example.org", ec=CODE))
    step("acc.create_user.at_sign", acc("create_user", un="a@b", pw=PASSWORD, em="ab@example.org", ec=CODE))
    step("acc.login", acc("login", **me))
    step("acc.login.wrong_password", acc("login", un=WIRE_USER, pw="nope"))
    step("acc.login.unknown_user", acc("login", un="ghost", pw=PASSWORD))
    step("acc.get_perms", acc("get_perms", **me))
    step("acc.get_dev", acc("get_dev", **me))

    start = datetime.now().replace(microsecond=0) - timedelta(seconds=1)
    at = lambda **delta: int((start + timedelta(**delta)).timestamp())  # noqa: E731
    reserved = acc("reserve_device", **me, dd=7, st=at(), et=at(minutes=15))
    step("acc.reserve", {k: v for k, v in reserved.items() if k != "Token"} | {"has_token": "Token" in reserved})
    step("acc.reserve.overlap", acc("reserve_device", **me, dd=7, st=at(), et=at(minutes=10)))
    step("acc.reserve.too_long", acc("reserve_device", **me, dd=7, st=at(hours=3), et=at(hours=5)))
    step("acc.get_res", acc("get_res", **me))
    token = reserved.get("Token")
    step("device.acquire_with_token", acquire(token))
    devices._super_token_path().write_text("legacy-master")
    step("device.acquire_with_master_token", acquire("legacy-master_7_force"))
    with sqlite3.connect(SERVER_HOME / ".config/remoterf/db/reservations.db") as conn:
        row = conn.execute("SELECT res_id FROM Reservations WHERE username=?", (WIRE_USER,)).fetchone()
    step("acc.cancel_res", acc("cancel_res", **me, res_id=row[0]) if row else "no reservation")
    step("device.acquire_after_cancel", acquire(token))
    # Left in place for the reopen leg: an active reservation must survive an upgrade.
    step("acc.set_enroll.second_group", acc("set_enroll", un=CLI_USER, pw=PASSWORD, ec=KEEP_CODE))
    kept = acc("reserve_device", un=CLI_USER, pw=PASSWORD, dd=7, st=at(), et=at(minutes=15))
    step("acc.reserve.kept", {k: v for k, v in kept.items() if k != "Token"} | {"has_token": "Token" in kept})
    (TMP / "kept_token").write_text(kept.get("Token", ""))
    step("acc.set_enroll", acc("set_enroll", **me, ec=CODE))
    step("acc.set_enroll.bad_code", acc("set_enroll", **me, ec="invalid"))

    step("console", console(grpc_server, user_group_cli, gid))

    groups.delete_user_group(group_id=gid)
    step("acc.get_perms.after_group_delete", acc("get_perms", **me))
    step("acc.reserve.after_group_delete", acc("reserve_device", **me, dd=7, st=at(hours=6), et=at(hours=6, minutes=15)))
    reservation_handler.remove_user(username=WIRE_USER)
    step("acc.login.after_account_delete", acc("login", **me))


def reopen(channel, devices, grpc_server) -> None:
    """A later Server on the lab the first one left: accounts, groups, codes and
    the live reservation (and its device token) must all still work."""
    from remoteRF_server.server import user_group_cli

    acc, acquire = acc_caller(channel), acquirer(devices)
    me = dict(un=CLI_USER, pw=PASSWORD)
    step("reopen.acc.login", acc("login", **me))
    step("reopen.acc.login.wrong_password", acc("login", un=CLI_USER, pw="nope"))
    step("reopen.acc.get_perms", acc("get_perms", **me))
    step("reopen.acc.get_dev", acc("get_dev", **me))
    step("reopen.acc.get_res", acc("get_res", **me))
    step("reopen.device.acquire_kept_token", acquire((TMP / "kept_token").read_text()))
    step("reopen.console", console(grpc_server, user_group_cli, 0,
                                   ["users list", "groups list", "codes list", "reservations list"]))


def console(grpc_server, user_group_cli, gid, commands=None) -> dict:
    """Read-only listings plus the interactive group/code wizards, with scripted answers."""
    answers = [  # first match wins, so the specific questions come first
        (r"(?i)(create|confirm|proceed|correct|save|use these)\b.*[\[(]y/n[\])]", "y"),
        (r"(?i)days ahead", ""), (r"(?i)characters per", "16"),
        (r"(?i)attach a user group", "y"), (r"(?i)how many", "1"), (r"(?i)group id", str(gid)), (r"(?i)uses", "3"),
        (r"(?i)code", "console-code"), (r"(?i)name", "console-group"), (r"(?i)device", "7"),
        (r"(?i)max.*(time|duration|length|sec)", "3600"), (r"(?i)max.*reserv", "2"),
        (r"(?i)(lifetime|expire|duration|valid)", "0"),
    ]

    class Session:
        def __init__(self):
            self.asked = []

        def prompt(self, message, *a, **k):
            text = _ANSI.sub("", message if isinstance(message, str) else str(message))
            self.asked.append(text)
            if len(self.asked) > 30:
                raise EOFError("harness: too many prompts")
            return next((reply for pattern, reply in answers if re.search(pattern, text)), "")

    out = {}
    owners = [m for m in (grpc_server, user_group_cli) if hasattr(m, "session")]
    for command in commands or ["users list", "groups list", "codes list", "reservations list", "devices list",
                                "groups create", "codes create", "groups list", "codes list"]:
        fake = Session()
        saved = [m.session for m in owners]
        for m in owners:
            m.session = fake
        try:
            output = captured(lambda: grpc_server.server_input(command))
        finally:
            for m, s in zip(owners, saved):
                m.session = s
        out[f"{len(out):02d} {command}"] = {"asked": fake.asked, "output": output}
    return out


def captured(fn) -> str:
    """Everything fn writes to fd 1 (prompt_toolkit keeps its own handle on stdout)."""
    sys.stdout.flush()
    saved = os.dup(1)
    with tempfile.TemporaryFile(mode="w+b") as sink:
        os.dup2(sink.fileno(), 1)
        error = ""
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001 - a crash is a result too
            error = f"\n[{type(exc).__name__}: {exc}]"
        finally:
            sys.stdout.flush()
            os.dup2(saved, 1)
            os.close(saved)
        sink.seek(0)
        return sink.read().decode("utf-8", "replace") + error


# Secrets and wall-clock values differ on every run; the rest is compared.
_SECRET_COLUMN = re.compile(r"(?i)(salt|hash|token|secret|_at$|created|expir|last_|^start|_start|^end|_end|seen)")


def dump(dbdir: Path) -> dict:
    out = {}
    for path in sorted(dbdir.glob("*.db")):
        with sqlite3.connect(path) as conn:
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            for table in tables:
                columns = [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')]
                keep = [c for c in columns if not _SECRET_COLUMN.search(c)]
                rows = conn.execute(f'SELECT {", ".join(chr(34) + c + chr(34) for c in keep) or "1"} FROM "{table}"').fetchall()
                rows = [["<float>" if isinstance(v, float) else v for v in row] for row in rows]  # wall-clock totals
                out[f"{path.name}:{table}"] = {"columns": columns, "rows": sorted(rows, key=repr)}
    return out


if __name__ == "__main__":
    main()
