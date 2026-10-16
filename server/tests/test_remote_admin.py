"""Remote admin, the lab side (docs/remote-admin-design.md): pins, codes, the
auth matrix, the shell's policy, the control socket's prompt bridge, and one
real OpenSSH session through the gRPC tunnel."""

import contextlib
import io
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

paramiko = pytest.importorskip("paramiko")

from remoteRF_server import remote_admin_shell as shell  # noqa: E402
from remoteRF_server.server import commands, control  # noqa: E402
from remoteRF_server.server import remote_admin as ra  # noqa: E402
from remoteRF_server.server import remote_admin_ssh as ssh  # noqa: E402


@pytest.fixture
def lab(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("REMOTERF_", "XDG_"))}
    env.update(XDG_CONFIG_HOME=str(tmp_path), XDG_DATA_HOME=str(tmp_path / "data"))
    with mock.patch.dict("os.environ", env, clear=True):
        from remoteRF_server.server import acc_perms, reservation
        from remoteRF_server.server import user_group_handler as ugh

        groups, handler, perms = ugh.UserGroupHandler(), reservation.ReservationHandler(), acc_perms.perms_db()
        with mock.patch.object(reservation, "perms", perms), \
             mock.patch.object(reservation, "user_group_handler", groups), \
             mock.patch.object(ugh, "user_group_handler", groups):
            ssh._sessions.clear()
            ssh._failures.clear()
            ssh._opens.clear()

            def account(name, *, admin=True):
                uid, error = handler.link_global_account(username=name, email=f"{name}@example.org", salt="00", hashed="x")
                assert error is None
                if admin:
                    with mock.patch("builtins.input", return_value="y"), contextlib.redirect_stdout(io.StringIO()):
                        perms.set_admin(name)
                return uid

            yield SimpleNamespace(tmp=tmp_path, h=handler, perms=perms, account=account)


def run(fn, argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        rc = fn(argv)
    return rc, out.getvalue()


def pin(lab, name="jdoe", *, read_only=False, password="correct horse battery"):
    lab.account(name)
    rc, out = run(ra.cmd_admins_add, [name] + (["--read-only"] if read_only else []))
    assert rc == 0, out
    code = out.split("pair ", 1)[1].split()[1]
    if password:
        with contextlib.closing(ra.connect()) as conn:
            ra.set_password(conn, ra.find_pin(conn, name)["admin_id"], password)
            conn.commit()
    return code


def device_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
    return paramiko.Ed25519Key.from_private_key(io.StringIO(pem.decode()))


def server(*, label="laptop-2"):
    return ssh._server_interface()("lan", label)


def login(srv, name, key, *answers_by_round, signed=True):
    """Drive the auth callbacks as paramiko would. The last result."""
    public = paramiko.Ed25519Key(data=key.asbytes())  # what paramiko builds from the request
    assert srv.check_auth_publickey(name, public) == paramiko.AUTH_PARTIALLY_SUCCESSFUL
    if signed:  # what paramiko does next with a signed request
        sig = key.sign_ssh_data(b"session blob")
        sig.rewind()
        assert public.verify_ssh_sig(b"session blob", sig)
    assert srv.get_allowed_auths(name) == ("keyboard-interactive" if signed else "publickey")
    result = srv.check_auth_interactive(name, "")
    for answers in answers_by_round:
        if not isinstance(result, paramiko.InteractiveQuery):
            break
        result = srv.check_auth_interactive_response(answers)
    return result


# -----------------------------
# Policy
# -----------------------------

def test_every_command_has_a_tier():
    missing = [c.names[0] for c in commands.commands() if c.names[0] not in shell.TIERS]
    assert missing == [], f"classify these for remote admin: {missing}"


def test_the_never_remote_list_is_console_only():
    never = {"stop", "wipe", "users purge", "db purge", "global leave", "global join", "global verify",
             "config wipe", "detach", "admins add", "admins remove", "admins code", "admins policy"}
    assert {name for name in never if shell.TIERS[name] != shell.NEVER} == set()
    assert all(shell.TIERS[c.names[0]] == shell.NEVER for c in commands.commands() if c.section == "Remote admin")


def test_read_only_admins_get_the_read_tier_only():
    assert shell.allowed(shell.READ, True)
    assert not shell.allowed(shell.WRITE, True) and not shell.allowed(shell.DESTRUCTIVE, True)
    assert shell.allowed(shell.DESTRUCTIVE, False) and not shell.allowed(shell.NEVER, False)
    prune = commands.resolve(["users", "prune-proxies", "-y"])
    assert shell.tier_for(prune[0], prune[1]) == shell.DESTRUCTIVE
    tokens = commands.resolve(["hosts", "tokens", "wipe"])
    assert shell.tier_for(tokens[0], tokens[1]) == shell.DESTRUCTIVE


# -----------------------------
# Pins and codes
# -----------------------------

def test_add_needs_an_existing_admin_and_never_grants_the_role(lab):
    assert run(ra.cmd_admins_add, ["nobody"])[0] == 1
    lab.account("student", admin=False)
    rc, out = run(ra.cmd_admins_add, ["student"])
    assert rc == 1 and "not an Admin" in out
    assert lab.perms.get_perms("student")[0][0] == "Normal User"
    lab.account("jdoe")
    rc, out = run(ra.cmd_admins_add, ["jdoe", "--read-only"])
    assert rc == 0
    key = ra.host_key()
    code = out.split("pair ", 1)[1].split()[1]
    assert code.split(".")[1] == key.fingerprint.split(":")[1][:12]
    assert oct(ra.host_key_path().stat().st_mode & 0o777) == "0o600"
    assert run(ra.cmd_admins_add, ["jdoe"])[0] == 1  # already pinned
    with contextlib.closing(ra.connect()) as conn:
        assert ra.find_pin(conn, "jdoe")["read_only"] == 1


def test_a_visitor_proxy_cannot_be_pinned(lab):
    uid = lab.account("fed-abc")
    rc, out = run(ra.cmd_admins_add, ["fed-abc"])
    assert rc == 1 and "visitor" in out


def test_pins_fail_closed(lab):
    pin(lab)
    with contextlib.closing(ra.connect()) as conn:
        assert ra.pin_problem(ra.find_pin(conn, "jdoe")) is None
        lab.perms.remove_user("jdoe")
        lab.perms.set_user("jdoe")
        assert ra.pin_problem(ra.find_pin(conn, "jdoe")) == "no longer an Admin"
        with mock.patch("builtins.input", return_value="y"), contextlib.redirect_stdout(io.StringIO()):
            lab.perms.set_admin("jdoe")
        lab.h.remove_user(username="jdoe")
        assert ra.pin_problem(ra.find_pin(conn, "jdoe")) == "account gone"
        lab.account("jdoe")  # same name, new account: no inherited pin
        assert ra.pin_problem(ra.find_pin(conn, "jdoe")) == "account gone"
    assert run(ra.cmd_admins_remove, ["jdoe"])[0] == 0
    with contextlib.closing(ra.connect()) as conn:
        assert ra.find_pin(conn, "jdoe") is None
    assert not ra.any_active_pin()


def test_codes_are_single_use_expire_and_allow_five_tries(lab):
    pin(lab)
    with contextlib.closing(ra.connect()) as conn:
        admin = ra.find_pin(conn, "jdoe")["admin_id"]
        code = ra.issue_code(conn, admin, "pair", length=16, ttl=60)
        for _ in range(9):  # 80 bits: guessing cannot burn a pairing code
            assert not ra.redeem_code(conn, admin, "pair", "WRONG")
        assert ra.redeem_code(conn, admin, "pair", code.lower() + ".AbCdEf")  # case, suffix tolerated
        assert not ra.redeem_code(conn, admin, "pair", code)  # one use
        code = ra.issue_code(conn, admin, "device", length=10, ttl=60, device_fp="SHA256:a", session_id="s1")
        for _ in range(5):
            assert not ra.redeem_code(conn, admin, "device", "WRONG", device_fp="SHA256:a", session_id="s1")
        assert not ra.redeem_code(conn, admin, "device", code, device_fp="SHA256:a", session_id="s1")  # five misses
        code = ra.issue_code(conn, admin, "pair", length=16, ttl=-1)
        assert not ra.redeem_code(conn, admin, "pair", code)  # expired
        code = ra.issue_code(conn, admin, "device", length=10, ttl=60, device_fp="SHA256:a", session_id="s1")
        assert not ra.redeem_code(conn, admin, "device", code, device_fp="SHA256:b", session_id="s1")
        assert not ra.redeem_code(conn, admin, "device", code, device_fp="SHA256:a", session_id="s2")
        assert ra.redeem_code(conn, admin, "device", code, device_fp="SHA256:a", session_id="s1")


def test_the_audit_log_is_append_only(lab):
    ra.audit("x")
    with contextlib.closing(ra.connect()) as conn, pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM remote_admin_audit")


# -----------------------------
# The auth matrix
# -----------------------------

def test_pairing_sets_the_password_and_approves_the_device(lab):
    code = pin(lab, password=None)
    key = device_key()
    result = login(server(), f"jdoe#{code.split('.')[0]}", key, ["short", "short"], ["a long password!", "a long password!"])
    assert result == paramiko.AUTH_SUCCESSFUL
    with contextlib.closing(ra.connect()) as conn:
        admin = ra.find_pin(conn, "jdoe")
        device = ra.device_for(conn, admin["admin_id"], ra.public_line(key))
        assert device["approved_via"] == "pair" and device["label"] == "laptop-2"
    assert login(server(), "jdoe", key, ["a long password!"]) == paramiko.AUTH_SUCCESSFUL
    # the code was single use
    assert login(server(), f"jdoe#{code}", device_key(), []) == paramiko.AUTH_FAILED


def test_a_key_counts_only_once_it_signed(lab):
    """paramiko asks check_auth_publickey before it checks a signature (and for a
    probe with none): naming an approved device's public key must get nowhere."""
    code = pin(lab, password=None)
    key = device_key()
    login(server(), f"jdoe#{code}", key, ["a long password!"] * 2)
    public = paramiko.Ed25519Key(data=key.asbytes())
    srv = server()
    assert login(srv, "jdoe", public, signed=False) == paramiko.AUTH_FAILED
    assert srv.check_auth_interactive_response(["a long password!"]) == paramiko.AUTH_FAILED
    bad = paramiko.Message()
    bad.add_string("ssh-ed25519")
    bad.add_string(b"\0" * 64)
    bad.rewind()
    srv = server()
    srv.check_auth_publickey("jdoe", public)
    assert not public.verify_ssh_sig(b"session blob", bad)
    assert srv.check_auth_interactive("jdoe", "") == paramiko.AUTH_FAILED


def test_known_device_needs_the_password_every_time(lab):
    code = pin(lab, password=None)
    key = device_key()
    login(server(), f"jdoe#{code}", key, ["a long password!"] * 2)
    assert login(server(), "jdoe", key, ["wrong"]) == paramiko.AUTH_FAILED
    assert login(server(), "nobody", key, ["a long password!"]) == paramiko.AUTH_FAILED


def test_five_wrong_passwords_lock_the_admin(lab):
    code = pin(lab, password=None)
    key = device_key()
    login(server(), f"jdoe#{code}", key, ["a long password!"] * 2)
    stranger = device_key()
    for _ in range(5):  # someone else's key: their guesses lock only unapproved devices
        assert login(server(), "jdoe", stranger, ["wrong"]) == paramiko.AUTH_FAILED
    assert login(server(), "jdoe", key, ["a long password!"]) == paramiko.AUTH_SUCCESSFUL
    ssh._sessions.clear()
    for _ in range(5):
        assert login(server(), "jdoe", key, ["wrong"]) == paramiko.AUTH_FAILED
    assert login(server(), "jdoe", key, ["a long password!"]) == paramiko.AUTH_FAILED
    with contextlib.closing(ra.connect()) as conn:
        reasons = [r[0] for r in conn.execute("SELECT argv_json FROM remote_admin_audit WHERE event='auth_fail'")]
    assert '{"reason": "locked"}' in reasons


def test_a_new_device_needs_a_code(lab):
    pin(lab)
    srv = server()
    result = login(srv, "jdoe", device_key(), ["correct horse battery"])
    assert isinstance(result, paramiko.InteractiveQuery) and not result.prompts
    assert "admins code jdoe" in result.instructions  # no email path: the console
    assert srv.check_auth_interactive_response([]) == paramiko.AUTH_FAILED

    sent = {}

    def email(pin_row, code, fp, label, route):
        sent.update(code=code, fp=fp, label=label)
        return "j***@example.org"

    key = device_key()
    with mock.patch.object(ra, "email_device_code", side_effect=email):
        srv = server()
        result = login(srv, "jdoe", key, ["correct horse battery"])
        assert result.prompts and "j***@example.org" in result.instructions and key.fingerprint in result.instructions
        assert srv.check_auth_interactive_response([sent["code"]]) == paramiko.AUTH_SUCCESSFUL
        assert sent["label"] == "laptop-2"
    assert login(server(), "jdoe", key, ["correct horse battery"]) == paramiko.AUTH_SUCCESSFUL
    run(ra.cmd_admins_policy, ["new-device", "console"])
    with mock.patch.object(ra, "email_device_code", side_effect=email) as emailed:
        result = login(server(), "jdoe", device_key(), ["correct horse battery"])
        assert "admins code" in result.instructions and not emailed.called


def test_demoted_or_removed_admins_cannot_log_in(lab):
    code = pin(lab, password=None)
    key = device_key()
    login(server(), f"jdoe#{code}", key, ["a long password!"] * 2)
    lab.perms.remove_user("jdoe")
    lab.perms.set_user("jdoe")
    assert login(server(), "jdoe", key, ["a long password!"]) == paramiko.AUTH_FAILED


def test_two_sessions_per_admin(lab):
    code = pin(lab, password=None)
    key = device_key()
    login(server(), f"jdoe#{code}", key, ["a long password!"] * 2)
    with contextlib.closing(ra.connect()) as conn:
        admin = ra.find_pin(conn, "jdoe")["admin_id"]
    ssh._sessions.clear()
    assert login(server(), "jdoe", key, ["a long password!"]) == paramiko.AUTH_SUCCESSFUL  # counted at auth
    assert login(server(), "jdoe", key, ["a long password!"]) == paramiko.AUTH_SUCCESSFUL
    result = login(server(), "jdoe", key, ["a long password!"])
    assert "already has 2 sessions" in result.instructions
    session = next(iter(ssh._sessions.values()))
    assert ssh._still_allowed(session) is None
    run(ra.cmd_admins_kick, ["jdoe"])
    assert ssh._still_allowed(session) == "ended from the console"


# -----------------------------
# The shell
# -----------------------------

@pytest.fixture
def remote(lab):
    code = pin(lab, password=None)
    key = device_key()
    login(server(), f"jdoe#{code}", key, ["a long password!"] * 2)
    with contextlib.closing(ra.connect()) as conn:
        admin = ra.find_pin(conn, "jdoe")["admin_id"]
    with mock.patch.dict("os.environ", {"REMOTERF_REMOTE_ADMIN": f"{admin}:sess1",
                                       "REMOTERF_REMOTE_ADMIN_DEVICE": key.fingerprint,
                                       "REMOTERF_REMOTE_ADMIN_ROUTE": "relay"}):
        yield shell.Shell()


def events(session="sess1"):
    with contextlib.closing(ra.connect()) as conn:
        return [(r[0], ra._detail(r[1])) for r in conn.execute(
            "SELECT event, argv_json FROM remote_admin_audit WHERE session_id=? ORDER BY id", (session,))]


def test_shell_refuses_never_remote_and_secrets(remote):
    with mock.patch.object(commands, "dispatch") as dispatch:
        for line in ("users purge", "stop", "admins add someone", "hosts tokens --secrets", "global leave",
                     "global cluster remove lab-pair"):
            assert run(lambda a: remote.run_line(a[0]), [line])[0] is True
        dispatch.assert_not_called()
    assert [e for e, _ in events()] == ["refused"] * 6


def test_log_hides_pairing_codes_and_is_for_full_admins(remote):
    from remoteRF_server.server import console

    pane = "serverrf> admins add jdoe\n  remoterf --remote-admin pair jdoe@ucla K7Q2-6XPM-4TDA-HHWZ.Qm9xYz12AbCd\n"
    with mock.patch.object(console, "running", return_value=True), \
         mock.patch("subprocess.run", return_value=SimpleNamespace(stdout=pane)):
        out = run(lambda a: remote.run_line(a[0]), ["log 5"])[1]
        assert "K7Q2" not in out and "XXXX-XXXX-XXXX-XXXX.Qm9xYz12AbCd" in out
        with contextlib.closing(ra.connect()) as conn:
            conn.execute("UPDATE remote_admins SET read_only=1")
            conn.commit()
        assert "not for read-only" in run(lambda a: remote.run_line(a[0]), ["log 5"])[1]


def test_shell_runs_writes_and_read_only_admins_cannot(remote):
    with mock.patch.object(commands, "dispatch", return_value=0) as dispatch:
        run(lambda a: remote.run_line(a[0]), ["devices rename 3 bench"])
        dispatch.assert_called_once_with(["devices", "rename", "3", "bench"], in_daemon=False)
        with contextlib.closing(ra.connect()) as conn:
            conn.execute("UPDATE remote_admins SET read_only=1")
            conn.commit()
        run(lambda a: remote.run_line(a[0]), ["devices rename 3 x"])
        run(lambda a: remote.run_line(a[0]), ["devices list"])
        assert dispatch.call_count == 2
    assert [e for e, _ in events()] == ["command", "command_end", "refused", "command", "command_end"]


def test_destructive_needs_password_word_and_backup(remote, lab):
    with mock.patch.object(commands, "dispatch", return_value=0) as dispatch, \
         mock.patch("getpass.getpass", return_value="wrong"):
        run(lambda a: remote.run_line(a[0]), ["devices wipe"])
        dispatch.assert_not_called()
    with mock.patch.object(commands, "dispatch", return_value=0) as dispatch, \
         mock.patch("getpass.getpass", return_value="a long password!"), \
         mock.patch("builtins.input", return_value="devices wipe"):
        rc, out = run(lambda a: remote.run_line(a[0]), ["devices wipe"])
        dispatch.assert_called_once_with(["devices", "wipe", "-y"], in_daemon=False)
    assert len(list(ra.backups_dir().glob("remoterf-export-*.tgz"))) == 1
    import tarfile

    with tarfile.open(next(ra.backups_dir().glob("*.tgz"))) as tar:
        assert "remoterf/db/remote_admin.db" in tar.getnames()
    assert [e for e, _ in events()] == ["stepup_fail", "refused", "command", "command_end"]


def test_shell_self_service(remote):
    rc, out = run(lambda a: remote.run_line(a[0]), ["me"])
    assert "this device" in out
    with mock.patch("getpass.getpass", side_effect=["a long password!", "another long one", "another long one"]):
        run(lambda a: remote.run_line(a[0]), ["passwd"])
    with contextlib.closing(ra.connect()) as conn:
        assert ra.check_password(ra.find_pin(conn, "jdoe"), "another long one")
    run(lambda a: remote.run_line(a[0]), [f"revoke {remote.fp[7:20]}"])
    assert ssh._still_allowed(ssh._Session(remote.admin_id, "jdoe", remote.fp, "lan", "l")) == "device revoked"


def test_interactive_daemon_commands_never_attach_a_remote_admin_to_the_console(lab):
    with mock.patch.dict("os.environ", {"REMOTERF_REMOTE_ADMIN": "1:s"}), \
         mock.patch.object(control, "running", return_value=True), \
         mock.patch.object(control, "call", return_value=(0, "done\n")) as call, \
         mock.patch("remoteRF_server.server.console.run_in_console") as attach:
        assert run(lambda a: commands.dispatch(a, in_daemon=False), ["users", "manage"])[0] == 0
        assert run(lambda a: commands.dispatch(a, in_daemon=False), ["detach"])[0] == 1
    attach.assert_not_called()
    call.assert_called_once()


# -----------------------------
# The control socket's prompt bridge
# -----------------------------

def test_prompt_bridge_round_trip():
    import tempfile

    tmp = tempfile.TemporaryDirectory()  # AF_UNIX paths are short; pytest's tmp_path is not
    path = Path(tmp.name) / "s.sock"

    def handler(argv):
        print("menu")
        name = control.ask("Enter username: ")
        secret = control.ask("Secret: ", secret=True)
        print(f"got {name}/{secret}")
        return 3

    daemon = control.ControlServer(handler, path=path)
    daemon.start()
    try:
        asked = []

        def answer(text, secret):
            asked.append((text, secret))
            return "jdoe" if not secret else "s3"

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            reply = control.call(["users", "manage"], path=path, ask=answer)
        assert reply == (3, "got jdoe/s3\n")
        assert out.getvalue() == "menu\n"
        assert asked == [("Enter username: ", False), ("Secret: ", True)]
        assert control.running(path)
        # a caller that goes away mid-prompt: the command sees EOF, the daemon carries on
        with pytest.raises(KeyboardInterrupt), contextlib.redirect_stdout(io.StringIO()):
            control.call(["x"], path=path, ask=mock.Mock(side_effect=KeyboardInterrupt))
        assert control.call(["y"], path=path, ask=answer)[0] == 3
    finally:
        daemon.stop()
        tmp.cleanup()


# -----------------------------
# One real session: OpenSSH -> ProxyCommand -> gRPC Tunnel -> paramiko -> the shell
# -----------------------------

PIPE = """
import sys, threading, grpc
channel = grpc.insecure_channel(sys.argv[1])
call = channel.stream_stream("/remote_rf.RemoteAdminV1/Tunnel")
def chunks():
    while True:
        data = sys.stdin.buffer.raw.read(65536)
        if not data:
            return
        yield data
md = [("x-remoterf-device-label", "testbox")]
for data in call(chunks(), metadata=md):
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
"""


def _expect(argv, steps, timeout=40.0):
    import pty

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    out, i, deadline = b"", 0, time.monotonic() + timeout
    while time.monotonic() < deadline:
        import select

        if fd in select.select([fd], [], [], 0.2)[0]:
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            out += data
        if i < len(steps) and steps[i][0].encode() in out[-2000:]:
            os.write(fd, steps[i][1].encode() + b"\r")
            out += b"<<sent>>"
            i += 1
    else:
        os.kill(pid, 9)
    os.waitpid(pid, 0)
    return out.decode(errors="replace")


@pytest.mark.skipif(shutil.which("ssh") is None or shutil.which("ssh-keygen") is None, reason="needs OpenSSH")
def test_a_real_openssh_session_through_the_tunnel(lab, tmp_path):
    import grpc
    from concurrent import futures

    code = pin(lab, password=None)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    ssh.register(server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    try:
        (tmp_path / "pipe.py").write_text(PIPE)
        os.system(f"ssh-keygen -q -t ed25519 -N '' -f {tmp_path}/id >/dev/null")
        key = ra.host_key()
        (tmp_path / "known").write_text(f"remoterf-test {ra.public_line(key)}\n")

        def ssh_argv(login):
            return ["ssh", "-F", "none", "-tt", "-o", f"ProxyCommand={sys.executable} {tmp_path}/pipe.py 127.0.0.1:{port}",
                    "-o", "HostKeyAlias=remoterf-test", "-o", f"UserKnownHostsFile={tmp_path}/known",
                    "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes", "-i", f"{tmp_path}/id",
                    "-o", "PubkeyAuthentication=yes", "-o", "PasswordAuthentication=no", "-l", login, "lab"]

        out = _expect(ssh_argv(f"jdoe#{code}"), [("(min 12):", "a long password!"),
                                         ("Repeat it:", "a long password!"), ("jdoe@lab>", "users purge"),
                                         ("console only", "devices wipe"), ("Remote-admin password:", "\x03"),
                                         ("Cancelled.", "me"), ("this device", "exit")])
        assert "console only" in out and "Cancelled." in out and "this device" in out, out
        out = _expect(ssh_argv("jdoe"), [("Password for remote admin jdoe:", "a long password!"),
                                          ("jdoe@lab>", "exit")])
        assert "jdoe@lab>" in out, out
        # session_end is written after the server closes the channel, so ssh can exit first.
        deadline = time.monotonic() + 20
        while True:
            with contextlib.closing(ra.connect()) as conn:
                seen = [r[0] for r in conn.execute("SELECT event FROM remote_admin_audit ORDER BY id")]
            if seen.count("session_end") >= 2 or time.monotonic() > deadline:
                break
            time.sleep(0.1)
        assert seen.count("session_start") == 2 and seen.count("session_end") == 2, seen
        assert "device_approved" in seen and "refused" in seen
    finally:
        server.stop(0)


# -----------------------------
# With RemoteRF Global: emailed device codes, `<user>@global` pins, revocation
# -----------------------------

SUB = "44444444-4444-4444-8444-444444444444"


def test_a_global_only_account_is_pinned_after_the_operator_confirms(lab):
    calls = []

    def global_call(path, payload):
        calls.append((path, payload))
        return {"subject": SUB, "username": "jdoe", "masked_email": "j***@example.org"} \
            if payload["op"] == "resolve" else {"registered": True}

    with mock.patch.object(ra, "_on_global", return_value=True), \
         mock.patch.object(ra, "_global_call", side_effect=global_call), \
         mock.patch("builtins.input", return_value="n"):
        assert run(ra.cmd_admins_add, ["jdoe@global"])[0] == 1
    assert [p["op"] for _, p in calls] == ["resolve"] and not ra.any_active_pin()
    with mock.patch.object(ra, "_on_global", return_value=True), \
         mock.patch.object(ra, "_global_call", side_effect=global_call), \
         mock.patch("builtins.input", return_value="y"):
        rc, out = run(ra.cmd_admins_add, ["jdoe@global"])
    assert rc == 0 and "pair jdoe@global@" in out
    assert calls[-1] == (ra.PINS_PATH, {"op": "register", "subject": SUB})
    with contextlib.closing(ra.connect()) as conn:
        pin_row = ra.find_pin(conn, "jdoe@global")
        assert (pin_row["kind"], pin_row["acc_id"], pin_row["subject_id"]) == ("global", None, SUB)
        assert ra.pin_problem(pin_row) is None  # no lab row, no role: the pin is the grant
        assert ra.find_pin(conn, "jdoe") is None
    with mock.patch.object(ra, "_on_global", return_value=False):
        assert run(ra.cmd_admins_add, ["other@global"])[0] == 1


def test_device_codes_go_to_the_global_subject_only(lab):
    pin(lab)
    with contextlib.closing(ra.connect()) as conn:
        lab_pin = ra.find_pin(conn, "jdoe")
    sent = []
    with mock.patch.object(ra, "_global_call", side_effect=lambda p, b: sent.append(b) or {"masked_email": "x"}), \
         mock.patch.object(ra, "_on_global", return_value=True):
        assert ra.email_device_code(lab_pin, "ABCDEFGH23", "SHA256:x", "l", "lan") is None  # not linked: console only
        with mock.patch.object(ra, "_link_subject", return_value=SUB):
            assert ra.email_device_code(lab_pin, "ABCDEFGH23", "SHA256:x", "l", "lan") == "x"
    assert sent == [{"subject": SUB, "template": "device_code", "code": "ABCDEFGH23", "device_fp": "SHA256:x",
                     "device_label": "l", "route": "lan"}]
    with mock.patch.object(ra, "_link_subject", return_value=SUB), mock.patch.object(ra, "_on_global", return_value=False):
        assert ra.email_device_code(lab_pin, "ABCDEFGH23", "SHA256:x", "l", "lan") is None


def test_lab_calls_to_global_are_signed_with_the_deployment_key(lab):
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from remoterf_federation_core import canonical_json

    from remoteRF_server.server import global_onboarding as g

    key = Ed25519PrivateKey.generate()
    posted = {}
    with mock.patch.object(g, "_signing_material", return_value=(key, "kid", "lab-id")), \
         mock.patch.object(ra, "_post", side_effect=lambda url, body: posted.update(url=url, body=body) or {"ok": 1}):
        assert ra._global_call(ra.NOTICE_PATH, {"subject": SUB}) == {"ok": 1}
    body = posted["body"]
    assert posted["url"].endswith(ra.NOTICE_PATH) and body["payload"]["deployment_id"] == "lab-id"
    key.public_key().verify(base64.b64decode(body["signature"]), canonical_json(body["payload"]).encode())


def test_global_revoking_an_account_ends_its_global_only_pins(lab):
    from remoteRF_server.server.federation import enrollment

    with contextlib.closing(ra.connect()) as conn:
        conn.execute("INSERT INTO remote_admins(kind,username,subject_id,created_at) VALUES ('global','jdoe',?,1)", (SUB,))
        admin = ra.find_pin(conn, "jdoe@global")["admin_id"]
        ra.approve_device(conn, admin, "ssh-ed25519 AAAA", "SHA256:dev", "l", "pair")
        conn.commit()
    handler = enrollment.ServerFederatedEnrollHandler.__new__(enrollment.ServerFederatedEnrollHandler)
    handler.local_deployment_id, handler.display_name = "lab", "Lab"
    handler._audit = mock.Mock()
    action = SimpleNamespace(state="active", claims={"iss": "not-global", "sub": SUB, "contract_id": "c",
                                                     "contract_version": 1},
                             request=SimpleNamespace(value={"payload": {"code_name": "admin_pin.revoke",
                                                                        "email": "x@example.org"}}))
    with mock.patch.object(enrollment.links, "global_home_id", return_value="global-home"):
        with pytest.raises(enrollment.FederationBusinessError):
            handler._admin_pin_revoke(None, action, 1)
        assert ra.any_active_pin()
        action.claims["iss"] = "global-home"
        with pytest.raises(enrollment.FederationBusinessError):  # a user's own enrolment naming this code
            handler._admin_pin_revoke(None, action, 1)
        assert ra.any_active_pin()
        del action.request.value["payload"]["email"]
        assert handler._admin_pin_revoke(None, action, 1)["status"] == "ok"
    assert not ra.any_active_pin()
    with contextlib.closing(ra.connect()) as conn:
        assert ra.device_for(conn, admin, "ssh-ed25519 AAAA") is None
        assert ra.revoke_global_pin(SUB) == 0  # a second revoke is a harmless ok
