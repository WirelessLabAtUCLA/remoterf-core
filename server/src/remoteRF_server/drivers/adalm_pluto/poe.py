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

"""PoE-powered ADALM-Pluto: power comes from a MikroTik RouterOS switch port.

A PoE Pluto stays off until something needs it. PoePluto stands in for the
adi.Pluto handle, so whatever a schema method touches powers the Pluto up and
connects first; power_down() cuts its switch port.
"""

import socket
import struct
import threading
import time

from remoteRF_server.common.utils import get_remoterf_root
from remoteRF_server.common.utils.ansi_codes import Sty, printf

IIOD_PORT = 30431
BOOT_TIMEOUT_S = 45
LINK_CHECK_S = 30  # no IIOD by then: ask the switch whether the port even has a link
OFF_S = 3  # long enough for the Pluto to lose power before it is switched back on


class RouterOS:
    """Minimal RouterOS API client (TCP 8728, RouterOS >= 6.43 plaintext login)."""

    def __init__(self, host, user, password, timeout=5):
        self.sock = socket.create_connection((host, 8728), timeout=timeout)
        self.cmd("/login", f"=name={user}", f"=password={password}")

    def close(self):
        self.sock.close()

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("RouterOS API closed the connection")
            buf += chunk
        return buf

    def _read_len(self):
        b = self._recv(1)[0]
        if b < 0x80: return b
        if b < 0xC0: return ((b & 0x3F) << 8) | self._recv(1)[0]
        if b < 0xE0: return ((b & 0x1F) << 16) | struct.unpack(">H", self._recv(2))[0]
        return ((b & 0x0F) << 24) | struct.unpack(">I", b"\0" + self._recv(3))[0]

    @staticmethod
    def _word(word):
        data = word.encode()
        n = len(data)
        if n < 0x80: head = bytes([n])
        elif n < 0x4000: head = struct.pack(">H", n | 0x8000)
        elif n < 0x200000: head = struct.pack(">I", n | 0xC00000)[1:]
        else: head = struct.pack(">I", n | 0xE0000000)
        return head + data

    def cmd(self, *words):
        self.sock.sendall(b"".join(self._word(w) for w in words) + b"\0")
        replies = []
        while True:
            sentence = []
            while n := self._read_len():
                sentence.append(self._recv(n).decode())
            replies.append(sentence)
            if sentence and sentence[0] in ("!done", "!trap", "!fatal"):
                if sentence[0] != "!done":
                    raise RuntimeError(" ".join(sentence))
                return replies


def set_poe(*, switch, user, password, port, on):
    ros = RouterOS(switch, user, password)
    try:
        ros.cmd("/interface/ethernet/poe/set", f"=.id={port}", f"=poe-out={'auto-on' if on else 'off'}")
    finally:
        ros.close()


def port_running(*, switch, user, password, port):
    """Whether the switch port has an Ethernet link (RouterOS 'running')."""
    ros = RouterOS(switch, user, password)
    try:
        replies = ros.cmd("/interface/ethernet/print", f"?name={port}", "=.proplist=name,running")
    finally:
        ros.close()
    for sentence in replies:
        if sentence[0] == "!re":
            return "=running=true" in sentence
    raise RuntimeError(f"switch has no interface {port}")


def _iiod_up(ip):
    try:
        socket.create_connection((ip, IIOD_PORT), timeout=1).close()
        return True
    except OSError:
        return False


class PoePluto:
    """Stands in for adi.Pluto on a PoE Pluto, powering it only while it is used."""

    def __init__(self, *, ip, port, serial="", switch="192.168.88.1", user="admin", password=""):
        # Bypass __setattr__, which forwards to the (powered) Pluto.
        vars(self).update(
            uri=f"ip:{ip}",
            _ip=ip,
            _port=port,
            _serial=str(serial or "").strip(),
            _switch={"switch": switch, "user": user, "password": password},
            _pluto=None,
            fault=None,  # message of the last failed boot; None once a boot succeeds
            _lock=threading.RLock(),
        )

    def __repr__(self):
        return f"<PoE Pluto {self.uri} on {self._port}, {'on' if self._pluto is not None else 'off'}>"

    def _poe(self, on):
        set_poe(port=self._port, on=on, **self._switch)

    @property
    def power_state(self):
        if self.fault:
            return "fault"
        return "on" if self._pluto is not None else "standby"

    def power_up(self):
        with self._lock:
            if self._pluto is not None:
                return
            try:
                self._boot()
            except Exception as e:
                vars(self)["fault"] = str(e)
                printf(f"{time.strftime('%H:%M:%S')} {e}", Sty.GRAY)
                raise
            vars(self)["fault"] = None

    def _boot(self):
        self._poe(True)
        started = time.monotonic()
        link_checked = False
        while not _iiod_up(self._ip):
            waited = time.monotonic() - started
            if waited > BOOT_TIMEOUT_S:
                self._poe(False)
                raise RuntimeError(f"PoE Pluto {self.uri} did not boot within {BOOT_TIMEOUT_S} s on {self._port}")
            if waited > LINK_CHECK_S and not link_checked:
                link_checked = True
                try:
                    running = port_running(port=self._port, **self._switch)
                except Exception:
                    running = True  # switch unreachable: keep waiting for IIOD
                if not running:
                    self._poe(False)
                    raise RuntimeError(
                        f"Pluto {self.uri}: PoE on {self._port} but no Ethernet link after {LINK_CHECK_S} s (cable/port/board fault)"
                    )
            time.sleep(1)
        import adi

        pluto = adi.Pluto(self.uri)
        found = str(pluto._ctx.attrs.get("hw_serial", "")).strip()
        if self._serial and found.lower() != self._serial.lower():
            del pluto
            self._poe(False)
            raise RuntimeError(f"{self.uri} on {self._port} is Pluto {found}, expected {self._serial}")
        vars(self)["_pluto"] = pluto

    def power_down(self):
        """Cut power. The Pluto boots with default settings: sample rate, LOs,
        gains and rx_buffer_size are all reset by the next power_up()."""
        with self._lock:
            # Drop the handle while the Pluto can still answer its buffer teardown.
            vars(self)["_pluto"] = None
            self._poe(False)

    def power_cycle(self):
        with self._lock:
            self.power_down()
            time.sleep(OFF_S)
            self.power_up()

    # The server closes device handles on shutdown: leave the Pluto off.
    close = power_down

    def __getattr__(self, name):
        if name.startswith("__") or "_lock" not in vars(self):
            raise AttributeError(name)
        self.power_up()
        return getattr(self._pluto, name)

    def __setattr__(self, name, value):
        self.power_up()
        setattr(self._pluto, name, value)


def is_poe(init):
    return str(init.get("poe", init.get("POE", ""))).strip().lower() in ("true", "yes", "1")


def poe_pluto_from_init(init):
    """A PoE Pluto from a devices.yml ``init:`` block, switched off (its default state).

    init: serial, poe: true, ip (the Pluto's static ipaddr_eth), poe_port (switch
    port, e.g. ether5), optional poe_switch (192.168.88.1) and poe_user (admin).
    The switch password is read from <config root>/poe_switch_password.
    """
    ip = str(init.get("ip") or "").strip()
    port = str(init.get("poe_port") or "").strip()
    if not ip or not port:
        raise ValueError("a PoE Pluto needs init.ip and init.poe_port")
    pw_file = get_remoterf_root() / "poe_switch_password"
    pluto = PoePluto(
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
        print(f"Warning: could not switch PoE Pluto {pluto.uri} off on {port}: {e}")
    return pluto
