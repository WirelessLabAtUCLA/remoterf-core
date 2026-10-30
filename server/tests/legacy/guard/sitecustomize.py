"""Legacy harness: record, and refuse, any traffic leaving this machine.

Loaded by the driver and, through PYTHONPATH, by every client it spawns.
Covers Python DNS and TCP, gRPC channels (C-core resolves on its own) and the
ssh child the Global relay would start. A UDP `connect` sends nothing, so it
is left alone.
"""
import os
import socket
import subprocess

_LOG = os.environ.get("LEGACY_EGRESS_LOG")

if _LOG:
    _LOCAL = {"localhost", "127.0.0.1", "::1", "0.0.0.0", os.environ.get("LEGACY_LAN_IP", "")}

    def _refuse(what: str):
        with open(_LOG, "a", encoding="utf-8") as f:
            f.write(f"{what}\n")
        return OSError(f"blocked by the legacy harness: {what}")

    def _host(name) -> str:
        return name.decode() if isinstance(name, bytes) else str(name)

    def _resolver(original):
        def resolve(host, *args, **kwargs):
            if _host(host) not in _LOCAL:
                _refuse(_host(host))
                raise socket.gaierror(socket.EAI_NONAME, "blocked by the legacy harness")
            return original(host, *args, **kwargs)
        return resolve

    for _name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        setattr(socket, _name, _resolver(getattr(socket, _name)))

    def _tcp(original):
        def connect(self, address):
            if self.type == socket.SOCK_STREAM and isinstance(address, tuple) and address[0] not in _LOCAL:
                raise _refuse(address[0])
            return original(self, address)
        return connect

    socket.socket.connect = _tcp(socket.socket.connect)
    socket.socket.connect_ex = _tcp(socket.socket.connect_ex)

    _popen_init = subprocess.Popen.__init__

    def _popen(self, args, *a, **k):
        argv = [args] if isinstance(args, (str, bytes)) else list(args)
        program = os.path.basename(_host(argv[0]).split()[0]) if argv else ""
        if program in {"ssh", "autossh"}:
            raise _refuse(f"exec:{program}")
        return _popen_init(self, args, *a, **k)

    subprocess.Popen.__init__ = _popen

    try:
        import grpc
    except ImportError:
        grpc = None
    if grpc is not None:
        def _channel(original):
            def channel(target, *args, **kwargs):
                where = target.split("///")[-1].rsplit(":", 1)[0].strip("[]")
                if where.startswith(("ipv4:", "ipv6:")):
                    where = where.split(":", 1)[1]
                if where not in _LOCAL:
                    raise _refuse(f"grpc:{where}")
                return original(target, *args, **kwargs)
            return channel

        grpc.secure_channel = _channel(grpc.secure_channel)
        grpc.insecure_channel = _channel(grpc.insecure_channel)
