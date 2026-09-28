"""Native Gate I punch from this machine to a HOME reached over its relay."""
import sys, time
from pathlib import Path
from remoteRF.config.cert_fetcher import fetch_ca_bytes
home, cert_port, user, pw, code = sys.argv[1:6]
host, port = home.rsplit(":", 1)
cfg = Path.home() / ".config" / "remoterf-client"; (cfg / "certs").mkdir(parents=True, exist_ok=True)
ca = cfg / "certs" / "home.crt"; ca.write_bytes(fetch_ca_bytes(host, int(cert_port), timeout_sec=10))
(cfg / ".env").write_text(f"REMOTERF_ADDR={home}\nREMOTERF_CA_CERT={ca}\nREMOTERF_TLS_SERVER_NAME={host}\nREMOTERF_PROFILE=probe\n")
from remoteRF.common.utils import map_arg, unmap_arg
from remoteRF.core.grpc_client import rpc_client
from remoteRF.core import direct_path
def acc(name, **kw):
    r = rpc_client(function_name=f"ACC:{name}", args={k: map_arg(v) for k, v in kw.items()})
    return {k: unmap_arg(v) for k, v in r.results.items()}
print("register", acc("create_user", un=user, pw=pw, em=f"{user}@soak.invalid", ec=code))
print("login", acc("login", un=user, pw=pw))
path = direct_path.start(username=user, secret=pw, route={"kind": "relay", "host": host, "port": int(port)})
t0 = time.monotonic(); ready = path.wait(25)
print("native punch:", ready, path.describe(), f"after {time.monotonic()-t0:.1f}s; state={path.state} reason={path.reason!r}")
direct_path.stop()
