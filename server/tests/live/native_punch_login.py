"""Native Gate I punch, login only (no registration), for A/B on the Client code."""
import sys, time
from pathlib import Path
from remoterf.config.cert_fetcher import fetch_ca_bytes
home, cert_port, user, pw = sys.argv[1:5]
host, port = home.rsplit(":", 1)
cfg = Path.home() / ".config" / "remoterf-client"; (cfg / "certs").mkdir(parents=True, exist_ok=True)
ca = cfg / "certs" / "home.crt"; ca.write_bytes(fetch_ca_bytes(host, int(cert_port), timeout_sec=10))
(cfg / ".env").write_text(f"REMOTERF_ADDR={home}\nREMOTERF_CA_CERT={ca}\nREMOTERF_TLS_SERVER_NAME={host}\nREMOTERF_PROFILE=probe\n")
from remoterf.common.utils import map_arg, unmap_arg
from remoterf.core.grpc_client import rpc_client
from remoterf.core import direct_path
r = rpc_client(function_name="ACC:login", args={"un": map_arg(user), "pw": map_arg(pw)})
print("login", {k: unmap_arg(v) for k, v in r.results.items()})
path = direct_path.start(username=user, secret=pw, route={"kind": "relay", "host": host, "port": int(port)})
t0 = time.monotonic(); ready = path.wait(25)
print("PUNCH", host, "->", ready, path.describe(), f"{time.monotonic()-t0:.1f}s state={path.state} reason={path.reason!r}")
direct_path.stop()
