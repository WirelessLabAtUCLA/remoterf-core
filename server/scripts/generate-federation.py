"""Generate only the additive Gate E bindings; never regenerate grpc.proto."""

from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
proto = root / "src/remoteRF_server/common/grpc"
subprocess.run(
    [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        f"-I{proto}",
        f"--python_out={proto}",
        f"--grpc_python_out={proto}",
        str(proto / "federation.proto"),
    ],
    check=True,
)
for name in ("federation_pb2.py", "federation_pb2_grpc.py"):
    path = proto / name
    content = path.read_text()
    for module in ("grpc_pb2", "federation_pb2"):
        content = content.replace(f"import {module} as ", f"from . import {module} as ")
    path.write_text(content)
