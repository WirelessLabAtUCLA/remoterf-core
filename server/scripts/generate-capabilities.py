"""Run with grpcio-tools==1.74.0/protobuf==6.31.1; never regenerate grpc.proto."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
proto = root / "src/remoteRF_server/common/grpc"
core = root.parent / "packages/remoterf-device-core/src/remoterf_device_core/grpc"  # grpc.proto
subprocess.run([sys.executable, "-m", "grpc_tools.protoc", f"-I{proto}", f"-I{core}",
                f"--python_out={proto}", f"--grpc_python_out={proto}",
                str(proto / "deployment_capabilities.proto")], check=True)
for name in ("deployment_capabilities_pb2.py", "deployment_capabilities_pb2_grpc.py"):
    path = proto / name
    text = path.read_text()
    for module in ("grpc_pb2", "deployment_capabilities_pb2"):
        text = text.replace(f"import {module} as ", f"from . import {module} as ")
    path.write_text(text)
