import shutil
from pathlib import Path

from dev_versions import main

ROOT = Path(__file__).resolve().parents[2]


def copy(tmp_path):
    for d in ["packages/remoterf-federation-core", "packages/remoterf-device-core", "server", "host", "client"]:
        (tmp_path / d).mkdir(parents=True)
        shutil.copy(ROOT / d / "pyproject.toml", tmp_path / d / "pyproject.toml")
    return tmp_path


def test_app_only(tmp_path):
    root = copy(tmp_path)
    assert main(7, ["server/src/x.py", "README.md"], root) == {"server": "1.7.6.dev7"}
    assert 'version = "1.7.6.dev7"' in (root / "server/pyproject.toml").read_text()
    assert main(7, [".github/workflows/ci.yml"], copy(tmp_path / "b")) == {}


def test_core_rebuilds_exact_pinners(tmp_path):
    root = copy(tmp_path)
    out = main(3, ["packages/remoterf-federation-core/src/a.py"], root)
    assert out == {"packages/remoterf-federation-core": "0.22.1.dev3", "server": "1.7.6.dev3", "host": "1.3.4.dev3"}
    assert '"remoterf-federation-core==0.22.1.dev3"' in (root / "server/pyproject.toml").read_text()
    assert '"remoterf-federation-core==0.16.0"' in (root / "client/pyproject.toml").read_text()
