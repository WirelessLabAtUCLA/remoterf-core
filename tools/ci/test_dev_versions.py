import shutil
import tomllib
from pathlib import Path

from dev_versions import main

ROOT = Path(__file__).resolve().parents[2]


def copy(tmp_path):
    for d in ["packages/remoterf-federation-core", "packages/remoterf-device-core", "server", "host", "client"]:
        (tmp_path / d).mkdir(parents=True)
        shutil.copy(ROOT / d / "pyproject.toml", tmp_path / d / "pyproject.toml")
    return tmp_path


def version(root, d):
    return tomllib.loads((root / d / "pyproject.toml").read_text())["project"]["version"]


def bump(v):
    major, minor, patch = v.split(".")
    return f"{major}.{minor}.{int(patch) + 1}"


def test_app_only(tmp_path):
    root = copy(tmp_path)
    want = bump(version(root, "server")) + ".dev7"
    assert main(7, ["server/src/x.py", "README.md"], root, lambda d: None) == {"server": want}
    assert f'version = "{want}"' in (root / "server/pyproject.toml").read_text()
    assert main(7, [".github/workflows/ci.yml"], copy(tmp_path / "b"), lambda d: None) == {}


def test_branch_already_bumped_builds_that_version(tmp_path):
    root = copy(tmp_path)
    released = version(root, "server")
    p = root / "server/pyproject.toml"
    p.write_text(p.read_text().replace(f'version = "{released}"', f'version = "{bump(released)}"', 1))
    out = main(9, ["server/src/x.py"], root, lambda d: released if d == "server" else None)
    assert out == {"server": bump(released) + ".dev9"}


def test_core_rebuilds_exact_pinners(tmp_path):
    root = copy(tmp_path)
    core = "packages/remoterf-federation-core"
    fed = bump(version(root, core)) + ".dev3"
    out = main(3, [f"{core}/src/a.py"], root, lambda d: None)
    assert out == {core: fed, "server": bump(version(ROOT, "server")) + ".dev3",
                   "host": bump(version(ROOT, "host")) + ".dev3"}
    assert f'"remoterf-federation-core=={fed}"' in (root / "server/pyproject.toml").read_text()
    assert "remoterf-federation-core==" + version(ROOT, core) not in (root / "client/pyproject.toml").read_text()
