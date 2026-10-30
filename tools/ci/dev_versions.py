"""Give the packages changed on this branch unique .devN versions, in place, before building.

    git diff --name-only origin/main...HEAD | python tools/ci/dev_versions.py <run_number>

Scheme: <major>.<minor>.<patch+1>.dev<run_number> (a .dev of the released version would sort
below it). A changed core under packages/ also gets its exact pins in server/, host/ and client/
rewritten to the new version, and those dependents are rebuilt. Prints `<dir>=<version>` for
each package to build, cores first.
"""

import re
import sys
import tomllib
from pathlib import Path

CORES = ["packages/remoterf-federation-core", "packages/remoterf-device-core"]
APPS = ["server", "host", "client"]


def dev_version(base, run):
    major, minor, patch = base.split(".")
    return f"{major}.{minor}.{int(patch) + 1}.dev{run}"


def main(run, changed, root=Path(".")):
    def meta(d):
        project = tomllib.loads((root / d / "pyproject.toml").read_text())["project"]
        return project["name"], project["version"]

    def touched(d):
        return any(f.startswith(d + "/") for f in changed)

    def set_version(d, base, new):
        p = root / d / "pyproject.toml"
        text, n = re.subn(rf'^version = "{re.escape(base)}"$', f'version = "{new}"', p.read_text(), count=1, flags=re.M)
        assert n == 1, f"{p}: no version line for {base}"
        p.write_text(text)

    out, rebuild = {}, set()
    for d in CORES:
        if not touched(d):
            continue
        name, base = meta(d)
        new = out[d] = dev_version(base, run)
        set_version(d, base, new)
        for app in APPS:
            p = root / app / "pyproject.toml"
            text = p.read_text()
            if f'"{name}=={base}"' in text:  # only exact pins of the current release follow
                p.write_text(text.replace(f'"{name}=={base}"', f'"{name}=={new}"'))
                rebuild.add(app)
    for d in APPS:
        if touched(d) or d in rebuild:
            _, base = meta(d)
            out[d] = dev_version(base, run)
            set_version(d, base, out[d])
    return out


if __name__ == "__main__":
    built = main(int(sys.argv[1]), [line.strip() for line in sys.stdin if line.strip()])
    for d, v in built.items():
        print(f"{d}={v}")
