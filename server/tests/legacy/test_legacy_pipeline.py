"""Requirement A: a lab that never joins Global behaves as it did before Global.

Every leg runs legacy_session.py (a real runtime, a real client CLI, raw ACC
calls, the console) and compares it step by step with baseline.json, the same
session against pre-Global Server 1.0.19 (c2b5a41) + Client 2.0.13 (2bab4ab).
The upgrade leg lets 1.0.19 build a lab, then starts today's Server on it.
A step may differ only as recorded in accepted_deltas.json, which the owner
reviews (no entry may stay "TODO"); anything else fails.

    REMOTERF_LEGACY_CHECK=1 .venv/bin/python -m pytest tests/legacy -q

REMOTERF_LEGACY_ACCEPT=1 rewrites accepted_deltas.json with today's
differences (new ones marked "TODO" for review); REMOTERF_LEGACY_BASELINE=1
re-records baseline.json. The pre-Global commits live only on local backup
branches, so legs that need them are skipped where they are missing.
"""

import difflib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SERVER = HERE.parents[1]
CLIENT = Path(os.environ.get("REMOTERF_LEGACY_CLIENT", SERVER.parent / "client"))
CLIENT_PYTHON = os.environ.get("REMOTERF_LEGACY_CLIENT_PYTHON", str(CLIENT / "venv/bin/python"))
SERVER_BASE, CLIENT_BASE = "c2b5a41", "2bab4ab"
BASELINE, ACCEPTED = HERE / "baseline.json", HERE / "accepted_deltas.json"
ACCEPT = os.environ.get("REMOTERF_LEGACY_ACCEPT") == "1"

pytestmark = pytest.mark.skipif(
    os.environ.get("REMOTERF_LEGACY_CHECK") != "1", reason="slow; set REMOTERF_LEGACY_CHECK=1"
)


@pytest.fixture(scope="module")
def trees(tmp_path_factory):
    out = {"server": {"head": SERVER / "src"}, "client": {"head": CLIENT / "src"}}
    for kind, repo, commit in (("server", SERVER, SERVER_BASE), ("client", CLIENT, CLIENT_BASE)):
        target = tmp_path_factory.mktemp(f"{kind}-{commit}")
        archive = subprocess.run(["git", "-C", str(repo), "archive", commit, "src"], capture_output=True)
        if archive.returncode == 0:
            subprocess.run(["tar", "-x", "-C", str(target)], input=archive.stdout, check=True)
            out[kind]["base"] = target / "src"
    return out


def run_leg(trees, tmp_path, server, client=None, home=None) -> dict:
    """One driver run; with `home`, keep the lab there (no client = reopen it)."""
    if server not in trees["server"] or (client and client not in trees["client"]):
        pytest.skip("pre-Global commit not in this checkout")
    out = tmp_path / f"{server}-{client or 'reopen'}.json"
    env = {**os.environ, "PYTHONPATH": str(trees["server"][server])}
    args = [sys.executable, str(HERE / "legacy_session.py"), "--out", str(out)]
    if client:
        args += ["--client-src", str(trees["client"][client]), "--client-python", CLIENT_PYTHON]
    if home:
        env.update(LEGACY_HOME=str(home), LEGACY_REOPEN="" if client else "1")
    done = subprocess.run(args, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)
    assert out.exists() and json.loads(out.read_text())["steps"], done.stdout[-3000:] + done.stderr[-3000:]
    assert done.returncode == 0, done.stderr[-3000:]
    result = json.loads(out.read_text())
    # Prove which code ran: an installed package can shadow a tree on PYTHONPATH.
    assert result["meta"]["server"].startswith(str(trees["server"][server])), result["meta"]
    if client:
        assert result["meta"]["client"].startswith(str(trees["client"][client])), result["meta"]
    return dict(result["steps"])


def test_baseline_is_recorded(trees, tmp_path):
    if os.environ.get("REMOTERF_LEGACY_BASELINE") == "1":
        session = run_leg(trees, tmp_path, "base", "base", home=tmp_path / "lab")
        recorded = {"session": session, "reopen": run_leg(trees, tmp_path, "base", home=tmp_path / "lab")}
        text = json.dumps(recorded, indent=1, ensure_ascii=False)
        for broken in ("Traceback", "[harness: TIMEOUT]", "[harness: 40 prompts", '"no token"', '"no reservation"'):
            assert broken not in text, f"baseline run is broken: {broken}"
        BASELINE.write_text(text + "\n")
    assert BASELINE.exists()


@pytest.mark.parametrize("server,client", [("head", "head"), ("head", "base"), ("base", "head")])
def test_leg_matches_pre_global(trees, tmp_path, server, client):
    check(f"server-{server}+client-{client}", "session", run_leg(trees, tmp_path, server, client))


def test_upgrade_in_place_from_pre_global(trees, tmp_path):
    run_leg(trees, tmp_path, "base", "base", home=tmp_path / "lab")
    check("upgrade-server-base-to-head", "reopen", run_leg(trees, tmp_path, "head", home=tmp_path / "lab"))


def check(leg: str, part: str, got: dict) -> None:
    baseline = json.loads(BASELINE.read_text())[part]
    accepted = json.loads(ACCEPTED.read_text()) if ACCEPTED.exists() else {}
    deltas = {name: got.get(name) for name in sorted(set(baseline) | set(got)) if not same(got.get(name), baseline.get(name))}

    if ACCEPT:
        old = accepted.get(leg, {})
        accepted[leg] = {
            name: old[name] if name in old and same(old[name]["value"], value)
            else {"kind": "review", "why": "TODO", "value": value}
            for name, value in deltas.items()
        }
        ACCEPTED.write_text(json.dumps(accepted, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
        return

    allowed = accepted.get(leg, {})
    unexplained = [name for name, value in deltas.items() if not same(allowed.get(name, {}).get("value", ...), value)]
    assert not unexplained, "\n\n".join(
        _diff(f"accepted {name}", allowed[name]["value"], got.get(name)) if name in allowed
        else _diff(f"pre-Global {name}", baseline.get(name), got.get(name))
        for name in unexplained
    )
    unreviewed = [name for name in deltas if allowed[name]["why"] == "TODO"]
    assert not unreviewed, f"{leg}: accepted_deltas.json still has unreviewed entries: {unreviewed}"


def same(a, b) -> bool:
    return _width_free(a) == _width_free(b)


def _width_free(value):
    """Box borders and padding follow the LAN IP's length (masked as <ip>), not behaviour."""
    if isinstance(value, dict):
        return {k: _width_free(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_width_free(v) for v in value]
    if isinstance(value, str):
        return re.sub(r" +([│╮╯])", r" \1", re.sub(r"─+", "─", value))
    return value


def _diff(label, before, after) -> str:
    text = lambda v: (v if isinstance(v, str) else json.dumps(v, indent=1, ensure_ascii=False)).splitlines()  # noqa: E731
    return "\n".join(difflib.unified_diff(text(before), text(after), label, "now", lineterm=""))
