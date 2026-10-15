"""`schema browse` / `schema download`: RemoteRF Global's approved driver
schemas, for a lab on Global only, each download checked against its hash."""

import json

import pytest

from remoteRF_server.server import commands, global_onboarding, schema_registry


def _schema(device_type="lab_radio", version="0.1.0"):
    schema = {"schema_version": "1.0", "device_type": device_type, "driver_version": version,
              "getters": {"get_gain": {}}, "setters": {}, "calls": {}}
    return {**schema, "schema_hash": schema_registry.digest(schema)}


@pytest.fixture
def lab(tmp_path, monkeypatch):
    approved = [_schema(), _schema("gps", "1.0"), _schema("gps", "1.1")]
    asked = []

    def call(method, path, payload=None, **_):
        asked.append((method, path, payload))
        if payload == {"registry": "browse"}:
            return {"schemas": [{"schema_hash": s["schema_hash"], "device_type": s["device_type"], "schema_version": "1.0",
                                 "driver_version": s["driver_version"], "deployment_name": "UCLA",
                                 "approved_at": 1800000000} for s in approved]}
        found = next(s for s in approved if s["schema_hash"] == payload["schema_hash"])
        return {"schema_hash": found["schema_hash"], "deployment_name": "UCLA", "schema": dict(found)}

    monkeypatch.setattr(global_onboarding, "state", lambda: "active")
    monkeypatch.setattr(global_onboarding, "call", call)
    monkeypatch.setattr(schema_registry, "registry_dir", lambda: tmp_path / "drivers" / "registry")
    return type("Lab", (), {"approved": approved, "asked": asked, "dir": tmp_path / "drivers" / "registry"})


def test_a_lab_off_global_is_told_it_needs_global(monkeypatch, capsys):
    monkeypatch.setattr(global_onboarding, "state", lambda: "unregistered")
    monkeypatch.setattr(global_onboarding, "call", lambda *a, **k: pytest.fail("asked Global"))
    assert commands.dispatch(["schema", "browse"], in_daemon=False) == 2
    assert commands.dispatch(["schemas", "download", "gps"], in_daemon=False) == 2
    assert capsys.readouterr().out.count("put this lab on Global first (global join)") == 2


def test_browse_lists_the_approved_schemas(lab, capsys):
    assert schema_registry.cmd_browse(["gps"]) == 0
    out = capsys.readouterr().out
    assert "gps" in out and "lab_radio" not in out and "UCLA" in out and "2027-01-15" in out
    assert lab.approved[1]["schema_hash"][7:19] in out
    assert lab.asked == [("POST", "/v2/broker/deployments/me", {"registry": "browse"})]


def test_download_checks_the_hash_and_never_replaces_a_file_unasked(lab, capsys, monkeypatch):
    assert schema_registry.cmd_download(["lab_radio"]) == 0
    [saved] = lab.dir.iterdir()
    assert json.loads(saved.read_text()) == lab.approved[0]
    assert "interface only" in capsys.readouterr().out

    assert schema_registry.cmd_download(["gps"]) == 2  # two approved gps schemas: name one by its hash
    assert "by its hash" in capsys.readouterr().out
    assert schema_registry.cmd_download([lab.approved[2]["schema_hash"][7:19]]) == 0

    saved.write_text("edited\n")
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    assert schema_registry.cmd_download(["lab_radio"]) == 1 and saved.read_text() == "edited\n"
    assert schema_registry.cmd_download(["lab_radio", "-y"]) == 0 and json.loads(saved.read_text()) == lab.approved[0]

    lab.approved[0]["getters"]["get_secret"] = {}  # Global sends other content than the approved hash names
    assert schema_registry.cmd_download(["lab_radio", "-y"]) == 1
    assert "does not match" in capsys.readouterr().out


def test_text_a_lab_chose_never_reaches_the_terminal_raw(lab, capsys):
    lab.approved[0]["driver_version"] = "1.0\x1b]52;c;cGF5bG9hZA==\x07\nfake line"
    assert schema_registry.cmd_browse([]) == 0
    assert "\x1b" not in capsys.readouterr().out
    from remoteRF_server.server.global_onboarding import client_is_current

    assert not client_is_current("9" * 5000 + ".1")  # never an int() of any length
