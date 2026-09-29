import json

from remoteRF_server.tools.gist_status import push_status


def test_push_writes_atomic_json_and_swallows_rsync_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("REMOTERF_CONFIG_DIR", str(tmp_path))

    ok = push_status(
        host="unreachable.invalid",
        key=str(tmp_path / "no_such_key"),
        remote="status.json",
        payload={"updated_unix": 1, "reservations": []},
    )

    assert ok is False
    assert [p.name for p in tmp_path.iterdir()] == ["status.json"]
    data = json.loads((tmp_path / "status.json").read_text())
    assert isinstance(data["generated_at"], int)
    assert data["reservations"] == []
