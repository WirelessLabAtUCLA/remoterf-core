from pathlib import Path

from remoteRF_server.host.host_directory_store import cfg_dir_from_file


def test_host_directory_uses_explicit_server_config_dir(monkeypatch, tmp_path):
    configured = tmp_path / "writable-server-config"
    monkeypatch.setenv("REMOTERF_CONFIG_DIR", str(configured))

    installed_module = "/usr/local/lib/python3.12/site-packages/remoteRF_server/host/module.py"

    assert cfg_dir_from_file(installed_module) == configured


def test_host_directory_preserves_repo_local_fallback(monkeypatch):
    monkeypatch.delenv("REMOTERF_CONFIG_DIR", raising=False)

    module = "/workspace/RemoteRF-Server/src/remoteRF_server/host/module.py"

    assert cfg_dir_from_file(module) == Path("/workspace/RemoteRF-Server/.config")
