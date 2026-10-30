from remoteRF_server import serverrf_cli
from remoteRF_server.server import control


def test_wipe_deletes_config_and_identity_only_when_stopped(tmp_path, monkeypatch):
    cfg, ident, other = tmp_path / "cfg", tmp_path / "share" / "identity", tmp_path / "other"
    for d in (cfg / "db", cfg / "certs", ident, other):
        d.mkdir(parents=True)
    (cfg / "db" / "usergroups.db").write_text("x")
    monkeypatch.setenv("REMOTERF_CONFIG_DIR", str(cfg))
    monkeypatch.delenv("REMOTERF_CERT_DIR", raising=False)
    monkeypatch.setenv("REMOTERF_FEDERATION_IDENTITY_DIR", str(ident))

    monkeypatch.setattr(control, "running", lambda: True)
    assert serverrf_cli.cmd_wipe(["-y"]) == 1
    assert cfg.exists() and ident.exists()

    monkeypatch.setattr(control, "running", lambda: False)
    assert serverrf_cli.cmd_wipe(["-y"]) == 0
    assert not cfg.exists() and not ident.exists() and other.exists()
