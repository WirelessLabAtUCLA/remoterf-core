"""`devices list` says where each device lives: a host it came from, or local."""

from types import SimpleNamespace
from unittest.mock import patch

from remoteRF_server.server import grpc_server


def test_devices_list_shows_the_host_of_each_device():
    reg = SimpleNamespace(list_devices=lambda: {
        "1": SimpleNamespace(host_id="lab-nuc", host_local_id=0, last_seen_ms=0),
    })
    with patch.object(grpc_server, "get_all_devices_str", return_value={0: "Pluto A (online)", 1: "a@b (online)"}), \
            patch.object(grpc_server, "handle_report", return_value={0: "Pluto_A"}), \
            patch.object(grpc_server.hts, "get_tunnel_registry", return_value=reg), \
            patch("remoteRF_server.common.utils.panel.print_table") as table:
        grpc_server.get_devices()
    rows = {r["device_id"]: r for r in table.call_args.args[1]}
    assert rows[0]["host"] == "local"
    assert (rows[0]["name"], rows[0]["handle"]) == ("Pluto A (online)", "Pluto_A")
    assert rows[1]["handle"] == "-"
    assert rows[1]["host"] == "lab-nuc #0" and rows[1]["last_seen"] == "-"
