from __future__ import annotations

import threading
from unittest import mock

from remoteRF_host.common.grpc import grpc_host_pb2 as pb
from remoteRF_host.server import device_manager
from remoteRF_host.server.tunnel_agent import HostTunnelAgent


def _agent(*gids: int) -> HostTunnelAgent:
    agent = HostTunnelAgent.__new__(HostTunnelAgent)
    agent._devices = {gid: {} for gid in gids}
    return agent


def test_reservation_start_queues_the_prepare() -> None:
    with mock.patch("remoteRF_host.server.tunnel_agent.prepare_reservation") as prepare:
        _agent(7)._handle_control(pb.Control(kind="reservation_start", device_id="7"))
    prepare.assert_called_once_with(7)


def test_reservation_start_for_unknown_gid_only_warns() -> None:
    with mock.patch("remoteRF_host.server.tunnel_agent.prepare_reservation") as prepare, mock.patch(
        "remoteRF_host.server.tunnel_agent.warn"
    ) as warn:
        _agent(7)._handle_control(pb.Control(kind="reservation_start", device_id="8"))
    prepare.assert_not_called()
    warn.assert_called_once_with(
        "reservation_start for unknown gid=8", component="hostrf.tunnel_agent"
    )


def test_hooks_run_in_order_off_the_caller_and_never_block_it() -> None:
    gid = 7001
    order = []
    release = threading.Event()

    class Schema:
        def prepare_for_holder(self) -> None:
            assert release.wait(2)  # a slow boot
            order.append(("prepare", threading.current_thread() is threading.main_thread()))

        def reset_for_next_holder(self) -> None:
            order.append(("reset", threading.current_thread() is threading.main_thread()))

    device_manager._devices[gid] = device_manager._DeviceState(
        schema=Schema(), name="test-device", ident="", dtype="test", init={}
    )
    try:
        first = device_manager.prepare_reservation(gid)
        second = device_manager.end_reservation(gid)  # returns at once, though the boot still runs
        assert not first.done() and not second.done()
        release.set()
        second.result(2)
        assert order == [("prepare", False), ("reset", False)]
        assert device_manager.prepare_reservation(99999) is None  # no such device
    finally:
        release.set()
        device_manager._devices.pop(gid, None)
        device_manager._reservation_hooks.pop(gid, None)
