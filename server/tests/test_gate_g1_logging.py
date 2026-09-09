from unittest.mock import Mock, patch

import numpy as np

from remoteRF_server.common.utils import map_arg
from remoteRF_server.server import reservation


class ImmediateThread:
    def __init__(self, *, target, args=(), **_kwargs):
        self.target = target
        self.args = args

    def start(self):
        self.target(*self.args)


def test_actual_activity_wrapper_never_persists_enrollment_credentials(tmp_path):
    log_path = tmp_path / "activity.npy"
    handler = object.__new__(reservation.ReservationHandler)
    outcomes = [
        {"UC": map_arg("confirmed")},
        {"UE": map_arg("rejected")},
        {"UE": map_arg("rejected")},
    ]
    handler._original_handle_call = Mock(side_effect=outcomes)
    secrets = (
        "rrf2.reusable-destination-code",
        "ordinary-local-enrollment-code",
        "another-rejected-code",
    )
    with (
        patch.object(reservation, "LOG_PATH", log_path),
        patch.object(reservation.threading, "Thread", ImmediateThread),
    ):
        for value in secrets:
            reservation.handle_call_wrapper(
                handler,
                function_name="set_enroll",
                args={
                    "un": map_arg("alice"),
                    "pw": map_arg("password-secret"),
                    "ec": map_arg(value),
                },
            )
    persisted = repr(np.load(log_path, allow_pickle=True).tolist())
    for secret in (*secrets, "password-secret"):
        assert secret not in persisted
    assert persisted.count("set_enroll") == 3
