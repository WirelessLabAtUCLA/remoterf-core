"""Typed Dynamic v2 errors and protobuf envelope conversion."""
from __future__ import annotations

import json
from typing import Any

from ..common.grpc import grpc_pb2


class RemoteRFError(Exception):
    code = "RemoteRFError"
    retryable = False
    fatal_to_session = False

    def __init__(self, message: str, *, details: dict[str, Any] | None = None, method: str = ""):
        super().__init__(message)
        self.details = dict(details or {})
        self.method = method


class RemoteRFTransportError(RemoteRFError):
    code = "RemoteRFTransportError"
    retryable = True


class RemoteRFSessionExpiredError(RemoteRFError):
    code = "RemoteRFSessionExpiredError"
    fatal_to_session = True


class RemoteRFReservationError(RemoteRFError):
    code = "RemoteRFReservationError"
    fatal_to_session = True


class RemoteRFPolicyError(RemoteRFError):
    code = "RemoteRFPolicyError"


class RemoteRFStaleHandleError(RemoteRFError):
    code = "RemoteRFStaleHandleError"


class RemoteRFProtocolError(RemoteRFError):
    code = "RemoteRFProtocolError"


class RemoteRFOverloadError(RemoteRFError):
    code = "RemoteRFOverloadError"


class RemoteRFServerOverloadedError(RemoteRFError):
    code = "RemoteRFServerOverloadedError"
    retryable = True


class RemoteRFNativeUHDError(RemoteRFError):
    code = "RemoteRFNativeUHDError"

    def __init__(
        self,
        message: str,
        *,
        native_exception: str = "",
        uhd_version: str = "",
        details: dict[str, Any] | None = None,
        method: str = "",
    ):
        super().__init__(message, details=details, method=method)
        self.native_exception = native_exception
        self.uhd_version = uhd_version


def error_envelope(exc: Exception, *, method: str = "", uhd_version: str = ""):
    if isinstance(exc, RemoteRFError):
        code = exc.code
        details = exc.details
        retryable = exc.retryable
        fatal = exc.fatal_to_session
        native_exception = getattr(exc, "native_exception", "")
        uhd_version = getattr(exc, "uhd_version", "") or uhd_version
        method = exc.method or method
    else:
        code = RemoteRFNativeUHDError.code
        details = {}
        retryable = False
        fatal = False
        native_exception = f"{type(exc).__module__}.{type(exc).__name__}"

    return grpc_pb2.ErrorEnvelope(
        code=code,
        message=str(exc),
        details_json=json.dumps(details, sort_keys=True, separators=(",", ":")),
        method=method,
        native_exception=native_exception,
        uhd_version=uhd_version,
        retryable=retryable,
        fatal_to_session=fatal,
    )
