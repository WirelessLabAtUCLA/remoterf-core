"""Gate H destination handlers for the federated device plane.

A federation peer never reaches hardware directly. Every action below runs
only after the destination executor has verified a one-time Ed25519 grant
bound to an active bilateral contract that allows the matching capability,
and every action then re-derives authorization from this deployment's own
tables: the proxy account for the remote subject, its local group/role
permissions, and its local reservations. The HOME's opinion is never trusted
for any of that, and the hardware bearer token this deployment mints for a
reservation is never returned to the HOME.

Discovery and reservation reuse the ordinary local code paths, so quotas,
overlap, and Policy B eligibility behave exactly as they do natively. A
device RPC is executed after the grant transaction commits, so a long
hardware call never holds the federation write lock, and it cannot be
replayed because the grant's JTI was already consumed.
"""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from remoterf_federation_core import (
    DeviceProtocolError,
    canonical_json,
    canonical_uuid,
    decode_device_b64,
    empty_device_payload,
    encode_device_b64,
    MAX_DEVICE_ACTION_REQUEST_BYTES,
    MAX_DEVICE_RESULT_BYTES,
)

from ...common.grpc import grpc_pb2
from ...common.utils import map_arg
from .destination import FINALIZE_PENDING, FederationBusinessError
from .migrations import configure_connection, migrate_gate_h_reservations_schema

# A device RPC frame must survive the base64 round trip inside the action
# request; the raw protobuf ceiling is therefore the decoded size.
MAX_DEVICE_RPC_REQUEST_BYTES = (MAX_DEVICE_ACTION_REQUEST_BYTES // 4) * 3
MAX_DEVICE_RPC_RESPONSE_BYTES = (MAX_DEVICE_RESULT_BYTES // 4) * 3


class _DeviceHandlerBase:
    """Shared destination-local resolution for every device action."""

    action = ""

    def __init__(
        self,
        *,
        reservations_path,
        local_deployment_id,
        display_name,
        clock=None,
        reservation_handler=None,
        rpc_manager=None,
    ):
        self.reservations_path = Path(reservations_path)
        self.local_deployment_id = canonical_uuid(local_deployment_id)
        self.display_name = str(display_name)
        self.clock = clock or (lambda: int(time.time()))
        self._reservation_handler = reservation_handler
        self._rpc_manager = rpc_manager
        with sqlite3.connect(self.reservations_path, timeout=10.0) as conn:
            configure_connection(conn)
            migrate_gate_h_reservations_schema(conn)

    # -- destination-local resolution ---------------------------------

    @property
    def reservations(self):
        if self._reservation_handler is None:
            from ..reservation import reservation_handler

            self._reservation_handler = reservation_handler
        return self._reservation_handler

    @property
    def rpc(self):
        if self._rpc_manager is None:
            from ..rpc_manager import rpc_manager

            self._rpc_manager = rpc_manager
        return self._rpc_manager

    @staticmethod
    def _principal(tx, claims) -> tuple[str, int]:
        """Return (principal_id, local_account_id) for an active proxy only.

        A device action never allocates a principal. A remote subject that has
        not completed federated enrollment at this deployment simply has no
        local identity here, and is refused.  The lookup runs on the executor's
        own usergroups transaction, which is where FederatedPrincipals lives,
        so it is serialized with the authorization decision that admitted it.
        """

        row = tx.execute(
            "SELECT id, local_account_id, status FROM FederatedPrincipals "
            "WHERE issuer_deployment_id = ? AND remote_subject_id = ?",
            (claims["iss"], claims["sub"]),
        ).fetchone()
        if row is None:
            raise FederationBusinessError("principal_unknown")
        if row[2] != "active":
            raise FederationBusinessError("principal_disabled")
        return str(row[0]), int(row[1])

    # -- result shaping ------------------------------------------------

    def _ok(self, action, payload, *, now):
        return {
            "status": "ok",
            "error_code": None,
            "deployment_id": self.local_deployment_id,
            "display_name": self.display_name,
            "contract_id": action.claims["contract_id"],
            "contract_version": action.claims["contract_version"],
            "state": action.state,
            "retrieved_at": now,
            "payload": payload,
        }

    def _receipt(self, tx, action, *, code, principal_id, device_id=None, reservation_id=None):
        claims = action.claims
        tx.execute(
            "INSERT OR IGNORE INTO FederatedDeviceReceipts"
            "(receipt_id,issuer_deployment_id,remote_subject_id,request_id,action,"
            "local_device_id,reservation_id,contract_id,contract_version,occurred_at,"
            "result_code) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                claims["iss"],
                claims["sub"],
                claims["request_id"],
                self.action,
                None if device_id is None else int(device_id),
                None if reservation_id is None else int(reservation_id),
                claims["contract_id"],
                claims["contract_version"],
                int(self.clock()),
                code,
            ),
        )

    def _audit(self, tx, action, *, code, principal_id=None, metadata=None):
        claims = action.claims
        tx.execute(
            "INSERT INTO FederationAuditEvents"
            "(id,occurred_at,actor_kind,actor_ref,event_type,principal_id,contract_id,"
            "version,request_id,result_code,metadata_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                int(self.clock()),
                "deployment",
                claims["iss"],
                self.action,
                principal_id,
                claims["contract_id"],
                claims["contract_version"],
                claims["request_id"],
                code,
                canonical_json(metadata or {}),
            ),
        )


class ServerDeviceListHandler(_DeviceHandlerBase):
    """Report only the devices this principal is locally permitted to see."""

    action = "device_list"

    def __call__(self, tx, action):
        now = int(self.clock())
        principal_id, account_id = self._principal(tx, action.claims)
        devices = self.reservations.federated_visible_devices(
            local_account_id=account_id
        )
        self._audit(
            tx,
            action,
            code="ok",
            principal_id=principal_id,
            metadata={"device_count": len(devices)},
        )
        return self._ok(action, {"devices": devices}, now=now)


class ServerDeviceReservationsHandler(_DeviceHandlerBase):
    """Report reservations on devices this principal may see."""

    action = "device_reservations"

    def __call__(self, tx, action):
        now = int(self.clock())
        principal_id, account_id = self._principal(tx, action.claims)
        reservations = self.reservations.federated_reservations(
            local_account_id=account_id
        )
        self._audit(
            tx,
            action,
            code="ok",
            principal_id=principal_id,
            metadata={"reservation_count": len(reservations)},
        )
        return self._ok(action, {"reservations": reservations}, now=now)


class ServerDeviceReserveHandler(_DeviceHandlerBase):
    """Create a reservation through the ordinary local validation path."""

    action = "device_reserve"

    def __call__(self, tx, action):
        now = int(self.clock())
        claims = action.claims
        payload = action.request.value["payload"]
        principal_id, account_id = self._principal(tx, claims)
        outcome = self.reservations.federated_reserve(
            local_account_id=account_id,
            device_id=int(payload["local_device_id"]),
            start_time=datetime.fromtimestamp(payload["start_time"]),
            end_time=datetime.fromtimestamp(payload["end_time"]),
            issuer_deployment_id=claims["iss"],
            remote_subject_id=claims["sub"],
            contract_id=claims["contract_id"],
            contract_version=claims["contract_version"],
            request_id=claims["request_id"],
        )
        if "error" in outcome:
            raise FederationBusinessError(outcome["error"])
        self._receipt(
            tx,
            action,
            code="ok",
            principal_id=principal_id,
            device_id=int(payload["local_device_id"]),
            reservation_id=int(outcome["reservation_id"]),
        )
        self._audit(tx, action, code="ok", principal_id=principal_id)
        # Make the reservation effective on the device immediately, exactly as
        # the native reserve path does.
        try:
            self.reservations.update_devices()
        except Exception:
            pass
        return self._ok(action, {"reservation": outcome}, now=now)


class ServerDeviceCancelHandler(_DeviceHandlerBase):
    """Cancel only a federation-created reservation this principal owns."""

    action = "device_cancel"

    def __call__(self, tx, action):
        now = int(self.clock())
        payload = action.request.value["payload"]
        principal_id, account_id = self._principal(tx, action.claims)
        outcome = self.reservations.federated_cancel(
            local_account_id=account_id,
            reservation_id=int(payload["reservation_id"]),
        )
        if "error" in outcome:
            raise FederationBusinessError(outcome["error"])
        self._receipt(
            tx,
            action,
            code="ok",
            principal_id=principal_id,
            reservation_id=int(payload["reservation_id"]),
        )
        self._audit(tx, action, code="ok", principal_id=principal_id)
        try:
            self.reservations.update_devices()
        except Exception:
            pass
        return self._ok(action, {"cancelled": True}, now=now)


class ServerDeviceRpcHandler(_DeviceHandlerBase):
    """Run one ordinary device RPC on behalf of a reserved federated principal.

    Authorization is decided and the grant's JTI consumed inside the executor's
    transaction; the hardware call itself runs in finalize(), after commit, so
    a slow radio never holds the federation write lock and a replayed grant is
    already rejected before any hardware is touched.
    """

    action = "device_rpc"

    # The one control-plane RPC a federated caller may run without a live
    # reservation: it returns the driver schema the Client needs to install a
    # driver before its reservation starts.  Natively this RPC is reachable by
    # anyone who knows a device id, so gating it on local visibility is
    # strictly tighter, not looser.
    IDL_FUNCTION = "IDL:get_drivers"

    @staticmethod
    def _parse_frame(payload):
        raw = decode_device_b64(
            payload["request_b64"],
            code="invalid_device_request",
            max_bytes=MAX_DEVICE_ACTION_REQUEST_BYTES,
        )
        if len(raw) > MAX_DEVICE_RPC_REQUEST_BYTES:
            raise FederationBusinessError("request_too_large")
        try:
            request = grpc_pb2.GenericRPCRequest()
            request.ParseFromString(raw)
        except Exception:
            raise FederationBusinessError("invalid_device_request") from None
        function_name = str(request.function_name)
        if function_name != ServerDeviceRpcHandler.IDL_FUNCTION:
            parts = function_name.split(":", 2)
            if len(parts) != 3 or not all(parts):
                raise FederationBusinessError("unsupported_device_rpc")
        return function_name, dict(request.args)

    def __call__(self, tx, action):
        now = int(self.clock())
        claims = action.claims
        payload = action.request.value["payload"]
        device_id = int(payload["local_device_id"])
        principal_id, account_id = self._principal(tx, claims)
        function_name, _args = self._parse_frame(payload)

        if function_name == self.IDL_FUNCTION:
            visible = {
                int(entry["local_device_id"])
                for entry in self.reservations.federated_visible_devices(
                    local_account_id=account_id
                )
            }
            if device_id not in visible:
                raise FederationBusinessError("device_not_visible")
        elif not self.reservations.federated_active_reservation(
            local_account_id=account_id, device_id=device_id
        ):
            # Equal local integer IDs across deployments are meaningless here:
            # the reservation is looked up on THIS deployment for THIS proxy.
            raise FederationBusinessError("no_active_reservation")

        self._receipt(
            tx, action, code="authorized", principal_id=principal_id, device_id=device_id
        )
        self._audit(
            tx,
            action,
            code="authorized",
            principal_id=principal_id,
            metadata={
                "local_device_id": str(device_id),
                "function_name": function_name[:200],
            },
        )
        # Authorized-but-pending marker; finalize() replaces it with the real
        # response once the hardware call has run.  The executor never signs
        # this marker as-is.
        return {
            **self._ok(action, empty_device_payload("device_rpc"), now=now),
            "status": "error",
            "error_code": FINALIZE_PENDING,
        }

    def finalize(self, action, result):
        payload = action.request.value["payload"]
        device_id = int(payload["local_device_id"])
        function_name, args = self._parse_frame(payload)

        # The HOME never holds this deployment's device bearer token, and a
        # federated caller may not smuggle one in to reach another device.
        args.pop("a", None)
        args.pop("token", None)

        try:
            if function_name == self.IDL_FUNCTION:
                # Pin the schema lookup to the device the grant named; a
                # caller-supplied name or id would otherwise widen it.
                args.pop("device_name", None)
                args["device_id"] = map_arg(int(device_id))
                results = self.rpc.run_rpc(function_name=function_name, args=args)
            else:
                results = self.rpc.run_device_rpc_for_gid(
                    gid=device_id, function_name=function_name, args=args
                )
        except Exception:
            raise FederationBusinessError("device_unavailable") from None

        response = grpc_pb2.GenericRPCResponse(results=results)
        encoded_raw = response.SerializeToString()
        if len(encoded_raw) > MAX_DEVICE_RPC_RESPONSE_BYTES:
            raise FederationBusinessError("response_too_large")
        try:
            encoded = encode_device_b64(
                encoded_raw,
                code="response_too_large",
                max_bytes=MAX_DEVICE_RESULT_BYTES,
            )
        except DeviceProtocolError:
            raise FederationBusinessError("response_too_large") from None
        return {
            **result,
            "status": "ok",
            "error_code": None,
            "payload": {"response_b64": encoded},
        }


def build_device_handlers(
    *,
    reservations_path,
    local_deployment_id,
    display_name,
    clock=None,
    reservation_handler=None,
    rpc_manager=None,
) -> dict:
    common = {
        "reservations_path": reservations_path,
        "local_deployment_id": local_deployment_id,
        "display_name": display_name,
        "clock": clock,
        "reservation_handler": reservation_handler,
        "rpc_manager": rpc_manager,
    }
    return {
        "device_list": ServerDeviceListHandler(**common),
        "device_reservations": ServerDeviceReservationsHandler(**common),
        "device_reserve": ServerDeviceReserveHandler(**common),
        "device_cancel": ServerDeviceCancelHandler(**common),
        "device_rpc": ServerDeviceRpcHandler(**common),
    }


def build_server_gate_h_executor(
    *,
    usergroups_path,
    reservations_path,
    local_deployment_id,
    private_key,
    signing_kid,
    display_name,
    perms_path=None,
    clock=None,
    reservation_handler=None,
    rpc_manager=None,
):
    """Gate G registry plus the five device actions.

    The Gate H usergroups migration runs first because it widens the grant
    replay table's action CHECK; without it a device grant's JTI could not be
    consumed and every device action would fail closed as an internal error.
    """

    from .migrations import migrate_gate_h_usergroups_schema
    from .permissions import build_server_gate_g_executor

    with sqlite3.connect(Path(usergroups_path), timeout=10.0) as conn:
        configure_connection(conn)
        migrate_gate_h_usergroups_schema(conn)
    executor = build_server_gate_g_executor(
        usergroups_path=usergroups_path,
        reservations_path=reservations_path,
        perms_path=perms_path,
        local_deployment_id=local_deployment_id,
        private_key=private_key,
        signing_kid=signing_kid,
        display_name=display_name,
        clock=clock,
    )
    for action, handler in build_device_handlers(
        reservations_path=reservations_path,
        local_deployment_id=local_deployment_id,
        display_name=display_name,
        clock=clock,
        reservation_handler=reservation_handler,
        rpc_manager=rpc_manager,
    ).items():
        executor.registry.register(action, handler)
    return executor
